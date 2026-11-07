//! Exact Linux symbols from local debug files or official distribution packages,
//! or derived from the image's own BTF and kallsyms.
mod btf;
pub mod from_image;
mod image_kallsyms;
mod indexes;
mod packages;
mod service;
mod stages;
mod vmcoreinfo;
use crate::bytes::JsonKey as _;
use crate::{
    Job,
    bytes::{le_u16, le_u32, le_u64},
    image::{Image, digest_reader},
    store,
    symbols::{Isf, http, matching},
};
use anyhow::{Context, Result, ensure};
pub use packages::{
    KernelPackage, PackageSource, find_packages, find_packages_with_refresh, local_generated,
    prepare_auto, prepare_package, supports_automatic_banner,
};
use serde_json::json;
pub use service::{Discovery, Generation, GenerationInput, symbol_library};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
const REVISION: &str = "9f14607e0d339d463ea725fbd5c08aa7b7d40f75";
pub const KALI_DEBUG: &str = "https://old.kali.org/kali/pool/main/l/linux/linux-image-6.8.11-arm64-dbg_6.8.11-1kali2_arm64.deb";
const KALI_IMAGE: &str =
    "https://old.kali.org/kali/pool/main/l/linux/linux-image-6.8.11-arm64_6.8.11-1kali2_arm64.deb";
fn read_at(file: &mut File, pos: u64, n: usize) -> Result<Vec<u8>> {
    ensure!(n <= 64 * 1024 * 1024, "ELF section 超过读取上限");
    file.seek(SeekFrom::Start(pos))?;
    let mut bytes = vec![0; n];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn u16le(bytes: &[u8], p: usize) -> Result<u16> {
    le_u16(bytes, p).context("ELF 数据被截断")
}
fn u32le(bytes: &[u8], p: usize) -> Result<u32> {
    le_u32(bytes, p).context("ELF 数据被截断")
}
fn u64le(bytes: &[u8], p: usize) -> Result<u64> {
    le_u64(bytes, p).context("ELF 数据被截断")
}
pub fn elf_metadata(path: &Path) -> Result<(u16, serde_json::Value)> {
    let mut file = File::open(path)?;
    let h = read_at(&mut file, 0, 64)?;
    ensure!(
        h.starts_with(b"\x7fELF\x02\x01\x01"),
        "需要小端 ELF64 调试文件"
    );
    let machine = u16le(&h, 18)?;
    ensure!(matches!(machine, 62 | 183), "ELF 架构不支持");
    let off = u64le(&h, 40)?;
    let size = u16le(&h, 58)? as usize;
    let count = u16le(&h, 60)? as usize;
    ensure!(size >= 64 && count > 0, "ELF section table 缺失");
    let sections = read_at(&mut file, off, size * count)?;
    let mut sizes = serde_json::Map::new();
    for s in sections.chunks_exact(size) {
        if u32le(s, 4)? != 2 {
            continue;
        }
        let link = u32le(s, 40)? as usize;
        ensure!(link < count, "ELF string section 越界");
        let st = sections
            .get(link * size..(link + 1) * size)
            .context("ELF string section 越界")?;
        let strings = read_at(&mut file, u64le(st, 24)?, usize::try_from(u64le(st, 32)?)?)?;
        let symbols = read_at(&mut file, u64le(s, 24)?, usize::try_from(u64le(s, 32)?)?)?;
        let entry = usize::try_from(u64le(s, 56)?)?;
        ensure!(entry >= 24, "ELF symbol entry 无效");
        for symbol in symbols.chunks_exact(entry) {
            let name = u32le(symbol, 0)? as usize;
            let Some(bytes) = strings.get(name..).filter(|bytes| !bytes.is_empty()) else {
                continue;
            };
            let name = bytes
                .split(|b| *b == 0)
                .next()
                .filter(|name| name.len() < bytes.len())
                .context("ELF symbol name 未终止")?;
            let name = std::str::from_utf8(name)?;
            if matches!(name, "sys_call_table" | "compat_sys_call_table") {
                sizes.insert(name.into(), json!(u64le(symbol, 16)?));
            }
        }
    }
    Ok((machine, sizes.into()))
}
fn run(command: &mut Command, job: &Job) -> Result<()> {
    run_limited(command, job, None)
}
fn run_limited(command: &mut Command, job: &Job, output: Option<&File>) -> Result<()> {
    job.check()?;
    let errors = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stderr(errors.try_clone()?)
        .spawn()
        .context("无法启动符号准备工具")?;
    let status = loop {
        let check = job.check().and_then(|_| {
            ensure!(
                output
                    .map(|f| f.metadata().map(|m| m.len() <= 256 * 1024 * 1024))
                    .transpose()?
                    .unwrap_or(true),
                "生成 ISF 超过 256 MiB"
            );
            ensure!(
                errors.metadata()?.len() <= 1024 * 1024,
                "符号准备工具错误输出超过 1 MiB"
            );
            Ok(())
        });
        if let Err(e) = check {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        if let Some(s) = child.try_wait()? {
            break s;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut errors = errors;
    errors.seek(SeekFrom::Start(0))?;
    let mut detail = String::new();
    errors.take(4096).read_to_string(&mut detail)?;
    ensure!(status.success(), "符号准备工具失败: {detail}");
    Ok(())
}
pub fn generate(
    elf: &Path,
    config: &Path,
    tool: &Path,
    image: &Image,
    cache: &Path,
    job: &Job,
) -> Result<PathBuf> {
    job.check()?;
    let _cache_lock = crate::cache::lock(cache, false)?;
    use sha2::{Digest, Sha256};
    let key = serde_json::to_vec(&(
        elf.canonicalize()?,
        config.canonicalize()?,
        tool.canonicalize()?,
    ))?;
    let _build_lock = stages::artifact_lock(
        &cache
            .join("symbols/build/manual")
            .join(format!("{:x}.lock", Sha256::digest(key))),
        "相同调试输入正在生成",
        job,
    )?;
    generate_with_provenance(
        (elf, config, tool),
        image,
        cache,
        job,
        serde_json::Value::Null,
    )
}
fn generate_with_provenance(
    inputs: (&Path, &Path, &Path),
    image: &Image,
    cache: &Path,
    job: &Job,
    provenance: serde_json::Value,
) -> Result<PathBuf> {
    generate_verified(inputs, image, cache, job, provenance, None)
}
#[derive(Clone)]
struct InputDigests {
    elf: String,
    config: String,
    tool: String,
}
fn generate_verified(
    inputs: (&Path, &Path, &Path),
    image: &Image,
    cache: &Path,
    job: &Job,
    provenance: serde_json::Value,
    verified: Option<&InputDigests>,
) -> Result<PathBuf> {
    let (elf, config, tool) = inputs;
    let _lock = crate::cache::lock(cache, false)?;
    let (machine, sizes) = elf_metadata(elf)?;
    let text = fs::read_to_string(config)?;
    let setting = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .map(|s| s.trim_matches('"'))
    };
    let bits = if machine == 183 {
        setting("CONFIG_ARM64_VA_BITS")
            .context("内核配置缺少 CONFIG_ARM64_VA_BITS")?
            .parse::<u8>()?
    } else {
        48
    };
    if machine == 183 {
        ensure!(
            setting("CONFIG_ARM64_4K_PAGES") == Some("y") && matches!(bits, 39 | 48),
            "目前仅支持 ARM64 4 KiB、39／48-bit VA 配置"
        );
    }
    ensure!(
        tool.is_file(),
        "缺少 dwarf2json；指定 --tool，或将固定版本 {REVISION} 编译到 {}",
        tool.display()
    );
    let output = tempfile::NamedTempFile::new()?;
    job.report("从调试 ELF 生成 ISF（可取消）");
    run_limited(
        Command::new(tool)
            .arg("linux")
            .arg("--elf")
            .arg(elf)
            .stdout(output.reopen()?),
        job,
        Some(output.as_file()),
    )?;
    ensure!(
        output.as_file().metadata()?.len() <= 256 * 1024 * 1024,
        "生成 ISF 超过 256 MiB"
    );
    let mut data: serde_json::Value = serde_json::from_reader(output.reopen()?)?;
    ensure!(
        data.is_object() && (data.key("metadata").is_object() || data.key("metadata").is_null()),
        "生成的 ISF 结构无效"
    );
    ensure!(
        data.key("user_types")
            .as_object()
            .is_some_and(|types| !types.is_empty()),
        "调试 ELF 未生成内核类型信息；需要包含 DWARF 的完整调试文件"
    );
    let digests = match verified {
        Some(hashes) => hashes.clone(),
        None => InputDigests {
            elf: digest_reader(File::open(elf)?, job)?,
            config: digest_reader(File::open(config)?, job)?,
            tool: digest_reader(File::open(tool)?, job)?,
        },
    };
    *data.key_mut("metadata")?.key_mut("zero")? = json!({"architecture":if machine==183{"aarch64"}else{"x86_64"},"page_shift":12,"va_bits":bits,"symbol_sizes":sizes,
        "elf_sha256":digests.elf,"config_sha256":digests.config,"dwarf2json_tool_sha256":digests.tool});
    let bytes = serde_json::to_vec(&data)?;
    let isf = Isf::parse(&bytes, "generated".into())?;
    ensure!(
        image.banners(job)?.iter().any(|(_, b)| *b == isf.banner),
        "生成 ISF 的完整 banner 与镜像不匹配"
    );
    if let Some(candidate) = provenance.get("kernel_package") {
        let candidate: KernelPackage = serde_json::from_value(candidate.clone())?;
        ensure!(
            candidate.accepts(String::from_utf8_lossy(&isf.banner).trim_end_matches(['\0', '\n'])),
            "生成 ISF 的完整 banner 不属于选中的内核构建"
        );
    }
    let path = cache
        .join("symbols/isf")
        .join(format!("{}.json.xz", isf.digest));
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&bytes)?;
    job.check()?;
    let compressed = encoder.finish()?;
    let source = path.with_extension("source.json");
    store::atomic_write(
        &source,
        &serde_json::to_vec_pretty(
            &json!({"elf":elf,"config":config,"banner":String::from_utf8_lossy(&isf.banner).trim_end_matches(['\0','\n']),"metadata":*data.key("metadata"),
                "url":provenance.key("kernel_package").key("debug_url"),
                "package_sha256":provenance.key("debug_package_sha256"),"provenance":provenance}),
        )?,
    )?;
    job.check()?;
    store::atomic_write(&path, &compressed)?;
    job.report(format!("已生成精确匹配 ISF: {}", path.display()));
    Ok(path)
}
fn download(url: &str, path: &Path, network: bool, job: &Job) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    ensure!(network, "离线模式且准备文件缺失: {url}");
    let parent = path.parent().context("下载缓存路径无效")?;
    fs::create_dir_all(parent)?;
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    job.report(format!("下载符号准备文件: {url}"));
    http::download(
        http::Request {
            url,
            range: None,
            limit: 8 * 1024 * 1024 * 1024,
            timeout: Duration::from_secs(1800),
            https_only: true,
        },
        temporary.reopen()?,
        job,
    )?;
    job.check()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    Ok(())
}
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const AR_HEADER: usize = 60;
/// Position `package` at the named ar member and return that member's size.
fn ar_member(package: &mut File, wanted: &str) -> Result<u64> {
    let mut magic = [0; AR_MAGIC.len()];
    package.read_exact(&mut magic).context("deb 文件过短")?;
    ensure!(magic == *AR_MAGIC, "不是有效的 deb(ar)文件");
    let total = package.metadata()?.len();
    let mut position = AR_MAGIC.len() as u64;
    loop {
        ensure!(position < total, "deb 缺少成员 {wanted}");
        let mut header = [0; AR_HEADER];
        package.seek(SeekFrom::Start(position))?;
        package
            .read_exact(&mut header)
            .context("deb 成员头被截断")?;
        ensure!(header.ends_with(b"`\n"), "deb 成员头无效");
        let field = |range: std::ops::Range<usize>| {
            header
                .get(range)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::trim_end)
                .context("deb 成员头无效")
        };
        let name = field(0..16)?;
        let size: u64 = field(48..58)?.parse().context("deb 成员大小无效")?;
        let data = position + AR_HEADER as u64;
        ensure!(
            data.checked_add(size).is_some_and(|end| end <= total),
            "deb 成员超出文件范围"
        );
        if name.trim_end_matches('/') == wanted {
            return Ok(size);
        }
        // ar pads each member to an even offset.
        position = data + size + (size & 1);
    }
}
fn plain(path: &str) -> &Path {
    let path = Path::new(path);
    path.strip_prefix(".").unwrap_or(path)
}
fn data_archive(package: &Path) -> Result<Box<dyn Read>> {
    // Probe member names without masking corrupt ar headers as another codec.
    let mut file = File::open(package)?;
    let (name, size) = ar_data_member(&mut file).context(stages::CorruptPackage)?;
    let reader = file.take(size);
    Ok(match name.as_str() {
        "data.tar.xz" => Box::new(xz2::read::XzDecoder::new_multi_decoder(reader)),
        "data.tar.gz" => Box::new(flate2::read::MultiGzDecoder::new(reader)),
        "data.tar.zst" => {
            Box::new(zstd::stream::read::Decoder::new(reader).context(stages::CorruptPackage)?)
        }
        "data.tar" => Box::new(reader),
        _ => anyhow::bail!("不支持的 deb 数据压缩格式: {name}"),
    })
}
fn ar_data_member(file: &mut File) -> Result<(String, u64)> {
    // ar_member validates every header and bound before exposing a member.
    for name in ["data.tar.xz", "data.tar.gz", "data.tar.zst", "data.tar"] {
        file.rewind()?;
        match ar_member(file, name) {
            Ok(size) => return Ok((name.into(), size)),
            Err(e) if e.to_string().starts_with("deb 缺少成员") => {}
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!("deb 缺少成员 data.tar（xz / gz / zst）")
}
/// Copy only the named regular files out of a package under `root`.
/// Names come from the caller, so archive-controlled paths never reach the filesystem.
fn extract(package: &Path, root: &Path, paths: &[&str], job: &Job) -> Result<()> {
    for path in paths {
        ensure!(
            plain(path)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
            "提取路径无效"
        );
    }
    let mut archive = tar::Archive::new(data_archive(package)?);
    let mut missing: Vec<&str> = paths.to_vec();
    for entry in archive.entries().context(stages::CorruptPackage)? {
        job.check()?;
        let mut entry = entry.context(stages::CorruptPackage)?;
        let name = entry.path()?.into_owned();
        // Packages name members `./boot/x` or `boot/x`; the two are the same file.
        let same = |path: &&str| name.strip_prefix(".").unwrap_or(&name) == plain(path);
        let Some(index) = missing.iter().position(same) else {
            continue;
        };
        let path = missing.swap_remove(index);
        copy_entry(&mut entry, &root.join(path), job)?;
        if missing.is_empty() {
            return Ok(());
        }
    }
    anyhow::bail!("deb 数据包缺少文件: {}", missing.join(", "))
}
fn copy_entry<R: Read>(entry: &mut tar::Entry<'_, R>, target: &Path, job: &Job) -> Result<()> {
    ensure!(
        entry.header().entry_type().is_file(),
        "{} 不是普通文件",
        target.display()
    );
    ensure!(entry.size() <= 8 * 1024 * 1024 * 1024, "调试文件超过 8 GiB");
    store::atomic_stream(target, job, |writer| {
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            job.check()?;
            let n = entry.read(&mut buffer).context(stages::CorruptPackage)?;
            if n == 0 {
                break;
            }
            writer.write_all(buffer.get(..n).context("读取 deb 数据失败")?)?;
        }
        Ok(())
    })
}
/// Executable lookup without running it; `path` is the `PATH` value to search.
fn on_path(tool: &str, path: Option<&std::ffi::OsStr>) -> bool {
    let name = format!("{tool}{}", std::env::consts::EXE_SUFFIX);
    path.is_some_and(|path| std::env::split_paths(path).any(|dir| dir.join(&name).is_file()))
}
/// Tools `prepare_kali` needs on first use. Analysis itself needs no external program.
const BUILD_TOOLS: [&str; 2] = ["git", "go"];
fn absent<'a>(tools: &[&'a str], path: Option<&std::ffi::OsStr>) -> Vec<&'a str> {
    tools
        .iter()
        .copied()
        .filter(|tool| !on_path(tool, path))
        .collect()
}
/// Optional tools missing from this environment, for startup hints and `zero doctor`.
pub fn missing_build_tools() -> Vec<&'static str> {
    absent(&BUILD_TOOLS, std::env::var_os("PATH").as_deref())
}
/// One line for `zero doctor` and the TUI; `None` when nothing is missing.
pub fn build_tools_hint() -> Option<String> {
    let missing = missing_build_tools();
    (!missing.is_empty()).then(|| {
        format!(
            "未找到 {}：分析不受影响，但无法自动准备 Linux 符号",
            missing.join("、")
        )
    })
}
fn require_tools(tools: &[&str], path: Option<&std::ffi::OsStr>) -> Result<()> {
    let missing = absent(tools, path);
    ensure!(
        missing.is_empty(),
        "编译 dwarf2json 需要 {}，请先安装；或提供已编译工具与调试 ELF，改用 --tool 生成 ISF",
        missing.join("、")
    );
    Ok(())
}
pub fn prepare_kali(image: &Image, cache: &Path, network: bool, job: &Job) -> Result<PathBuf> {
    let package = packages::kali_candidate(image, job)?;
    if let Some(path) = local_generated(image, Path::new("symbols"), cache, job)? {
        return Ok(path);
    }
    prepare_package(&package, None, image, cache, network, job)
}

/// Build the pinned converter once, or reuse it without network access.
fn ensure_tool(cache: &Path, network: bool, job: &Job) -> Result<PathBuf> {
    let _cache_lock = crate::cache::lock(cache, false)?;
    let _tool_lock = stages::artifact_lock(
        &cache.join("symbols/build/converter.lock"),
        "符号转换工具正在准备",
        job,
    )?;
    let tool_root = cache.join("symbols/build/dwarf2json");
    let tool = tool_root.join(format!("dwarf2json{}", std::env::consts::EXE_SUFFIX));
    if !tool.is_file() {
        ensure!(
            network,
            "离线模式且 dwarf2json 尚未准备；可用 --tool 指定本地工具"
        );
        require_tools(&BUILD_TOOLS, std::env::var_os("PATH").as_deref())?;
        fs::create_dir_all(cache.join("symbols/build"))?;
    }
    if !tool.is_file() {
        if !tool_root.exists() {
            job.report("工具准备阶段：获取固定版本转换工具源码");
            let staging = tempfile::tempdir_in(cache.join("symbols/build"))?;
            run(
                Command::new("git")
                    .args([
                        "clone",
                        "https://github.com/volatilityfoundation/dwarf2json.git",
                    ])
                    .arg(staging.path())
                    .stdout(Stdio::null()),
                job,
            )?;
            job.check()?;
            fs::rename(staging.path(), &tool_root)?;
        }
        run(
            Command::new("git")
                .arg("-C")
                .arg(&tool_root)
                .args(["checkout", "--detach", REVISION])
                .stdout(Stdio::null()),
            job,
        )?;
        run(
            Command::new("go")
                .current_dir(&tool_root)
                .arg("build")
                .arg("-o")
                .arg(tool.file_name().context("符号转换工具路径无效")?)
                .arg(".")
                .stdout(Stdio::null()),
            job,
        )?;
    }
    Ok(tool)
}

/// Persist a validated generated ISF outside the regenerable build cache.
pub fn save_generated_symbol(path: &Path, library: &Path, job: &Job) -> Result<PathBuf> {
    service::save(path, library, job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn debug_elf() -> Vec<u8> {
        let mut b = vec![0; 512];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[18..20].copy_from_slice(&183u16.to_le_bytes());
        b[40..48].copy_from_slice(&64u64.to_le_bytes());
        b[58..60].copy_from_slice(&64u16.to_le_bytes());
        b[60..62].copy_from_slice(&3u16.to_le_bytes());
        // Section 1: symbol strings; section 2: exact ELF symbol sizes.
        b[152..160].copy_from_slice(&256u64.to_le_bytes());
        b[160..168].copy_from_slice(&16u64.to_le_bytes());
        b[196..200].copy_from_slice(&2u32.to_le_bytes());
        b[216..224].copy_from_slice(&280u64.to_le_bytes());
        b[224..232].copy_from_slice(&24u64.to_le_bytes());
        b[232..236].copy_from_slice(&1u32.to_le_bytes());
        b[248..256].copy_from_slice(&24u64.to_le_bytes());
        b[256..272].copy_from_slice(b"\0sys_call_table\0");
        b[280..284].copy_from_slice(&1u32.to_le_bytes());
        b[296..304].copy_from_slice(&3696u64.to_le_bytes());
        b
    }
    /// A section entry smaller than the fields we read must be rejected, not
    /// sliced past the end. `elf_metadata` parses a caller-supplied file, so a
    /// malformed header must surface as an error rather than a panic.
    #[test]
    fn malformed_section_entry_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for size in [1u16, 8, 40, 47] {
            let mut elf = debug_elf();
            elf[58..60].copy_from_slice(&size.to_le_bytes());
            let path = dir.path().join(format!("bad-{size}.elf"));
            fs::write(&path, &elf).unwrap();
            let error = elf_metadata(&path).unwrap_err();
            assert!(
                error.to_string().contains("section"),
                "size {size} should be rejected: {error}"
            );
        }
    }
    /// Symbol entry sizes and string offsets come from the file, so both must
    /// be validated before use.
    #[test]
    fn out_of_range_symbol_table_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut elf = debug_elf();
        // Section 2 is the symbol table; sh_link (@232) is its string table
        // index. Point it past the section table.
        elf[232..236].copy_from_slice(&99u32.to_le_bytes());
        let path = dir.path().join("bad-link.elf");
        fs::write(&path, &elf).unwrap();
        assert!(elf_metadata(&path).is_err());
    }
    #[test]
    fn debug_sizes_and_generation_validate_banner_and_provenance() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let elf = dir.path().join("debug ELF");
        let config = dir.path().join("config");
        fs::write(&elf, debug_elf())?;
        let (machine, sizes) = elf_metadata(&elf)?;
        assert_eq!(machine, 183);
        assert_eq!(sizes["sys_call_table"], 3696);
        fs::write(
            &config,
            "CONFIG_ARM64_4K_PAGES=y\nCONFIG_ARM64_VA_BITS=48\n",
        )?;
        let (_, mut isf) = crate::linux::tests::fixture();
        use base64::Engine;
        isf.data["symbols"]["linux_banner"] = json!({"address":0,"constant_data":base64::engine::general_purpose::STANDARD.encode(&isf.banner)});
        let tool = dir.path().join("fixture tool");
        fs::write(&tool, "#!/bin/sh\ncat \"$0.json\"\n")?;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700))?;
        fs::write(tool.with_extension("json"), serde_json::to_vec(&isf.data)?)?;
        let raw = dir.path().join("image");
        fs::write(&raw, &isf.banner)?;
        let cache = dir.path().join("cache");
        let job = Job::default();
        let image = Image::open(&raw, &cache, &job)?;
        let path = generate(&elf, &config, &tool, &image, &cache, &job)?;
        let found = matching(&path, &image, &job)?;
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].data["metadata"]["zero"]["symbol_sizes"]["sys_call_table"],
            3696
        );
        assert_eq!(
            found[0].data["metadata"]["zero"]["dwarf2json_tool_sha256"],
            digest_reader(File::open(&tool)?, &job)?
        );
        assert!(
            found[0].data["metadata"]["zero"]
                .get("dwarf2json_revision")
                .is_none()
        );
        fs::write(
            &config,
            "CONFIG_ARM64_4K_PAGES=y\nCONFIG_ARM64_VA_BITS=52\n",
        )?;
        assert!(generate(&elf, &config, &tool, &image, &cache, &job).is_err());
        fs::write(&elf, [0; 64])?;
        assert!(elf_metadata(&elf).is_err());
        Ok(())
    }
    fn deb(root: &Path, members: &[(&str, &[u8])]) -> PathBuf {
        let path = root.join("package.deb");
        let mut out = AR_MAGIC.to_vec();
        for (name, data) in members {
            out.extend_from_slice(
                format!(
                    "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    0,
                    0,
                    0,
                    100644,
                    data.len()
                )
                .as_bytes(),
            );
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        fs::write(&path, out).unwrap();
        path
    }
    fn data_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, *data).unwrap();
        }
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(&tar.into_inner().unwrap()).unwrap();
        xz.finish().unwrap()
    }
    #[test]
    fn extracts_only_requested_files_from_data_member() {
        let dir = tempfile::tempdir().unwrap();
        let data = data_tar(&[
            ("./boot/other", b"skip"),
            ("./boot/config-6.8.11-arm64", b"CONFIG=y"),
        ]);
        let package = deb(
            dir.path(),
            &[
                ("debian-binary", b"2.0\n"),
                ("control.tar.xz", b"odd"),
                ("data.tar.xz", &data),
            ],
        );
        let root = dir.path().join("root");
        extract(
            &package,
            &root,
            &["./boot/config-6.8.11-arm64"],
            &Job::default(),
        )
        .unwrap();
        assert_eq!(
            fs::read(root.join("boot/config-6.8.11-arm64")).unwrap(),
            b"CONFIG=y"
        );
        assert!(!root.join("boot/other").exists());
    }
    #[test]
    fn missing_or_malformed_packages_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let data = data_tar(&[("./a", b"a")]);
        let package = deb(dir.path(), &[("data.tar.xz", &data)]);
        let error = extract(&package, dir.path(), &["./b"], &Job::default()).unwrap_err();
        assert!(error.to_string().contains("缺少文件"), "{error:#}");
        let package = deb(dir.path(), &[("debian-binary", b"2.0\n")]);
        let error = extract(&package, dir.path(), &["./a"], &Job::default()).unwrap_err();
        assert!(format!("{error:#}").contains("缺少成员"), "{error:#}");
        let truncated = dir.path().join("short.deb");
        let mut bytes = AR_MAGIC.to_vec();
        bytes.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "data.tar.xz", 0, 0, 0, 100644, 999
            )
            .as_bytes(),
        );
        fs::write(&truncated, bytes).unwrap();
        let error = extract(&truncated, dir.path(), &["./a"], &Job::default()).unwrap_err();
        assert!(format!("{error:#}").contains("超出文件范围"), "{error:#}");
        fs::write(&truncated, b"not an archive").unwrap();
        assert!(extract(&truncated, dir.path(), &["./a"], &Job::default()).is_err());
    }
    #[test]
    fn missing_build_tools_are_named_before_any_download() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path()
                .join(format!("git{}", std::env::consts::EXE_SUFFIX)),
            b"",
        )
        .unwrap();
        let error = require_tools(&["git", "go"], Some(dir.path().as_os_str())).unwrap_err();
        assert!(error.to_string().contains("go"), "{error:#}");
        assert!(!error.to_string().contains("git"), "{error:#}");
        assert!(require_tools(&["git"], Some(dir.path().as_os_str())).is_ok());
        assert!(require_tools(&["git"], None).is_err());
    }
    #[test]
    fn extracts_gzip_and_zstd_and_rejects_unsafe_paths_and_symlinks() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let xz = data_tar(&[("./boot/config-test", b"CONFIG_X86_64=y\n")]);
        let mut raw = Vec::new();
        xz2::read::XzDecoder::new(&xz[..]).read_to_end(&mut raw)?;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&raw)?;
        let gzip = gz.finish()?;
        let zstd = zstd::stream::encode_all(&raw[..], 1)?;
        for (name, bytes) in [("data.tar.gz", gzip), ("data.tar.zst", zstd)] {
            let package = deb(dir.path(), &[(name, &bytes)]);
            extract(&package, dir.path(), &["boot/config-test"], &Job::default())?;
            assert_eq!(
                fs::read(dir.path().join("boot/config-test"))?,
                b"CONFIG_X86_64=y\n"
            );
            assert!(extract(&package, dir.path(), &["../outside"], &Job::default()).is_err());
            assert!(extract(&package, dir.path(), &["/absolute"], &Job::default()).is_err());
        }
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        tar.append_link(&mut header, "boot/config-test", "../../outside")?;
        let package = deb(dir.path(), &[("data.tar", &tar.into_inner()?)]);
        assert!(extract(&package, dir.path(), &["boot/config-test"], &Job::default()).is_err());
        Ok(())
    }

    #[test]
    fn downloaded_package_generation_persists_provenance_and_survives_cache_cleanup() -> Result<()>
    {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join("cache");
        let library = dir.path().join("local symbols");
        let (_, mut isf) = crate::linux::tests::fixture();
        isf.banner =
            b"Linux version 6.8.11-arm64 (aarch64-linux-gnu-gcc) #1 SMP Kali 6.8.11-1kali2\n\0"
                .to_vec();
        isf.data["symbols"]["linux_banner"] = json!({"address":0,"constant_data":base64::engine::general_purpose::STANDARD.encode(&isf.banner)});
        let raw = dir.path().join("image.raw");
        let other_banner = b"Linux version 6.8.11-arm64 (aarch64-linux-gnu-gcc) #1 SMP Kali 6.8.11-1kali2 other-build\n\0";
        fs::write(&raw, [isf.banner.as_slice(), other_banner].concat())?;
        let job = Job::default();
        let image = Image::open(&raw, &cache, &job)?;
        let candidate = KernelPackage {
            banners: Vec::new(),
            sources: Vec::new(),
            banner: String::from_utf8_lossy(&isf.banner)
                .trim_end_matches(['\0', '\n'])
                .into(),
            distribution: "Kali".into(),
            release: "6.8.11-arm64".into(),
            architecture: "arm64".into(),
            version: "6.8.11-1kali2".into(),
            debug_url: KALI_DEBUG.into(),
            kernel_url: KALI_IMAGE.into(),
            download_size: None,
        };
        let key = format!(
            "{:x}",
            Sha256::digest(format!("{}\n{}", candidate.debug_url, candidate.kernel_url).as_bytes())
        );
        let build = cache.join("symbols/build/kernels").join(key);
        fs::create_dir_all(&build)?;
        let elf = debug_elf();
        let data = data_tar(&[("usr/lib/debug/lib/modules/6.8.11-arm64/vmlinux", &elf)]);
        let package = deb(dir.path(), &[("data.tar.xz", &data)]);
        fs::copy(package, build.join("debug.deb"))?;
        let data = data_tar(&[(
            "boot/config-6.8.11-arm64",
            b"CONFIG_ARM64_4K_PAGES=y\nCONFIG_ARM64_VA_BITS=48\n",
        )]);
        let package = deb(dir.path(), &[("data.tar.xz", &data)]);
        fs::copy(package, build.join("kernel.deb"))?;
        let tool = dir.path().join("fixture-converter");
        fs::write(
            &tool,
            "#!/bin/sh\nprintf x >> \"$0.count\"\ncat \"$0.json\"\n",
        )?;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700))?;
        fs::write(tool.with_extension("json"), serde_json::to_vec(&isf.data)?)?;
        let generated = prepare_package(&candidate, Some(&tool), &image, &cache, false, &job)?;
        let elf_path = build.join("usr/lib/debug/lib/modules/6.8.11-arm64/vmlinux");
        let elf_time = elf_path.metadata()?.modified()?;
        assert_eq!(fs::read(tool.with_extension("count"))?.len(), 1);
        assert_eq!(
            prepare_package(&candidate, Some(&tool), &image, &cache, false, &job)?,
            generated
        );
        assert_eq!(elf_path.metadata()?.modified()?, elf_time);
        assert_eq!(fs::read(tool.with_extension("count"))?.len(), 1);
        // An unavailable primary source can fall back to an already cached official mirror.
        let mut mirrored = candidate.clone();
        mirrored.debug_url = candidate.debug_url.replace("old.kali.org", "http.kali.org");
        mirrored.kernel_url = candidate
            .kernel_url
            .replace("old.kali.org", "http.kali.org");
        mirrored.sources = vec![PackageSource {
            debug_url: candidate.debug_url.clone(),
            kernel_url: candidate.kernel_url.clone(),
        }];
        assert_eq!(
            prepare_package(&mirrored, Some(&tool), &image, &cache, false, &job)?,
            generated
        );
        assert_eq!(fs::read(tool.with_extension("count"))?.len(), 1);
        // A partially completed extraction resumes without rewriting the verified ELF.
        let mut checkpoint = stages::State::load(&build);
        checkpoint.config = None;
        checkpoint.generated = None;
        checkpoint.save(&build, &job)?;
        fs::remove_file(build.join("boot/config-6.8.11-arm64"))?;
        assert_eq!(
            prepare_package(&candidate, Some(&tool), &image, &cache, false, &job)?,
            generated
        );
        assert_eq!(elf_path.metadata()?.modified()?, elf_time);
        // A modified extracted ELF is restored from the unchanged cached package.
        fs::write(&elf_path, b"damaged ELF")?;
        assert_eq!(
            prepare_package(&candidate, Some(&tool), &image, &cache, false, &job)?,
            generated
        );
        assert_eq!(fs::read(&elf_path)?, debug_elf());
        let saved = save_generated_symbol(&generated, &library, &job)?;
        assert!(saved.starts_with(library.canonicalize()?));
        let source: serde_json::Value =
            serde_json::from_slice(&fs::read(saved.with_extension("source.json"))?)?;
        assert_eq!(
            source["provenance"]["kernel_package"]["debug_url"],
            KALI_DEBUG
        );
        assert_eq!(
            source["provenance"]["debug_package_sha256"],
            digest_reader(File::open(build.join("debug.deb"))?, &job)?
        );
        assert!(source["metadata"]["zero"]["elf_sha256"].as_str().is_some());
        assert_eq!(save_generated_symbol(&generated, &library, &job)?, saved);
        // An incompatible converter output must not publish another ISF.
        isf.data["symbols"]["linux_banner"]["constant_data"] =
            json!(base64::engine::general_purpose::STANDARD.encode(other_banner));
        fs::write(tool.with_extension("json"), serde_json::to_vec(&isf.data)?)?;
        fs::OpenOptions::new()
            .append(true)
            .open(&tool)?
            .write_all(b"# changed converter fixture\n")?;
        let error =
            prepare_package(&candidate, Some(&tool), &image, &cache, false, &job).unwrap_err();
        assert!(error.to_string().contains("选中"), "{error:#}");
        assert_eq!(fs::read_dir(cache.join("symbols/isf"))?.count(), 2);
        let cancel = Job::default();
        cancel
            .cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(prepare_package(&candidate, Some(&tool), &image, &cache, false, &cancel).is_err());
        assert!(save_generated_symbol(&generated, &dir.path().join("cancelled"), &cancel).is_err());
        assert!(!dir.path().join("cancelled").exists());
        drop(image);
        crate::cache::clear(&cache, &[crate::cache::Scope::Symbols])?;
        assert!(!generated.exists());
        assert!(saved.is_file());
        assert!(saved.with_extension("source.json").is_file());
        fs::remove_file(saved.with_extension("source.json"))?;
        let reopened = Image::open(&raw, &cache, &job)?;
        assert_eq!(
            prepare_auto(&reopened, &library, &cache, false, None, &job)?,
            saved
        );
        assert_eq!(matching(&saved, &reopened, &job)?.len(), 1);
        // A name collision cannot replace an existing local symbol.
        fs::write(&saved, b"existing different content")?;
        let cached = cache.join("symbols/isf").join(saved.file_name().unwrap());
        store::atomic_write(&cached, b"new content")?;
        store::atomic_write(&cached.with_extension("source.json"), b"{}")?;
        assert!(save_generated_symbol(&cached, &library, &job).is_err());
        assert_eq!(fs::read(&saved)?, b"existing different content");
        Ok(())
    }
}
