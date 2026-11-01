//! Offline symbol generation from an explicit debug ELF and kernel config.
use crate::{
    Job,
    image::{Image, digest_reader},
    store,
    symbols::{Isf, http, matching},
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
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
fn u16le(bytes: &[u8], p: usize) -> u16 {
    u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap())
}
fn u32le(bytes: &[u8], p: usize) -> u32 {
    u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap())
}
fn u64le(bytes: &[u8], p: usize) -> u64 {
    u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap())
}
pub fn elf_metadata(path: &Path) -> Result<(u16, serde_json::Value)> {
    let mut file = File::open(path)?;
    let h = read_at(&mut file, 0, 64)?;
    ensure!(&h[..7] == b"\x7fELF\x02\x01\x01", "需要小端 ELF64 调试文件");
    let machine = u16le(&h, 18);
    ensure!(matches!(machine, 62 | 183), "ELF 架构不支持");
    let off = u64le(&h, 40);
    let size = u16le(&h, 58) as usize;
    let count = u16le(&h, 60) as usize;
    ensure!(size >= 64 && count > 0, "ELF section table 缺失");
    let sections = read_at(&mut file, off, size * count)?;
    let mut sizes = serde_json::Map::new();
    for s in sections.chunks_exact(size) {
        if u32le(s, 4) != 2 {
            continue;
        }
        let link = u32le(s, 40) as usize;
        ensure!(link < count, "ELF string section 越界");
        let st = &sections[link * size..(link + 1) * size];
        let strings = read_at(&mut file, u64le(st, 24), usize::try_from(u64le(st, 32))?)?;
        let symbols = read_at(&mut file, u64le(s, 24), usize::try_from(u64le(s, 32))?)?;
        let entry = u64le(s, 56) as usize;
        ensure!(entry >= 24, "ELF symbol entry 无效");
        for symbol in symbols.chunks_exact(entry) {
            let name = u32le(symbol, 0) as usize;
            if name >= strings.len() {
                continue;
            }
            let bytes = &strings[name..];
            let end = bytes
                .iter()
                .position(|b| *b == 0)
                .context("ELF symbol name 未终止")?;
            let name = std::str::from_utf8(&bytes[..end])?;
            if matches!(name, "sys_call_table" | "compat_sys_call_table") {
                sizes.insert(name.into(), json!(u64le(symbol, 16)));
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
    data["metadata"]["zero"] = json!({"architecture":if machine==183{"aarch64"}else{"x86_64"},"page_shift":12,"va_bits":bits,"symbol_sizes":sizes,
        "elf_sha256":digest_reader(File::open(elf)?,job)?,"config_sha256":digest_reader(File::open(config)?,job)?,"dwarf2json_tool_sha256":digest_reader(File::open(tool)?,job)?});
    let bytes = serde_json::to_vec(&data)?;
    let isf = Isf::parse(&bytes, "generated".into())?;
    ensure!(
        image.banners(job)?.iter().any(|(_, b)| *b == isf.banner),
        "生成 ISF 的完整 banner 与镜像不匹配"
    );
    let path = cache
        .join("symbols/isf")
        .join(format!("{}.json.xz", isf.digest));
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&bytes)?;
    job.check()?;
    store::atomic_write(&path, &encoder.finish()?)?;
    let source = path.with_extension("source.json");
    store::atomic_write(
        &source,
        &serde_json::to_vec_pretty(
            &json!({"elf":elf,"config":config,"metadata":data["metadata"]}),
        )?,
    )?;
    job.report(format!("已生成精确匹配 ISF: {}", path.display()));
    Ok(path)
}
fn download(url: &str, path: &Path, network: bool, job: &Job) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    ensure!(network, "离线模式且准备文件缺失: {url}");
    let temporary = path.with_extension("part");
    job.report(format!("下载符号准备文件: {url}"));
    let result = http::download(
        http::Request {
            url,
            range: None,
            limit: 1024 * 1024 * 1024,
            timeout: Duration::from_secs(1800),
            https_only: true,
        },
        File::create(&temporary)?,
        job,
    );
    if let Err(e) = result {
        let _ = fs::remove_file(&temporary);
        return Err(e);
    }
    fs::rename(temporary, path)?;
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
/// Copy only the named regular files out of a package's data.tar.xz under `root`.
/// Names come from the caller, so archive-controlled paths never reach the filesystem.
fn extract(package: &Path, root: &Path, paths: &[&str], job: &Job) -> Result<()> {
    let mut file = File::open(package)?;
    let size = ar_member(&mut file, "data.tar.xz")?;
    let xz = xz2::read::XzDecoder::new_multi_decoder(file.take(size));
    let mut archive = tar::Archive::new(xz);
    let mut missing: Vec<&str> = paths.to_vec();
    for entry in archive.entries().context("读取 deb 数据包失败")? {
        job.check()?;
        let mut entry = entry.context("读取 deb 数据包失败")?;
        let name = entry.path()?.into_owned();
        // Packages name members `./boot/x` or `boot/x`; the two are the same file.
        let same = |path: &&str| name.strip_prefix(".").unwrap_or(&name) == plain(path);
        let Some(index) = missing.iter().position(same) else {
            continue;
        };
        let path = missing.swap_remove(index);
        ensure!(entry.header().entry_type().is_file(), "{path} 不是普通文件");
        let target = root.join(path);
        store::atomic_stream(&target, job, |writer| {
            std::io::copy(&mut entry, writer)?;
            Ok(())
        })?;
        if missing.is_empty() {
            return Ok(());
        }
    }
    anyhow::bail!("deb 数据包缺少文件: {}", missing.join(", "))
}
/// Executable lookup without running it; `path` is the `PATH` value to search.
fn on_path(tool: &str, path: Option<&std::ffi::OsStr>) -> bool {
    let name = format!("{tool}{}", std::env::consts::EXE_SUFFIX);
    path.is_some_and(|path| std::env::split_paths(path).any(|dir| dir.join(&name).is_file()))
}
fn require_tools(tools: &[&str], path: Option<&std::ffi::OsStr>) -> Result<()> {
    let missing: Vec<_> = tools
        .iter()
        .copied()
        .filter(|tool| !on_path(tool, path))
        .collect();
    ensure!(
        missing.is_empty(),
        "编译 dwarf2json 需要 {}，请先安装；或提供已编译工具与调试 ELF，改用 --tool 生成 ISF",
        missing.join("、")
    );
    Ok(())
}
pub fn prepare_kali(image: &Image, cache: &Path, network: bool, job: &Job) -> Result<PathBuf> {
    let _lock = crate::cache::lock(cache, false)?;
    let banners = image.banners(job)?;
    ensure!(
        banners.iter().any(|(_, b)| String::from_utf8_lossy(b)
            .contains("Linux version 6.8.11-arm64")
            && String::from_utf8_lossy(b).contains("6.8.11-1kali2")),
        "此准备入口仅适用于 Kali 6.8.11-arm64 / 6.8.11-1kali2；其他版本请提供调试 ELF 与配置"
    );
    for path in [PathBuf::from("symbols"), cache.join("symbols/isf")] {
        if let Ok(matches) = matching(&path, image, job)
            && let Some(isf) = matches.iter().find(|s| {
                s.data["metadata"]["zero"]["symbol_sizes"]["sys_call_table"]
                    .as_u64()
                    .is_some()
            })
        {
            return Ok(PathBuf::from(&isf.label));
        }
    }
    let tool_root = cache.join("symbols/build/dwarf2json");
    let tool = tool_root.join("dwarf2json");
    if !tool.is_file() {
        // Fail before downloading a gigabyte of packages that could not be used.
        ensure!(network, "离线模式且 dwarf2json 尚未准备");
        require_tools(&["git", "go"], std::env::var_os("PATH").as_deref())?;
    }
    let root = cache.join("symbols/build/kali-6.8.11");
    fs::create_dir_all(&root)?;
    let debug = root.join("kernel.deb");
    let package = root.join("image.deb");
    download(KALI_DEBUG, &debug, network, job)?;
    download(KALI_IMAGE, &package, network, job)?;
    let elf = root.join("usr/lib/debug/boot/vmlinux-6.8.11-arm64");
    let config = root.join("boot/config-6.8.11-arm64");
    if !elf.exists() {
        extract(
            &debug,
            &root,
            &["./usr/lib/debug/boot/vmlinux-6.8.11-arm64"],
            job,
        )?;
    }
    if !config.exists() {
        extract(
            &package,
            &root,
            &[
                "./boot/config-6.8.11-arm64",
                "./boot/System.map-6.8.11-arm64",
            ],
            job,
        )?;
    }
    if !tool.is_file() {
        if !tool_root.exists() {
            run(
                Command::new("git")
                    .args([
                        "clone",
                        "https://github.com/volatilityfoundation/dwarf2json.git",
                    ])
                    .arg(&tool_root)
                    .stdout(Stdio::null()),
                job,
            )?;
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
                .args(["build", "-o", "dwarf2json", "."])
                .stdout(Stdio::null()),
            job,
        )?;
    }
    let path = generate(&elf, &config, &tool, image, cache, job)?;
    let source = path.with_extension("source.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&source)?)?;
    value["source_url"] = json!(KALI_DEBUG);
    value["package_sha256"] = json!(digest_reader(File::open(debug)?, job)?);
    store::atomic_write(&source, &serde_json::to_vec_pretty(&value)?)?;
    Ok(path)
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
        assert!(error.to_string().contains("缺少成员"), "{error:#}");
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
        assert!(error.to_string().contains("超出文件范围"), "{error:#}");
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
}
