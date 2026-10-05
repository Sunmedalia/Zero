//! Offline symbol generation from an explicit debug ELF and kernel config.
use crate::{
    Job,
    image::{Image, digest_reader},
    store,
    symbols::{Isf, matching},
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
    let result = run(
        Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--connect-timeout",
                "10",
                "--max-time",
                "1800",
                "--max-filesize",
                "1073741824",
                "--output",
            ])
            .arg(&temporary)
            .arg("--")
            .arg(url)
            .stdout(Stdio::null()),
        job,
    );
    if let Err(e) = result {
        let _ = fs::remove_file(&temporary);
        return Err(e);
    }
    fs::rename(temporary, path)?;
    Ok(())
}
fn extract(package: &Path, root: &Path, paths: &[&str], job: &Job) -> Result<()> {
    let tar = tempfile::NamedTempFile::new()?;
    run(
        Command::new("ar")
            .arg("-p")
            .arg(package)
            .arg("data.tar.xz")
            .stdout(tar.reopen()?),
        job,
    )?;
    run(
        Command::new("tar")
            .arg("-xJf")
            .arg(tar.path())
            .arg("-C")
            .arg(root)
            .args(paths)
            .stdout(Stdio::null()),
        job,
    )
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
    let tool_root = cache.join("symbols/build/dwarf2json");
    let tool = tool_root.join("dwarf2json");
    if !tool.is_file() {
        ensure!(network, "离线模式且 dwarf2json 尚未准备");
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
        let (_, mut isf) = crate::extended::tests::fixture();
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
}
