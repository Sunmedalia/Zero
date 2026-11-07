//! Bounded discovery in official package pools. Directory listings are hints;
//! only the generated ELF banner can establish an exact match to an image.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelPackage {
    pub banner: String,
    #[serde(default)]
    pub banners: Vec<String>,
    #[serde(default)]
    pub sources: Vec<PackageSource>,
    pub distribution: String,
    pub release: String,
    pub architecture: String,
    pub version: String,
    pub debug_url: String,
    pub kernel_url: String,
    pub download_size: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageSource {
    pub debug_url: String,
    pub kernel_url: String,
}
impl KernelPackage {
    pub(super) fn accepts(&self, banner: &str) -> bool {
        self.banner == banner || self.banners.iter().any(|b| b == banner)
    }
}

#[derive(Debug)]
struct Identity {
    banner: String,
    distribution: &'static str,
    release: String,
    architecture: &'static str,
    version: Option<String>,
}

fn identity(banner: &str) -> Result<Identity> {
    let banner = banner.trim_end_matches(['\0', '\n']);
    let release = banner
        .strip_prefix("Linux version ")
        .and_then(|s| s.split_whitespace().next())
        .context("缺少 Linux 内核版本")?;
    ensure!(safe_name(release), "内核版本包含无效字符");
    let distribution = if banner.contains("Ubuntu") {
        "Ubuntu"
    } else if banner.contains("Kali") || banner.contains("kali") {
        "Kali"
    } else if banner.contains("Debian") || banner.contains("debian-kernel@") {
        "Debian"
    } else {
        anyhow::bail!("无法识别发行版；请手动提供匹配的调试 ELF 和 config")
    };
    let architecture = if release.ends_with("arm64") || banner.contains("aarch64") {
        "arm64"
    } else if release.ends_with("amd64") || banner.contains("x86_64") {
        "amd64"
    } else {
        anyhow::bail!("无法从 banner 确定 amd64 / arm64 架构；请使用手动生成")
    };
    let version = if distribution == "Ubuntu" {
        // 6.8.0-40-generic #40~22.04.3-Ubuntu -> 6.8.0-40.40~22.04.3
        let abi = release.rsplit_once('-').map(|(abi, _)| abi);
        let build = banner
            .split_whitespace()
            .find_map(|s| s.strip_prefix('#'))
            .and_then(|s| s.strip_suffix("-Ubuntu"));
        abi.zip(build).map(|(abi, build)| format!("{abi}.{build}"))
    } else {
        banner
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find_map(|pair| {
                let [name, version] = pair else { return None };
                (*name == distribution
                    && safe_name(version)
                    && version.as_bytes().first().is_some_and(u8::is_ascii_digit))
                .then(|| (*version).to_owned())
            })
    };
    Ok(Identity {
        banner: banner.into(),
        distribution,
        release: release.into(),
        architecture,
        version,
    })
}

/// Only offer automatic discovery when both distribution and architecture are known.
pub fn supports_automatic_banner(banner: &str) -> bool {
    identity(banner).is_ok()
}

fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+~".contains(&b))
}

/// Pool pages use relative ASCII filenames. Never follow arbitrary page links.
pub(super) fn links(html: &str) -> Vec<(String, Option<String>)> {
    let mut found = Vec::new();
    for line in html.lines() {
        for chunk in line.split("href=").skip(1) {
            let Some(quote @ ('\'' | '"')) = chunk.chars().next() else {
                continue;
            };
            let Some(raw) = chunk.get(1..).and_then(|s| s.split(quote).next()) else {
                continue;
            };
            let name = raw
                .replace("%2b", "+")
                .replace("%2B", "+")
                .replace("%7e", "~")
                .replace("%7E", "~");
            if safe_name(name.trim_end_matches('/')) {
                // Apache and nginx listings put human-readable size after </a>.
                let size = line.rsplit_once("</a>").and_then(|(_, tail)| {
                    tail.split_whitespace()
                        .rev()
                        .find(|s| {
                            s.as_bytes().first().is_some_and(u8::is_ascii_digit)
                                && s.chars().last().is_some_and(|c| "KMG".contains(c))
                        })
                        .map(str::to_owned)
                });
                found.push((name, size));
            }
        }
    }
    found
}

fn package_name(name: &str) -> Option<(&str, &str, &str)> {
    let name = name
        .strip_suffix(".ddeb")
        .or_else(|| name.strip_suffix(".deb"))?;
    let mut parts = name.split('_');
    let package = parts.next()?;
    let version = parts.next()?;
    let arch = parts.next()?;
    (parts.next().is_none()).then_some((package, version, arch))
}

fn candidates(
    id: &Identity,
    debug_base: &str,
    debug: &[(String, Option<String>)],
    kernel_base: &str,
    kernel: &[(String, Option<String>)],
) -> Vec<KernelPackage> {
    let regular = kernel;
    let mut result = Vec::new();
    for (file, size) in debug {
        let Some((name, version, arch)) = package_name(file) else {
            continue;
        };
        if arch != id.architecture || id.version.as_ref().is_some_and(|v| v != version) {
            continue;
        }
        let names = [
            format!("linux-image-{}-dbg", id.release),
            format!("linux-image-{}-dbgsym", id.release),
            format!("linux-image-unsigned-{}-dbgsym", id.release),
        ];
        if !names.iter().any(|n| n == name) {
            continue;
        }
        let kernel_name = name
            .strip_suffix("-dbgsym")
            .or_else(|| name.strip_suffix("-dbg"));
        let Some(kernel_file) = regular.iter().find_map(|(file, _)| {
            let (name, v, a) = package_name(file)?;
            let matches = Some(name) == kernel_name
                || kernel_name.is_some_and(|base| name == format!("{base}-unsigned"));
            (matches && v == version && a == arch).then_some(file)
        }) else {
            continue;
        };
        result.push(KernelPackage {
            banner: id.banner.clone(),
            banners: vec![id.banner.clone()],
            sources: Vec::new(),
            distribution: id.distribution.into(),
            release: id.release.clone(),
            architecture: arch.into(),
            version: version.into(),
            debug_url: format!("{debug_base}{file}"),
            kernel_url: format!("{kernel_base}{kernel_file}"),
            download_size: size.clone(),
        });
    }
    result
}

fn ubuntu_directories(id: &Identity, entries: &[(String, Option<String>)]) -> Vec<String> {
    let mut parts = id.release.split('.');
    let major = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    let series = format!("{major}.{minor}");
    let flavor = id.release.rsplit('-').next().unwrap_or("");
    let mut dirs: Vec<_> = entries
        .iter()
        .map(|(name, _)| name.clone())
        .filter(|n| {
            n.ends_with('/')
                && (n == "linux/"
                    || (n.starts_with("linux-") && n.contains(&series))
                    || (!matches!(flavor, "generic" | "lowlatency" | "oem")
                        && n.starts_with(&format!("linux-{flavor}"))))
        })
        .collect();
    dirs.sort_by_key(|n| (n != "linux/", n.clone()));
    dirs.truncate(64);
    dirs
}

/// Find candidates using cached indexes, refreshing a miss once when online.
pub fn find_packages(
    image: &Image,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<Vec<KernelPackage>> {
    find_packages_with_refresh(image, cache, network, false, job)
}
pub fn find_packages_with_refresh(
    image: &Image,
    cache: &Path,
    network: bool,
    refresh: bool,
    job: &Job,
) -> Result<Vec<KernelPackage>> {
    let _lock = crate::cache::lock(cache, false)?;
    ensure!(!refresh || network, "离线模式不能强制刷新官方索引");
    let mut identities = Vec::new();
    let mut errors = Vec::new();
    for (_, bytes) in image.banners(job)? {
        match identity(&String::from_utf8_lossy(&bytes)) {
            Ok(id)
                if !identities
                    .iter()
                    .any(|old: &Identity| old.banner == id.banner) =>
            {
                identities.push(id)
            }
            Ok(_) => {}
            Err(e) => errors.push(e.to_string()),
        }
    }
    let mut indexes = indexes::Indexes::new(cache, network, refresh, job);
    loop {
        let found = discover(&identities, &mut indexes, &mut errors, job)?;
        if !found.is_empty() {
            return Ok(merge_candidates(found));
        }
        if !indexes.refresh_cached() {
            break;
        }
        job.report("缓存索引未命中，刷新官方索引后重试一次");
    }
    job.check()?;
    errors.sort();
    errors.dedup();
    anyhow::bail!(
        "官方源未找到可用的匹配调试包；请提供本地 ELF / config。{}",
        errors.join("；")
    )
}
fn discover(
    identities: &[Identity],
    indexes: &mut indexes::Indexes<'_>,
    errors: &mut Vec<String>,
    job: &Job,
) -> Result<Vec<KernelPackage>> {
    let mut result = Vec::new();
    for id in identities {
        job.check()?;
        let roots: Vec<(String, String)> = match id.distribution {
            "Ubuntu" => {
                let base = "https://ddebs.ubuntu.com/pool/main/l/";
                match indexes.get(base) {
                    Ok(html) => ubuntu_directories(id, &html)
                        .iter()
                        .map(|dir| {
                            (
                                format!("{base}{dir}"),
                                format!(
                                    "{}pool/main/l/{dir}",
                                    if id.architecture == "arm64" {
                                        "https://ports.ubuntu.com/ubuntu-ports/"
                                    } else {
                                        "https://archive.ubuntu.com/ubuntu/"
                                    }
                                ),
                            )
                        })
                        .collect(),
                    Err(e) => {
                        errors.push(format!("{e:#}"));
                        continue;
                    }
                }
            }
            "Debian" => [
                "https://deb.debian.org/debian/pool/main/l/linux/",
                "https://security.debian.org/debian-security/pool/updates/main/l/linux/",
                "https://archive.debian.org/debian/pool/main/l/linux/",
            ]
            .map(|s| (s.into(), s.into()))
            .into(),
            _ => [
                "https://http.kali.org/kali/pool/main/l/linux/",
                "https://old.kali.org/kali/pool/main/l/linux/",
            ]
            .map(|s| (s.into(), s.into()))
            .into(),
        };
        for (debug_base, kernel_base) in roots {
            job.check()?;
            let debug = match indexes.get(&debug_base) {
                Ok(v) => v,
                Err(e) => {
                    job.check()?;
                    errors.push(format!("{e:#}"));
                    continue;
                }
            };
            // Avoid fetching regular-package indexes for directories with no matching debug package.
            if !debug.iter().any(|(file, _)| {
                package_name(file).is_some_and(|(n, v, a)| {
                    a == id.architecture
                        && n.contains(&id.release)
                        && (n.ends_with("-dbg") || n.ends_with("-dbgsym"))
                        && id.version.as_ref().is_none_or(|expected| expected == v)
                })
            }) {
                continue;
            }
            let kernel = if kernel_base == debug_base {
                debug.clone()
            } else {
                match indexes.get(&kernel_base) {
                    Ok(v) => v,
                    Err(e) => {
                        job.check()?;
                        errors.push(format!("{e:#}"));
                        continue;
                    }
                }
            };
            result.extend(candidates(id, &debug_base, &debug, &kernel_base, &kernel));
        }
    }
    job.check()?;
    Ok(result)
}
fn merge_candidates(packages: Vec<KernelPackage>) -> Vec<KernelPackage> {
    let mut merged: BTreeMap<(String, String, String, String), KernelPackage> = BTreeMap::new();
    for mut package in packages {
        let key = (
            package.distribution.clone(),
            package.release.clone(),
            package.architecture.clone(),
            package.version.clone(),
        );
        if let Some(existing) = merged.get_mut(&key) {
            for banner in std::iter::once(package.banner).chain(package.banners) {
                if !existing.banners.contains(&banner) {
                    existing.banners.push(banner);
                }
            }
            let source = PackageSource {
                debug_url: package.debug_url,
                kernel_url: package.kernel_url,
            };
            if (source.debug_url != existing.debug_url || source.kernel_url != existing.kernel_url)
                && !existing.sources.contains(&source)
            {
                existing.sources.push(source);
            }
        } else {
            if !package.banners.contains(&package.banner) {
                package.banners.push(package.banner.clone());
            }
            merged.insert(key, package);
        }
    }
    merged.into_values().collect()
}

/// Reuse a validated, locally generated ISF before requiring indexes or tools.
pub fn local_generated(
    image: &Image,
    library: &Path,
    cache: &Path,
    job: &Job,
) -> Result<Option<PathBuf>> {
    for dir in [library.to_path_buf(), cache.join("symbols/isf")] {
        if !dir.exists() {
            continue;
        }
        if let Ok(matches) = matching(&dir, image, job) {
            for isf in matches {
                // Image-derived ISFs are not debug-package results; never reuse them here.
                if isf.data.key("metadata")["zero"].is_object()
                    && isf.data.key("metadata")["zero"].key("source").as_str() != Some("image")
                    && Path::new(&isf.label).is_file()
                {
                    return Ok(Some(Path::new(&isf.label).canonicalize()?));
                }
            }
        }
        job.check()?;
    }
    Ok(None)
}

pub fn prepare_auto(
    image: &Image,
    library: &Path,
    cache: &Path,
    network: bool,
    tool: Option<&Path>,
    job: &Job,
) -> Result<PathBuf> {
    Generation {
        image,
        library,
        cache,
        network,
        tool,
        job,
    }
    .run(GenerationInput::Auto {
        candidate: None,
        refresh: false,
    })
}

/// Extract the required regular files only; no package installation or scripts.
pub fn prepare_package(
    package: &KernelPackage,
    tool: Option<&Path>,
    image: &Image,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<PathBuf> {
    let _lock = crate::cache::lock(cache, false)?;
    ensure!(safe_name(&package.release), "内核版本包含无效字符");
    let image_banners = image.banners(job)?;
    ensure!(
        image_banners.iter().any(
            |(_, b)| package.accepts(String::from_utf8_lossy(b).trim_end_matches(['\0', '\n']))
        ),
        "调试包候选不属于当前镜像"
    );
    let mut sources = vec![PackageSource {
        debug_url: package.debug_url.clone(),
        kernel_url: package.kernel_url.clone(),
    }];
    sources.extend(package.sources.clone());
    for source in &sources {
        for url in [&source.debug_url, &source.kernel_url] {
            let (base, name) = url.rsplit_once('/').context("调试包 URL 无效")?;
            ensure!(
                safe_name(name) && official_pool(&format!("{base}/")),
                "调试包 URL 不属于支持的官方源"
            );
        }
    }
    let identity = serde_json::to_vec(&(
        &package.distribution,
        &package.release,
        &package.architecture,
        &package.version,
    ))?;
    let _build_lock = stages::artifact_lock(
        &cache
            .join("symbols/build/locks")
            .join(format!("{:x}.lock", Sha256::digest(identity))),
        "该内核构建正在生成",
        job,
    )?;
    let mut failures = Vec::new();
    for source in sources {
        let mut selected = package.clone();
        selected.debug_url = source.debug_url;
        selected.kernel_url = source.kernel_url;
        // Fall back only for unavailable sources; converter/config/banner failures are final.
        match prepare_source(&selected, tool, image, cache, network, job) {
            Ok(path) => return Ok(path),
            Err(error) => {
                job.check()?;
                if error.is::<SourceUnavailable>() {
                    job.report(format!("该官方来源不可用，尝试下一来源: {error:#}"));
                    failures.push(format!("{error:#}"));
                } else {
                    return Err(error);
                }
            }
        }
    }
    anyhow::bail!(
        "候选的官方来源均不可用；可重试或提供本地 ELF / config。{}",
        failures.join("；")
    )
}
#[derive(Debug)]
struct SourceUnavailable;
impl std::fmt::Display for SourceUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("下载阶段失败，已完成阶段保持可复用")
    }
}
impl std::error::Error for SourceUnavailable {}

fn prepare_source(
    package: &KernelPackage,
    tool: Option<&Path>,
    image: &Image,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<PathBuf> {
    let tool = match tool {
        Some(p) => {
            ensure!(p.is_file(), "转换工具文件不存在");
            p.to_path_buf()
        }
        None => ensure_tool(cache, network, job)?,
    };
    let key = format!(
        "{:x}",
        Sha256::digest(format!("{}\n{}", package.debug_url, package.kernel_url).as_bytes())
    );
    let root = cache.join("symbols/build/kernels").join(key);
    let _build_lock = stages::artifact_lock(&root.join("build.lock"), "该内核构建正在生成", job)?;
    let mut state = stages::State::load(&root);
    let debug = root.join("debug.deb");
    let kernel = root.join("kernel.deb");
    // Adopt old fixed-Kali downloads once; extraction still passes normal verification.
    if package.debug_url == KALI_DEBUG {
        for (old, new) in [
            (cache.join("symbols/build/kali-6.8.11/kernel.deb"), &debug),
            (cache.join("symbols/build/kali-6.8.11/image.deb"), &kernel),
        ] {
            if !new.exists() && old.is_file() {
                store::atomic_stream(new, job, |writer| {
                    let mut file = File::open(&old)?;
                    std::io::copy(&mut file, writer)?;
                    Ok(())
                })?;
            }
        }
    }
    job.report("下载阶段：准备调试包和内核配置包");
    let debug_hash = package_file(
        &package.debug_url,
        &debug,
        state.debug.as_ref().map(|s| s.package_sha256.as_str()),
        network,
        job,
    )?;
    let kernel_hash = package_file(
        &package.kernel_url,
        &kernel,
        state.config.as_ref().map(|s| s.package_sha256.as_str()),
        network,
        job,
    )?;
    let elf = if let Some(record) = &state.debug
        && elf_paths(&package.release).contains(&record.relative)
        && record.verify(&root, &debug_hash, job)?
    {
        job.report("复用已验证的调试 ELF，跳过解包");
        root.join(&record.relative)
    } else {
        state.debug = None;
        state.generated = None;
        state.save(&root, job)?;
        job.report("提取阶段：从调试包提取 ELF");
        let elf =
            stages::invalidate_corrupt(extract_elf(&debug, &root, &package.release, job), &debug)?;
        state.debug = Some(stages::Extracted {
            package_sha256: debug_hash.clone(),
            relative: elf.strip_prefix(&root)?.to_string_lossy().into(),
            sha256: digest_reader(File::open(&elf)?, job)?,
        });
        state.save(&root, job)?;
        elf
    };
    let config_relative = format!("boot/config-{}", package.release);
    let config = root.join(&config_relative);
    if state
        .config
        .as_ref()
        .map(|record| {
            if record.relative == config_relative {
                record.verify(&root, &kernel_hash, job)
            } else {
                Ok(false)
            }
        })
        .transpose()?
        .unwrap_or(false)
    {
        job.report("复用已验证的内核配置，跳过解包");
    } else {
        state.config = None;
        state.generated = None;
        state.save(&root, job)?;
        stages::invalidate_corrupt(extract(&kernel, &root, &[&config_relative], job), &kernel)?;
        state.config = Some(stages::Extracted {
            package_sha256: kernel_hash.clone(),
            relative: config_relative,
            sha256: digest_reader(File::open(&config)?, job)?,
        });
        state.save(&root, job)?;
    }
    let (machine, _) = elf_metadata(&elf)?;
    ensure!(
        matches!(
            (package.architecture.as_str(), machine),
            ("arm64", 183) | ("amd64", 62)
        ),
        "调试 ELF 架构与候选包不匹配"
    );
    let hashes = InputDigests {
        elf: state
            .debug
            .as_ref()
            .context("缺少 ELF 阶段记录")?
            .sha256
            .clone(),
        config: state
            .config
            .as_ref()
            .context("缺少配置阶段记录")?
            .sha256
            .clone(),
        tool: digest_reader(File::open(&tool)?, job)?,
    };
    if let Some(record) = &state.generated
        && record.elf_sha256 == hashes.elf
        && record.config_sha256 == hashes.config
        && record.tool_sha256 == hashes.tool
        && record.isf_sha256.len() == 64
        && record.isf_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let output = cache
            .join("symbols/isf")
            .join(format!("{}.json.xz", record.isf_sha256));
        if let Ok(matches) = matching(&output, image, job)
            && matches.iter().any(|isf| {
                isf.digest == record.isf_sha256
                    && isf.data.key("metadata")["zero"].key("elf_sha256").as_str()
                        == Some(hashes.elf.as_str())
                    && isf.data.key("metadata")["zero"]
                        .key("config_sha256")
                        .as_str()
                        == Some(hashes.config.as_str())
                    && isf.data.key("metadata")["zero"]
                        .key("dwarf2json_tool_sha256")
                        .as_str()
                        == Some(hashes.tool.as_str())
                    && package.accepts(
                        String::from_utf8_lossy(&isf.banner).trim_end_matches(['\0', '\n']),
                    )
            })
        {
            job.report("复用已验证的生成结果，跳过转换");
            return Ok(output);
        }
        job.check()?;
    }
    state.generated = None;
    state.save(&root, job)?;
    let provenance = json!({"kernel_package":package,"banner":package.banner,"debug_package_sha256":debug_hash,"kernel_package_sha256":kernel_hash});
    let path = generate_verified(
        (&elf, &config, &tool),
        image,
        cache,
        job,
        provenance,
        Some(&hashes),
    )?;
    let isf_sha256 = path
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_suffix(".json.xz"))
        .context("生成结果路径无效")?
        .to_owned();
    state.generated = Some(stages::Generated {
        elf_sha256: hashes.elf,
        config_sha256: hashes.config,
        tool_sha256: hashes.tool,
        isf_sha256,
    });
    state.save(&root, job)?;
    Ok(path)
}
fn package_file(
    url: &str,
    path: &Path,
    expected: Option<&str>,
    network: bool,
    job: &Job,
) -> Result<String> {
    download(url, path, network, job).context(SourceUnavailable)?;
    let mut hash = digest_reader(File::open(path)?, job)?;
    let valid = data_archive(path).is_ok() && expected.is_none_or(|expected| expected == hash);
    if !valid {
        job.check()?;
        ensure!(
            network,
            "离线缓存包损坏；联网后重试以重新下载: {}",
            path.display()
        );
        job.report("缓存包损坏，仅重新下载该软件包");
        fs::remove_file(path)?;
        download(url, path, network, job).context(SourceUnavailable)?;
        hash = digest_reader(File::open(path)?, job)?;
        data_archive(path).context("重新下载的软件包仍无法解析")?;
    }
    Ok(hash)
}

pub(super) fn kali_candidate(image: &Image, job: &Job) -> Result<KernelPackage> {
    let mut banners = Vec::new();
    for (_, bytes) in image.banners(job)? {
        let banner = String::from_utf8_lossy(&bytes)
            .trim_end_matches(['\0', '\n'])
            .to_owned();
        if banner.starts_with("Linux version 6.8.11-arm64 ")
            && banner.contains("6.8.11-1kali2")
            && !banners.contains(&banner)
        {
            banners.push(banner);
        }
    }
    let banner = banners
        .first()
        .context(
            "--kali 仅适用于 Kali 6.8.11-arm64 / 6.8.11-1kali2；其他构建请使用 --auto 或本地 ELF",
        )?
        .clone();
    Ok(KernelPackage {
        banner,
        banners,
        sources: Vec::new(),
        distribution: "Kali".into(),
        release: "6.8.11-arm64".into(),
        architecture: "arm64".into(),
        version: "6.8.11-1kali2".into(),
        debug_url: KALI_DEBUG.into(),
        kernel_url: KALI_IMAGE.into(),
        download_size: None,
    })
}

fn official_pool(base: &str) -> bool {
    [
        "https://ddebs.ubuntu.com/pool/main/l/",
        "https://archive.ubuntu.com/ubuntu/pool/main/l/",
        "https://ports.ubuntu.com/ubuntu-ports/pool/main/l/",
    ]
    .iter()
    .any(|prefix| {
        base.strip_prefix(prefix)
            .is_some_and(|dir| dir.strip_suffix('/').is_some_and(safe_name))
    }) || [
        "https://deb.debian.org/debian/pool/main/l/linux/",
        "https://security.debian.org/debian-security/pool/updates/main/l/linux/",
        "https://archive.debian.org/debian/pool/main/l/linux/",
        "https://http.kali.org/kali/pool/main/l/linux/",
        "https://old.kali.org/kali/pool/main/l/linux/",
    ]
    .contains(&base)
}

fn elf_paths(release: &str) -> [String; 3] {
    [
        format!("usr/lib/debug/boot/vmlinux-{release}"),
        format!("usr/lib/debug/lib/modules/{release}/vmlinux"),
        format!("usr/lib/debug/boot/vmlinux-{release}.debug"),
    ]
}
fn extract_elf(package: &Path, root: &Path, release: &str, job: &Job) -> Result<PathBuf> {
    let paths = elf_paths(release);
    let mut archive = tar::Archive::new(data_archive(package)?);
    for entry in archive.entries().context(stages::CorruptPackage)? {
        job.check()?;
        let mut entry = entry.context(stages::CorruptPackage)?;
        let name = entry.path()?.into_owned();
        if let Some(path) = paths
            .iter()
            .find(|p| plain(p) == plain(&name.to_string_lossy()))
        {
            copy_entry(&mut entry, &root.join(path), job)?;
            return Ok(root.join(path));
        }
    }
    anyhow::bail!("调试包缺少对应 vmlinux；请解出调试 ELF 后使用手动生成")
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: &str = "Linux version 6.8.0-40-generic (buildd@lcy02) (x86_64-linux-gnu-gcc-13) #40~22.04.3-Ubuntu SMP PREEMPT_DYNAMIC\n";
    const DEBIAN: &str = "Linux version 6.12.105+deb13-amd64 (debian-kernel@lists.debian.org) (x86_64-linux-gnu-gcc-14) #1 SMP PREEMPT_DYNAMIC Debian 6.12.105-1 (2026-08-24)\n";
    const KALI: &str = "Linux version 6.8.11-arm64 (devel@kali.org) (aarch64-linux-gnu-gcc-13) #1 SMP Kali 6.8.11-1kali2 (2024-05-30)\n";

    fn html(files: &[&str]) -> String {
        files
            .iter()
            .map(|name| format!("<a href=\"{name}\">{name}</a> 2026-01-01 12:00 100M\n"))
            .collect()
    }
    fn cache_index(cache: &Path, url: &str, html: &str) {
        let key = format!("{:x}", Sha256::digest(url.as_bytes()));
        store::atomic_write(
            &cache.join(format!("symbols/build/indexes/{key}.html")),
            html.as_bytes(),
        )
        .unwrap();
    }
    #[test]
    fn detects_exact_distribution_build_and_architecture_without_guessing() {
        for (banner, distro, arch, version) in [
            (UBUNTU, "Ubuntu", "amd64", "6.8.0-40.40~22.04.3"),
            (DEBIAN, "Debian", "amd64", "6.12.105-1"),
            (KALI, "Kali", "arm64", "6.8.11-1kali2"),
        ] {
            let id = identity(banner).unwrap();
            assert_eq!(id.distribution, distro);
            assert_eq!(id.architecture, arch);
            assert_eq!(id.version.as_deref(), Some(version));
        }
        assert!(identity("Linux version 6.8.0-generic #1 Ubuntu").is_err());
        assert!(identity("Linux version 6.8.0-custom x86_64 #1 custom").is_err());
        assert!(identity("Linux version ../../bad-amd64 Debian #1").is_err());
    }
    #[test]
    fn ignores_foreign_links_wrong_versions_architectures_and_missing_companion_packages() {
        let id = identity(KALI).unwrap();
        let files = html(&[
            "linux-image-6.8.11-arm64-dbg_6.8.11-1kali2_arm64.deb",
            "linux-image-6.8.11-arm64_6.8.11-1kali2_arm64.deb",
            "linux-image-6.8.11-arm64-dbg_6.8.11-1kali3_arm64.deb",
            "linux-image-6.8.11-arm64-dbg_6.8.11-1kali2_amd64.deb",
            "https://evil.test/payload.deb",
            "../payload.deb",
            "/absolute.deb",
        ]);
        let found = candidates(
            &id,
            "https://old.kali.org/",
            &links(&files),
            "https://old.kali.org/",
            &links(&files),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].version, "6.8.11-1kali2");
        assert_eq!(found[0].download_size.as_deref(), Some("100M"));
        assert!(candidates(&id, "", &links(&files), "", &[]).is_empty());
        assert!(!official_pool(
            "https://old.kali.org.evil/kali/pool/main/l/linux/"
        ));
        assert!(!official_pool(
            "https://ddebs.ubuntu.com/pool/main/l/../../"
        ));
    }
    #[test]
    fn discovers_all_three_distributions_from_cached_official_listings_offline() {
        for banner in [
            UBUNTU.to_owned(),
            UBUNTU.replace("x86_64", "aarch64"),
            DEBIAN.to_owned(),
            DEBIAN
                .replace("amd64", "arm64")
                .replace("x86_64", "aarch64"),
            KALI.to_owned(),
            KALI.replace("arm64", "amd64").replace("aarch64", "x86_64"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cache = dir.path().join("cache");
            let id = identity(&banner).unwrap();
            let version = id.version.as_ref().unwrap();
            let prefix = if id.distribution == "Ubuntu" {
                "linux-image-unsigned-"
            } else {
                "linux-image-"
            };
            let suffix = if id.distribution == "Ubuntu" {
                "dbgsym"
            } else {
                "dbg"
            };
            let regular = format!(
                "{prefix}{}{}_{version}_{}.deb",
                id.release,
                if id.distribution == "Debian" {
                    "-unsigned"
                } else {
                    ""
                },
                id.architecture
            );
            let debug = format!(
                "{prefix}{}-{suffix}_{version}_{}.{}",
                id.release,
                id.architecture,
                if suffix == "dbgsym" { "ddeb" } else { "deb" }
            );
            let files = html(&[&debug, &regular]);
            match id.distribution {
                "Ubuntu" => {
                    cache_index(
                        &cache,
                        "https://ddebs.ubuntu.com/pool/main/l/",
                        &html(&["linux/", "linux-hwe-5.15/", "../", "https://evil.test/"]),
                    );
                    cache_index(
                        &cache,
                        "https://ddebs.ubuntu.com/pool/main/l/linux/",
                        &files,
                    );
                    cache_index(
                        &cache,
                        if id.architecture == "arm64" {
                            "https://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux/"
                        } else {
                            "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/"
                        },
                        &files,
                    );
                }
                "Debian" => cache_index(
                    &cache,
                    "https://deb.debian.org/debian/pool/main/l/linux/",
                    &files,
                ),
                _ => cache_index(
                    &cache,
                    "https://old.kali.org/kali/pool/main/l/linux/",
                    &files,
                ),
            }
            let raw = dir.path().join("image.raw");
            fs::write(&raw, format!("{banner}\0")).unwrap();
            let image = Image::open(&raw, &cache, &Job::default()).unwrap();
            let found = find_packages(&image, &cache, false, &Job::default()).unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].release, id.release);
            assert!(official_pool(
                found[0]
                    .debug_url
                    .rsplit_once('/')
                    .map(|(base, _)| format!("{base}/"))
                    .as_deref()
                    .unwrap()
            ));
        }
    }
    #[test]
    fn ubuntu_flavor_discovery_is_bounded_and_includes_current_hwe_series() {
        let dirs = ubuntu_directories(
            &identity(UBUNTU).unwrap(),
            &links(&html(&[
                "linux/",
                "linux-hwe-6.8/",
                "linux-hwe-5.15/",
                "linux-meta/",
                "linux-tools/",
            ])),
        );
        assert_eq!(dirs, ["linux/", "linux-hwe-6.8/"]);
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    #[test]
    fn same_build_merges_banners_and_prioritized_sources_but_different_builds_stay_distinct() {
        let first = KernelPackage {
            banner: "banner one".into(),
            banners: vec![],
            sources: vec![],
            distribution: "Debian".into(),
            release: "6.12-amd64".into(),
            architecture: "amd64".into(),
            version: "6.12-1".into(),
            debug_url: "https://primary.test/debug.deb".into(),
            kernel_url: "https://primary.test/kernel.deb".into(),
            download_size: None,
        };
        let mut second = first.clone();
        second.banner = "banner two".into();
        let mut mirror = second.clone();
        mirror.debug_url = "https://mirror.test/debug.deb".into();
        mirror.kernel_url = "https://mirror.test/kernel.deb".into();
        let mut other = first.clone();
        other.version = "6.12-2".into();
        let merged = merge_candidates(vec![first, second, mirror, other]);
        assert_eq!(merged.len(), 2);
        let build = merged.iter().find(|p| p.version == "6.12-1").unwrap();
        assert!(build.accepts("banner one") && build.accepts("banner two"));
        assert!(!build.accepts("unrelated banner"));
        assert_eq!(build.banners.len(), 2);
        assert_eq!(build.sources.len(), 1);
        assert_eq!(build.debug_url, "https://primary.test/debug.deb");
    }
}
