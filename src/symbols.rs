use crate::{Job, image::Image};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

pub struct Isf {
    pub slide: std::sync::atomic::AtomicU64,
    pub data: Value,
    pub label: String,
    pub digest: String,
    pub banner: Vec<u8>,
    pub locations: Vec<u64>,
}
impl Isf {
    pub fn parse(bytes: &[u8], label: String) -> Result<Self> {
        let data: Value = serde_json::from_slice(bytes).context("ISF JSON 解析失败")?;
        ensure!(
            data["base_types"]["pointer"]["size"].as_u64() == Some(8),
            "仅支持 64 位 ISF"
        );
        let encoded = data["symbols"]["linux_banner"]["constant_data"]
            .as_str()
            .context("ISF 缺少完整 linux_banner constant_data")?;
        let banner = STANDARD.decode(encoded)?;
        ensure!(
            banner.starts_with(b"Linux version ")
                && banner.last() == Some(&0)
                && banner.len() <= 65536
                && !banner[..banner.len() - 1].contains(&0),
            "ISF banner 无效或不完整"
        );
        Ok(Self {
            slide: std::sync::atomic::AtomicU64::new(0),
            data,
            label,
            digest: format!("{:x}", Sha256::digest(bytes)),
            banner,
            locations: Vec::new(),
        })
    }
    pub fn address(&self, name: &str) -> Result<u64> {
        Ok(self
            .raw_address(name)?
            .wrapping_add(self.slide.load(std::sync::atomic::Ordering::Relaxed)))
    }
    pub fn raw_address(&self, name: &str) -> Result<u64> {
        self.data["symbols"][name]["address"]
            .as_u64()
            .with_context(|| format!("ISF 缺少符号 {name}"))
    }
    fn resolved_field<'a>(
        &'a self,
        structure: &str,
        field: &str,
        depth: usize,
    ) -> Result<(u64, &'a Value)> {
        ensure!(depth < 32, "ISF 匿名结构循环或嵌套过深");
        if let Some((first, rest)) = field.split_once('.') {
            let (offset, f) = self.resolved_field(structure, first, depth + 1)?;
            let (inner, f) = self.resolved_field(
                f["type"]["name"].as_str().context("ISF 嵌套类型无效")?,
                rest,
                depth + 1,
            )?;
            return Ok((offset.checked_add(inner).context("ISF offset 溢出")?, f));
        }
        let fields = self.data["user_types"][structure]["fields"]
            .as_object()
            .context("ISF 结构缺失")?;
        if let Some(f) = fields.get(field) {
            let offset = f["offset"].as_u64().context("ISF offset 无效")?;
            let size = self.data["user_types"][structure]["size"]
                .as_u64()
                .context("ISF 结构 size 无效")?;
            let length = self.type_size(&f["type"])?;
            ensure!(
                offset.checked_add(length).is_some_and(|end| end <= size),
                "ISF 字段越界 {structure}.{field}"
            );
            return Ok((offset, f));
        }
        let mut found = None;
        for (name, f) in fields {
            if name.starts_with("unnamed_field_")
                && matches!(f["type"]["kind"].as_str(), Some("union" | "struct"))
                && let Some(ty) = f["type"]["name"].as_str()
                && let Ok((offset, leaf)) = self.resolved_field(ty, field, depth + 1)
            {
                ensure!(found.is_none(), "ISF 匿名字段歧义 {structure}.{field}");
                found = Some((
                    f["offset"]
                        .as_u64()
                        .context("匿名字段 offset 无效")?
                        .checked_add(offset)
                        .context("ISF offset 溢出")?,
                    leaf,
                ));
            }
        }
        found.with_context(|| format!("ISF 缺少字段 {structure}.{field}"))
    }
    pub fn field(&self, structure: &str, field: &str) -> Result<&Value> {
        Ok(self.resolved_field(structure, field, 0)?.1)
    }
    pub fn type_size(&self, ty: &Value) -> Result<u64> {
        let name = || ty["name"].as_str().context("ISF type name 无效");
        match ty["kind"].as_str() {
            Some("pointer") => Ok(8),
            Some("array") => ty["count"]
                .as_u64()
                .context("ISF array count 无效")?
                .checked_mul(if ty.get("subtype").is_some() {
                    self.type_size(&ty["subtype"])?
                } else {
                    1
                })
                .context("ISF array size 溢出"),
            Some("base") => self.data["base_types"][name()?]["size"]
                .as_u64()
                .context("ISF base size 无效"),
            Some("struct" | "union") => self.data["user_types"][name()?]["size"]
                .as_u64()
                .context("ISF structure size 无效"),
            Some("enum") => self.data["enums"][name()?]["size"]
                .as_u64()
                .context("ISF enum size 无效"),
            Some("bitfield") => self.type_size(&ty["type"]),
            _ => bail!("不支持 ISF 字段类型: {ty}"),
        }
    }
    pub fn offset(&self, structure: &str, field: &str) -> Result<u64> {
        let (offset, f) = self.resolved_field(structure, field, 0)?;
        let size = self.data["user_types"][structure]["size"]
            .as_u64()
            .context("ISF 结构 size 无效")?;
        let length = self.type_size(&f["type"])?;
        ensure!(
            offset.checked_add(length).is_some_and(|end| end <= size),
            "ISF 字段越界 {structure}.{field}"
        );
        Ok(offset)
    }
    pub fn size(&self, structure: &str, field: &str) -> Result<usize> {
        self.offset(structure, field)?;
        usize::try_from(self.type_size(&self.field(structure, field)?["type"])?)
            .context("ISF 字段过大")
    }
}
fn read_stream(mut r: impl Read, job: &Job) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buffer = [0; 65536];
    loop {
        job.check()?;
        let n = r.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        ensure!(data.len() + n <= 256 * 1024 * 1024, "ISF 超过 256 MiB 限制");
        data.extend_from_slice(&buffer[..n]);
    }
    Ok(data)
}
fn decode(r: impl Read, name: &str, job: &Job) -> Result<Vec<u8>> {
    if name.ends_with(".xz") {
        read_stream(xz2::read::XzDecoder::new(r), job)
    } else {
        read_stream(r, job)
    }
}
fn collect(path: &Path, job: &Job, out: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    job.check()?;
    if path.is_dir() {
        let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| e.path());
        for e in entries {
            if !e.file_type()?.is_symlink()
                && !e.file_name().to_string_lossy().ends_with(".source.json")
            {
                collect(&e.path(), job, out)?;
            }
        }
    } else {
        let name = path.to_string_lossy().into_owned();
        if name.ends_with(".zip") {
            let mut z = zip::ZipArchive::new(File::open(path)?)?;
            for index in 0..z.len() {
                job.check()?;
                let member = z.by_index(index)?;
                let entry = member.name().to_owned();
                if entry.ends_with(".json") || entry.ends_with(".json.xz") {
                    let bytes = decode(member, &entry, job)?;
                    out.push((format!("{name}::{entry}"), bytes));
                }
            }
        } else if name.ends_with(".json") || name.ends_with(".json.xz") {
            out.push((name.clone(), decode(File::open(path)?, &name, job)?));
        } else {
            ensure!(path.exists(), "符号路径不存在: {}", path.display());
        }
    }
    Ok(())
}
pub fn inspect(path: &Path, job: &Job) -> Result<Vec<Isf>> {
    let mut entries = Vec::new();
    collect(path, job, &mut entries)?;
    ensure!(!entries.is_empty(), "符号路径不含 ISF");
    let mut parsed = Vec::new();
    for (name, bytes) in entries {
        job.check()?;
        parsed.push(Isf::parse(&bytes, name)?);
    }
    Ok(parsed)
}
pub fn matching(path: &Path, image: &Image, job: &Job) -> Result<Vec<Isf>> {
    job.report("读取本地 ISF");
    let mut entries = Vec::new();
    collect(path, job, &mut entries)?;
    ensure!(!entries.is_empty(), "符号路径不含 JSON / JSON.XZ / ZIP ISF");
    let banners = image.banners(job)?;
    let mut matches = Vec::new();
    let mut issues = Vec::new();
    for (name, bytes) in entries {
        job.check()?;
        match Isf::parse(&bytes, name.clone()) {
            Ok(mut isf) => {
                job.report(format!("匹配符号 {name}"));
                isf.locations = banners
                    .iter()
                    .filter(|(_, bytes)| bytes == &isf.banner)
                    .map(|(p, _)| *p)
                    .collect();
                if !isf.locations.is_empty() {
                    matches.push(isf);
                }
            }
            Err(e) => issues.push(format!("{name}: {e}")),
        }
    }
    ensure!(
        !matches.is_empty(),
        "完整内核 banner 与本地符号不匹配。{}",
        issues.join("; ")
    );
    Ok(matches)
}

#[derive(Default)]
pub struct LocalMatches {
    pub matched: std::collections::HashMap<std::path::PathBuf, Vec<String>>,
    pub diagnostics: Vec<String>,
}
/// Compare full banners only; page-table validation still happens during analysis.
pub fn match_local_files(
    paths: &[std::path::PathBuf],
    image: &Image,
    job: &Job,
) -> Result<LocalMatches> {
    let banners = image.banners(job)?;
    let mut report = LocalMatches::default();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        job.check()?;
        let mut entries = Vec::new();
        if let Err(error) = collect(path, job, &mut entries) {
            job.check()?;
            report
                .diagnostics
                .push(format!("{}: {error:#}", path.display()));
            continue;
        }
        for (label, bytes) in entries {
            job.check()?;
            match Isf::parse(&bytes, label.clone()) {
                Ok(isf)
                    if banners.iter().any(|(_, banner)| *banner == isf.banner)
                        && seen.insert(isf.digest.clone()) =>
                {
                    report.matched.entry(path.clone()).or_default().push(label);
                }
                Ok(_) => (),
                Err(error) => report.diagnostics.push(format!("{label}: {error:#}")),
            }
        }
        job.report(format!(
            "本地匹配：{} 个文件匹配 · {}",
            report.matched.len(),
            path.display()
        ));
    }
    Ok(report)
}
pub const REPOSITORY: &str = "https://github.com/Abyss-W4tcher/volatility3-symbols";
const RAW: &str = "https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/";
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RemoteMatch {
    pub banner: String,
    pub path: String,
    pub url: String,
}
pub fn repository_url(path: &str) -> Result<String> {
    ensure!(
        path.ends_with(".json.xz")
            && !path.starts_with('/')
            && path
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..")
            && !path.contains(['\\', '\0', ':']),
        "仓库 ISF 路径无效"
    );
    let mut encoded = String::new();
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(format!("{RAW}{encoded}"))
}
fn fetch(url: &str, job: &Job) -> Result<Vec<u8>> {
    use std::{
        process::{Command, Stdio},
        thread,
        time::Duration,
    };
    job.check()?;
    let file = tempfile::NamedTempFile::new()?;
    let errors = tempfile::tempfile()?;
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "10",
            "--max-time",
            "90",
            "--max-filesize",
            "268435456",
            "--output",
        ])
        .arg(file.path())
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(errors.try_clone()?)
        .spawn()
        .context("无法启动 curl；安装 curl 或使用本地 ISF / --offline")?;
    let status = loop {
        if let Err(e) = job.check() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut error = String::new();
    use std::io::{Seek, SeekFrom};
    let mut errors = errors;
    errors.seek(SeekFrom::Start(0))?;
    errors.take(4096).read_to_string(&mut error)?;
    ensure!(status.success(), "符号下载失败: {} ({error})", url);
    read_stream(File::open(file.path())?, job)
}
pub fn lookup_index(index: &Value, banners: &[(u64, Vec<u8>)]) -> Result<Vec<RemoteMatch>> {
    let index = index.as_object().context("远程 banner 索引格式无效")?;
    let mut found = std::collections::BTreeMap::new();
    for (_, bytes) in banners {
        let banner = String::from_utf8_lossy(bytes)
            .trim_end_matches(['\0', '\n'])
            .to_string();
        if let Some(paths) = index.get(&banner).and_then(Value::as_array) {
            for path in paths {
                let path = path.as_str().context("索引路径无效")?;
                let url = repository_url(path)?;
                let arm = banner.contains("aarch64") || banner.contains("-arm64");
                if !(if arm {
                    path.contains("/arm64/") || path.contains("/aarch64/")
                } else {
                    path.contains("/amd64/") || path.contains("/x86_64/")
                }) {
                    continue;
                }
                found.insert(
                    path.to_string(),
                    RemoteMatch {
                        banner: banner.clone(),
                        path: path.into(),
                        url,
                    },
                );
            }
        }
    }
    Ok(found.into_values().collect())
}
pub fn remote_matches(
    image: &Image,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<Vec<RemoteMatch>> {
    let banners = image.banners(job)?;
    let path = cache.join("symbols/banners_plain.json");
    let cached = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object);
    let fresh = fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age.as_secs() < 86400);
    let index = if (fresh || !network)
        && let Some(index) = &cached
    {
        index.clone()
    } else {
        ensure!(network, "离线模式且没有有效的远程 banner 索引缓存");
        job.report("获取 GitHub 完整 banner 索引（仅下载索引，不上传镜像）");
        match fetch(&format!("{RAW}banners/banners_plain.json"), job) {
            Ok(bytes) => {
                let index: Value = serde_json::from_slice(&bytes)?;
                ensure!(index.is_object(), "banner 索引格式无效");
                crate::store::atomic_write(&path, &bytes)?;
                index
            }
            Err(error) => {
                job.check()?;
                if let Some(index) = cached {
                    job.report(format!("索引更新失败，使用已缓存索引: {error}"));
                    index
                } else {
                    return Err(error);
                }
            }
        }
    };
    lookup_index(&index, &banners)
}
pub fn catalog_search(
    cache: &Path,
    query: &str,
    network: bool,
    job: &Job,
) -> Result<Vec<RemoteMatch>> {
    let path = cache.join("symbols/banners_plain.json");
    if !path.is_file() {
        ensure!(network, "离线模式且索引未缓存；按 o 开启在线后刷新索引");
        refresh_index(cache, job)?;
    }
    let index: Value = serde_json::from_slice(&fs::read(path)?)?;
    let words: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
    let mut found = std::collections::BTreeMap::new();
    for (banner, paths) in index.as_object().context("远程索引格式无效")? {
        job.check()?;
        if !banner.starts_with("Linux version ") {
            continue;
        }
        for path in paths.as_array().context("远程索引路径列表无效")? {
            let path = path.as_str().context("远程索引路径无效")?;
            let text = format!("{banner} {path}").to_lowercase();
            if words.iter().all(|w| text.contains(w)) {
                found.insert(
                    (path.to_owned(), banner.clone()),
                    RemoteMatch {
                        banner: banner.clone(),
                        path: path.into(),
                        url: repository_url(path)?,
                    },
                );
            }
        }
    }
    Ok(found.into_values().collect())
}

pub fn cache_filename(path: &str) -> Result<String> {
    repository_url(path)?;
    let stem = path
        .rsplit('/')
        .next()
        .unwrap_or("symbols")
        .trim_end_matches(".json.xz");
    let name: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(100)
        .collect();
    Ok(format!(
        "{}-{:x}.json.xz",
        name,
        Sha256::digest(path.as_bytes())
    ))
}
pub fn download(
    m: &RemoteMatch,
    image: &Image,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<Isf> {
    download_checked(m, Some(image), cache, network, job)
}
pub fn download_catalog(m: &RemoteMatch, cache: &Path, network: bool, job: &Job) -> Result<Isf> {
    let _guard = crate::cache::lock(cache, false)?;
    download_checked(m, None, cache, network, job)
}
fn download_checked(
    m: &RemoteMatch,
    image: Option<&Image>,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<Isf> {
    ensure!(
        m.url == repository_url(&m.path)?,
        "下载链接不属于指定符号仓库"
    );
    let key = format!("{:x}", Sha256::digest(m.path.as_bytes()));
    let legacy = cache.join("symbols/isf").join(format!("{key}.json.xz"));
    let readable = cache.join("symbols/isf").join(cache_filename(&m.path)?);
    let target = if !readable.exists() && legacy.exists() {
        legacy
    } else {
        readable
    };
    let existing = fs::read(&target).ok();
    let mut replace = existing.is_none();
    let mut bytes = if let Some(bytes) = &existing {
        bytes.clone()
    } else {
        ensure!(network, "离线模式且所需 ISF 尚未下载: {}", m.url);
        job.report(format!("下载匹配 ISF: {}", m.url));
        fetch(&m.url, job)?
    };
    let validate = |bytes: &[u8]| -> Result<Isf> {
        let decoded = decode(bytes, "isf.json.xz", job)?;
        let mut isf = Isf::parse(&decoded, target.display().to_string())?;
        ensure!(
            String::from_utf8_lossy(&isf.banner).trim_end_matches(['\0', '\n']) == m.banner,
            "下载 ISF 的完整 banner 与索引不一致"
        );
        if let Some(image) = image {
            isf.locations = image
                .banners(job)?
                .into_iter()
                .filter(|(_, b)| b == &isf.banner)
                .map(|(p, _)| p)
                .collect();
            ensure!(
                !isf.locations.is_empty(),
                "下载 ISF 与镜像完整 banner 不匹配"
            );
        }
        Ok(isf)
    };
    let isf = match validate(&bytes) {
        Ok(isf) => isf,
        Err(error) if existing.is_some() && network => {
            job.check()?;
            job.report(format!("下载缓存校验失败，重新获取: {error}"));
            bytes = fetch(&m.url, job)?;
            replace = true;
            validate(&bytes)?
        }
        Err(error) => return Err(error.context("ISF 校验失败；在线模式可重新下载")),
    };
    job.check()?;
    if replace {
        crate::store::atomic_write(&target, &bytes)?;
    }
    // Retain the exact source link alongside the validated symbol file.
    crate::store::atomic_write(
        &target.with_extension("source.json"),
        &serde_json::to_vec_pretty(m)?,
    )?;
    Ok(isf)
}
pub fn resolve(
    local: &Path,
    image: &Image,
    cache: &Path,
    network: bool,
    job: &Job,
) -> Result<Vec<Isf>> {
    match matching(local, image, job) {
        Ok(matches) => return Ok(matches),
        Err(e) => {
            job.check()?;
            job.report(format!("本地符号未匹配: {e}"));
        }
    }
    let downloaded = cache.join("symbols/isf");
    if downloaded.exists()
        && let Ok(matches) = matching(&downloaded, image, job)
        && !matches.is_empty()
    {
        return Ok(matches);
    }
    let matches = remote_matches(image, cache, network, job)?;
    ensure!(
        !matches.is_empty(),
        "仓库没有匹配的完整 banner；请用 y 指定本地 ISF（Kali 6.8.11 ARM64 可用 g 准备）。{REPOSITORY}"
    );
    matches
        .iter()
        .map(|m| download(m, image, cache, network, job))
        .collect()
}

pub fn refresh_index(cache: &Path, job: &Job) -> Result<()> {
    let _guard = crate::cache::lock(cache, false)?;
    job.report("刷新 GitHub 符号索引");
    let bytes = fetch(&format!("{RAW}banners/banners_plain.json"), job)?;
    let index: Value = serde_json::from_slice(&bytes)?;
    ensure!(index.is_object(), "banner 索引格式无效");
    job.check()?;
    crate::store::atomic_write(&cache.join("symbols/banners_plain.json"), &bytes)
}
