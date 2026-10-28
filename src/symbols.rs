use crate::{Job, image::Image};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    sync::RwLock,
};

mod network;
pub use network::GithubAccess;
use network::fetch_github;

pub struct Isf {
    pub slide: std::sync::atomic::AtomicU64,
    pub(crate) validation_diagnostics: RwLock<Vec<String>>,
    /// Field layouts are memoized on first lookup; mutate `user_types` only before reading.
    pub data: Value,
    pub label: String,
    pub digest: String,
    pub banner: Vec<u8>,
    pub locations: Vec<u64>,
    pub(crate) layouts: LayoutCache,
}
/// Resolved placement of one (possibly dotted or anonymous-member) field.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub offset: u64,
    pub size: u64,
    /// `(bit_position, bit_length)` exactly as the ISF states them, for bitfields.
    pub bits: Option<(Option<u64>, Option<u64>)>,
}
/// structure -> field -> layout; only successful resolutions are kept so
/// errors keep their full context chain.
#[derive(Default)]
pub(crate) struct LayoutCache(
    RwLock<std::collections::HashMap<String, std::collections::HashMap<String, Layout>>>,
);
impl Isf {
    pub fn parse(bytes: &[u8], label: String) -> Result<Self> {
        let data: Value = serde_json::from_slice(bytes).context("ISF JSON 解析失败")?;
        ensure!(
            data["base_types"]["pointer"]["size"].as_u64() == Some(8)
                || (data["metadata"]["windows"]["pdb"].is_object()
                    && data["base_types"]["pointer"]["size"].as_u64() == Some(4)),
            "仅支持 64 位 ISF"
        );
        let banner = if data["metadata"]["windows"]["pdb"].is_object() {
            let p = &data["metadata"]["windows"]["pdb"];
            ensure!(
                p["database"].is_string() && p["GUID"].is_string() && p["age"].is_u64(),
                "Windows ISF PDB 身份不完整"
            );
            format!(
                "Windows PDB {} {} age {}\0",
                p["database"].as_str().unwrap(),
                p["GUID"].as_str().unwrap(),
                p["age"]
            )
            .into_bytes()
        } else {
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
            banner
        };
        let windows = data["metadata"]["windows"]["pdb"].is_object();
        let isf = Self {
            slide: std::sync::atomic::AtomicU64::new(0),
            validation_diagnostics: RwLock::default(),
            data,
            label,
            digest: format!("{:x}", Sha256::digest(bytes)),
            banner,
            locations: Vec::new(),
            layouts: LayoutCache::default(),
        };
        if windows {
            crate::windows_symbols::PdbIdentity::from_isf(&isf)?;
            crate::windows::Architecture::from_isf(&isf)?;
        }
        Ok(isf)
    }
    pub fn is_windows(&self) -> bool {
        self.data["metadata"]["windows"]["pdb"].is_object()
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
    /// Size of a typed global, without inferring its type from its name/address.
    pub fn symbol_size(&self, name: &str) -> Result<u64> {
        self.raw_address(name)?;
        let symbol = &self.data["symbols"][name];
        ensure!(symbol["type_conflict"] != true, "ISF 符号类型冲突: {name}");
        let size = self.type_size(
            symbol
                .get("type")
                .with_context(|| format!("ISF 缺少符号类型 {name}"))?,
        )?;
        ensure!(size > 0, "ISF 符号类型为空: {name}");
        Ok(size)
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
    /// Whether `structure.field` resolves.
    ///
    /// Deliberately not memoized: `data` is public and callers rewrite it to
    /// model another kernel, so a cached answer can outlive the structure it
    /// described. The callers that need this in a loop hoist the probe out of
    /// the loop instead.
    pub fn has_field(&self, structure: &str, field: &str) -> bool {
        self.field(structure, field).is_ok()
    }
    pub fn type_size(&self, ty: &Value) -> Result<u64> {
        let name = || ty["name"].as_str().context("ISF type name 无效");
        match ty["kind"].as_str() {
            Some("pointer") => {
                let width = self.data["base_types"]["pointer"]["size"]
                    .as_u64()
                    .unwrap_or(8);
                ensure!(matches!(width, 4 | 8), "ISF pointer size 无效");
                Ok(width)
            }
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
    /// Offset, width and bitfield placement of a field, bounds-checked against
    /// the outer structure. Resolved once per (structure, field).
    pub fn layout(&self, structure: &str, field: &str) -> Result<Layout> {
        if let Some(layout) = self
            .layouts
            .0
            .read()
            .ok()
            .and_then(|cache| cache.get(structure)?.get(field).copied())
        {
            return Ok(layout);
        }
        let (offset, f) = self.resolved_field(structure, field, 0)?;
        let size = self.data["user_types"][structure]["size"]
            .as_u64()
            .context("ISF 结构 size 无效")?;
        let length = self.type_size(&f["type"])?;
        ensure!(
            offset.checked_add(length).is_some_and(|end| end <= size),
            "ISF 字段越界 {structure}.{field}"
        );
        let ty = &f["type"];
        let layout = Layout {
            offset,
            size: length,
            bits: (ty["kind"] == "bitfield")
                .then(|| (ty["bit_position"].as_u64(), ty["bit_length"].as_u64())),
        };
        if let Ok(mut cache) = self.layouts.0.write() {
            cache
                .entry(structure.to_owned())
                .or_default()
                .insert(field.to_owned(), layout);
        }
        Ok(layout)
    }
    /// Forget memoized layouts after editing `data` in place.
    /// Drop every memoized layout and field-presence answer.
    ///
    /// Callers may edit `data` to model a different kernel, so both caches must
    /// be invalidated together or a stale probe silently changes behaviour.
    pub fn invalidate_layouts(&mut self) {
        if let Ok(cache) = self.layouts.0.get_mut() {
            cache.clear();
        }
    }
    pub fn offset(&self, structure: &str, field: &str) -> Result<u64> {
        Ok(self.layout(structure, field)?.offset)
    }
    pub fn size(&self, structure: &str, field: &str) -> Result<usize> {
        usize::try_from(self.layout(structure, field)?.size).context("ISF 字段过大")
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
pub(crate) fn decode(r: impl Read, name: &str, job: &Job) -> Result<Vec<u8>> {
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
pub(crate) fn entries(path: &Path, job: &Job) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    collect(path, job, &mut out)?;
    Ok(out)
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
    if image.banners(job)?.is_empty() && !image.windows_candidates(job)?.is_empty() {
        return crate::windows_symbols::resolve(
            path,
            image,
            Path::new("/nonexistent-zero-cache"),
            false,
            job,
        );
    }
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
    let windows = if banners.is_empty() {
        image
            .windows_candidates(job)?
            .iter()
            .map(|c| c.pdb.clone())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
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
                    if (banners.iter().any(|(_, banner)| *banner == isf.banner)
                        || (isf.is_windows()
                            && crate::windows_symbols::PdbIdentity::from_isf(&isf)
                                .is_ok_and(|p| windows.contains(&p))))
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
/// Default symbol repository; settings may name another GitHub repository.
pub const REPOSITORY: &str = "https://github.com/Abyss-W4tcher/volatility3-symbols";
/// A GitHub symbol repository laid out like the default one: an index at
/// `banners/banners_plain.json` on a branch, ISFs as files or release assets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    /// `https://github.com/<owner>/<repo>`, without a trailing slash.
    pub web: String,
    /// `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/`.
    raw: String,
    branch: String,
}
impl Repository {
    /// Accept `https://github.com/<owner>/<repo>` with an optional
    /// `/tree/<branch>` (default `master`); nothing else is a repository.
    pub fn parse(url: &str) -> Result<Self> {
        let rest = url
            .trim()
            .trim_end_matches('/')
            .strip_prefix("https://github.com/")
            .context("符号仓库必须是 https://github.com/<所有者>/<仓库> 形式")?;
        let mut parts = rest.splitn(3, '/');
        let (owner, repo) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        let branch = match parts.next() {
            None => "master",
            Some(tail) => tail
                .strip_prefix("tree/")
                .context("仓库地址只能附加 /tree/<分支>")?,
        };
        let name = |s: &str| {
            !s.is_empty()
                && s.len() <= 100
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        };
        ensure!(name(owner) && name(repo), "符号仓库的所有者或仓库名无效");
        ensure!(
            !branch.is_empty() && branch.len() <= 100 && branch.split('/').all(name),
            "符号仓库分支名无效"
        );
        Ok(Self {
            web: format!("https://github.com/{owner}/{repo}"),
            raw: format!("https://raw.githubusercontent.com/{owner}/{repo}/{branch}/"),
            branch: branch.to_owned(),
        })
    }
    pub fn default_repository() -> Self {
        Self::parse(REPOSITORY).expect("default repository")
    }
    /// The repository named in this cache's settings.
    pub fn configured(cache: &Path) -> Result<Self> {
        Self::parse(&crate::store::settings(cache)?.symbol_repository)
    }
    pub fn is_default(&self) -> bool {
        *self == Self::default_repository()
    }
    /// Where this repository's index is saved. The default keeps its historic
    /// name; any other repository gets its own file, so indexes never mix.
    pub fn index_file(&self, cache: &Path) -> std::path::PathBuf {
        if self.is_default() {
            cache.join("symbols/banners_plain.json")
        } else {
            let id = format!(
                "{:x}",
                Sha256::digest(format!("{}\0{}", self.web, self.branch))
            );
            cache.join(format!("symbols/banners_plain-{}.json", &id[..16]))
        }
    }
    fn index_url(&self) -> String {
        format!("{}banners/banners_plain.json", self.raw)
    }
    /// Download URL of a repository-relative ISF path.
    pub fn url(&self, path: &str) -> Result<String> {
        ensure!(
            path.ends_with(".json.xz")
                && !path.starts_with('/')
                && path
                    .split('/')
                    .all(|p| !p.is_empty() && p != "." && p != "..")
                && !path.contains(['\\', '\0', ':'])
                && (!path.starts_with(RELEASES) || path.split('/').count() == 4),
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
        Ok(if path.starts_with(RELEASES) {
            format!("{}/{encoded}", self.web)
        } else {
            format!("{}{encoded}", self.raw)
        })
    }
    /// Normalize one index entry (a repository path or a percent-encoded
    /// release asset URL of this repository) to its repository-relative path.
    pub fn index_path(&self, entry: &str) -> Result<String> {
        let path = match entry
            .strip_prefix(self.web.as_str())
            .and_then(|p| p.strip_prefix('/'))
            .filter(|p| p.starts_with(RELEASES))
        {
            Some(release) => percent_decode(release)?,
            None => entry.to_owned(),
        };
        self.url(&path)?;
        Ok(path)
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RemoteMatch {
    pub banner: String,
    pub path: String,
    pub url: String,
}
/// Repository-relative prefix of release assets; the index now lists them as full URLs.
const RELEASES: &str = "releases/download/";
/// Download URL of an ISF path in the default repository.
pub fn repository_url(path: &str) -> Result<String> {
    Repository::default_repository().url(path)
}
/// Normalize an index entry of the default repository.
pub fn index_path(entry: &str) -> Result<String> {
    Repository::default_repository().index_path(entry)
}
fn percent_decode(value: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(b) = input.next() {
        if b == b'%' {
            let hex = [input.next(), input.next()];
            let digit = |d: Option<u8>| (d? as char).to_digit(16);
            let (Some(high), Some(low)) = (digit(hex[0]), digit(hex[1])) else {
                bail!("仓库 ISF 路径编码无效");
            };
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(b);
        }
    }
    Ok(String::from_utf8(bytes)?)
}
fn has_token(path: &str, token: &str) -> bool {
    let separator = |c: Option<char>| c.is_none_or(|c| "/_-.".contains(c));
    path.match_indices(token).any(|(at, _)| {
        separator(path[..at].chars().next_back())
            && separator(path[at + token.len()..].chars().next())
    })
}
/// Architecture named by an ISF path: `Some(true)` ARM64, `Some(false)` x86_64,
/// `None` for an architecture the native engine cannot translate or no marker.
fn path_arm64(path: &str) -> Option<bool> {
    if ["arm64", "aarch64"].iter().any(|t| has_token(path, t)) {
        Some(true)
    } else if ["amd64", "x86_64"].iter().any(|t| has_token(path, t)) {
        Some(false)
    } else {
        None
    }
}
#[derive(Debug)]
pub(crate) struct HttpError {
    pub status: u16,
    pub url: String,
}
impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "符号下载 HTTP {}：{}", self.status, self.url)
    }
}
impl std::error::Error for HttpError {}
pub(crate) fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<HttpError>()
        .is_some_and(|e| e.status == 404)
}
pub(crate) struct RangeResponse {
    pub bytes: Vec<u8>,
    pub start: u64,
    pub total: u64,
}
pub(crate) fn fetch_range(
    url: &str,
    range: &str,
    limit: usize,
    job: &Job,
) -> Result<RangeResponse> {
    let (bytes, status, headers) = transfer(url, Some(range), limit, job)?;
    ensure!(
        status == 206,
        "官方符号包服务器未返回 HTTP 206；无法按需读取 ZIP"
    );
    let value = headers
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-range")
                .then_some(value.trim())
        })
        .next_back()
        .context("Range 响应缺少 Content-Range")?;
    let (span, total) = value
        .strip_prefix("bytes ")
        .and_then(|v| v.split_once('/'))
        .context("Content-Range 格式无效")?;
    let (start, end) = span.split_once('-').context("Content-Range 范围无效")?;
    let (start, end, total): (u64, u64, u64) = (start.parse()?, end.parse()?, total.parse()?);
    ensure!(
        start <= end && end < total && end - start + 1 == bytes.len() as u64,
        "Range 响应长度或边界不一致"
    );
    Ok(RangeResponse {
        bytes,
        start,
        total,
    })
}
pub(crate) fn fetch(url: &str, job: &Job) -> Result<Vec<u8>> {
    Ok(transfer(url, None, 256 * 1024 * 1024, job)?.0)
}
fn transfer(
    url: &str,
    range: Option<&str>,
    limit: usize,
    job: &Job,
) -> Result<(Vec<u8>, u16, String)> {
    transfer_with_timeout(url, range, limit, 90, job)
}
fn transfer_with_timeout(
    url: &str,
    range: Option<&str>,
    limit: usize,
    timeout: u64,
    job: &Job,
) -> Result<(Vec<u8>, u16, String)> {
    use std::{
        process::{Command, Stdio},
        thread,
        time::Duration,
    };
    job.check()?;
    let file = tempfile::NamedTempFile::new()?;
    let headers = tempfile::NamedTempFile::new()?;
    let errors = tempfile::tempfile()?;
    let status_output = tempfile::tempfile()?;
    let mut command = Command::new("curl");
    command
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
        ])
        .arg(timeout.to_string())
        .arg("--max-filesize")
        .arg(limit.to_string())
        .arg("--output")
        .arg(file.path())
        .arg("--dump-header")
        .arg(headers.path())
        .args(["--write-out", "%{http_code}"]);
    if let Some(range) = range {
        command.arg("--range").arg(range);
    }
    let mut child = command
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(status_output.try_clone()?)
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
    use std::io::{Seek, SeekFrom};
    let mut status_output = status_output;
    status_output.seek(SeekFrom::Start(0))?;
    let mut code = String::new();
    status_output.take(16).read_to_string(&mut code)?;
    let code: u16 = code.trim().parse().unwrap_or(0);
    if code >= 400 {
        return Err(HttpError {
            status: code,
            url: url.into(),
        }
        .into());
    }
    let mut error = String::new();
    let mut errors = errors;
    errors.seek(SeekFrom::Start(0))?;
    errors.take(4096).read_to_string(&mut error)?;
    ensure!(status.success(), "符号下载失败: {url} ({})", error.trim());
    job.check()?;
    ensure!(
        fs::metadata(file.path())?.len() <= limit as u64,
        "下载响应超过大小限制"
    );
    let bytes = read_stream(File::open(file.path())?, job)?;
    let headers = fs::read_to_string(headers.path())?;
    Ok((bytes, code, headers))
}
pub fn lookup_index(index: &Value, banners: &[(u64, Vec<u8>)]) -> Result<Vec<RemoteMatch>> {
    lookup_index_in(&Repository::default_repository(), index, banners)
}
pub fn lookup_index_in(
    repository: &Repository,
    index: &Value,
    banners: &[(u64, Vec<u8>)],
) -> Result<Vec<RemoteMatch>> {
    let index = index.as_object().context("远程 banner 索引格式无效")?;
    let mut found = std::collections::BTreeMap::new();
    for (_, bytes) in banners {
        let banner = String::from_utf8_lossy(bytes)
            .trim_end_matches(['\0', '\n'])
            .to_string();
        if let Some(paths) = index.get(&banner).and_then(Value::as_array) {
            let arm = banner.contains("aarch64") || banner.contains("-arm64");
            for path in paths {
                let path = repository.index_path(path.as_str().context("索引路径无效")?)?;
                if path_arm64(&path) != Some(arm) {
                    continue;
                }
                found.insert(
                    path.clone(),
                    RemoteMatch {
                        banner: banner.clone(),
                        url: repository.url(&path)?,
                        path,
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
    if image.banners(job)?.is_empty() {
        // One PDB identity is often found at several offsets (kernel copies in
        // memory); it is still one symbol to fetch, listed once in offset order.
        let mut seen = std::collections::HashSet::new();
        return image
            .windows_candidates(job)?
            .iter()
            .filter(|c| seen.insert(c.pdb.key()))
            .map(|c| {
                Ok(RemoteMatch {
                    banner: format!("Windows PDB {}", c.pdb.key()),
                    path: c.pdb.key(),
                    url: c.pdb.url()?,
                })
            })
            .collect();
    }
    let banners = image.banners(job)?;
    let repository = Repository::configured(cache)?;
    let path = repository.index_file(cache);
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
        match fetch_github(&repository.index_url(), cache, job) {
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
    lookup_index_in(&repository, &index, &banners)
}
/// Linux entries of the cached index, parsed once per index file version.
struct ParsedIndex {
    path: std::path::PathBuf,
    stamp: (std::time::SystemTime, u64),
    banners: usize,
    entries: Vec<(RemoteMatch, String)>,
}
static PARSED_INDEX: std::sync::Mutex<Option<std::sync::Arc<ParsedIndex>>> =
    std::sync::Mutex::new(None);
fn parsed_index(
    repository: &Repository,
    path: &Path,
    job: &Job,
) -> Result<std::sync::Arc<ParsedIndex>> {
    let meta = fs::metadata(path)?;
    let stamp = (meta.modified()?, meta.len());
    let mut slot = PARSED_INDEX
        .lock()
        .map_err(|_| anyhow::anyhow!("远程索引缓存锁损坏"))?;
    if let Some(parsed) = slot.as_ref()
        && parsed.path == path
        && parsed.stamp == stamp
    {
        return Ok(parsed.clone());
    }
    job.report("解析远程符号索引");
    let index: Value = serde_json::from_slice(&fs::read(path)?)?;
    let index = index.as_object().context("远程索引格式无效")?;
    let mut entries = Vec::new();
    for (banner, paths) in index {
        job.check()?;
        if !banner.starts_with("Linux version ") {
            continue;
        }
        for entry in paths.as_array().context("远程索引路径列表无效")? {
            // Skip entries outside the repository and kernels the native
            // engine cannot translate (only x86_64 and ARM64).
            let Some(path) = entry.as_str().and_then(|e| repository.index_path(e).ok()) else {
                continue;
            };
            if path_arm64(&path).is_none() {
                continue;
            }
            let text = format!("{banner} {path}").to_lowercase();
            entries.push((
                RemoteMatch {
                    banner: banner.clone(),
                    url: repository.url(&path)?,
                    path,
                },
                text,
            ));
        }
    }
    entries.sort_by(|a, b| {
        natural_cmp(&b.0.path, &a.0.path).then_with(|| a.0.banner.cmp(&b.0.banner))
    });
    entries.dedup_by(|a, b| a.0.path == b.0.path && a.0.banner == b.0.banner);
    let parsed = std::sync::Arc::new(ParsedIndex {
        path: path.to_owned(),
        stamp,
        banners: index.len(),
        entries,
    });
    *slot = Some(parsed.clone());
    Ok(parsed)
}
fn at_word_start(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
    })
}
/// Compare with digit runs as numbers so `5.15.0-91` sorts after `5.15.0-9`.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a.first(), b.first()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, _) => return std::cmp::Ordering::Less,
            (_, None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let run = |s: &[u8]| s.iter().take_while(|c| c.is_ascii_digit()).count();
                let (ra, rb) = (run(a), run(b));
                let trim = |s: &[u8]| {
                    let zeros = s.iter().take_while(|c| **c == b'0').count();
                    s[zeros..].to_vec()
                };
                let (na, nb) = (trim(&a[..ra]), trim(&b[..rb]));
                let order = na.len().cmp(&nb.len()).then_with(|| na.cmp(&nb));
                if order.is_ne() {
                    return order;
                }
                (a, b) = (&a[ra..], &b[rb..]);
            }
            (Some(x), Some(y)) => {
                if x != y {
                    return x.cmp(y);
                }
                (a, b) = (&a[1..], &b[1..]);
            }
        }
    }
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct IndexInfo {
    /// Banners of every system in the index file.
    pub banners: usize,
    /// Searchable Linux x86_64 / ARM64 entries.
    pub entries: usize,
    pub bytes: u64,
    pub age_seconds: Option<u64>,
}
pub struct CatalogPage {
    pub matches: Vec<RemoteMatch>,
    /// Number of entries matching the query before `limit`.
    pub total: usize,
    pub index: IndexInfo,
}
/// Search the cached index. Every word must occur in the banner or path; a word
/// that starts the kernel release ranks first, then newest paths first.
pub fn catalog(
    cache: &Path,
    query: &str,
    limit: usize,
    network: bool,
    job: &Job,
) -> Result<CatalogPage> {
    let repository = Repository::configured(cache)?;
    let path = repository.index_file(cache);
    if !path.is_file() {
        ensure!(network, "离线模式且索引未缓存；按 o 开启在线后刷新索引");
        refresh_index(cache, job)?;
    }
    let parsed = parsed_index(&repository, &path, job)?;
    let words: Vec<_> = query.split_whitespace().map(str::to_lowercase).collect();
    let release = |banner: &str| {
        banner
            .split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .to_lowercase()
    };
    let mut ranked = Vec::new();
    for (index, (candidate, text)) in parsed.entries.iter().enumerate() {
        if index % 4096 == 0 {
            job.check()?;
        }
        if words.iter().all(|w| text.contains(w.as_str())) {
            let release = release(&candidate.banner);
            let exact = words.iter().any(|w| release.starts_with(w.as_str()));
            // `3.2.0-4` should not rank `13.2.0-4` as highly as a whole word.
            let partial = words.iter().filter(|w| !at_word_start(text, w)).count();
            ranked.push((!exact, partial, index));
        }
    }
    ranked.sort_unstable();
    let meta = fs::metadata(&path)?;
    Ok(CatalogPage {
        total: ranked.len(),
        matches: ranked
            .iter()
            .take(limit)
            .map(|(_, _, index)| parsed.entries[*index].0.clone())
            .collect(),
        index: IndexInfo {
            banners: parsed.banners,
            entries: parsed.entries.len(),
            bytes: meta.len(),
            age_seconds: meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| d.as_secs()),
        },
    })
}
pub fn catalog_search(
    cache: &Path,
    query: &str,
    network: bool,
    job: &Job,
) -> Result<Vec<RemoteMatch>> {
    Ok(catalog(cache, query, usize::MAX, network, job)?.matches)
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
    if m.url
        .starts_with("https://msdl.microsoft.com/download/symbols/")
    {
        let candidate = image
            .windows_candidates(job)?
            .iter()
            .find(|c| c.pdb.key() == m.path)
            .context("下载项与 Windows 镜像身份不匹配")?;
        ensure!(m.url == candidate.pdb.url()?, "Windows 符号 URL 不匹配");
        return crate::windows_symbols::acquire(&candidate.pdb, cache, network, job);
    }
    download_checked(m, Some(image), cache, network, job)
}
pub fn validate_remote(repository: &Repository, m: &RemoteMatch) -> Result<()> {
    let expected = if m
        .url
        .starts_with("https://msdl.microsoft.com/download/symbols/")
    {
        crate::windows_symbols::PdbIdentity::from_key(&m.path)?.url()?
    } else {
        repository.url(&m.path)?
    };
    ensure!(expected == m.url, "符号来源 URL 不匹配");
    Ok(())
}
pub fn download_catalog(m: &RemoteMatch, cache: &Path, network: bool, job: &Job) -> Result<Isf> {
    let _guard = crate::cache::lock(cache, false)?;
    if m.url
        .starts_with("https://msdl.microsoft.com/download/symbols/")
    {
        validate_remote(&Repository::configured(cache)?, m)?;
        return crate::windows_symbols::acquire(
            &crate::windows_symbols::PdbIdentity::from_key(&m.path)?,
            cache,
            network,
            job,
        );
    }
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
        m.url == Repository::configured(cache)?.url(&m.path)?,
        "下载链接不属于设置中的符号仓库"
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
        fetch_github(&m.url, cache, job)?
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
            bytes = fetch_github(&m.url, cache, job)?;
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
    if image.banners(job)?.is_empty() && !image.windows_candidates(job)?.is_empty() {
        return crate::windows_symbols::resolve(local, image, cache, network, job);
    }
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
        "仓库没有匹配的完整 banner；请用 y 指定本地 ISF（Kali 6.8.11 ARM64 可用 g 准备）。{}",
        Repository::configured(cache)?.web
    );
    matches
        .iter()
        .map(|m| download(m, image, cache, network, job))
        .collect()
}

pub fn refresh_index(cache: &Path, job: &Job) -> Result<()> {
    let _guard = crate::cache::lock(cache, false)?;
    let repository = Repository::configured(cache)?;
    job.report(format!("刷新符号索引 {}", repository.web));
    let bytes = fetch_github(&repository.index_url(), cache, job)?;
    let index: Value = serde_json::from_slice(&bytes)?;
    ensure!(index.is_object(), "banner 索引格式无效");
    job.check()?;
    crate::store::atomic_write(&repository.index_file(cache), &bytes)
}
