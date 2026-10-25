use crate::{ENGINE_VERSION, Job};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Results {
    pub plugin: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub complete: bool,
    pub diagnostics: Vec<String>,
    pub banner: String,
    pub symbol: String,
    pub page_table: u64,
    pub historical: bool,
    #[serde(default)]
    pub system: String,
    #[serde(default)]
    pub kernel_identity: serde_json::Value,
}
impl Results {
    pub fn metadata(&self) -> Self {
        Self {
            rows: Vec::new(),
            plugin: self.plugin.clone(),
            columns: self.columns.clone(),
            complete: self.complete,
            diagnostics: self.diagnostics.clone(),
            banner: self.banner.clone(),
            symbol: self.symbol.clone(),
            page_table: self.page_table,
            historical: self.historical,
            system: self.system.clone(),
            kernel_identity: self.kernel_identity.clone(),
        }
    }
    pub fn filtered(&self, query: &str) -> Vec<Vec<String>> {
        let query = query.to_lowercase();
        self.rows
            .iter()
            .filter(|r| r.iter().any(|v| v.to_lowercase().contains(&query)))
            .cloned()
            .collect()
    }
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_stream(path, &Job::default(), |writer| {
        writer.write_all(bytes)?;
        Ok(())
    })
}
/// Publish only a fully written, synced file. A failed producer leaves the old file intact.
pub fn atomic_stream(
    path: &Path,
    job: &Job,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    job.check()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut writer = std::io::BufWriter::new(temp.as_file_mut());
        struct Checked<'a, W> {
            writer: W,
            job: &'a Job,
            remaining: usize,
        }
        impl<W: Write> Write for Checked<'_, W> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    self.job.check().map_err(std::io::Error::other)?;
                    self.remaining = 65536;
                }
                let n = self
                    .writer
                    .write(&bytes[..bytes.len().min(self.remaining)])?;
                self.remaining -= n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.writer.flush()
            }
        }
        write(&mut Checked {
            writer: &mut writer,
            job,
            remaining: 0,
        })?;
        writer.flush()?;
    }
    job.check()?;
    temp.as_file().sync_all()?;
    job.check()?;
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
pub fn key(image: &str, symbol: &str, plugin: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{ENGINE_VERSION}\0{image}\0{symbol}\0{plugin}").as_bytes())
    )
}
#[derive(Serialize, Deserialize)]
struct CacheEntry {
    version: String,
    key: String,
    result: Results,
}
/// The image a cached result belongs to: its content digest and the path it
/// was analysed from. Recorded so the cache page can group results by image.
#[derive(Clone, Debug, Default)]
pub struct Owner {
    pub digest: String,
    pub source: PathBuf,
}
impl Owner {
    pub fn new(digest: &str, source: &Path) -> Self {
        Self {
            digest: digest.to_owned(),
            source: source.to_path_buf(),
        }
    }
}
/// The header of a cached result, written before the rows so it can be read
/// without parsing them. Entries written before it was recorded read as empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub source: PathBuf,
    #[serde(default)]
    pub plugin: String,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub rows: usize,
    #[serde(default)]
    pub diagnostics: usize,
}
/// Read the header of a result cache file from its first bytes only.
pub fn summary(path: &Path) -> Option<Summary> {
    use std::io::Read;
    let mut head = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(64 * 1024)
        .read_to_end(&mut head)
        .ok()?;
    // `,"` never occurs inside a JSON string (its quote would be escaped), so
    // the first `,"result":` ends the header fields written before it.
    let end = memchr::memmem::find(&head, br#","result":"#)?;
    let mut header = head[..end].to_vec();
    header.push(b'}');
    #[derive(Deserialize)]
    struct Head {
        version: String,
        #[serde(flatten)]
        summary: Summary,
    }
    let head: Head = serde_json::from_slice(&header).ok()?;
    (head.version == ENGINE_VERSION).then_some(head.summary)
}
/// Progress line for a cache hit, naming which cache answered.
pub fn cache_message(result: &Results) -> &'static str {
    if result.complete {
        "读取成功缓存"
    } else {
        "读取部分结果缓存（诊断一并保存）"
    }
}
/// A complete result from the successful-result cache.
pub fn load(cache: &Path, key: &str) -> Option<Results> {
    read_entry(cache, key, "result.json").filter(|r| r.complete)
}
/// A partial result, with its diagnostics, from the separate partial cache.
/// It never satisfies a lookup for a complete result.
pub fn load_partial(cache: &Path, key: &str) -> Option<Results> {
    read_entry(cache, key, "partial.json").filter(|r| !r.complete)
}
fn read_entry(cache: &Path, key: &str, suffix: &str) -> Option<Results> {
    let entry: CacheEntry = serde_json::from_reader(std::io::BufReader::new(
        fs::File::open(cache.join(format!("{key}.{suffix}"))).ok()?,
    ))
    .ok()?;
    (entry.version == ENGINE_VERSION && entry.key == key && !entry.result.historical)
        .then_some(entry.result)
}
/// Name the image on an entry written before entries recorded it, so the cache
/// page can group it. The key already binds the entry to that digest; the
/// result is rewritten unchanged.
pub fn adopt(cache: &Path, key: &str, owner: &Owner, result: &Results, job: &Job) {
    let suffix = if result.complete {
        "result.json"
    } else {
        "partial.json"
    };
    let path = cache.join(format!("{key}.{suffix}"));
    if !owner.digest.is_empty() && summary(&path).is_some_and(|s| s.image.is_empty()) {
        let _ = write_entry(&path, key, owner, result, job);
    }
}
/// Persist a fresh result: complete ones in the successful-result cache,
/// partial ones (diagnostics included) in the separate partial cache.
pub fn save_any(cache: &Path, key: &str, owner: &Owner, result: &Results, job: &Job) -> Result<()> {
    save(cache, key, owner, result, job)?;
    save_partial(cache, key, owner, result, job)
}
pub fn save_partial(
    cache: &Path,
    key: &str,
    owner: &Owner,
    result: &Results,
    job: &Job,
) -> Result<()> {
    job.check()?;
    if !result.complete && !result.historical {
        write_entry(
            &cache.join(format!("{key}.partial.json")),
            key,
            owner,
            result,
            job,
        )?;
    }
    Ok(())
}
fn write_entry(path: &Path, key: &str, owner: &Owner, result: &Results, job: &Job) -> Result<()> {
    // Header fields come before `result`; `summary` reads only them.
    #[derive(Serialize)]
    struct Entry<'a> {
        version: &'a str,
        key: &'a str,
        image: &'a str,
        source: &'a Path,
        plugin: &'a str,
        complete: bool,
        rows: usize,
        diagnostics: usize,
        result: &'a Results,
    }
    atomic_stream(path, job, |writer| {
        serde_json::to_writer(
            writer,
            &Entry {
                version: ENGINE_VERSION,
                key,
                image: &owner.digest,
                source: &owner.source,
                plugin: &result.plugin,
                complete: result.complete,
                rows: result.rows.len(),
                diagnostics: result.diagnostics.len(),
                result,
            },
        )?;
        Ok(())
    })
}
/// Successful-result cache: complete results only.
pub fn save(cache: &Path, key: &str, owner: &Owner, result: &Results, job: &Job) -> Result<()> {
    job.check()?;
    if result.complete && !result.historical {
        write_entry(
            &cache.join(format!("{key}.result.json")),
            key,
            owner,
            result,
            job,
        )?;
    }
    Ok(())
}
/// Compatibility wrapper; internal callers borrow rows through `export_rows`.
pub fn export(path: &Path, result: &Results, rows: Vec<Vec<String>>) -> Result<()> {
    export_rows(path, result, rows.iter(), &Job::default())
}
pub fn export_rows<'a>(
    path: &Path,
    result: &Results,
    rows: impl IntoIterator<Item = &'a Vec<String>>,
    job: &Job,
) -> Result<()> {
    export_fallible(path, result, rows.into_iter().map(Ok), job)
}
/// Also supports disk-backed snapshot rows without materializing the full result.
pub fn export_fallible<R: AsRef<[String]>>(
    path: &Path,
    result: &Results,
    rows: impl IntoIterator<Item = Result<R>>,
    job: &Job,
) -> Result<()> {
    let extension = path.extension().and_then(|s| s.to_str());
    ensure!(
        matches!(extension, Some("json" | "csv")),
        "导出扩展名必须为 .csv 或 .json"
    );
    atomic_stream(path, job, |mut writer| {
        if extension == Some("json") {
            let mut metadata = serde_json::to_value(result.metadata())?;
            metadata
                .as_object_mut()
                .expect("result object")
                .remove("rows");
            let mut prefix = serde_json::to_vec_pretty(&metadata)?;
            prefix.pop();
            writer.write_all(&prefix)?;
            writer.write_all(b",\n  \"rows\": [".as_slice())?;
            for (index, row) in rows.into_iter().enumerate() {
                job.check()?;
                if index != 0 {
                    writer.write_all(b",")?;
                }
                writer.write_all(b"\n    ")?;
                serde_json::to_writer(&mut writer, row?.as_ref())?;
            }
            writer.write_all(b"\n  ]\n}\n")?;
        } else {
            let mut csv = csv::Writer::from_writer(writer);
            csv.write_record(&result.columns)?;
            for row in rows {
                job.check()?;
                csv.write_record(row?.as_ref())?;
            }
            csv.flush()?;
        }
        Ok(())
    })
}
pub fn exported(path: &Path) -> Result<Results> {
    ensure!(
        fs::metadata(path)?.len() <= 256 * 1024 * 1024,
        "导出记录超过 256 MiB"
    );
    if path.extension().and_then(|s| s.to_str()) == Some("json") {
        let mut result: Results = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            result.rows.iter().all(|r| r.len() == result.columns.len()),
            "导出行与列数不一致"
        );
        result.historical = true;
        Ok(result)
    } else {
        history(path)
    }
}
pub fn history(path: &Path) -> Result<Results> {
    let mut reader = csv::Reader::from_path(path)?;
    let columns = reader.headers()?.iter().map(String::from).collect();
    let rows = reader
        .records()
        .map(|r| r.map(|r| r.iter().map(String::from).collect()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Results {
        plugin: format!("历史: {}", path.display()),
        columns,
        rows,
        complete: false,
        diagnostics: vec!["旧 CSV 历史记录；未经原生引擎验证".into()],
        banner: String::new(),
        symbol: String::new(),
        page_table: 0,
        historical: true,
        system: String::new(),
        kernel_identity: serde_json::Value::Null,
    })
}
pub fn history_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                paths.extend(history_paths(&e.path()));
            } else if e.path().extension().is_some_and(|s| s == "csv") {
                paths.push(e.path());
            }
        }
    }
    paths.sort();
    paths
}
/// One successful export, recorded under `<cache>/exports/` with a verified
/// copy of the exported bytes so it can be reopened after the file moves.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportRecord {
    pub key: String,
    pub recorded: u64,
    pub destination: PathBuf,
    pub format: String,
    pub plugin: String,
    pub rows: usize,
    pub bytes: u64,
    pub sha256: String,
    pub complete: bool,
    pub diagnostics: usize,
    pub banner: String,
    pub symbol: String,
}
const RECORD_LIMIT: u64 = 256 * 1024 * 1024;
fn record_dir(cache: &Path) -> PathBuf {
    cache.join("exports")
}
fn record_copy(cache: &Path, key: &str, format: &str) -> PathBuf {
    record_dir(cache).join(format!("{key}.{format}"))
}
/// Record a finished export. The copy is streamed from the published file and
/// hashed on the way, so the record always describes exactly what was written.
pub fn record_export(
    cache: &Path,
    destination: &Path,
    result: &Results,
    rows: usize,
    job: &Job,
) -> Result<ExportRecord> {
    let format = destination
        .extension()
        .and_then(|s| s.to_str())
        .filter(|e| matches!(*e, "csv" | "json"))
        .context("导出扩展名必须为 .csv 或 .json")?
        .to_owned();
    let bytes = fs::metadata(destination)?.len();
    ensure!(bytes <= RECORD_LIMIT, "导出超过 256 MiB，未记录本地副本");
    let destination = fs::canonicalize(destination)?;
    let _guard = crate::cache::lock(cache, false)?;
    let digest = |job: &Job| -> Result<String> {
        let mut hasher = Sha256::new();
        let mut source = fs::File::open(&destination)?;
        let mut buffer = vec![0; 1 << 16];
        loop {
            job.check()?;
            let n = std::io::Read::read(&mut source, &mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    };
    let sha256 = digest(job)?;
    let key = format!(
        "{:x}",
        Sha256::digest(format!("{}\0{sha256}", destination.display()).as_bytes())
    );
    let copy = record_copy(cache, &key, &format);
    atomic_stream(&copy, job, |writer| {
        std::io::copy(&mut fs::File::open(&destination)?, writer)?;
        Ok(())
    })?;
    if digest(job)? != sha256 {
        let _ = fs::remove_file(&copy);
        anyhow::bail!("导出文件在记录期间被修改；未记录");
    }
    let record = ExportRecord {
        key: key.clone(),
        recorded: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        destination,
        format,
        plugin: result.plugin.clone(),
        rows,
        bytes,
        sha256,
        complete: result.complete,
        diagnostics: result.diagnostics.len(),
        banner: result.banner.clone(),
        symbol: result.symbol.clone(),
    };
    atomic_write(
        &record_dir(cache).join(format!("{key}.export.json")),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    Ok(record)
}
/// Every readable record, newest first. Records without their copy are skipped.
pub fn export_records(cache: &Path) -> Vec<ExportRecord> {
    let mut records: Vec<ExportRecord> = fs::read_dir(record_dir(cache))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".export.json"))
        .filter(|e| {
            e.metadata()
                .is_ok_and(|m| m.is_file() && m.len() <= 1 << 20)
        })
        .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
        .filter(|r: &ExportRecord| {
            r.key.len() == 64
                && r.key.bytes().all(|b| b.is_ascii_hexdigit())
                && matches!(r.format.as_str(), "csv" | "json")
                && record_copy(cache, &r.key, &r.format).is_file()
        })
        .collect();
    records.sort_by(|a, b| b.recorded.cmp(&a.recorded).then_with(|| a.key.cmp(&b.key)));
    records
}
/// Reopen a record from its local copy after checking the recorded digest.
pub fn open_record(cache: &Path, key: &str, job: &Job) -> Result<Results> {
    let record = export_records(cache)
        .into_iter()
        .find(|r| r.key == key)
        .context("导出记录不存在或副本已清理")?;
    let copy = record_copy(cache, &record.key, &record.format);
    job.check()?;
    let digest = {
        let mut hasher = Sha256::new();
        std::io::copy(&mut fs::File::open(&copy)?, &mut hasher)?;
        format!("{:x}", hasher.finalize())
    };
    ensure!(
        digest == record.sha256,
        "导出记录副本 SHA256 不一致；请清理该记录"
    );
    job.check()?;
    let mut result = exported(&copy)?;
    if record.format == "csv" {
        result.plugin = record.plugin.clone();
        result.banner = record.banner.clone();
        result.symbol = record.symbol.clone();
        result.diagnostics.clear();
    }
    result.historical = true;
    result.complete = record.complete;
    result.diagnostics.push(format!(
        "导出记录：{} → {}；本地副本 SHA256 已校验；历史数据未经原生引擎重新验证",
        record.plugin,
        record.destination.display()
    ));
    Ok(result)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub resources: crate::resources::Limits,
    pub layout_version: u32,
    pub image_dir: String,
    pub page_size: usize,
    pub export_dir: String,
    pub symbols: String,
    pub history_dir: String,
    pub enable_cache: bool,
    #[serde(default = "remote_default")]
    pub remote_symbols: bool,
    /// Interface colour theme id; the interface falls back to its default for unknown ids.
    pub theme: String,
    /// GitHub repository for the remote symbol index and ISF downloads.
    pub symbol_repository: String,
    /// Reuse the content digest recorded by an earlier session while the
    /// file's metadata stamp and content sample are unchanged. Off by default:
    /// every new session then reads the whole image to verify its digest.
    pub reuse_recorded_digest: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            resources: Default::default(),
            layout_version: 2,
            image_dir: "images".into(),
            page_size: 0,
            export_dir: "exports".into(),
            symbols: "symbols".into(),
            history_dir: "exports".into(),
            enable_cache: true,
            remote_symbols: true,
            theme: "auto".into(),
            symbol_repository: crate::symbols::REPOSITORY.into(),
            reuse_recorded_digest: false,
        }
    }
}
pub fn save_settings(cache: &Path, settings: &Settings) -> Result<()> {
    ensure!(
        settings.page_size <= 10000,
        "每页行数应为 0（自动）或 1–10000"
    );
    ensure!(
        valid_theme(&settings.theme),
        "主题名应为 1–32 个小写字母、数字或连字符"
    );
    crate::symbols::Repository::parse(&settings.symbol_repository)?;
    atomic_write(
        &cache.join("settings.json"),
        &serde_json::to_vec_pretty(settings)?,
    )
}
fn valid_theme(theme: &str) -> bool {
    (1..=32).contains(&theme.len())
        && theme
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
/// Settings without side effects: defaults when the file is missing, and no
/// migration or creation (for readers such as image preparation).
pub fn read_settings(cache: &Path) -> Settings {
    fs::read(cache.join("settings.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}
pub fn settings(cache: &Path) -> Result<Settings> {
    let path = cache.join("settings.json");
    if path.exists() {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(path)?).context("Rust settings.json 无效")?;
        let legacy_layout = value.get("layout_version").is_none();
        let mut settings: Settings = serde_json::from_value(value)?;
        if !valid_theme(&settings.theme) {
            settings.theme = Settings::default().theme;
        }
        if crate::symbols::Repository::parse(&settings.symbol_repository).is_err() {
            settings.symbol_repository = Settings::default().symbol_repository;
        }
        if legacy_layout {
            settings.page_size = 0;
            save_settings(cache, &settings)?;
        }
        ensure!(
            settings.page_size <= 10000,
            "每页行数应为 0（自动）或 1–10000"
        );
        return Ok(settings);
    }
    let settings = Settings::default();
    atomic_write(&path, &serde_json::to_vec_pretty(&settings)?)?;
    Ok(settings)
}
pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

fn remote_default() -> bool {
    true
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    #[test]
    fn failed_or_cancelled_producer_preserves_destination() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("existing.json");
        fs::write(&path, b"original")?;
        let failed = atomic_stream(&path, &Job::default(), |writer| {
            writer.write_all(b"half")?;
            anyhow::bail!("injected failure")
        });
        assert!(failed.is_err());
        let cancelled = Job::default();
        cancelled
            .cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            atomic_stream(&path, &cancelled, |writer| {
                writer.write_all(b"new")?;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(fs::read(&path)?, b"original");
        assert_eq!(fs::read_dir(dir.path())?.count(), 1);
        Ok(())
    }
}
