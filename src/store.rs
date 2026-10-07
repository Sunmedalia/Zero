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
pub fn load(cache: &Path, key: &str) -> Option<Results> {
    let entry: CacheEntry = serde_json::from_reader(std::io::BufReader::new(
        fs::File::open(cache.join(format!("{key}.result.json"))).ok()?,
    ))
    .ok()?;
    (entry.version == ENGINE_VERSION
        && entry.key == key
        && entry.result.complete
        && !entry.result.historical)
        .then_some(entry.result)
}
pub fn save(cache: &Path, key: &str, result: &Results, job: &Job) -> Result<()> {
    job.check()?;
    if result.complete && !result.historical {
        #[derive(Serialize)]
        struct Entry<'a> {
            version: &'a str,
            key: &'a str,
            result: &'a Results,
        }
        atomic_stream(&cache.join(format!("{key}.result.json")), job, |writer| {
            serde_json::to_writer(
                writer,
                &Entry {
                    version: ENGINE_VERSION,
                    key,
                    result,
                },
            )?;
            Ok(())
        })?;
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
#[derive(Serialize, Deserialize)]
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
        }
    }
}
pub fn save_settings(cache: &Path, settings: &Settings) -> Result<()> {
    ensure!(
        settings.page_size <= 10000,
        "每页行数应为 0（自动）或 1–10000"
    );
    atomic_write(
        &cache.join("settings.json"),
        &serde_json::to_vec_pretty(settings)?,
    )
}
pub fn settings(cache: &Path) -> Result<Settings> {
    let path = cache.join("settings.json");
    if path.exists() {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(path)?).context("Rust settings.json 无效")?;
        let legacy_layout = value.get("layout_version").is_none();
        let mut settings: Settings = serde_json::from_value(value)?;
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
