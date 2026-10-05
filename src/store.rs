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
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
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
    let entry: CacheEntry =
        serde_json::from_slice(&fs::read(cache.join(format!("{key}.result.json"))).ok()?).ok()?;
    (entry.version == ENGINE_VERSION
        && entry.key == key
        && entry.result.complete
        && !entry.result.historical)
        .then_some(entry.result)
}
pub fn save(cache: &Path, key: &str, result: &Results, job: &Job) -> Result<()> {
    job.check()?;
    if result.complete && !result.historical {
        atomic_write(
            &cache.join(format!("{key}.result.json")),
            &serde_json::to_vec(&CacheEntry {
                version: ENGINE_VERSION.into(),
                key: key.into(),
                result: result.clone(),
            })?,
        )?;
    }
    Ok(())
}
pub fn export(path: &Path, result: &Results, rows: Vec<Vec<String>>) -> Result<()> {
    let bytes = if path.extension().and_then(|s| s.to_str()) == Some("json") {
        let mut r = result.clone();
        r.rows = rows;
        serde_json::to_vec_pretty(&r)?
    } else {
        ensure!(
            path.extension().and_then(|s| s.to_str()) == Some("csv"),
            "导出扩展名必须为 .csv 或 .json"
        );
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer.write_record(&result.columns)?;
        for row in rows {
            writer.write_record(row)?;
        }
        writer.into_inner()?.to_vec()
    };
    atomic_write(path, &bytes)
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
