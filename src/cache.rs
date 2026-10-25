//! Cache inventory is allowlisted. Never recursively remove the cache root.
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize)]
pub enum Scope {
    Results,
    Identification,
    Images,
    Symbols,
    Dumps,
    Exports,
    All,
}
pub const SCOPES: [Scope; 6] = [
    Scope::Results,
    Scope::Exports,
    Scope::Identification,
    Scope::Images,
    Scope::Symbols,
    Scope::Dumps,
];
impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Results => "分析结果",
            Self::Identification => "识别信息",
            Self::Images => "解压镜像",
            Self::Symbols => "符号／构建缓存",
            Self::Dumps => "进程转储",
            Self::Exports => "导出记录",
            Self::All => "全部缓存",
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub path: PathBuf,
    pub scope: Scope,
    pub bytes: u64,
    /// Modification time in seconds since the Unix epoch.
    pub modified: Option<u64>,
}
#[derive(Default, Serialize)]
pub struct Report {
    pub removed: usize,
    pub bytes: u64,
    pub failures: Vec<String>,
}
pub fn lock(root: &Path, exclusive: bool) -> Result<File> {
    fs::create_dir_all(root)?;
    ensure!(
        !fs::symlink_metadata(root)?.file_type().is_symlink(),
        "缓存目录不能是符号链接"
    );
    let path = root.join("cache.lock");
    if path.exists() {
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "缓存锁不能是符号链接"
        );
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    if exclusive {
        file.try_lock().context("缓存正被其他分析会话使用")?;
    } else {
        file.try_lock_shared().context("缓存正在清理，请稍后重试")?;
    }
    Ok(file)
}
fn digest_name(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix)
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
/// Digest stem of an export record file: its metadata or its exported copy.
fn record_stem(name: &str) -> Option<&str> {
    [".export.json", ".csv", ".json"]
        .iter()
        .find(|suffix| digest_name(name, suffix))
        .map(|suffix| &name[..name.len() - suffix.len()])
}
pub fn inventory(root: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    if !root.exists() {
        return Ok(entries);
    }
    ensure!(
        !fs::symlink_metadata(root)?.file_type().is_symlink(),
        "缓存目录不能是符号链接"
    );
    fn visit(path: &Path, root: &Path, entries: &mut Vec<Entry>, depth: usize) -> Result<()> {
        ensure!(depth < 32, "缓存目录层级异常");
        for item in fs::read_dir(path)? {
            let item = item?;
            let p = item.path();
            let meta = fs::symlink_metadata(&p)?;
            if meta.file_type().is_symlink() {
                continue;
            }
            let relative = p.strip_prefix(root)?;
            let name = item.file_name().to_string_lossy().into_owned();
            if meta.is_dir() {
                if relative == Path::new("symbols")
                    || relative == Path::new("identification")
                    || relative.starts_with("symbols/isf")
                    || relative.starts_with("symbols/build")
                    || relative == Path::new("dumps")
                    || relative.starts_with("dumps")
                    || relative == Path::new("exports")
                {
                    visit(&p, root, entries, depth + 1)?;
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let scope = if path == root
                && (digest_name(&name, ".result.json") || digest_name(&name, ".partial.json"))
            {
                Some(Scope::Results)
            } else if path == root
                && (digest_name(&name, ".image") || digest_name(&name, ".sha256"))
            {
                Some(Scope::Images)
            } else if relative.starts_with("identification") {
                Some(Scope::Identification)
            } else if relative == Path::new("symbols/banners_plain.json")
                || (relative.parent() == Some(Path::new("symbols"))
                    && name
                        .strip_prefix("banners_plain-")
                        .and_then(|rest| rest.strip_suffix(".json"))
                        .is_some_and(|id| {
                            id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())
                        }))
                || relative.starts_with("symbols/build")
                || relative.starts_with("symbols/isf")
            {
                Some(Scope::Symbols)
            } else if relative.starts_with("dumps") {
                Some(Scope::Dumps)
            } else if relative.parent() == Some(Path::new("exports"))
                && record_stem(&name).is_some()
            {
                Some(Scope::Exports)
            } else {
                None
            };
            if let Some(scope) = scope {
                entries.push(Entry {
                    path: p,
                    scope,
                    bytes: meta.len(),
                    modified: meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs()),
                });
            }
        }
        Ok(())
    }
    visit(root, root, &mut entries, 0)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}
pub fn selected(entries: &[Entry], scopes: &[Scope]) -> Vec<Entry> {
    entries
        .iter()
        .filter(|e| scopes.contains(&Scope::All) || scopes.contains(&e.scope))
        .cloned()
        .collect()
}
pub fn clear(root: &Path, scopes: &[Scope]) -> Result<Report> {
    clear_with_job(root, scopes, &crate::Job::default())
}
pub fn clear_with_job(root: &Path, scopes: &[Scope], job: &crate::Job) -> Result<Report> {
    job.check()?;
    let _guard = lock(root, true)?;
    let entries = selected(&inventory(root)?, scopes);
    let mut report = Report::default();
    for entry in entries {
        if let Err(e) = job.check() {
            report.failures.push(e.to_string());
            break;
        }
        match fs::remove_file(&entry.path) {
            Ok(()) => {
                report.removed += 1;
                report.bytes += entry.bytes;
            }
            Err(e) => report
                .failures
                .push(format!("{}: {e}", entry.path.display())),
        }
    }
    Ok(report)
}

/// Remove individual inventory entries. Paths outside the allowlisted
/// inventory are refused; an export record is always removed with its copy.
pub fn remove(root: &Path, paths: &[PathBuf], job: &crate::Job) -> Result<Report> {
    job.check()?;
    let _guard = lock(root, true)?;
    let entries = inventory(root)?;
    let mut chosen = Vec::new();
    for path in paths {
        let entry = entries
            .iter()
            .find(|e| &e.path == path)
            .with_context(|| format!("不是可清理的缓存文件: {}", path.display()))?;
        let stem = (entry.scope == Scope::Exports)
            .then(|| {
                entry
                    .path
                    .file_name()
                    .and_then(|n| record_stem(n.to_str()?))
            })
            .flatten();
        chosen.extend(entries.iter().filter(|e| {
            &e.path == path
                || stem.is_some_and(|stem| {
                    e.scope == Scope::Exports
                        && e.path.file_name().and_then(|n| record_stem(n.to_str()?)) == Some(stem)
                })
        }));
    }
    chosen.sort_by(|a, b| a.path.cmp(&b.path));
    chosen.dedup_by(|a, b| a.path == b.path);
    let mut report = Report::default();
    for entry in chosen {
        match fs::remove_file(&entry.path) {
            Ok(()) => {
                report.removed += 1;
                report.bytes += entry.bytes;
            }
            Err(e) => report
                .failures
                .push(format!("{}: {e}", entry.path.display())),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classification_protection_links_and_lock() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let name = "a".repeat(64);
        fs::write(root.join(format!("{name}.result.json")), b"result")?;
        fs::write(root.join(format!("{name}.image")), b"image")?;
        for p in [
            "settings.json",
            "workspace.json",
            "migration/snapshot",
            "credentials/key",
            "export.json",
        ] {
            let p = root.join(p);
            fs::create_dir_all(p.parent().unwrap())?;
            fs::write(p, b"keep")?;
        }
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("keep"), b"keep")?;
        fs::create_dir_all(root.join("symbols"))?;
        std::os::unix::fs::symlink(outside.path(), root.join("symbols/isf"))?;
        assert_eq!(inventory(root)?.len(), 2);
        let guard = lock(root, false)?;
        assert!(clear(root, &[Scope::All]).is_err());
        drop(guard);
        assert_eq!(clear(root, &[Scope::Results])?.bytes, 6);
        assert_eq!(inventory(root)?.len(), 1);
        assert_eq!(clear(root, &[Scope::All])?.removed, 1);
        assert!(root.join("migration/snapshot").exists());
        assert!(root.join("settings.json").exists());
        assert!(root.join("workspace.json").exists());
        assert!(outside.path().join("keep").exists());
        Ok(())
    }
    #[test]
    fn export_records_reopen_verify_and_remove_together() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("cache");
        let job = crate::Job::default();
        let result = crate::store::Results {
            plugin: "pslist".into(),
            columns: vec!["PID".into()],
            rows: vec![vec!["1".into()], vec!["2".into()]],
            complete: false,
            diagnostics: vec!["partial".into()],
            banner: String::new(),
            symbol: String::new(),
            page_table: 0,
            historical: false,
            system: "linux".into(),
            kernel_identity: serde_json::Value::Null,
        };
        let output = dir.path().join("out.csv");
        crate::store::export_rows(&output, &result, result.rows.iter(), &job)?;
        let record = crate::store::record_export(&root, &output, &result, 2, &job)?;
        assert_eq!(
            crate::store::record_export(&root, &output, &result, 2, &job)?.key,
            record.key,
            "the same export is recorded once"
        );
        let entries = inventory(&root)?;
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|e| e.scope == Scope::Exports && e.modified.is_some())
        );
        let reopened = crate::store::open_record(&root, &record.key, &job)?;
        assert_eq!(
            (reopened.plugin.as_str(), reopened.rows.len()),
            ("pslist", 2)
        );
        assert!(reopened.historical && !reopened.complete);
        // A moved or deleted export stays reopenable from its verified copy.
        fs::remove_file(&output)?;
        assert!(crate::store::open_record(&root, &record.key, &job).is_ok());
        fs::write(
            root.join(format!("exports/{}.csv", record.key)),
            b"PID\n9\n",
        )?;
        assert!(crate::store::open_record(&root, &record.key, &job).is_err());
        assert!(remove(&root, &[dir.path().join("out.csv")], &job).is_err());
        let metadata = root.join(format!("exports/{}.export.json", record.key));
        assert_eq!(remove(&root, &[metadata], &job)?.removed, 2);
        assert!(inventory(&root)?.is_empty());
        assert!(crate::store::export_records(&root).is_empty());
        Ok(())
    }
}
