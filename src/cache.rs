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
    All,
}
pub const SCOPES: [Scope; 4] = [
    Scope::Results,
    Scope::Identification,
    Scope::Images,
    Scope::Symbols,
];
impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Results => "分析结果",
            Self::Identification => "识别信息",
            Self::Images => "解压镜像",
            Self::Symbols => "符号／构建缓存",
            Self::All => "全部缓存",
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub path: PathBuf,
    pub scope: Scope,
    pub bytes: u64,
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
                {
                    visit(&p, root, entries, depth + 1)?;
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let scope = if path == root && digest_name(&name, ".result.json") {
                Some(Scope::Results)
            } else if path == root
                && (digest_name(&name, ".image") || digest_name(&name, ".sha256"))
            {
                Some(Scope::Images)
            } else if relative.starts_with("identification") {
                Some(Scope::Identification)
            } else if relative == Path::new("symbols/banners_plain.json")
                || relative.starts_with("symbols/build")
                || relative.starts_with("symbols/isf")
            {
                Some(Scope::Symbols)
            } else {
                None
            };
            if let Some(scope) = scope {
                entries.push(Entry {
                    path: p,
                    scope,
                    bytes: meta.len(),
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
}
