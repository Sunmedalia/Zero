//! Verified, cancellable checkpoints. File existence alone never completes a stage.
use super::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;

pub(super) fn artifact_lock(path: &Path, label: &str, job: &Job) -> Result<File> {
    job.check()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    ensure!(
        !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()),
        "阶段锁不能是符号链接"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.try_lock()
        .with_context(|| format!("{label}，请稍后重试"))?;
    Ok(file)
}
pub(super) fn read_json(path: &Path) -> Option<serde_json::Value> {
    let meta = path.metadata().ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?)
        .ok()
        .filter(serde_json::Value::is_object)
}

#[derive(Debug)]
pub(super) struct CorruptPackage;
impl std::fmt::Display for CorruptPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("软件包压缩数据或归档损坏")
    }
}
impl std::error::Error for CorruptPackage {}

pub(super) fn invalidate_corrupt<T>(result: Result<T>, package: &Path) -> Result<T> {
    match result {
        Err(error) if error.is::<CorruptPackage>() => {
            let _ = fs::remove_file(package);
            Err(error.context("已使该软件包缓存失效；重试将重新下载，有效的其他阶段保留"))
        }
        other => other,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Extracted {
    pub package_sha256: String,
    pub relative: String,
    pub sha256: String,
}
#[derive(Default, Serialize, Deserialize)]
pub(super) struct State {
    pub debug: Option<Extracted>,
    pub config: Option<Extracted>,
    pub generated: Option<Generated>,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Generated {
    pub elf_sha256: String,
    pub config_sha256: String,
    pub tool_sha256: String,
    pub isf_sha256: String,
}
impl State {
    pub fn load(root: &Path) -> Self {
        read_json(&root.join("state.json"))
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, root: &Path, job: &Job) -> Result<()> {
        store::atomic_stream(&root.join("state.json"), job, |writer| {
            serde_json::to_writer_pretty(writer, self)?;
            Ok(())
        })
    }
}
impl Extracted {
    pub fn verify(&self, root: &Path, package_hash: &str, job: &Job) -> Result<bool> {
        if self.package_sha256 != package_hash {
            return Ok(false);
        }
        let relative = Path::new(&self.relative);
        if !relative
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            return Ok(false);
        }
        let path = root.join(relative);
        let result = File::open(path);
        match result {
            Ok(file) => Ok(digest_reader(file, job)? == self.sha256),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_and_converter_locks_are_exclusive_and_cancel_before_creating_files() {
        let dir = tempfile::tempdir().unwrap();
        let job = Job::default();
        let path = dir.path().join("build.lock");
        let lock = artifact_lock(&path, "该构建正在生成", &job).unwrap();
        assert!(
            artifact_lock(&path, "该构建正在生成", &job)
                .unwrap_err()
                .to_string()
                .contains("稍后重试")
        );
        drop(lock);
        assert!(artifact_lock(&path, "该构建正在生成", &job).is_ok());
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let unused = dir.path().join("unused.lock");
        assert!(artifact_lock(&unused, "tool", &job).is_err());
        assert!(!unused.exists());
    }
    #[test]
    fn checkpoints_validate_content_and_reject_paths_outside_the_build_root() {
        let dir = tempfile::tempdir().unwrap();
        let job = Job::default();
        fs::write(dir.path().join("elf"), b"one").unwrap();
        let record = Extracted {
            package_sha256: "package".into(),
            relative: "elf".into(),
            sha256: digest_reader(File::open(dir.path().join("elf")).unwrap(), &job).unwrap(),
        };
        assert!(record.verify(dir.path(), "package", &job).unwrap());
        assert!(!record.verify(dir.path(), "other package", &job).unwrap());
        fs::write(dir.path().join("elf"), b"two").unwrap();
        assert!(!record.verify(dir.path(), "package", &job).unwrap());
        let outside = Extracted {
            relative: "../elf".into(),
            ..record
        };
        assert!(!outside.verify(dir.path(), "package", &job).unwrap());
    }
    #[test]
    fn corrupt_archives_invalidate_only_the_failed_package() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken.deb");
        let valid = dir.path().join("valid.deb");
        fs::write(&broken, b"bad").unwrap();
        fs::write(&valid, b"good").unwrap();
        let result: Result<()> = Err(anyhow::anyhow!("bad tar").context(CorruptPackage));
        assert!(
            invalidate_corrupt(result, &broken)
                .unwrap_err()
                .to_string()
                .contains("重试")
        );
        assert!(!broken.exists());
        assert!(valid.exists());
        let unrelated: Result<()> = Err(anyhow::anyhow!("unsupported kernel configuration"));
        assert!(invalidate_corrupt(unrelated, &valid).is_err());
        assert!(valid.exists());
    }
}
