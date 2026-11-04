//! Shared generation orchestration for command-line and terminal clients.
use super::*;

pub enum GenerationInput {
    Auto {
        candidate: Option<usize>,
        refresh: bool,
    },
    Kali,
    Package(KernelPackage),
    Local {
        elf: PathBuf,
        config: PathBuf,
        tool: PathBuf,
    },
}
pub enum Discovery {
    Ready(PathBuf),
    Candidates(Vec<KernelPackage>),
}
pub struct Generation<'a> {
    pub image: &'a Image,
    pub library: &'a Path,
    pub cache: &'a Path,
    pub network: bool,
    pub tool: Option<&'a Path>,
    pub job: &'a Job,
}
impl Generation<'_> {
    pub fn discover(&self, refresh: bool) -> Result<Discovery> {
        if !refresh
            && let Some(path) = local_generated(self.image, self.library, self.cache, self.job)?
        {
            return self.save(&path).map(Discovery::Ready);
        }
        find_packages_with_refresh(self.image, self.cache, self.network, refresh, self.job)
            .map(Discovery::Candidates)
    }
    pub fn run(&self, input: GenerationInput) -> Result<PathBuf> {
        let path = match input {
            GenerationInput::Auto { candidate, refresh } => {
                let packages = if candidate.is_none() {
                    match self.discover(refresh)? {
                        Discovery::Ready(path) => return Ok(path),
                        Discovery::Candidates(packages) => packages,
                    }
                } else {
                    find_packages_with_refresh(
                        self.image,
                        self.cache,
                        self.network,
                        refresh,
                        self.job,
                    )?
                };
                for (index, package) in packages.iter().enumerate() {
                    self.job.report(format!(
                        "候选 {}: {} {} {} {}",
                        index + 1,
                        package.distribution,
                        package.release,
                        package.version,
                        package.debug_url
                    ));
                }
                ensure!(
                    candidate.is_some() || packages.len() == 1,
                    "找到多个候选；请使用 --auto --candidate <序号> 选择"
                );
                let selected = candidate
                    .unwrap_or(1)
                    .checked_sub(1)
                    .and_then(|i| packages.get(i))
                    .with_context(|| format!("候选序号应为 1..={}", packages.len()))?;
                prepare_package(
                    selected,
                    self.tool,
                    self.image,
                    self.cache,
                    self.network,
                    self.job,
                )?
            }
            GenerationInput::Kali => {
                let package = packages::kali_candidate(self.image, self.job)?;
                if let Some(path) = local_generated(self.image, self.library, self.cache, self.job)?
                {
                    return self.save(&path);
                }
                prepare_package(
                    &package,
                    self.tool,
                    self.image,
                    self.cache,
                    self.network,
                    self.job,
                )?
            }
            GenerationInput::Package(package) => prepare_package(
                &package,
                self.tool,
                self.image,
                self.cache,
                self.network,
                self.job,
            )?,
            GenerationInput::Local { elf, config, tool } => {
                generate(&elf, &config, &tool, self.image, self.cache, self.job)?
            }
        };
        self.save(&path)
    }
    fn save(&self, path: &Path) -> Result<PathBuf> {
        let saved = save_generated_symbol(path, self.library, self.job)?;
        self.job.check()?;
        crate::workspace::Registry::load(self.cache)?
            .register(&saved, crate::workspace::Kind::Symbols, self.cache)
            .with_context(|| {
                format!(
                    "符号已保存到 {}，资源库登记失败；可重新运行或导入该文件",
                    saved.display()
                )
            })?;
        self.job
            .report(format!("符号已保存到本地库: {}", saved.display()));
        Ok(saved)
    }
}

pub fn symbol_library(root: &Path, configured: &str) -> PathBuf {
    let path = store::expand_home(configured);
    let path = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    if path.extension().is_some() && !path.is_dir() {
        root.join("symbols")
    } else {
        path
    }
}

pub(super) fn save(path: &Path, library: &Path, job: &Job) -> Result<PathBuf> {
    job.check()?;
    fs::create_dir_all(library)?;
    let name = path.file_name().context("生成符号路径无效")?;
    let target = library.join(name);
    use sha2::{Digest, Sha256};
    let key = format!("{:x}", Sha256::digest(name.as_encoded_bytes()));
    let _lock = stages::artifact_lock(
        &library.join(".locks").join(format!("{key}.lock")),
        "本地符号正在保存",
        job,
    )?;
    let bytes = fs::read(path)?;
    if target.exists() {
        ensure!(fs::read(&target)? == bytes, "同名符号内容不同，拒绝覆盖");
        if stages::read_json(&target.with_extension("source.json")).is_none() {
            job.report("本地符号有效，来源记录缺失或损坏；仍可独立用于分析");
        }
        job.report("复用本地相同符号，保留已有来源记录");
        return Ok(target.canonicalize()?);
    }
    let sidecar = target.with_extension("source.json");
    let source = stages::read_json(&path.with_extension("source.json"));
    let mut published_source = false;
    let result = (|| {
        if let Some(source) = source {
            // Never replace an existing provenance record, even for an unfinished prior save.
            if !sidecar.exists() {
                store::atomic_stream(&sidecar, job, |writer| {
                    serde_json::to_writer_pretty(writer, &source)?;
                    Ok(())
                })?;
                published_source = true;
            }
        } else {
            job.report("来源记录缺失或损坏；保留有效符号，可独立用于分析");
        }
        store::atomic_stream(&target, job, |writer| {
            writer.write_all(&bytes)?;
            Ok(())
        })?;
        Ok(target.canonicalize()?)
    })();
    if result.is_err() && published_source {
        let _ = fs::remove_file(sidecar);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saving_same_content_preserves_provenance_and_missing_sidecar_does_not_block_copy() {
        let dir = tempfile::tempdir().unwrap();
        let job = Job::default();
        let input = dir.path().join("input.json.xz");
        let library = dir.path().join("symbols");
        fs::write(&input, b"validated generator output").unwrap();
        store::atomic_write(
            &input.with_extension("source.json"),
            br#"{"origin":"first"}"#,
        )
        .unwrap();
        let saved = save(&input, &library, &job).unwrap();
        store::atomic_write(
            &input.with_extension("source.json"),
            br#"{"origin":"second"}"#,
        )
        .unwrap();
        assert_eq!(save(&input, &library, &job).unwrap(), saved);
        assert_eq!(
            stages::read_json(&saved.with_extension("source.json")).unwrap()["origin"],
            "first"
        );
        fs::remove_file(input.with_extension("source.json")).unwrap();
        let recovered = save(&input, &dir.path().join("other"), &job).unwrap();
        assert!(recovered.is_file());
        assert!(!recovered.with_extension("source.json").exists());
        fs::write(&input, b"different output").unwrap();
        assert!(save(&input, &library, &job).is_err());
        assert_eq!(fs::read(&saved).unwrap(), b"validated generator output");
    }
    #[test]
    fn library_path_resolution_is_identical_for_relative_absolute_and_file_settings() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            symbol_library(dir.path(), "symbols"),
            dir.path().join("symbols")
        );
        assert_eq!(
            symbol_library(dir.path(), "old.json.xz"),
            dir.path().join("symbols")
        );
        let dotted = dir.path().join("symbols.local");
        fs::create_dir(&dotted).unwrap();
        assert_eq!(
            symbol_library(dir.path(), &dotted.to_string_lossy()),
            dotted
        );
    }
}
