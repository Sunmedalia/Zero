//! 项目内的本地 YARA 规则集登记和校验结果。
pub use crate::engine_service::{
    yara_library_add, yara_library_check, yara_library_list, yara_library_remove,
    yara_library_set_enabled,
};
use crate::{Job, store, yara::YaraSpec};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const REGISTRY_FILE: &str = "yara-library.json";
pub(crate) const LOCK_FILE: &str = "yara-library.lock";
const MAX_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum YaraLibrarySelection {
    AllEnabled,
    Named(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFingerprint {
    pub path: PathBuf,
    pub size: u64,
    pub modified: String,
}

impl SourceFingerprint {
    pub(crate) fn new(path: &Path, meta: &fs::Metadata) -> Result<Self> {
        let modified = meta.modified()?;
        let modified = match modified.duration_since(UNIX_EPOCH) {
            Ok(age) => age.as_nanos().to_string(),
            Err(before) => format!("-{}", before.duration().as_nanos()),
        };
        Ok(Self {
            path: path.into(),
            size: meta.len(),
            modified,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub rule_count: Option<usize>,
    pub file_count: usize,
    pub sha256: Option<String>,
    pub fingerprint: Vec<SourceFingerprint>,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub checked_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub name: String,
    pub path: PathBuf,
    pub enabled: bool,
    pub added_at: u64,
    pub last_check: Option<CheckResult>,
}

#[derive(Default, Serialize, Deserialize)]
struct Registry {
    sets: BTreeMap<String, RuleSet>,
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "YARA 规则集名称须由英文字母、数字、下划线或连字符组成"
    );
    Ok(())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Registry {
    fn load(cache: &Path) -> Result<Self> {
        let path = cache.join(REGISTRY_FILE);
        let meta = match path.symlink_metadata() {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(err).context("读取 YARA 规则库失败"),
        };
        ensure!(meta.is_file(), "YARA 规则库登记必须是普通文件");
        ensure!(
            meta.len() <= MAX_REGISTRY_BYTES,
            "YARA 规则库登记超过 16 MiB"
        );
        let registry: Self =
            serde_json::from_slice(&fs::read(path)?).context("YARA 规则库登记格式无效")?;
        for (name, set) in &registry.sets {
            validate_name(name)?;
            ensure!(&set.name == name, "YARA 规则集名称与登记键不一致");
        }
        Ok(registry)
    }

    fn save(&self, cache: &Path, job: &Job) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(
            bytes.len() as u64 <= MAX_REGISTRY_BYTES,
            "YARA 规则库登记超过 16 MiB"
        );
        store::atomic_stream(&cache.join(REGISTRY_FILE), job, |writer| {
            writer.write_all(&bytes)?;
            Ok(())
        })
    }

    fn update<T>(
        cache: &Path,
        job: &Job,
        change: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        job.check()?;
        fs::create_dir_all(cache)?;
        ensure!(cache.symlink_metadata()?.is_dir(), "缓存目录必须是普通目录");
        let path = cache.join(LOCK_FILE);
        match path.symlink_metadata() {
            Ok(meta) => ensure!(meta.is_file(), "YARA 规则库锁必须是普通文件"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => return Err(err).context("读取 YARA 规则库锁失败"),
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        lock.try_lock().context("YARA 规则库正在更新，请稍后重试")?;
        let mut registry = Self::load(cache)?;
        let result = change(&mut registry)?;
        registry.save(cache, job)?;
        Ok(result)
    }

    fn get(&self, name: &str) -> Result<&RuleSet> {
        self.sets
            .get(name)
            .with_context(|| format!("YARA 规则集 {name} 不存在"))
    }
}

pub(crate) fn list(cache: &Path) -> Result<Vec<RuleSet>> {
    Ok(Registry::load(cache)?.sets.into_values().collect())
}

pub(crate) fn add(cache: &Path, name: &str, path: &Path) -> Result<RuleSet> {
    validate_name(name)?;
    let meta = path
        .symlink_metadata()
        .with_context(|| format!("无法读取 YARA 规则集路径 {}", path.display()))?;
    ensure!(
        meta.is_dir() || meta.is_file() && crate::yara::is_library_rule_file(path),
        "YARA 规则集路径须为普通 .yar / .yara 文件或目录"
    );
    let set = RuleSet {
        name: name.into(),
        path: path.canonicalize()?,
        enabled: true,
        added_at: now(),
        last_check: None,
    };
    Registry::update(cache, &Job::default(), |registry| {
        ensure!(
            !registry.sets.contains_key(name),
            "YARA 规则集 {name} 已存在"
        );
        registry.sets.insert(name.into(), set.clone());
        Ok(set)
    })
}

pub(crate) fn remove(cache: &Path, name: &str) -> Result<RuleSet> {
    Registry::update(cache, &Job::default(), |registry| {
        registry
            .sets
            .remove(name)
            .with_context(|| format!("YARA 规则集 {name} 不存在"))
    })
}

pub(crate) fn set_enabled(cache: &Path, name: &str, enabled: bool) -> Result<RuleSet> {
    Registry::update(cache, &Job::default(), |registry| {
        let set = registry
            .sets
            .get_mut(name)
            .with_context(|| format!("YARA 规则集 {name} 不存在"))?;
        set.enabled = enabled;
        Ok(set.clone())
    })
}

pub(crate) fn check(cache: &Path, name: Option<&str>, job: &Job) -> Result<Vec<RuleSet>> {
    Registry::update(cache, job, |registry| {
        let names = if let Some(name) = name {
            vec![registry.get(name)?.name.clone()]
        } else {
            registry.sets.keys().cloned().collect()
        };
        let mut checked = Vec::new();
        for name in names {
            job.check()?;
            job.report(format!("正在校验 YARA 规则集 {name}"));
            let set = registry
                .sets
                .get_mut(&name)
                .context("校验时找不到 YARA 规则集")?;
            let mut fingerprint = Vec::new();
            let compiled = crate::yara::prepare_library_sources(
                set,
                &mut crate::yara::LibrarySourceLimits::default(),
                &mut fingerprint,
                job,
            )
            .and_then(|source| crate::yara::compile_library_sources(&[source], job));
            job.check()?;
            let mut report = CheckResult {
                rule_count: None,
                file_count: fingerprint.len(),
                sha256: None,
                fingerprint,
                error: None,
                warnings: Vec::new(),
                checked_at: now(),
            };
            match compiled {
                Ok(compiled) => {
                    report.rule_count = Some(compiled.rule_count);
                    report.sha256 = Some(compiled.sha256);
                    report.warnings = compiled.warnings;
                }
                Err(error) => report.error = Some(format!("{error:#}")),
            }
            set.last_check = Some(report);
            checked.push(set.clone());
        }
        Ok(checked)
    })
}

pub(crate) fn compile(
    cache: &Path,
    selection: &YaraLibrarySelection,
    job: &Job,
) -> Result<(YaraSpec, Vec<String>)> {
    let registry = Registry::load(cache)?;
    let sets: Vec<_> = match selection {
        YaraLibrarySelection::AllEnabled => {
            registry.sets.values().filter(|set| set.enabled).collect()
        }
        YaraLibrarySelection::Named(names) => {
            ensure!(!names.is_empty(), "请指定至少一个 YARA 规则集名称");
            let mut sets = BTreeMap::new();
            for name in names {
                let set = registry.get(name)?;
                ensure!(set.enabled, "YARA 规则集 {name} 已停用");
                sets.insert(&set.name, set);
            }
            sets.into_values().collect()
        }
    };
    ensure!(!sets.is_empty(), "YARA 规则库没有已启用的规则集");
    let mut diagnostics = Vec::new();
    let mut sources = Vec::new();
    let mut limits = crate::yara::LibrarySourceLimits::default();
    for set in sets {
        job.check()?;
        let mut fingerprint = Vec::new();
        let source = crate::yara::prepare_library_sources(set, &mut limits, &mut fingerprint, job)
            .with_context(|| format!("读取 YARA 规则集 {} 失败", set.name))?;
        if set
            .last_check
            .as_ref()
            .is_some_and(|checked| checked.fingerprint != fingerprint)
        {
            let message = format!("YARA 规则集 {} 的源文件已变化，重新编译", set.name);
            job.report(&message);
            diagnostics.push(message);
        }
        sources.push(source);
    }
    let compiled = crate::yara::compile_library_sources(&sources, job)?;
    diagnostics.extend(compiled.warnings);
    Ok((compiled.spec, diagnostics))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{self, Options, Outcome, Plugin, Request, Session};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    const RULE: &str = r#"rule same { strings: $a = "LIBRARY_SENTINEL" condition: $a }"#;

    #[test]
    fn registration_and_checks_round_trip_without_changing_sources() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join(".zero/rust");
        let file = dir.path().join("a.yar");
        fs::write(&file, RULE)?;
        for name in ["", "a/b", "two names", "中文", "dot.name"] {
            assert!(add(&cache, name, &file).is_err());
        }
        assert!(list(&cache)?.is_empty());
        let added = add(&cache, "set_01-A", &file)?;
        assert!(added.enabled);
        assert_eq!(added.path, file.canonicalize()?);
        assert_eq!(list(&cache)?, vec![added.clone()]);
        assert!(add(&cache, &added.name, &file).is_err());
        assert!(!set_enabled(&cache, &added.name, false)?.enabled);
        let job = Job::default();
        let checked = check(&cache, None, &job)?;
        assert_eq!(list(&cache)?, checked);
        let report = checked[0].last_check.as_ref().unwrap();
        assert_eq!(report.rule_count, Some(1));
        assert_eq!(report.file_count, 1);
        assert_eq!(report.sha256.as_ref().unwrap().len(), 64);
        assert_eq!(report.fingerprint[0].size, RULE.len() as u64);
        assert!(report.error.is_none());
        assert!(set_enabled(&cache, &added.name, true)?.enabled);
        assert!(remove(&cache, &added.name)?.enabled);
        assert!(list(&cache)?.is_empty());
        assert_eq!(fs::read_to_string(file)?, RULE);
        Ok(())
    }

    #[test]
    fn selection_and_compile_errors_are_explicit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join("cache");
        let file = dir.path().join("broken.yar");
        fs::write(&file, "\nrule broken { condition: unknown_identifier }")?;
        let job = Job::default();
        let all = YaraLibrarySelection::AllEnabled;
        assert!(
            compile(&cache, &all, &job)
                .unwrap_err()
                .to_string()
                .contains("没有已启用")
        );
        let named = |name: &str| YaraLibrarySelection::Named(vec![name.into()]);
        assert!(
            compile(&cache, &named("missing"), &job)
                .unwrap_err()
                .to_string()
                .contains("不存在")
        );
        assert!(compile(&cache, &YaraLibrarySelection::Named(vec![]), &job).is_err());
        add(&cache, "broken", &file)?;
        let checked = check(&cache, Some("broken"), &job)?;
        let report = checked[0].last_check.as_ref().unwrap();
        let error = report.error.as_deref().unwrap();
        assert!(error.contains("broken.yar:2"), "{error}");
        assert!(error.contains("unknown_identifier"));
        assert_eq!(report.file_count, 1);
        assert!(report.sha256.is_none());
        assert!(compile(&cache, &all, &job).is_err());
        set_enabled(&cache, "broken", false)?;
        assert!(
            compile(&cache, &named("broken"), &job)
                .unwrap_err()
                .to_string()
                .contains("已停用")
        );
        let empty = dir.path().join("empty");
        fs::create_dir(&empty)?;
        add(&cache, "empty", &empty)?;
        assert!(
            compile(&cache, &named("empty"), &job)
                .unwrap_err()
                .chain()
                .any(|error| error.to_string().contains("没有 .yar"))
        );
        Ok(())
    }

    #[test]
    fn includes_are_fingerprinted_and_source_changes_compile_once_per_analysis() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join("cache");
        let root = dir.path().join("rules");
        fs::create_dir(&root)?;
        let file = root.join("root.yar");
        let include = root.join("included.yara");
        fs::write(
            &file,
            "include \"included.yara\"\nrule derived { condition: same }",
        )?;
        fs::write(&include, RULE)?;
        add(&cache, "examples", &root)?;
        let checked = check(&cache, Some("examples"), &Job::default())?;
        let report = checked[0].last_check.as_ref().unwrap();
        assert!(report.error.is_none(), "{report:?}");
        assert_eq!((report.rule_count, report.file_count), (Some(2), 2));
        assert!(
            report
                .fingerprint
                .iter()
                .any(|file| file.path.ends_with("included.yara"))
        );
        let image = dir.path().join("sample.raw");
        fs::write(&image, b"start LIBRARY_SENTINEL end")?;
        let request = Request {
            image: &image,
            symbols: dir.path(),
            choice: None,
            plugin: Plugin::LinuxYarascan,
            cache: &cache,
            use_cache: true,
            network: false,
        };
        let options = Options {
            os: analysis::Os::Linux,
            yara_library: Some(YaraLibrarySelection::AllEnabled),
            ..Options::default()
        };
        let mut session = Session::default();
        let Outcome::Ready(before) =
            analysis::analyze(&mut session, &request, None, &options, &Job::default())?
        else {
            anyhow::bail!("未获得 YARA 扫描结果");
        };
        assert!(before.rows.iter().any(|row| row[1] == "examples:same"));
        fs::write(
            &include,
            RULE.replace("LIBRARY_SENTINEL", "NO_LONGER_MATCHES"),
        )?;
        let starts = Arc::new(AtomicUsize::new(0));
        let observed = starts.clone();
        let job = Job::new(move |progress| {
            if progress.starts_with("正在编译 YARA 规则文件 ") {
                observed.fetch_add(1, Ordering::Relaxed);
            }
        });
        let Outcome::Ready(after) =
            analysis::analyze(&mut session, &request, None, &options, &job)?
        else {
            anyhow::bail!("未获得 YARA 扫描结果");
        };
        assert_eq!(starts.load(Ordering::Relaxed), 2);
        assert!(!job.served_from_cache());
        assert!(after.rows.is_empty());
        assert!(
            after
                .diagnostics
                .iter()
                .any(|message| message.contains("源文件已变化，重新编译"))
        );
        let cached = Job::default();
        analysis::analyze(&mut session, &request, None, &options, &cached)?;
        assert!(cached.served_from_cache());
        Ok(())
    }

    #[test]
    fn same_rule_name_is_independent_across_namespaces() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join("cache");
        let path = dir.path().join("a.yar");
        fs::write(&path, RULE)?;
        add(&cache, "1-alpha", &path)?;
        add(&cache, "_beta", &path)?;
        let job = Job::default();
        let (spec, _) = compile(&cache, &YaraLibrarySelection::AllEnabled, &job)?;
        let mut file = tempfile::tempfile()?;
        std::io::Write::write_all(&mut file, b"prefix LIBRARY_SENTINEL")?;
        let image = crate::image::Image::from_file(file, "synthetic".into())?;
        let result = crate::yara::physical_results(&image, Plugin::LinuxYarascan, &spec, &job)?;
        let names: std::collections::BTreeSet<_> =
            result.rows.iter().map(|row| row[1].as_str()).collect();
        assert_eq!(names, ["1-alpha:same", "_beta:same"].into());
        Ok(())
    }

    #[test]
    fn includes_reject_escape_absolute_cycles_and_report_original_line() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join("cache");
        let outside = dir.path().join("outside.inc");
        fs::write(&outside, RULE)?;
        let root = dir.path().join("rules");
        fs::create_dir(&root)?;
        let main = root.join("entry.yar");
        let inner = root.join("nested.inc");
        fs::write(&main, RULE)?;
        add(&cache, "set", &main)?;
        let job = Job::default();
        let error = || -> Result<String> {
            Ok(check(&cache, Some("set"), &job)?[0]
                .last_check
                .as_ref()
                .unwrap()
                .error
                .clone()
                .unwrap())
        };
        fs::write(&main, "include \"../outside.inc\"")?;
        assert!(error()?.contains("跳出规则集根目录"));
        fs::write(
            &main,
            format!("include {:?}", outside.display().to_string()),
        )?;
        assert!(error()?.contains("必须使用相对路径"));
        #[cfg(unix)]
        {
            let linked = root.join("link.inc");
            std::os::unix::fs::symlink(&outside, &linked)?;
            fs::write(&main, "include \"link.inc\"")?;
            assert!(error()?.contains("link.inc"));
        }
        fs::write(&main, "include \"nested.inc\"")?;
        fs::write(&inner, "include \"entry.yar\"")?;
        assert!(error()?.contains("循环 include"));
        let oversized = fs::File::create(&inner)?;
        oversized.set_len(16 * 1024 * 1024 + 1)?;
        assert!(error()?.contains("16 MiB"));
        fs::write(&inner, "\n\nrule broken { condition: unknown_name }")?;
        assert!(error()?.contains("nested.inc:3"));
        fs::write(&inner, RULE)?;
        fs::write(
            &main,
            "\ninclude \"nested.inc\"\n\nrule broken { condition: unknown_name }",
        )?;
        assert!(error()?.contains("entry.yar:4"));
        Ok(())
    }

    #[test]
    fn cancelled_check_preserves_previous_report() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("a.yar");
        let cache = dir.path().join("cache");
        fs::write(&file, RULE)?;
        add(&cache, "example", &file)?;
        let before = check(&cache, None, &Job::default())?;
        fs::write(&file, "rule changed { condition: false }")?;
        let flag = Arc::new(AtomicBool::new(false));
        let observed = flag.clone();
        let mut job = Job::new(move |message| {
            if message.starts_with("正在编译") {
                observed.store(true, Ordering::Relaxed);
            }
        });
        job.cancel = flag;
        assert!(check(&cache, None, &job).is_err());
        assert_eq!(list(&cache)?, before);
        Ok(())
    }
}
