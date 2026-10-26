//! Shared native operations for the terminal and the JSON-RPC adapter.
use crate::{
    Job,
    linux::{self, Outcome, Plugin, Session},
    store::{self, Settings},
    symbols::{self, Isf, RemoteMatch},
};
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};
/// Everything a worker needs, captured before the thread starts so the UI keeps
/// responding while evidence is read.
#[derive(Clone)]
pub(crate) struct EngineContext {
    pub(crate) root: PathBuf,
    pub(crate) cache: PathBuf,
    pub(crate) settings: Settings,
}

impl EngineContext {
    pub(crate) fn expand(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
    }
    /// A configured directory, resolved against the project root.
    ///
    /// Settings store `images`, `symbols` and `exports` relative to the project;
    /// the interface process has a different working directory, so resolving
    /// them here (not with the process cwd) keeps both views of the project
    /// identical.
    pub(crate) fn directory(&self, value: &str) -> PathBuf {
        self.expand(&store::expand_home(value))
    }
    pub(crate) fn image_dir(&self) -> PathBuf {
        self.directory(&self.settings.image_dir)
    }
    pub(crate) fn symbol_dir(&self) -> PathBuf {
        self.directory(&self.settings.symbols)
    }
    pub(crate) fn history_dir(&self) -> PathBuf {
        self.directory(&self.settings.history_dir)
    }
    pub(crate) fn symbol_source(&self, given: Option<PathBuf>) -> PathBuf {
        given
            .map(|p| self.expand(&p))
            .unwrap_or_else(|| self.symbol_dir())
    }
    pub(crate) fn library(&self) -> PathBuf {
        let library = self.symbol_dir();
        if library.extension().is_some() && !library.is_dir() {
            self.root.join("symbols")
        } else {
            library
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Verified {
    pub digest: String,
    pub computed: bool,
    pub seconds: f64,
}
impl EngineContext {
    pub(crate) fn verify(
        &self,
        session: &mut Session,
        image: &Path,
        job: &Job,
    ) -> Result<Verified> {
        let started = std::time::Instant::now();
        let prepared = session.prepare_image(&self.expand(image), &self.cache, job)?;
        Ok(Verified {
            digest: prepared.digest.clone(),
            computed: job.prepared_image(),
            seconds: started.elapsed().as_secs_f64(),
        })
    }
    pub(crate) fn identify(
        &self,
        session: &mut Session,
        image: &Path,
        job: &Job,
    ) -> Result<store::Results> {
        let prepared = session.identify_image(&self.expand(image), &self.cache, job)?;
        linux::banner_result(&prepared, job)
    }
    pub(crate) fn match_local(
        &self,
        session: &mut Session,
        image: &Path,
        paths: &[PathBuf],
        job: &Job,
    ) -> Result<(symbols::LocalMatches, store::Results)> {
        let prepared = session.identify_image(&self.expand(image), &self.cache, job)?;
        let banner = linux::banner_result(&prepared, job)?;
        let report = symbols::match_local_files(paths, &prepared, job)?;
        Ok((report, banner))
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn analyze(
        &self,
        session: &mut Session,
        image: &Path,
        symbols: &Path,
        choice: Option<&str>,
        plugin: Plugin,
        force: bool,
        dump: Option<&crate::dump::DumpOptions>,
        options: &crate::analysis::Options,
        job: &Job,
    ) -> Result<Outcome> {
        let mut options = options.clone();
        for attachment in &mut options.pagefiles {
            attachment.path = self.expand(&attachment.path);
        }
        options.swapfile = options.swapfile.as_ref().map(|path| self.expand(path));
        let dump = dump.map(|dump| {
            let mut dump = dump.clone();
            dump.directory = self.expand(&dump.directory);
            dump
        });
        crate::analysis::analyze(
            session,
            &linux::Request {
                image: &self.expand(image),
                symbols: &self.expand(symbols),
                choice,
                plugin,
                cache: &self.cache,
                use_cache: self.settings.enable_cache && !force,
                network: self.settings.remote_symbols,
            },
            dump.as_ref(),
            &options,
            job,
        )
    }
}
pub(crate) fn save_remote_symbol(
    candidate: &RemoteMatch,
    isf: &Isf,
    library: &Path,
    job: &Job,
) -> Result<PathBuf> {
    job.check()?;
    std::fs::create_dir_all(library)?;
    let stem = candidate
        .path
        .rsplit('/')
        .next()
        .unwrap_or("symbol.json.xz")
        .trim_end_matches(".json.xz");
    let extension = if isf.is_windows() { "json" } else { "json.xz" };
    let target = library.join(format!(
        "{}-{}.{extension}",
        stem.chars().take(100).collect::<String>(),
        isf.digest
    ));
    let bytes = std::fs::read(&isf.label)?;
    if target.exists() {
        ensure!(
            std::fs::read(&target)? == bytes,
            "同名本地符号内容不同，拒绝覆盖: {}",
            target.display()
        );
    } else {
        store::atomic_write(&target, &bytes)?;
    }
    job.check()?;
    store::atomic_write(
        &target.with_extension("source.json"),
        &serde_json::to_vec_pretty(candidate)?,
    )?;
    Ok(target.canonicalize()?)
}

pub(crate) fn save_generated_symbol(path: &Path, library: &Path, job: &Job) -> Result<PathBuf> {
    job.check()?;
    std::fs::create_dir_all(library)?;
    let name = path.file_name().context("生成符号路径无效")?;
    let target = library.join(name);
    let bytes = std::fs::read(path)?;
    if target.exists() {
        ensure!(
            std::fs::read(&target)? == bytes,
            "同名符号内容不同，拒绝覆盖"
        );
    } else {
        store::atomic_write(&target, &bytes)?;
    }
    job.check()?;
    let source = path.with_extension("source.json");
    if source.is_file() {
        store::atomic_write(
            &target.with_extension("source.json"),
            &std::fs::read(source)?,
        )?;
    }
    Ok(target.canonicalize()?)
}

pub(crate) struct Inventory {
    pub entries: Vec<crate::cache::Entry>,
    pub records: Vec<store::ExportRecord>,
    pub summaries: std::collections::HashMap<PathBuf, store::Summary>,
}
impl EngineContext {
    pub(crate) fn inventory(&self, job: &Job) -> Result<Inventory> {
        let mut entries = crate::cache::inventory(&self.cache)?;
        entries.sort_by(|a, b| {
            b.modified
                .cmp(&a.modified)
                .then_with(|| a.path.cmp(&b.path))
        });
        let mut summaries = std::collections::HashMap::new();
        for entry in &entries {
            job.check()?;
            if entry.scope == crate::cache::Scope::Results
                && let Some(summary) = store::summary(&entry.path)
            {
                summaries.insert(entry.path.clone(), summary);
            }
        }
        Ok(Inventory {
            entries,
            records: store::export_records(&self.cache),
            summaries,
        })
    }
}
