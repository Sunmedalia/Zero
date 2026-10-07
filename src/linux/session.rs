//! Per-image session: prepared image, matched symbols and validated page tables.
use super::*;
fn source_stamp(path: &Path, job: &Job) -> Result<String> {
    fn visit(path: &Path, out: &mut Vec<String>, depth: usize, job: &Job) -> Result<()> {
        job.check()?;
        ensure!(depth < 128, "符号目录超过 128 层");
        if !path.exists() {
            out.push(format!("{}:missing", path.display()));
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            out.push(format!(
                "{}:{}",
                path.display(),
                crate::image::metadata_stamp(&metadata)?
            ));
            if depth == 0 {
                visit(&path.canonicalize()?, out, depth + 1, job)?;
            }
            return Ok(());
        }
        out.push(format!(
            "{}:{}",
            path.display(),
            crate::image::metadata_stamp(&metadata)?
        ));
        if metadata.is_dir() {
            let mut entries = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                visit(&entry.path(), out, depth + 1, job)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(path, &mut out, 0, job)?;
    Ok(out.join("\n"))
}
#[derive(Default)]
pub struct Session {
    image: Option<std::sync::Arc<Image>>,
    image_stamp: String,
    physical_stamp: String,
    symbol_stamp: String,
    symbols: Vec<std::sync::Arc<Isf>>,
    windows_stamp: String,
    windows_symbols: Vec<std::sync::Arc<Isf>>,
    roots: std::collections::HashMap<String, u64>,
}
impl Session {
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn prepare_image(
        &mut self,
        path: &Path,
        cache: &Path,
        job: &Job,
    ) -> Result<std::sync::Arc<Image>> {
        job.check()?;
        let image_stamp = source_stamp(path, job)?;
        if self.image.is_none()
            || self.image_stamp != image_stamp
            || self
                .image
                .as_ref()
                .is_some_and(|i| i.stamp().ok().as_ref() != Some(&self.physical_stamp))
        {
            self.clear();
            let mut image = Image::open(path, cache, job)?;
            image.set_limits(store::settings(cache)?.resources);
            self.physical_stamp = image.stamp()?;
            self.image = Some(std::sync::Arc::new(image));
            self.image_stamp = image_stamp;
        }
        Ok(self.image.as_ref().context("镜像未准备")?.clone())
    }
    pub(crate) fn analyze_windows(
        &mut self,
        image: &Image,
        request: &Request<'_>,
        dump: Option<&crate::dump::DumpOptions>,
        options: &crate::analysis::Options,
        job: &Job,
    ) -> Result<Outcome> {
        // Container-only paths do not need kernel symbols or a symbol cache.
        if image.windows_container.as_ref().is_some_and(|m| {
            m.virtual_memory
                || m.kernel_virtual
                || image.segments.is_empty()
                || request.plugin == Plugin::WinCrashinfo
        }) {
            return crate::windows::analyze(image, request, dump, options, job);
        }
        crate::windows::validate_request(request, dump, options)?;
        let stamp = || -> Result<String> {
            Ok(format!(
                "{}:{}:{}:{}",
                image.digest,
                crate::windows_symbols::CONVERTER_VERSION,
                source_stamp(request.symbols, job)?,
                source_stamp(&request.cache.join("symbols/isf/windows"), job)?
            ))
        };
        let current = stamp()?;
        if self.windows_stamp != current || self.windows_symbols.is_empty() {
            self.windows_symbols = crate::windows_symbols::resolve(
                request.symbols,
                image,
                request.cache,
                request.network,
                job,
            )?
            .into_iter()
            .map(std::sync::Arc::new)
            .collect();
            self.windows_stamp = stamp()?;
        } else {
            job.report("复用精确匹配的 Windows ISF");
        }
        crate::windows::analyze_resolved(image, request, dump, options, job, &self.windows_symbols)
    }
    pub fn analyze(&mut self, request: &Request<'_>, job: &Job) -> Result<Outcome> {
        self.analyze_with_dump(request, None, job)
    }
    pub fn analyze_with_dump(
        &mut self,
        request: &Request<'_>,
        dump: Option<&crate::dump::DumpOptions>,
        job: &Job,
    ) -> Result<Outcome> {
        if request.plugin.is_dump() {
            dump.context("Dump 插件需要 --pid、--dump-dir；memdump 还需要 --start、--end")?
                .validate(request.plugin)?;
        } else {
            ensure!(dump.is_none(), "非 Dump 插件不接受转储参数");
        }
        job.check()?;
        let image = self.prepare_image(request.image, request.cache, job)?;
        if request.plugin.is_windows() {
            return self.analyze_windows(
                &image,
                request,
                dump,
                &crate::analysis::Options::default(),
                job,
            );
        }

        if request.plugin == Plugin::Banners {
            let key = store::key(&image.digest, "no-isf", "banners");
            if request.use_cache
                && let Some(result) = store::load(request.cache, &key)
            {
                return Ok(Outcome::Ready(result));
            }
            let result = banner_result(&image, job)?;
            if request.use_cache {
                store::save(request.cache, &key, &result, job)?;
            }
            return Ok(Outcome::Ready(result));
        }
        let symbols_stamp = || -> Result<String> {
            Ok(format!(
                "{}\n{}",
                source_stamp(request.symbols, job)?,
                source_stamp(&request.cache.join("symbols/isf"), job)?
            ))
        };
        let stamp = symbols_stamp()?;
        if self.symbol_stamp != stamp || self.symbols.is_empty() {
            self.symbols =
                symbols::resolve(request.symbols, &image, request.cache, request.network, job)?
                    .into_iter()
                    .map(std::sync::Arc::new)
                    .collect();
            // Resolving may download a new ISF; record the resulting cache state.
            self.symbol_stamp = symbols_stamp()?;
            self.roots.clear();
        } else {
            job.report("复用已验证镜像和符号；无需重新计算摘要／扫描");
        }
        let symbol = if let Some(choice) = request.choice {
            self.symbols
                .iter()
                .find(|s| s.label == choice)
                .context("指定符号不在完整 banner 匹配候选中")?
                .clone()
        } else {
            if self.symbols.len() > 1 {
                return Ok(Outcome::Choose(
                    self.symbols.iter().map(|s| s.label.clone()).collect(),
                ));
            }
            self.symbols[0].clone()
        };
        let key = store::key(&image.digest, &symbol.digest, request.plugin.name());
        if !request.plugin.is_dump()
            && request.use_cache
            && let Some(mut result) = store::load(request.cache, &key)
        {
            job.check()?;
            result.symbol = symbol.label.clone();
            job.report("读取成功缓存");
            return Ok(Outcome::Ready(result));
        }
        let root = if let Some(root) = self.roots.get(&symbol.digest) {
            *root
        } else {
            job.report("验证内核页表和完整 banner");
            let root = discover(&image, &symbol, job)?;
            self.roots.insert(symbol.digest.clone(), root);
            root
        };
        let engine = Linux {
            vm: VirtualMemory::new(&image, root),
            isf: &symbol,
        };
        let result = if request.plugin.is_dump() {
            engine.run_dump(request.plugin, dump.context("Dump 插件需要转储参数")?, job)?
        } else {
            engine.run(request.plugin, job)?
        };
        job.check()?;
        if request.use_cache && !request.plugin.is_dump() {
            store::save(request.cache, &key, &result, job)?;
        }
        Ok(Outcome::Ready(result))
    }
}
