//! Project asset registry. Import/remove affects the registry, never source files.
use crate::{Job, store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Image,
    Symbols,
}
#[derive(Clone, Debug)]
pub struct Asset {
    pub path: PathBuf,
    pub kind: Kind,
    pub bytes: u64,
    pub available: bool,
    pub directory: bool,
    pub stamp: Option<String>,
    pub origin: &'static str,
}
impl Asset {
    pub fn id(&self) -> String {
        use sha2::{Digest, Sha256};
        format!(
            "{:x}",
            Sha256::digest(self.path.to_string_lossy().as_bytes())
        )[..12]
            .into()
    }
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .unwrap_or(self.path.as_os_str())
            .to_string_lossy()
            .into()
    }
    pub fn format(&self) -> &'static str {
        let name = self.path.to_string_lossy().to_lowercase();
        if self.directory {
            "目录"
        } else if name.ends_with(".json.xz") {
            "ISF/XZ"
        } else if name.ends_with(".zip") {
            "ZIP"
        } else if name.ends_with(".json") {
            "ISF"
        } else if name.ends_with(".gz") {
            "gzip"
        } else if name.ends_with(".lime") {
            "LiME"
        } else {
            "RAW/LiME"
        }
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Registry {
    images: Vec<PathBuf>,
    symbols: Vec<PathBuf>,
    hidden: Vec<PathBuf>,
    active_image: Option<PathBuf>,
    active_symbols: Option<PathBuf>,
}
impl Registry {
    pub fn load(cache: &Path) -> Result<Self> {
        let path = cache.join("workspace.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        ensure!(
            fs::metadata(&path)?.len() <= 4 * 1024 * 1024,
            "项目清单超过 4 MiB"
        );
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }
    pub fn selected(&self, kind: Kind) -> Option<&Path> {
        if kind == Kind::Image {
            self.active_image.as_deref()
        } else {
            self.active_symbols.as_deref()
        }
    }
    pub fn excluded(&self, path: &Path) -> bool {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        self.hidden.contains(&path)
    }
    fn save(&self, cache: &Path) -> Result<()> {
        store::atomic_write(
            &cache.join("workspace.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }
    pub fn import(&mut self, path: &Path, kind: Kind, cache: &Path) -> Result<PathBuf> {
        self.add(path, kind, cache, true)
    }
    /// Register a saved asset without changing the current analysis selection.
    pub fn register(&mut self, path: &Path, kind: Kind, cache: &Path) -> Result<PathBuf> {
        self.add(path, kind, cache, false)
    }
    fn add(&mut self, path: &Path, kind: Kind, cache: &Path, select: bool) -> Result<PathBuf> {
        let path = path.canonicalize()?;
        let meta = fs::metadata(&path)?;
        ensure!(
            meta.is_file() || kind == Kind::Symbols && meta.is_dir(),
            "镜像必须是文件；符号可为文件或目录"
        );
        let _guard = registry_lock(cache)?;
        let mut next = Self::load(cache)?;
        if select {
            if kind == Kind::Image {
                if next.active_image.as_ref() != Some(&path) {
                    next.active_symbols = None;
                }
                next.active_image = Some(path.clone());
            } else {
                next.active_symbols = Some(path.clone());
            }
        }
        next.hidden.retain(|p| p != &path);
        let list = if kind == Kind::Image {
            &mut next.images
        } else {
            &mut next.symbols
        };
        if !list.contains(&path) {
            list.push(path.clone());
        }
        ensure!(list.len() <= 10000, "项目清单达到 10000 项上限");
        next.save(cache)?;
        *self = next;
        Ok(path)
    }
    pub fn remove(&mut self, path: &Path, cache: &Path) -> Result<()> {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let _guard = registry_lock(cache)?;
        let mut next = Self::load(cache)?;
        if next.active_image.as_ref() == Some(&path) {
            next.active_image = None;
        }
        if next.active_symbols.as_ref() == Some(&path) {
            next.active_symbols = None;
        }
        next.images.retain(|p| p != &path);
        next.symbols.retain(|p| p != &path);
        if !next.hidden.contains(&path) {
            next.hidden.push(path);
        }
        ensure!(next.hidden.len() <= 10000, "移出记录达到 10000 项上限");
        next.save(cache)?;
        *self = next;
        Ok(())
    }
    pub fn discover(&self, root: &Path, cache: &Path) -> Result<Vec<Asset>> {
        self.discover_with_dirs(root, cache, &root.join("images"), &root.join("symbols"))
    }
    pub fn discover_with_dirs(
        &self,
        _root: &Path,
        cache: &Path,
        image_dir: &Path,
        symbol_dir: &Path,
    ) -> Result<Vec<Asset>> {
        let mut found = BTreeMap::new();
        fn add(
            found: &mut BTreeMap<PathBuf, Asset>,
            path: PathBuf,
            kind: Kind,
            origin: &'static str,
        ) -> Result<()> {
            ensure!(found.len() < 10000, "资产发现达到 10000 项上限");
            let path = path.canonicalize().unwrap_or(path);
            let meta = fs::metadata(&path).ok();
            found.insert(
                path.clone(),
                Asset {
                    path,
                    kind,
                    bytes: meta.as_ref().map_or(0, |m| m.len()),
                    available: meta
                        .as_ref()
                        .is_some_and(|m| m.is_file() || kind == Kind::Symbols && m.is_dir()),
                    directory: meta.as_ref().is_some_and(|m| m.is_dir()),
                    stamp: meta
                        .as_ref()
                        .and_then(|m| crate::image::metadata_stamp(m).ok()),
                    origin,
                },
            );
            Ok(())
        }
        fn scan(
            found: &mut BTreeMap<PathBuf, Asset>,
            dir: &Path,
            kind: Option<Kind>,
            origin: &'static str,
            depth: usize,
        ) -> Result<()> {
            if !dir.exists() {
                return Ok(());
            }
            ensure!(depth < 8, "资产目录超过 8 层");
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let ty = entry.file_type()?;
                let path = entry.path();
                if ty.is_symlink() {
                    continue;
                }
                if ty.is_dir() {
                    if kind.is_some() {
                        scan(found, &path, kind, origin, depth + 1)?;
                    }
                    continue;
                }
                if !ty.is_file() {
                    continue;
                }
                // Directory names are browsing defaults, not evidence types.
                let detected = match crate::browser::file_kind(&path) {
                    crate::browser::FileKind::Image => Some(Kind::Image),
                    crate::browser::FileKind::Symbols => Some(Kind::Symbols),
                    crate::browser::FileKind::Other => None,
                };
                if let Some(kind) = detected {
                    add(found, path, kind, origin)?;
                }
            }
            Ok(())
        }
        scan(&mut found, image_dir, Some(Kind::Image), "项目", 0)?;
        if symbol_dir.is_file() {
            add(&mut found, symbol_dir.into(), Kind::Symbols, "项目")?;
        } else {
            scan(&mut found, symbol_dir, Some(Kind::Symbols), "项目", 0)?;
        }
        scan(
            &mut found,
            &cache.join("symbols/isf"),
            Some(Kind::Symbols),
            "下载／生成",
            0,
        )?;
        for (paths, kind) in [(&self.images, Kind::Image), (&self.symbols, Kind::Symbols)] {
            for path in paths {
                add(&mut found, path.clone(), kind, "已导入")?;
            }
        }
        Ok(found
            .into_values()
            .filter(|a| !self.hidden.contains(&a.path))
            .collect())
    }
}
fn registry_lock(cache: &Path) -> Result<fs::File> {
    fs::create_dir_all(cache)?;
    let path = cache.join("workspace.lock");
    ensure!(
        !cache.symlink_metadata()?.file_type().is_symlink(),
        "缓存目录不能是符号链接"
    );
    if path.exists() {
        ensure!(
            !path.symlink_metadata()?.file_type().is_symlink(),
            "项目锁不能是符号链接"
        );
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    use anyhow::Context;
    file.try_lock().context("项目清单正被另一个会话更新")?;
    Ok(file)
}
pub fn inspect_symbols(path: &Path, job: &Job) -> Result<String> {
    let entries = crate::symbols::inspect(path, job)?;
    let mut details = Vec::new();
    for isf in entries {
        let architecture = isf.data["metadata"]["zero"]["architecture"]
            .as_str()
            .unwrap_or("未附配置；以完整 banner 匹配为准");
        details.push(format!(
            "来源: {}\nSHA256: {}\n架构: {}\n完整 banner: {}\nVA_BITS: {}\n页大小配置: {}",
            isf.label,
            isf.digest,
            architecture,
            String::from_utf8_lossy(&isf.banner).trim_end_matches('\0'),
            isf.data["metadata"]["zero"]["va_bits"],
            isf.data["metadata"]["zero"]["page_shift"]
        ));
    }
    let side = path.with_extension("source.json");
    if side.metadata().is_ok_and(|m| m.len() <= 1024 * 1024)
        && let Ok(bytes) = fs::read(side)
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
    {
        for key in ["url", "source_url", "package_sha256"] {
            if let Some(value) = value[key].as_str() {
                details.push(format!("{key}: {value}"));
            }
        }
    }
    Ok(details.join("\n\n"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_named_images_have_distinct_path_identifiers() -> Result<()> {
        let dir = tempfile::tempdir()?;
        for sub in ["one", "two"] {
            fs::create_dir(dir.path().join(sub))?;
            fs::write(dir.path().join(sub).join("same.raw"), sub)?;
        }
        let registry = Registry::default();
        let assets = registry.discover_with_dirs(
            dir.path(),
            &dir.path().join("cache"),
            dir.path(),
            &dir.path().join("symbols"),
        )?;
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].name(), assets[1].name());
        assert_ne!(assets[0].id(), assets[1].id());
        assert_ne!(
            crate::symbols::cache_filename("Debian/amd64/one/same.json.xz")?,
            crate::symbols::cache_filename("Debian/amd64/two/same.json.xz")?
        );
        Ok(())
    }
    #[test]
    fn independent_registries_merge_selections_and_lock_busy_writers() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join("cache");
        let image = dir.path().join("one.raw");
        let symbols = dir.path().join("one.json.xz");
        fs::write(&image, b"image")?;
        fs::write(&symbols, b"symbols")?;
        let image = image.canonicalize()?;
        let symbols = symbols.canonicalize()?;
        let mut one = Registry::default();
        let mut two = Registry::default();
        one.import(&image, Kind::Image, &cache)?;
        two.import(&symbols, Kind::Symbols, &cache)?;
        let loaded = Registry::load(&cache)?;
        assert_eq!(loaded.selected(Kind::Image), Some(image.as_path()));
        assert_eq!(loaded.selected(Kind::Symbols), Some(symbols.as_path()));
        let guard = registry_lock(&cache)?;
        assert!(one.remove(&image, &cache).is_err());
        drop(guard);
        one.remove(&image, &cache)?;
        assert_eq!(
            Registry::load(&cache)?.selected(Kind::Symbols),
            Some(symbols.as_path())
        );
        assert!(image.exists());
        assert!(Registry::load(&cache)?.excluded(&image));
        fs::write(cache.join("workspace.json"), b"corrupt")?;
        assert!(two.import(&symbols, Kind::Symbols, &cache).is_err());
        assert_eq!(fs::read(cache.join("workspace.json"))?, b"corrupt");
        Ok(())
    }
    #[test]
    fn project_scan_import_hidden_missing_and_source_preservation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join(".zero/rust");
        let mut registry = Registry::default();
        fs::create_dir(dir.path().join("images"))?;
        fs::write(dir.path().join("images/test.raw"), b"image")?;
        fs::write(dir.path().join("images/linux.zip"), b"symbol")?;
        fs::write(
            dir.path().join("unrelated.raw"),
            b"outside managed directories",
        )?;
        fs::create_dir(dir.path().join("symbols"))?;
        fs::write(dir.path().join("symbols/a.source.json"), b"sidecar")?;
        assert_eq!(registry.discover(dir.path(), &cache)?.len(), 2);
        let external = tempfile::tempdir()?;
        let path = external.path().join("capture");
        fs::write(&path, b"original")?;
        registry.import(&path, Kind::Image, &cache)?;
        registry.import(&path, Kind::Image, &cache)?;
        assert_eq!(registry.discover(dir.path(), &cache)?.len(), 3);
        registry.remove(&dir.path().join("images/test.raw"), &cache)?;
        assert!(dir.path().join("images/test.raw").exists());
        let registry = Registry::load(&cache)?;
        assert_eq!(registry.discover(dir.path(), &cache)?.len(), 2);
        fs::remove_file(path)?;
        assert!(
            registry
                .discover(dir.path(), &cache)?
                .iter()
                .any(|a| !a.available)
        );
        Ok(())
    }
}
