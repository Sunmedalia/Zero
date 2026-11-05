//! Asset inventory refresh and the list, text and detail views built from it.
use super::*;
use crate::bytes::JsonKey as _;
use crate::bytes::Row as _;

impl App {
    pub(super) fn refresh_assets(&mut self) {
        // The asset list is the only thing that can change a path's resolved
        // form, so the display cache is rebuilt with it.
        self.path_cache.borrow_mut().clear();
        self.canonical_cache.borrow_mut().clear();
        self.root_cached = std::cell::OnceCell::new();
        match Registry::load(&self.cache) {
            Ok(registry) => self.registry = registry,
            Err(e) => {
                self.status = format!("项目清单读取失败: {e:#}");
                self.last_error = Some(self.status.clone());
                return;
            }
        }
        match self.registry.discover_with_dirs(
            &self.root,
            &self.cache,
            &self.directory(&self.settings.image_dir),
            &self.directory(&self.settings.symbols),
        ) {
            Ok(assets) => {
                let previous = std::mem::replace(&mut self.assets, assets);
                *self.asset_index_cache.borrow_mut() = Default::default();
                self.asset_details.retain(|p, _| {
                    self.assets.iter().any(|a| {
                        &a.path == p
                            && !a.directory
                            && previous
                                .iter()
                                .any(|old| old.path == a.path && old.stamp == a.stamp)
                    })
                });
                let mut cached_sources = Vec::new();
                // Prefer the managed library over an identical regenerable download copy.
                for asset in self
                    .assets
                    .iter()
                    .filter(|a| a.origin == "下载／生成")
                    .chain(self.assets.iter().filter(|a| a.origin != "下载／生成"))
                {
                    let side = asset.path.with_extension("source.json");
                    if asset.kind == Kind::Symbols
                        && side.metadata().is_ok_and(|m| m.len() <= 1024 * 1024)
                        && let Ok(bytes) = std::fs::read(side)
                        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                        && let Some(url) = value.key("url").as_str()
                    {
                        self.downloads.insert(url.into(), asset.path.clone());
                        if asset.origin == "下载／生成" {
                            cached_sources.push((asset.path.clone(), url.to_owned()));
                        }
                    }
                }
                self.hidden_cache_copies = cached_sources
                    .into_iter()
                    .filter(|(path, url)| {
                        self.downloads
                            .get(url)
                            .is_some_and(|local| local != path && local.is_file())
                    })
                    .map(|(path, _)| path)
                    .collect();
            }
            Err(e) => {
                self.status = format!("资产清单读取失败: {e:#}");
                self.last_error = Some(self.status.clone());
            }
        }
        (self.asset_identities, self.asset_digests) = recorded_manifests(&self.assets, &self.cache);
        if self
            .local_match_stamp
            .as_ref()
            .is_some_and(|stamp| *stamp != self.local_stamp())
        {
            self.local_match_stamp = None;
            self.local_matches.clear();
            self.local_only_matches = false;
        }
        for section in [
            AssetSection::Images,
            AssetSection::Symbols,
            AssetSection::Remote,
        ] {
            let count = if section == AssetSection::Remote {
                self.remote_list().len()
            } else {
                self.asset_list_for(section).len()
            };
            self.asset_rows[section.slot()] =
                self.asset_rows[section.slot()].min(count.saturating_sub(1));
        }
    }

    /// Shorten a path relative to the project root.
    ///
    /// This runs for every visible asset row on every frame, and each
    /// `canonicalize` is a pair of system calls, so resolved paths are cached
    /// by input. The cache is dropped whenever the asset list is rebuilt, which
    /// is the only time a path's resolved form can change.
    pub(super) fn display_path(&self, path: &std::path::Path) -> String {
        if let Some(hit) = self.path_cache.borrow().get(path) {
            return hit.clone();
        }
        let root = self
            .root_cached
            .get_or_init(|| {
                self.root
                    .canonicalize()
                    .unwrap_or_else(|_| self.root.clone())
            })
            .clone();
        let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let shown = resolved
            .strip_prefix(&root)
            .unwrap_or(&resolved)
            .display()
            .to_string();
        self.path_cache
            .borrow_mut()
            .insert(path.to_path_buf(), shown.clone());
        shown
    }
    /// `same_path` with canonical forms memoized until the asset list is
    /// rebuilt; drawing compares every row against the active inputs.
    pub(super) fn same_asset_path(&self, a: &std::path::Path, b: &std::path::Path) -> bool {
        if a == b {
            return true;
        }
        let canonical = |path: &std::path::Path| {
            if let Some(hit) = self.canonical_cache.borrow().get(path) {
                return hit.clone();
            }
            let resolved = path.canonicalize().ok();
            self.canonical_cache
                .borrow_mut()
                .insert(path.to_path_buf(), resolved.clone());
            resolved
        };
        canonical(a).zip(canonical(b)).is_some_and(|(a, b)| a == b)
    }
    pub(super) fn asset_list(&self) -> Vec<&Asset> {
        self.asset_list_for(self.section)
    }
    /// Assets shown in `section`, filtered by kind, search query and the
    /// matched-only toggle.
    ///
    /// This is called several times per frame, and with a few hundred assets
    /// the path lowercasing alone is measurable, so the index is cached until
    /// one of the filter inputs changes.
    pub(super) fn asset_list_for(&self, section: AssetSection) -> Vec<&Asset> {
        let kind = if section == AssetSection::Images {
            Kind::Image
        } else {
            Kind::Symbols
        };
        let key = AssetIndexKey {
            identity: self.assets.as_ptr() as usize,
            len: self.assets.len(),
            query: self.asset_queries[section.slot()].to_lowercase(),
            local_only: section == AssetSection::Symbols && self.local_only_matches,
            hidden: self.hidden_cache_copies.len(),
            matches: self.local_matches.len(),
        };
        let slot = section.slot();
        let cached = {
            let mut cache = self.asset_index_cache.borrow_mut();
            match cache[slot].as_ref() {
                Some((previous, indices)) if *previous == key => Some(indices.clone()),
                _ => {
                    let indices = self
                        .assets
                        .iter()
                        .enumerate()
                        .filter(|(_, a)| {
                            a.kind == kind
                                && !self.hidden_cache_copies.contains(&a.path)
                                && (!key.local_only || self.local_matches.contains_key(&a.path))
                                && a.path.to_string_lossy().to_lowercase().contains(&key.query)
                        })
                        .map(|(i, _)| i)
                        .collect::<Vec<_>>();
                    cache[slot] = Some((key, indices.clone()));
                    Some(indices)
                }
            }
        };
        cached
            .unwrap_or_default()
            .into_iter()
            .filter_map(|i| self.assets.get(i))
            .collect()
    }
    pub(super) fn remote_cached(&self, candidate: &RemoteMatch) -> bool {
        self.downloads
            .get(&candidate.url)
            .is_some_and(|p| p.is_file())
            || symbols::cache_filename(&candidate.path)
                .is_ok_and(|name| self.cache.join("symbols/isf").join(name).is_file())
    }
    /// Remote index entries matching the search box.
    ///
    /// The filter lowercases the banner, path and URL of every entry, and the
    /// index can hold thousands of rows while this runs several times per
    /// frame, so the result is cached until the list or the query changes.
    pub(super) fn remote_list(&self) -> Vec<&RemoteMatch> {
        let remote = if self.remote_catalog {
            &self.remote
        } else {
            self.remote_matches.as_ref().unwrap_or(&self.remote)
        };
        let key = RemoteIndexKey {
            identity: remote.as_ptr() as usize,
            len: remote.len(),
            query: self.asset_queries[2].to_lowercase(),
        };
        let cached = {
            let mut cache = self.remote_index_cache.borrow_mut();
            match cache.as_ref() {
                Some((previous, indices)) if *previous == key => indices.clone(),
                _ => {
                    let indices = remote
                        .iter()
                        .enumerate()
                        .filter(|(_, m)| {
                            let text = format!("{} {} {}", m.path, m.banner, m.url).to_lowercase();
                            key.query.split_whitespace().all(|word| text.contains(word))
                        })
                        .map(|(i, _)| i)
                        .collect::<Vec<_>>();
                    *cache = Some((key, indices.clone()));
                    indices
                }
            }
        };
        cached.into_iter().filter_map(|i| remote.get(i)).collect()
    }
    pub(super) fn asset_count(&self) -> usize {
        if self.section == AssetSection::Remote {
            self.remote_list().len()
        } else {
            self.asset_list().len()
        }
    }
    pub(super) fn selected_asset(&self) -> Option<Asset> {
        self.asset_list()
            .get(self.asset_rows[self.section.slot()])
            .map(|a| (*a).clone())
    }
    pub(super) fn asset_text(&self) -> String {
        if self.section == AssetSection::Remote {
            return self.remote_list().get(self.asset_rows[2]).map(|m|format!("远程符号索引\n\n完整 banner: {}\n\n仓库路径: {}\n\n下载链接: {}\n\n下载前校验索引路径和 ISF。手动获取的符号会加入本地库，选用后再验证镜像。",escaped(&m.banner),escaped(&m.path),escaped(&m.url)))
                .unwrap_or_else(||"g 获取或刷新完整符号索引。\n/ 输入关键词筛选；选中条目后按 d 查看详情，Enter 进入分析控制台，w 下载。\nM 按当前镜像 banner 精确匹配。".into());
        }
        let Some(asset) = self.selected_asset() else {
            return "按 a 导入路径，或将文件放入配置的 images／symbols 目录。\n\nSpace 选用；Enter 进入分析控制台；d 详情；Delete 移出清单，原文件保留。".into();
        };
        self.local_asset_text(&asset)
    }
    pub(super) fn local_asset_text(&self, asset: &Asset) -> String {
        let mut text = format!(
            "{}\n\n路径: {}\n格式: {}\n大小: {:.2} MiB\n来源: {}\n状态: {}\n\nSpace 选用 · Enter 进入分析控制台 · d 详情 · Delete 移出清单（保留文件）",
            escaped(&asset.name()),
            escaped(&asset.path.display().to_string()),
            asset.format(),
            asset.bytes as f64 / 1048576.0,
            asset.origin,
            if asset.available {
                "可用"
            } else {
                "文件缺失；重新导入路径"
            }
        );
        if asset.kind == Kind::Image && !self.asset_identities.contains_key(&asset.path) {
            text.push_str(
                "

尚未识别：点击镜像可后台读取内核信息，识别结果与此镜像绑定。",
            );
        }
        if let Some(digest) = self.asset_digests.get(&asset.path) {
            text.push_str(&format!(
                "

上次校验 SHA256: {digest}"
            ));
        }
        if let Some(identity) = self.asset_identities.get(&asset.path) {
            text.push_str(&format!(
                "

已识别 {}:
{}",
                identity.system,
                identity
                    .kernels
                    .iter()
                    .map(|kernel| escaped(kernel))
                    .collect::<Vec<_>>()
                    .join(
                        "
"
                    )
            ));
        }
        if asset.kind == Kind::Symbols {
            if let Some(labels) = self.local_matches.get(&asset.path) {
                text.push_str(&format!(
                    "\n\n完整 banner 匹配: {} 个 ISF\n{}\nSpace 选用；x 开始分析并验证页表。",
                    labels.len(),
                    labels
                        .iter()
                        .map(|s| escaped(s))
                        .collect::<Vec<_>>()
                        .join("\n")
                ));
            }
            let errors: Vec<_> = self
                .local_match_errors
                .iter()
                .filter(|error| error.starts_with(&asset.path.display().to_string()))
                .map(|error| escaped(error))
                .collect();
            if !errors.is_empty() {
                text.push_str(&format!(
                    "\n\n匹配诊断（其余成员继续读取）:\n{}",
                    errors.join("\n")
                ));
            }
            if let Some(detail) = self.asset_details.get(&asset.path) {
                text.push_str("\n\n");
                text.push_str(&detail.lines().map(escaped).collect::<Vec<_>>().join("\n"));
            } else {
                text.push_str("\n\nd 查看符号详情：读取完整 banner、符号摘要和架构配置。");
            }
        } else if self
            .image
            .as_ref()
            .is_some_and(|p| self.same_asset_path(p, &asset.path))
        {
            if let Some(result) = self.results.get("banners") {
                text.push_str(&format!(
                    "\n\n共 {} 个原始候选；优先展示完整格式，banners 插件保留全部命中。",
                    result.rows.len()
                ));
                for row in banner_candidates(result) {
                    text.push_str(&format!(
                        "\n\n候选 @ {}: {}",
                        row.cell(0),
                        escaped(row.cell(1))
                    ));
                }
            } else {
                text.push_str("\n\nb 识别内核候选；M 获取远程符号匹配。");
            }
        }
        text
    }
    pub(super) fn asset_detail_body(&self, asset: &Asset, read_only: bool) -> String {
        let text = self.local_asset_text(asset);
        if read_only {
            text.lines()
                .filter(|line| {
                    !line.starts_with("Space 选用")
                        && !line.starts_with("d 查看符号详情：")
                        && !line.starts_with("b 识别内核候选；")
                })
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            text
        }
    }
    pub(super) fn asset_active(&self, asset: &Asset) -> bool {
        if asset.kind == Kind::Image {
            self.image
                .as_ref()
                .is_some_and(|p| self.same_asset_path(p, &asset.path))
        } else {
            self.same_asset_path(&self.symbols, &asset.path)
        }
    }
}

/// Bound identities and recorded digests of every image, reading each image's
/// manifest once.
pub(super) fn recorded_manifests(
    assets: &[Asset],
    cache: &std::path::Path,
) -> (
    HashMap<PathBuf, crate::image::BoundIdentity>,
    HashMap<PathBuf, String>,
) {
    let mut identities = HashMap::new();
    let mut digests = HashMap::new();
    for asset in assets.iter().filter(|a| a.kind == Kind::Image) {
        let (identity, digest) = crate::image::recorded_summary(&asset.path, cache);
        if let Some(identity) = identity {
            identities.insert(asset.path.clone(), identity);
        }
        if let Some(digest) = digest {
            digests.insert(asset.path.clone(), digest);
        }
    }
    (identities, digests)
}
