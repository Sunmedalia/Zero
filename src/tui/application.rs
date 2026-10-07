use super::*;

impl App {
    pub(super) fn select_os(&mut self, os: crate::analysis::Os) {
        if self.job.is_some() {
            self.cancel();
            self.pending_work = None;
            self.pending_os = Some(os);
            self.status = "正在取消任务并切换分析系统…".into();
            return;
        }
        self.parameter_drafts.clear();
        self.prepared_stamp = None;
        self.analysis_options.os = os;
        let banner = self.results.get("banners").cloned();
        self.windows = match os {
            crate::analysis::Os::Windows => true,
            crate::analysis::Os::Linux => false,
            crate::analysis::Os::Auto => self.windows,
        };
        if let Some(result) = &banner {
            self.apply_identification(result);
        }
        self.plugin = if self.windows {
            Plugin::WinPslist
        } else {
            Plugin::Pslist
        };
        self.menu = self
            .navigation_plugins()
            .iter()
            .position(|p| *p == self.plugin)
            .unwrap_or(0);
        self.analysis_options.pid = None;
        self.analysis_options.hive = None;
        self.analysis_options.key.clear();
        if !self.windows {
            self.analysis_options.arch = Default::default();
            self.analysis_options.pagefiles.clear();
            self.analysis_options.swapfile = None;
        }
        self.results.clear();
        if let Some(banner) = banner {
            self.results.insert("banners".into(), banner);
        }
        self.local_matches.clear();
        self.local_match_stamp = None;
        self.local_match_errors.clear();
        self.local_only_matches = false;
        self.views.clear();
        self.history = None;
        self.query.clear();
        self.sort = None;
        self.row = 0;
        self.horizontal = 0;
        self.detail_scroll = 0;
        self.collapsed.clear();
        self.choice = None;
        self.dump_options = None;
        self.last_error = None;
        self.object_version += 1;
        self.page = Page::Assets;
        self.focus = Focus::Navigation;
        self.status = format!(
            "已选择 {} · i 镜像 / y 符号 / p 插件",
            match os {
                crate::analysis::Os::Auto => "自动识别系统",
                crate::analysis::Os::Linux => "Linux",
                crate::analysis::Os::Windows => "Windows",
            }
        );
        if self.image.is_some() {
            self.prepare_selected_image();
        }
    }
    pub(super) fn navigation_plugins(&self) -> Vec<Plugin> {
        if !self.windows {
            return navigation_plugins();
        }
        [
            "Process",
            "System",
            "Memory",
            "Files",
            "Network",
            "Integrity",
        ]
        .into_iter()
        .flat_map(|category| {
            PLUGINS
                .iter()
                .filter(move |d| {
                    d.plugin.is_windows() && !d.plugin.is_dump() && d.plugin.category() == category
                })
                .map(|d| d.plugin)
        })
        .collect()
    }
    pub(super) fn menu_items(&self) -> Vec<String> {
        if !self.windows {
            return menu_items();
        }
        let mut items = Vec::new();
        items.extend(
            self.navigation_plugins()
                .iter()
                .map(|p| plugin_label(*p).to_string()),
        );
        items.push("dump".into());
        items
    }
    pub(super) fn plugin_matches(&self, query: &str) -> Vec<Plugin> {
        if !self.windows {
            return plugin_matches(query);
        }
        let query = query.to_lowercase();
        let mut items = self
            .navigation_plugins()
            .into_iter()
            .filter(|p| plugin_search_hit(*p, &query))
            .collect::<Vec<_>>();
        if "dump".contains(&query) {
            items.push(Plugin::WinProcdump);
        }
        items
    }
    pub(super) fn apply_identification(&mut self, result: &Results) {
        let detected_windows = result.system == "windows"
            || result
                .rows
                .iter()
                .any(|r| r.get(1).is_some_and(|s| s.starts_with("Windows PDB ")));
        let detected_linux = result
            .rows
            .iter()
            .any(|r| r.get(1).is_some_and(|s| s.starts_with("Linux version ")))
            || (result.system == "linux" && !result.rows.is_empty());
        if self.analysis_options.os == crate::analysis::Os::Auto
            && !detected_windows
            && !detected_linux
        {
            return;
        }
        let windows = match self.analysis_options.os {
            crate::analysis::Os::Windows => true,
            crate::analysis::Os::Linux => false,
            crate::analysis::Os::Auto => detected_windows,
        };
        if self.windows != windows {
            self.windows = windows;
            self.plugin = if windows {
                Plugin::WinPslist
            } else {
                Plugin::Pslist
            };
            self.menu = self
                .navigation_plugins()
                .iter()
                .position(|p| *p == self.plugin)
                .unwrap_or(0);
            self.analysis_options.pid = None;
            self.analysis_options.hive = None;
            self.analysis_options.key.clear();
            if !windows {
                self.analysis_options.arch = Default::default();
                self.analysis_options.pagefiles.clear();
                self.analysis_options.swapfile = None;
            }
            self.query.clear();
            self.sort = None;
            self.row = 0;
            self.horizontal = 0;
            self.collapsed.clear();
            self.history = None;
        }
    }
    pub(super) fn identification_status(&self, result: &Results) -> &'static str {
        if self.analysis_options.os != crate::analysis::Os::Auto {
            return "保留手动系统选择";
        }
        if result.system == "windows"
            || result
                .rows
                .iter()
                .any(|r| r.get(1).is_some_and(|s| s.starts_with("Windows PDB ")))
        {
            "自动识别 Windows · 已切换插件列表"
        } else if result.system == "linux" && !result.rows.is_empty() {
            "自动识别 Linux · 已切换插件列表"
        } else {
            "未识别系统 · 可手动选择 Linux / Windows"
        }
    }
    pub fn new(
        image: Option<PathBuf>,
        symbols: PathBuf,
        cache: PathBuf,
        settings: Settings,
    ) -> Self {
        for directory in [&settings.image_dir, &settings.export_dir, &settings.symbols] {
            let path = store::expand_home(directory);
            if !path.exists() && path.extension().is_none() {
                let _ = std::fs::create_dir_all(path);
            }
        }
        let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let (mut registry, mut error) = match Registry::load(&cache) {
            Ok(r) => (r, None),
            Err(e) => (
                Registry::default(),
                Some(format!("项目清单读取失败: {e:#}")),
            ),
        };
        if error.is_none() {
            for (path, kind) in image
                .iter()
                .map(|p| (p, Kind::Image))
                .chain(std::iter::once((&symbols, Kind::Symbols)))
            {
                if path.exists()
                    && let Err(e) = registry.import(path, kind, &cache)
                {
                    error = Some(format!("资产登记失败: {e:#}"));
                }
            }
        }
        let (assets, error) = match registry.discover_with_dirs(
            &root,
            &cache,
            &store::expand_home(&settings.image_dir),
            &store::expand_home(&settings.symbols),
        ) {
            Ok(a) => (a, error),
            Err(e) => (vec![], Some(format!("资产发现失败: {e:#}"))),
        };
        let asset_rows = [Kind::Image, Kind::Symbols].map(|kind| {
            assets
                .iter()
                .filter(|a| a.kind == kind)
                .position(|a| {
                    if kind == Kind::Image {
                        image.as_ref().is_some_and(|p| same_path(p, &a.path))
                    } else {
                        same_path(&symbols, &a.path)
                    }
                })
                .unwrap_or(0)
        });
        Self {
            page: Page::Assets,
            section: AssetSection::Images,
            symbol_source: AssetSection::Symbols,
            root,
            registry,
            assets,
            asset_rows: [asset_rows[0], asset_rows[1], 0],
            asset_scroll: [0; 3],
            asset_queries: Default::default(),
            asset_states: RefCell::new(Default::default()),
            asset_details: HashMap::new(),
            remote: vec![],
            remote_catalog: true,
            download_url: None,
            downloads: HashMap::new(),
            hidden_cache_copies: HashSet::new(),
            local_matches: HashMap::new(),
            local_match_stamp: None,
            prepared_stamp: None,
            local_match_errors: Vec::new(),
            local_only_matches: false,
            image,
            symbols,
            cache,
            settings,
            hits: RefCell::new(HitMap::default()),
            table_state: RefCell::new(TableState::default()),
            focus: Focus::Navigation,
            menu: 0,
            plugin: Plugin::Pslist,
            windows: false,
            analysis_options: Default::default(),
            results: HashMap::new(),
            history: None,
            query: String::new(),
            sort: None,
            descending: false,
            row: 0,
            collapsed: HashSet::new(),
            status: "资源库：Space 选用镜像 · Enter 选用并进入分析 · i 导入 · ? 命令面板".into(),
            logs: VecDeque::new(),
            started: None,
            progress: None,
            dialog: None,
            choice: None,
            dump_options: None,
            receiver: None,
            job: None,
            worker: None,
            session: Arc::new(Mutex::new(linux::Session::default())),
            last_error: error,
            back_dialog: None,
            pending_work: None,
            pending_path: None,
            pending_execution: None,
            preparation: Preparation::ChooseImage,
            preparation_candidates: vec![],
            task_id: 0,
            object_version: 0,
            active_request: None,
            symbol_retry: None,
            preparation_lookup: false,
            parameter_drafts: HashMap::new(),
            result_requests: HashMap::new(),
            pending_os: None,
            horizontal: 0,
            inspector: false,
            detail_scroll: 0,
            views: HashMap::new(),
            enter_when_ready: false,
            quit_armed: false,
        }
    }
    pub(super) fn switch_page(&mut self, page: Page) {
        let changed = self.page != page;
        self.page = page;
        // Replace the previous page's hint, but never hide a running task or an error.
        if changed && self.job.is_none() && self.last_error.as_deref() != Some(&self.status) {
            self.status = match page {
                Page::Analysis if self.image.is_none() => {
                    "分析：尚未选用镜像；F2 资源库选用".into()
                }
                Page::Analysis => "分析：点击或 Enter 运行插件 · / 筛选 · ? 命令面板".into(),
                Page::Assets => "资源库：Space 选用 · Enter 选用并进入分析 · ? 命令面板".into(),
            };
        }

        self.focus = Focus::Navigation;
        if page != Page::Analysis {
            self.refresh_assets();
        }
    }
    pub(super) fn switch_section(&mut self, section: AssetSection) {
        self.page = Page::Assets;
        self.section = section;
        if section != AssetSection::Images {
            self.symbol_source = section;
        }
        self.focus = Focus::Navigation;
        self.refresh_assets();
    }
    pub(super) fn available_commands(&self, query: &str) -> Vec<(&'static str, KeyCode)> {
        if self.page == Page::Analysis
            && self.windows
            && (query.is_empty()
                || "Windows 参数"
                    .to_lowercase()
                    .contains(&query.to_lowercase()))
        {
            let mut commands = command_matches(query, self.page, self.focus)
                .into_iter()
                .map(|i| COMMANDS[i])
                .collect::<Vec<_>>();
            commands.push(("Windows 参数 [P]", KeyCode::Char('P')));
            return commands;
        }
        if self.page == Page::Analysis {
            command_matches(query, self.page, self.focus)
                .into_iter()
                .map(|i| COMMANDS[i])
                .collect()
        } else {
            let mut commands = asset_actions(self.section);
            commands.extend([
                ("打开分析页 F3", KeyCode::F(3)),
                ("打开资源库 F2", KeyCode::F(2)),
                ("选择分析系统 F6", KeyCode::F(6)),
                ("目录设置 ,", KeyCode::Char(',')),
                ("缓存管理 c", KeyCode::Char('c')),
                ("任务日志 l", KeyCode::Char('l')),
                ("帮助 F1", KeyCode::F(1)),
                ("取消任务 Esc", KeyCode::Esc),
            ]);
            commands
                .into_iter()
                .filter(|(label, _)| query_matches(label, query))
                .collect()
        }
    }
    pub(super) fn asset_disabled(
        &self,
        section: AssetSection,
        key: KeyCode,
    ) -> Option<&'static str> {
        let busy = self.job.is_some();
        if key == KeyCode::Char('K') && self.windows {
            return Some("Windows 请使用 M 获取精确 PDB 符号");
        }
        // Enter on a highlighted image selects it first, so it only needs an image row.
        let enter_selects = key == KeyCode::Enter
            && section == AssetSection::Images
            && !self.asset_list_for(section).is_empty();
        if (matches!(key, KeyCode::Char('m' | 'M' | 'b' | 'x' | 'K'))
            || (key == KeyCode::Enter && !enter_selects))
            && self.image.is_none()
        {
            return Some("请先选用镜像");
        }
        if key == KeyCode::Char('a') && section == AssetSection::Remote {
            return Some("远程符号请使用下载");
        }
        if key == KeyCode::Char('w')
            && (section != AssetSection::Remote
                || self.remote_list().get(self.asset_rows[2]).is_none())
        {
            return Some("请先选择远程符号");
        }
        if matches!(key, KeyCode::Delete | KeyCode::Char('d' | ' ')) {
            let empty = if section == AssetSection::Remote {
                self.remote_list().is_empty()
            } else {
                self.asset_list_for(section).is_empty()
            };
            if empty {
                return Some("列表为空，请导入或搜索");
            }
        }
        if busy
            && matches!(
                key,
                KeyCode::Char('a' | 'i' | 'y' | 'm' | 'M' | 'b' | 'K' | 'w' | 'g' | 'r' | 'o')
                    | KeyCode::Delete
            )
        {
            return Some("任务执行中，请等待或取消");
        }

        None
    }
    pub(super) fn remote_detail_text(&self, candidate: &RemoteMatch) -> String {
        let path = self.downloads.get(&candidate.url).filter(|p| p.is_file());
        let state = if self.download_url.as_ref() == Some(&candidate.url) && self.job.is_some() {
            "正在下载"
        } else if path.is_some() {
            "已保存到本地库"
        } else if self.remote_cached(candidate) {
            "缓存可用，点击下载保存到本地库"
        } else {
            "尚未下载"
        };
        format!(
            "完整 banner: {}\n\n仓库路径: {}\n\n下载链接: {}\n\n状态: {state}\n保存位置: {}\n\n{}\n{}",
            escaped(&candidate.banner),
            escaped(&candidate.path),
            escaped(&candidate.url),
            path.map(|p| escaped(&p.display().to_string()))
                .unwrap_or_else(|| self.settings.symbols.clone()),
            escaped(&self.status),
            self.last_error.as_deref().map(escaped).unwrap_or_default()
        )
    }
    pub(super) fn refresh_assets(&mut self) {
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
            &store::expand_home(&self.settings.image_dir),
            &store::expand_home(&self.settings.symbols),
        ) {
            Ok(assets) => {
                let previous = std::mem::replace(&mut self.assets, assets);
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
                        && let Some(url) = value["url"].as_str()
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
    pub(super) fn invalidate_source(&mut self) {
        self.object_version += 1;
        self.prepared_stamp = None;
        self.symbol_retry = None;
        self.preparation = Preparation::ChooseImage;
        self.preparation_candidates.clear();
        self.result_requests.clear();
        self.parameter_drafts.clear();
        self.local_matches.clear();
        self.local_match_stamp = None;
        self.local_match_errors.clear();
        self.local_only_matches = false;
        self.dump_options = None;
        self.analysis_options = crate::analysis::Options {
            os: self.analysis_options.os,
            arch: self.analysis_options.arch,
            ..Default::default()
        };
        self.results.clear();
        self.views.clear();
        self.history = None;
        self.choice = None;
        self.query.clear();
        self.sort = None;
        self.row = 0;
        self.horizontal = 0;
        self.collapsed.clear();
        self.remote.clear();
        self.asset_rows[2] = 0;
        self.asset_queries[2].clear();
    }
    pub(super) fn invalidate_symbols(&mut self) {
        let banner = self.results.get("banners").cloned();
        let matched = std::mem::take(&mut self.local_matches);
        let stamp = self.local_match_stamp.take();
        let errors = std::mem::take(&mut self.local_match_errors);
        let only = self.local_only_matches;
        self.invalidate_source();
        if let Some(banner) = banner {
            self.results.insert("banners".into(), banner);
        }
        self.local_matches = matched;
        self.local_match_stamp = stamp;
        self.local_match_errors = errors;
        self.local_only_matches = only;
    }
    pub(super) fn local_stamp(&self) -> String {
        let image = self
            .image
            .as_ref()
            .map(|p| {
                format!(
                    "{}:{:?}",
                    p.display(),
                    std::fs::metadata(p)
                        .ok()
                        .and_then(|m| crate::image::metadata_stamp(&m).ok())
                )
            })
            .unwrap_or_default();
        format!(
            "{image}:{:?}",
            self.assets
                .iter()
                .filter(|a| a.kind == Kind::Symbols
                    && !a.directory
                    && !self.hidden_cache_copies.contains(&a.path))
                .map(|a| (&a.path, &a.stamp))
                .collect::<Vec<_>>()
        )
    }
    pub(super) fn symbol_target(&mut self, remote: bool) {
        if self.job.is_some() {
            self.status = "等待当前任务完成；Esc 可取消后匹配符号".into();
            return;
        }
        self.switch_section(if remote {
            AssetSection::Remote
        } else {
            AssetSection::Symbols
        });
        if remote {
            self.remote_catalog = false;
            self.asset_queries[2].clear();
            self.start_work(Work::FetchMatched);
        } else {
            self.asset_queries[1].clear();
            self.asset_rows[1] = 0;
            let stamp = self.local_stamp();
            if self.image.is_some() && self.local_match_stamp.as_ref() == Some(&stamp) {
                self.local_only_matches = true;
                self.status = format!(
                    "复用本地完整 banner 匹配：{} 个文件；t 远程，x 开始分析",
                    self.local_matches.len()
                );
            } else {
                self.local_only_matches = false;
                let paths = self
                    .assets
                    .iter()
                    .filter(|a| {
                        a.kind == Kind::Symbols
                            && a.available
                            && !a.directory
                            && !self.hidden_cache_copies.contains(&a.path)
                    })
                    .map(|a| a.path.clone())
                    .collect();
                self.start_work(Work::MatchLocal(paths, stamp));
            }
        }
    }
    pub(super) fn focus_asset(&mut self, kind: Kind, path: &std::path::Path) {
        let slot = usize::from(kind == Kind::Symbols);
        self.asset_queries[slot].clear();
        self.asset_rows[slot] = self
            .assets
            .iter()
            .filter(|a| {
                a.kind == kind
                    && !self.hidden_cache_copies.contains(&a.path)
                    && (kind != Kind::Symbols
                        || !self.local_only_matches
                        || self.local_matches.contains_key(&a.path))
            })
            .position(|a| same_path(&a.path, path))
            .unwrap_or(0);
        self.asset_scroll[slot] = 0;
        self.asset_states.borrow_mut()[slot] = ListState::default();
    }
    pub(super) fn page_rows(&self) -> usize {
        let height = self.hits.borrow().result.height;
        let available = height.saturating_sub(3).max(1) as usize;
        if self.settings.page_size == 0 {
            available
        } else if height == 0 {
            self.settings.page_size
        } else {
            self.settings.page_size.min(available)
        }
    }
    pub(super) fn display_path(&self, path: &std::path::Path) -> String {
        let root = self.root.canonicalize().unwrap_or(self.root.clone());
        let path = path.canonicalize().unwrap_or(path.to_path_buf());
        path.strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
    }
    pub(super) fn asset_list(&self) -> Vec<&Asset> {
        self.asset_list_for(self.section)
    }
    pub(super) fn asset_list_for(&self, section: AssetSection) -> Vec<&Asset> {
        let kind = if section == AssetSection::Images {
            Kind::Image
        } else {
            Kind::Symbols
        };
        let query = self.asset_queries[section.slot()].to_lowercase();
        self.assets
            .iter()
            .filter(|a| {
                a.kind == kind
                    && !self.hidden_cache_copies.contains(&a.path)
                    && (section != AssetSection::Symbols
                        || !self.local_only_matches
                        || self.local_matches.contains_key(&a.path))
                    && a.path.to_string_lossy().to_lowercase().contains(&query)
            })
            .collect()
    }
    pub(super) fn remote_cached(&self, candidate: &RemoteMatch) -> bool {
        self.downloads
            .get(&candidate.url)
            .is_some_and(|p| p.is_file())
            || symbols::cache_filename(&candidate.path)
                .is_ok_and(|name| self.cache.join("symbols/isf").join(name).is_file())
    }
    pub(super) fn remote_list(&self) -> Vec<&RemoteMatch> {
        let query = self.asset_queries[2].to_lowercase();
        self.remote
            .iter()
            .filter(|m| {
                let text = format!("{} {} {}", m.path, m.banner, m.url).to_lowercase();
                query.split_whitespace().all(|word| text.contains(word))
            })
            .collect()
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
            .is_some_and(|p| same_path(p, &asset.path))
        {
            if let Some(result) = self.results.get("banners") {
                text.push_str(&format!(
                    "\n\n共 {} 个原始候选；优先展示完整格式，banners 插件保留全部命中。",
                    result.rows.len()
                ));
                for row in banner_candidates(result) {
                    text.push_str(&format!("\n\n候选 @ {}: {}", row[0], escaped(&row[1])));
                }
            } else {
                text.push_str("\n\nb 识别内核候选；M 获取远程符号匹配。");
            }
        }
        text
    }
    pub(super) fn asset_active(&self, asset: &Asset) -> bool {
        if asset.kind == Kind::Image {
            self.image
                .as_ref()
                .is_some_and(|p| same_path(p, &asset.path))
        } else {
            same_path(&self.symbols, &asset.path)
        }
    }
    /// Enter in the image / local symbol lists: select the highlighted row if it is not
    /// already in use, then open the analysis page now or as soon as matching is ready.
    pub(super) fn select_and_enter(&mut self) {
        let pending = self.section != AssetSection::Remote
            && self
                .selected_asset()
                .is_some_and(|asset| !self.asset_active(&asset));
        if !pending {
            self.enter_workbench();
            return;
        }
        if !self.use_selected_asset() {
            return;
        }
        if self.section == AssetSection::Images {
            self.symbol_source = AssetSection::Symbols;
            self.prepare_selected_image();
        }
        if self.preparation == Preparation::Ready && self.job.is_none() && self.dialog.is_none() {
            self.enter_workbench();
        } else {
            self.enter_when_ready = true;
            self.status = "已选用；匹配完成后自动进入分析（Esc 取消）".into();
        }
    }
    /// Follow through on a pending Enter once preparation settles.
    pub(super) fn resolve_enter_intent(&mut self) -> bool {
        if !self.enter_when_ready || self.job.is_some() {
            return false;
        }
        match self.preparation {
            Preparation::Ready if self.dialog.is_none() => {
                self.enter_when_ready = false;
                self.enter_workbench()
            }
            // Still matching, or the user is picking among exact candidates.
            Preparation::Ready | Preparation::Matching | Preparation::ChooseSymbols => false,
            // Missing symbols / unknown system: stay put; the status explains the next step.
            _ => {
                self.enter_when_ready = false;
                false
            }
        }
    }
    pub(super) fn request_quit(&mut self) -> bool {
        if self.job.is_none() || self.quit_armed {
            return true;
        }
        self.quit_armed = true;
        self.status = "任务执行中；再按 q 退出，Esc 取消任务".into();
        false
    }
    pub(super) fn use_selected_asset(&mut self) -> bool {
        let Some(asset) = self.selected_asset() else {
            self.status = "没有选中的资产；按 a 导入路径".into();
            return false;
        };
        if self.job.is_some() {
            self.cancel();
            self.pending_path = Some((
                if asset.kind == Kind::Image {
                    InputKind::Image
                } else {
                    InputKind::Symbols
                },
                asset.path,
            ));
            self.status = "正在取消；随后选用新对象".into();
            return false;
        }
        if !asset.available {
            self.status = "文件缺失；按 a 导入新路径".into();
            return false;
        }
        if let Err(e) = self.registry.import(&asset.path, asset.kind, &self.cache) {
            self.status = format!("资产登记失败: {e:#}");
            return false;
        }
        let changed = if asset.kind == Kind::Image {
            !self
                .image
                .as_ref()
                .is_some_and(|p| same_path(p, &asset.path))
        } else {
            !same_path(&self.symbols, &asset.path)
        };
        if changed {
            if asset.kind == Kind::Symbols {
                self.invalidate_symbols();
            } else {
                self.invalidate_source();
                self.symbols = PathBuf::new();
                self.choice = None;
            }
        }
        if asset.kind == Kind::Image {
            self.image = Some(asset.path);
        } else {
            self.choice = self
                .local_matches
                .get(&asset.path)
                .filter(|labels| labels.len() == 1)
                .map(|labels| labels[0].clone());
            self.symbols = asset.path;
        }
        if asset.kind == Kind::Symbols {
            if self.choice.is_some() {
                self.preparation = Preparation::Ready;
            } else if let Some(labels) = self
                .local_matches
                .get(&self.symbols)
                .filter(|labels| labels.len() > 1)
            {
                self.dialog = Some(Dialog::Symbols {
                    labels: labels.clone(),
                    selected: 0,
                });
                self.preparation = Preparation::ChooseSymbols;
            } else {
                if self.image.is_some() {
                    self.page = Page::Assets;
                    self.prepare_selected_image();
                }
            }
        }
        self.status = if self.preparation == Preparation::Ready {
            "已选用；可进入工作台，运行时验证页表"
        } else {
            "已选用；完成精确匹配后可进入工作台"
        }
        .into();
        true
    }
    pub(super) fn footer_actions(&self) -> Vec<(&'static str, KeyCode)> {
        let mut actions = if self.page == Page::Analysis {
            match self.focus {
                Focus::Context => vec![
                    ("i镜像", KeyCode::Char('i')),
                    ("y符号", KeyCode::Char('y')),
                    ("b识别", KeyCode::Char('b')),
                    ("m本地匹配", KeyCode::Char('m')),
                ],
                Focus::Navigation => vec![
                    ("Tab内容", KeyCode::Tab),
                    ("运行 Ctrl+R", KeyCode::F(5)),
                    ("p插件", KeyCode::Char('p')),
                    ("D Dump", KeyCode::Char('D')),
                    ("r重跑", KeyCode::Char('r')),
                ],
                Focus::Detail => vec![
                    ("↑上滚", KeyCode::Up),
                    ("↓下滚", KeyCode::Down),
                    ("PgDn翻页", KeyCode::PageDown),
                    ("d关闭", KeyCode::Char('d')),
                    ("Tab内容", KeyCode::Tab),
                ],
                _ => vec![
                    ("/搜索", KeyCode::Char('/')),
                    ("s排序", KeyCode::Char('s')),
                    ("e导出", KeyCode::Char('e')),
                    ("上页", KeyCode::Char('[')),
                    ("下页", KeyCode::Char(']')),
                    ("n行数", KeyCode::Char('n')),
                    ("d详情", KeyCode::Char('d')),
                    ("D Dump", KeyCode::Char('D')),
                    ("v诊断", KeyCode::Char('v')),
                ],
            }
        } else if self.focus == Focus::Content && self.hits.borrow().asset_detail.height > 0 {
            vec![
                ("↑上滚", KeyCode::Up),
                ("↓下滚", KeyCode::Down),
                ("PgDn翻页", KeyCode::PageDown),
                ("完整详情 d", KeyCode::Char('d')),
                ("Tab列表", KeyCode::Tab),
            ]
        } else {
            asset_actions(self.section)
        };
        actions.insert(
            0,
            (
                if self.windows {
                    "Windows F6"
                } else {
                    "Linux F6"
                },
                KeyCode::F(6),
            ),
        );
        if self.job.is_some() {
            actions.insert(0, ("Esc取消", KeyCode::Esc));
        }
        actions.push(("?更多", KeyCode::Char('?')));
        actions
    }
    pub(super) fn result(&self) -> Option<&Results> {
        self.history
            .as_ref()
            .or_else(|| self.results.get(&self.request_key()))
            .or_else(|| self.results.get(self.plugin.name()))
    }
    pub(super) fn rows(&self) -> Vec<Vec<String>> {
        let Some(result) = self.result() else {
            return Vec::new();
        };
        let mut rows = result.filtered(&self.query);
        if let Some(column) = self.sort {
            rows.sort_by(|a, b| {
                let a = a.get(column).map(String::as_str).unwrap_or("");
                let b = b.get(column).map(String::as_str).unwrap_or("");
                let order = compare_values(a, b);
                if self.descending {
                    order.reverse()
                } else {
                    order
                }
            });
        }
        rows
    }
    pub(super) fn visible(&self) -> Vec<Vec<String>> {
        let rows = self.rows();
        if self.history.is_some() || !self.plugin.is_tree() {
            return rows;
        }
        if self.plugin == Plugin::WinPstree {
            tree_rows_with_columns(rows, &self.collapsed, 1, 2)
        } else {
            tree_rows(rows, &self.collapsed)
        }
    }
    pub(super) fn picker_filter(kind: InputKind) -> crate::browser::Filter {
        use crate::browser::Filter;
        match kind {
            InputKind::Image | InputKind::Symbols => Filter::Files,
            InputKind::History => Filter::Exports,
            _ => Filter::Directories,
        }
    }
    pub(super) fn settings_labels(&self) -> Vec<String> {
        vec![
            format!("镜像目录: {}", escaped(&self.settings.image_dir)),
            format!("符号目录: {}", escaped(&self.settings.symbols)),
            format!("导出目录: {}", escaped(&self.settings.export_dir)),
            format!(
                "每页行数: {}（Enter 输入）",
                if self.settings.page_size == 0 {
                    "自动填满".into()
                } else {
                    self.settings.page_size.to_string()
                }
            ),
            format!(
                "远程模式: {}（Enter 切换）",
                if self.settings.remote_symbols {
                    "在线"
                } else {
                    "离线"
                }
            ),
        ]
    }
    pub(super) fn persist_settings(&mut self) {
        match store::save_settings(&self.cache, &self.settings) {
            Ok(()) => self.status = "设置已保存".into(),
            Err(e) => {
                self.status = format!("设置保存失败: {e:#}");
                self.last_error = Some(self.status.clone());
            }
        }
    }
    pub(super) fn resize(&mut self, width: u16, height: u16) {
        if self.page == Page::Assets && self.focus == Focus::Content && (width < 100 || height < 28)
        {
            self.focus = Focus::Navigation;
        }
        if width < 140 && self.focus == Focus::Detail {
            self.focus = Focus::Content;
        }
    }
    pub(super) fn select_plugin(&mut self, plugin: Plugin) {
        self.views.insert(
            self.request_key(),
            View {
                query: self.query.clone(),
                sort: self.sort,
                descending: self.descending,
                row: self.row,
                collapsed: self.collapsed.clone(),
                state: *self.table_state.borrow(),
                horizontal: self.horizontal,
            },
        );
        self.page = Page::Analysis;
        self.parameter_drafts
            .insert(self.plugin.name().into(), self.analysis_options.clone());
        let shared = self.analysis_options.clone();
        self.analysis_options =
            self.parameter_drafts
                .get(plugin.name())
                .cloned()
                .unwrap_or(crate::analysis::Options {
                    os: shared.os,
                    arch: shared.arch,
                    pagefiles: shared.pagefiles,
                    swapfile: shared.swapfile,
                    ..Default::default()
                });
        self.plugin = plugin;
        if plugin != Plugin::WinPrintkey {
            self.analysis_options.hive = None;
            self.analysis_options.key.clear();
        }
        if !plugin.descriptor().columns.contains(&"PID") {
            self.analysis_options.pid = None;
        }
        self.last_error = None;
        self.menu = if plugin.is_dump() {
            self.menu_items().len() - 1
        } else {
            self.navigation_plugins()
                .iter()
                .position(|p| *p == plugin)
                .unwrap()
        };
        self.history = None;
        self.query.clear();
        self.sort = None;
        self.row = 0;
        self.collapsed.clear();
        let view = self.views.remove(&self.request_key()).unwrap_or_default();
        self.query = view.query;
        self.sort = view.sort;
        self.descending = view.descending;
        self.row = view.row;
        self.collapsed = view.collapsed;
        self.horizontal = view.horizontal;
        *self.table_state.borrow_mut() = view.state;
        self.detail_scroll = 0;
        if let Some(result) = self.results.get(plugin.name()) {
            self.focus = Focus::Content;
            self.status = format!(
                "{} · {} 条 · {} · {} 条诊断（v）",
                plugin_label(plugin),
                result.rows.len(),
                if result.complete { "完整" } else { "部分" },
                result.diagnostics.len()
            );
        } else {
            self.focus = Focus::Content;
            self.status = "已选择插件；检查参数后按 Ctrl+R 运行".into();
        }
        if plugin.is_dump() {
            self.open_dump(plugin, false);
        }
    }
    pub(super) fn supports_kali_symbols(&self) -> bool {
        !self.windows
            && self.results.get("banners").is_some_and(|result| {
                result.rows.iter().any(|row| {
                    row.iter().any(|banner| {
                        banner.contains("Linux version 6.8.11-arm64")
                            && banner.contains("6.8.11-1kali2")
                    })
                })
            })
    }
    pub(super) fn activate_plugin(&mut self, plugin: Plugin) {
        self.select_plugin(plugin);
        self.focus = Focus::Content;
        if plugin.is_dump() {
            return;
        }
        if self.image.is_some() && self.job.is_none() {
            self.refresh_assets();
            if self
                .prepared_stamp
                .as_ref()
                .is_some_and(|stamp| *stamp != self.local_stamp())
            {
                self.request_analysis(false);
                return;
            }
        }
        // Selecting an existing result is instant; a different parameter draft runs anew.
        let cached = self.results.contains_key(&self.request_key())
            || (self.results.contains_key(plugin.name())
                && self
                    .result_requests
                    .get(plugin.name())
                    .is_none_or(|parameters| *parameters == self.parameter_summary()));
        let running = self
            .active_request
            .as_ref()
            .is_some_and(|request| request.key == self.request_key() && self.job.is_some());
        if !cached && !running {
            self.request_analysis(false);
        }
    }
    pub(super) fn detail_text(&self) -> String {
        if let (Some(result), Some(row)) = (self.result(), self.visible().get(self.row)) {
            result
                .columns
                .iter()
                .zip(row)
                .map(|(key, value)| format!("{}: {}", escaped(key), escaped(value)))
                .collect::<Vec<_>>()
                .join("\n\n")
        } else {
            "选择一行查看完整字段。".into()
        }
    }
    pub(super) fn result_column_count(&self) -> usize {
        self.result().map_or(0, |r| r.columns.len())
    }
}
