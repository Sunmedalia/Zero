use super::*;

impl App {
    pub(super) fn directory(&self, value: &str) -> PathBuf {
        let path = store::expand_home(value);
        if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        }
    }
    pub(super) fn engine_context(&self) -> crate::engine_service::EngineContext {
        crate::engine_service::EngineContext {
            root: self.root.clone(),
            cache: self.cache.clone(),
            settings: self.settings.clone(),
        }
    }

    pub(super) fn shown_os(&self) -> crate::analysis::Os {
        if self.analysis_options.os != crate::analysis::Os::Auto {
            return self.analysis_options.os;
        }
        match self.results.get("banners").map(|r| r.system.as_str()) {
            Some("linux") => crate::analysis::Os::Linux,
            Some("windows") => crate::analysis::Os::Windows,
            _ => crate::analysis::Os::Auto,
        }
    }
    pub(super) fn select_os(&mut self, os: crate::analysis::Os) {
        if self.job.is_some() {
            self.cancel();
            self.pending_work = None;
            self.pending_os = Some(os);
            self.status = "正在取消任务并切换分析系统…".into();
            return;
        }
        self.kernel_report = None;
        self.parameter_drafts.clear();
        self.prepared_stamp = None;
        self.verified = None;
        self.result_origins.clear();
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
        self.clear_plugin_tabs();
        self.results.clear();
        if let Some(banner) = banner {
            self.results.insert("banners".into(), banner);
        }
        self.local_matches.clear();
        self.local_match_stamp = None;
        self.local_match_errors.clear();
        self.local_only_matches = false;
        self.views.clear();
        self.history_revision += 1;
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
        self.focus = if self.page == Page::Analysis && self.plugins_collapsed {
            Focus::Content
        } else {
            Focus::Navigation
        };
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
    /// Menu order for the active platform. Both lists are fixed at compile
    /// time, so each is built once and shared.
    pub(super) fn navigation_plugins(&self) -> &'static [Plugin] {
        if self.windows {
            windows_navigation_plugins()
        } else {
            navigation_plugins()
        }
    }
    pub(super) fn menu_items(&self) -> &'static [&'static str] {
        if self.windows {
            windows_menu_items()
        } else {
            menu_items()
        }
    }
    pub(super) fn plugin_matches(&self, query: &str) -> Vec<Plugin> {
        if !self.windows {
            return plugin_matches(query);
        }
        let query = query.to_lowercase();
        let mut items = self
            .navigation_plugins()
            .iter()
            .copied()
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
            self.history_revision += 1;
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
        let root = if cache.is_absolute() {
            cache.parent().and_then(|p| p.parent()).map(PathBuf::from)
        } else {
            None
        }
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        for directory in [&settings.image_dir, &settings.export_dir, &settings.symbols] {
            let path = store::expand_home(directory);
            let path = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            if !path.exists() && path.extension().is_none() {
                let _ = std::fs::create_dir_all(path);
            }
        }

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
            &root.join(store::expand_home(&settings.image_dir)),
            &root.join(store::expand_home(&settings.symbols)),
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
        let (asset_identities, asset_digests) =
            super::asset_views::recorded_manifests(&assets, &cache);
        Self {
            terminal_size: std::cell::Cell::new(None),
            cache_page: Default::default(),
            open_tabs: Vec::new(),
            drag: None,
            active_tab: None,
            tab_offset: std::cell::Cell::new(0),
            tab_layout: std::cell::Cell::new(None),
            plugins_collapsed: false,
            kernel_report: None,
            diagnosis_running: false,
            page: Page::Assets,
            section: AssetSection::Images,
            symbol_source: AssetSection::Symbols,
            root,
            root_cached: std::cell::OnceCell::new(),
            path_cache: RefCell::new(HashMap::new()),
            canonical_cache: RefCell::new(HashMap::new()),
            asset_index_cache: RefCell::new(Default::default()),
            registry,
            asset_rows: PerSection([asset_rows[0], asset_rows[1], 0]),
            image_preview: None,
            asset_scroll: PerSection([0; 3]),
            asset_queries: Default::default(),
            asset_states: RefCell::new(Default::default()),
            asset_identities,
            asset_digests,
            asset_details: HashMap::new(),
            assets,
            remote: vec![],
            remote_matches: None,
            remote_loaded: false,
            remote_total: 0,
            remote_index_cache: RefCell::new(None),
            remote_catalog: true,
            download_url: None,
            downloads: HashMap::new(),
            hidden_cache_copies: HashSet::new(),
            local_matches: HashMap::new(),
            local_match_stamp: None,
            prepared_stamp: None,
            verified: None,
            result_origins: HashMap::new(),
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
            menu_scroll: std::cell::Cell::new(0),
            plugin: Plugin::Pslist,
            windows: false,
            analysis_options: Default::default(),
            results: ResultStore::default(),
            view_cache: RefCell::new(None),
            width_cache: RefCell::new(None),
            history_revision: 0,
            history: None,
            history_source: None,
            query: String::new(),
            sort: None,
            descending: false,
            row: 0,
            collapsed: HashSet::new(),
            status: "Space 选用镜像 · Enter 选用并进入分析 · i 导入 · ? 命令面板".into(),
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
            asset_console: false,
            console: Default::default(),
        }
    }
    pub(super) fn switch_page(&mut self, page: Page) {
        let changed = self.page != page;
        if changed {
            self.inspector = false;
        }
        self.page = page;
        if page == Page::Assets && self.image.is_none() {
            self.section = AssetSection::Images;
            self.focus = Focus::Content;
        }
        // Replace the previous page's hint, but never hide a running task or an error.
        if changed && self.job.is_none() && self.last_error.as_deref() != Some(&self.status) {
            self.status = match page {
                Page::Cache => {
                    "Tab 切换范围/条目 · Enter 打开 · Delete 删除 · x 清理已勾选 · r 刷新".into()
                }
                Page::Analysis if self.image.is_none() => "尚未选用镜像；1 资源库选用".into(),
                Page::Analysis => "点击或 Enter 运行插件 · / 筛选 · ? 命令面板".into(),
                Page::Assets => "Space 选用 · Enter 选用并进入分析 · ? 命令面板".into(),
            };
        }

        self.focus = if page == Page::Analysis {
            Focus::Content
        } else {
            Focus::Navigation
        };
        if page == Page::Cache {
            self.refresh_cache_page();
        }
        if page != Page::Analysis {
            self.refresh_assets();
        }
    }
    pub(super) fn switch_section(&mut self, section: AssetSection) {
        self.set_section(section);
        if section == AssetSection::Remote && !self.remote_loaded && self.job.is_none() {
            self.load_saved_catalog();
        }
    }
    pub(super) fn load_saved_catalog(&mut self) {
        self.remote_loaded = true;
        let present = symbols::Repository::configured(&self.cache)
            .is_ok_and(|repo| repo.index_file(&self.cache).is_file());
        if present {
            self.start_work(Work::SavedCatalog(self.asset_queries[2].clone()));
        } else {
            self.status = "尚未获取远程索引；g 获取".into();
        }
    }
    pub(super) fn set_section(&mut self, section: AssetSection) {
        self.page = Page::Assets;
        self.asset_console = false;
        self.section = section;
        if section != AssetSection::Images {
            self.symbol_source = section;
        }
        self.focus = Focus::Navigation;
        self.refresh_assets();
    }
    pub(super) fn available_commands(&self, query: &str) -> Vec<(&'static str, KeyCode)> {
        command_matches(
            query,
            self.page,
            self.focus,
            (self.page == Page::Assets).then_some(self.section),
        )
        .into_iter()
        .filter_map(|i| ACTIONS.get(i).map(|action| (action.label, action.key)))
        .collect()
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
        let mut fields = remote_fields(candidate);
        fields.push(("状态".into(), state.into()));
        fields.push((
            "保存位置".into(),
            path.map(|p| p.display().to_string())
                .unwrap_or_else(|| self.settings.symbols.clone()),
        ));
        let width = fields
            .iter()
            .map(|(label, _)| Span::raw(label).width())
            .max()
            .unwrap_or(0);
        let mut lines = fields
            .into_iter()
            .map(|(label, value)| {
                format!(
                    "{}{}  {}",
                    label,
                    " ".repeat(width - Span::raw(&label).width()),
                    escaped(&value)
                )
            })
            .collect::<Vec<_>>();
        lines.extend([
            String::new(),
            "完整 banner".into(),
            escaped(&candidate.banner),
            String::new(),
            format!(
                "文件  {}",
                escaped(candidate.path.rsplit('/').next().unwrap_or(&candidate.path))
            ),
            format!("链接  {}", escaped(&candidate.url)),
            String::new(),
            format!(
                "操作：{}w 仅下载到本地库",
                if self.image.is_some() {
                    "Space 下载并选用 · "
                } else {
                    ""
                }
            ),
        ]);
        if let Some(error) = &self.last_error {
            lines.push(escaped(error));
        }
        lines.join(
            "
",
        )
    }
    pub(super) fn invalidate_source(&mut self) {
        self.kernel_report = None;
        self.object_version += 1;
        self.prepared_stamp = None;
        self.verified = None;
        self.result_origins.clear();
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
        self.clear_plugin_tabs();
        self.results.clear();
        self.views.clear();
        self.history_revision += 1;
        self.history = None;
        self.choice = None;
        self.query.clear();
        self.sort = None;
        self.row = 0;
        self.horizontal = 0;
        self.collapsed.clear();
        self.remote_matches = None;
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
        self.set_section(if remote {
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
                self.prepare_selected_image();
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
    pub(super) fn move_result_page(&mut self, down: bool) {
        let size = self.page_rows();
        self.row = if down {
            self.row
                .saturating_add(size)
                .min(self.visible().len().saturating_sub(1))
        } else {
            self.row.saturating_sub(size)
        };
        let maximum = self.visible().len().saturating_sub(size);
        let offset = self.table_state.borrow().offset();
        *self.table_state.borrow_mut().offset_mut() = if down {
            offset.saturating_add(size).min(maximum)
        } else {
            offset.saturating_sub(size)
        };
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
        self.dialog = Some(Dialog::Quit { confirm: true });
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
                self.analysis_options.os = crate::analysis::Os::Auto;
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
                .and_then(|labels| labels.first().cloned());
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
    /// Analysis footer entries for the focused region. Region movement (`Tab`)
    /// is not a command, so it is prepended here; a running task adds the
    /// cancellation entry first so it is never scrolled off.
    pub(super) fn footer_actions(&self) -> Vec<(&'static str, KeyCode)> {
        if self.page == Page::Cache {
            let mut actions = ACTIONS
                .iter()
                .filter(|a| a.scope == Scope::Cache)
                .map(|a| (a.label, a.key))
                .collect::<Vec<_>>();
            if self.job.is_some() {
                actions.insert(0, ("取消 Esc", KeyCode::Esc));
            }
            actions.push(("命令面板 ?", KeyCode::Char('?')));
            return actions;
        }
        if self.page != Page::Analysis {
            return Vec::new();
        }
        if self.active_detail().is_some() {
            return vec![
                ("复制 c", KeyCode::Char('c')),
                ("上一页 PgUp", KeyCode::PageUp),
                ("下一页 PgDn", KeyCode::PageDown),
            ];
        }
        let mut actions = footer_actions(self.focus);
        actions.sort_by_key(|(_, key)| match key {
            KeyCode::Char('R' | 'r') => 0,
            KeyCode::Char('/') => 1,
            KeyCode::Char('d') => 2,
            KeyCode::Char('e') => 3,
            KeyCode::Char('p') => 4,
            KeyCode::Char('s') => 5,
            KeyCode::Char('[' | ']') => 6,
            _ => 7,
        });
        if self.focus == Focus::Navigation {
            actions.insert(0, ("内容 Tab", KeyCode::Tab));
        }
        if self.job.is_some() {
            actions.insert(0, ("取消 Esc", KeyCode::Esc));
        }
        actions
    }
    pub(super) fn result(&self) -> Option<&Results> {
        if self.active_detail().is_some() {
            return None;
        }
        self.history
            .as_deref()
            .or_else(|| self.results.get(&self.request_key()))
            .or_else(|| self.results.get(self.plugin.name()))
    }
    pub(super) fn view_index(&self) -> std::rc::Rc<crate::result_view::Index> {
        let result = self.result();
        let tree = if self.history.is_some() || !self.plugin.is_tree() {
            None
        } else if self.plugin == Plugin::WinPstree {
            Some((1, 2))
        } else {
            Some((2, 3))
        };
        let key = ViewKey {
            revision: self.results.revision,
            identity: result.map_or(0, |r| r.rows.as_ptr() as usize),
            history_revision: self.history_revision,
            query: self.query.clone(),
            sort: self.sort,
            descending: self.descending,
            tree,
            collapsed: collapsed_fingerprint(&self.collapsed),
        };
        let mut cache = self.view_cache.borrow_mut();
        if let Some((previous, index)) = cache.as_ref()
            && *previous == key
        {
            return index.clone();
        }
        let index = std::rc::Rc::new(result.map_or_else(Default::default, |r| {
            crate::result_view::Index::build(
                r,
                &self.query,
                self.sort,
                self.descending,
                tree,
                &self.collapsed,
            )
        }));
        *cache = Some((key, index.clone()));
        index
    }
    #[cfg(test)]
    pub(super) fn rows(&self) -> Vec<Vec<String>> {
        self.result().map_or_else(Vec::new, |r| {
            self.view_index()
                .filtered
                .iter()
                .map(|&i| r.rows[i].clone())
                .collect()
        })
    }
    pub(super) fn visible(&self) -> IndexedRows<'_> {
        IndexedRows {
            result: self.result(),
            index: self.view_index(),
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
            format!(
                "主题: {}（Enter 切换）",
                THEMES
                    .iter()
                    .find(|(id, _)| *id == self.settings.theme)
                    .map_or("石板", |(_, label)| *label)
            ),
            format!(
                "远程符号仓库: {}（Enter 编辑）",
                self.settings.symbol_repository
            ),
            format!(
                "镜像摘要: {}（Enter 切换）",
                if self.settings.reuse_recorded_digest {
                    "文件未变时复用上次摘要"
                } else {
                    "每个新会话完整校验"
                }
            ),
            format!("结果缓存: {}", self.settings.enable_cache),
            format!(
                "GitHub 下载: {}（Enter 切换）",
                self.settings.github_access.label()
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
    /// Which focusable regions the current layout draws.
    ///
    /// Read from the last frame's hit map, so it always describes what the user
    /// can actually see rather than what the window size suggests.
    pub(super) fn toggle_plugins(&mut self) {
        self.plugins_collapsed = !(self.plugins_collapsed || self.hits.borrow().menu.width == 0);
        self.focus = if self.plugins_collapsed {
            Focus::Content
        } else {
            Focus::Navigation
        };
    }
    pub(super) fn next_focus(&mut self, back: bool) {
        self.focus = self.focus.next(back, self.visible_regions());
        if self.plugins_collapsed && self.focus == Focus::Navigation {
            self.focus = self.focus.next(back, self.visible_regions());
        }
    }
    pub(super) fn visible_regions(&self) -> Visible {
        let hits = self.hits.borrow();
        Visible {
            // The analysis page's inspector column, or the resource page's
            // detail panel: both are the `Focus::Detail` target.
            detail: hits.inspector.width > 0 || hits.asset_detail.height > 0,
            // Only the analysis header is focusable; the resource header is a
            // pair of labels that open pickers.
            header: self.page == Page::Analysis && hits.header.height > 0,
        }
    }
    pub(super) fn resize(&mut self, width: u16, height: u16) {
        // Keep focus on a region this size actually draws. The thresholds here
        // mirror the ones the layout uses, and the clamp below catches anything
        // they miss once the next frame has been measured.
        let layout = Space::new(width, height);
        if self.page == Page::Assets && self.focus == Focus::Content && !layout.asset_detail() {
            self.focus = Focus::Navigation;
        }
        if !self.inspector && !layout.inspector() && self.focus == Focus::Detail {
            self.focus = Focus::Content;
        }
        self.focus = self.focus.clamp(self.visible_regions());
        if self.page == Page::Analysis && self.plugins_collapsed && self.focus == Focus::Navigation
        {
            self.focus = Focus::Content;
        }
    }
    pub(super) fn select_plugin(&mut self, plugin: Plugin) {
        self.save_view();
        self.history_source = None;
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
        if !plugin.accepts_pid_list() && !plugin.descriptor().columns.contains(&"PID") {
            self.analysis_options.pid = None;
        }
        self.last_error = None;
        self.menu = if plugin.is_dump() {
            self.menu_items().len() - 1
        } else {
            self.navigation_plugins()
                .iter()
                .position(|p| *p == plugin)
                .unwrap_or(0)
        };
        self.history_revision += 1;
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
                "{} · {} 条 · {} · {} 条诊断（v） · 本次会话已加载，未重新运行（r 重新分析）",
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
    pub(super) fn supports_automatic_symbols(&self) -> bool {
        !self.windows
            && self.results.get("banners").is_some_and(|result| {
                result.rows.iter().any(|row| {
                    row.iter()
                        .any(|banner| crate::prepare::supports_automatic_banner(banner))
                })
            })
    }
    pub(super) fn activate_plugin(&mut self, plugin: Plugin) {
        self.select_plugin(plugin);
        self.ensure_plugin_tab(plugin);
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
        if !cached && !running && self.image.is_some() {
            self.request_analysis(false);
        } else if !cached && self.image.is_none() {
            self.status = "尚未选用镜像；1 资源库选用".into();
        }
    }
    pub(super) fn detail_text(&self) -> String {
        if let (Some(result), Some(row)) = (self.result(), self.visible().get(self.row)) {
            result
                .columns
                .iter()
                .zip(row)
                .map(|(key, value)| format!("{}: {}", escaped(key), escaped(&value)))
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
