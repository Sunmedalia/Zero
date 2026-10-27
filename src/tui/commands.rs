//! Handlers behind [`Command`] variants that have more than a one-line body.
//!
//! Keeping them here lets `run_command` stay a flat dispatch table while the
//! behaviour of each action remains independently testable.
use super::*;

impl App {
    pub(super) fn open_task_log(&mut self) {
        self.dialog = Some(Dialog::Detail {
            text: format!(
                "任务日志（最近 200 条）\n\n{}",
                self.logs
                    .iter()
                    .map(|s| escaped(s))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            scroll: 0,
        });
    }
    pub(super) fn open_history(&mut self) {
        self.open_files(InputKind::History);
    }
    pub(super) fn open_system_dialog(&mut self) {
        self.dialog = Some(Dialog::System {
            selected: usize::from(self.shown_os() == crate::analysis::Os::Windows),
        });
    }
    /// Flip the symbol network mode. One implementation, one message, whichever
    /// page the user pressed `o` on.
    pub(super) fn toggle_online(&mut self) {
        if self.job.is_some() {
            self.status = "任务执行中；等待完成或按 Esc 取消后再切换".into();
            return;
        }
        self.settings.remote_symbols = !self.settings.remote_symbols;
        self.persist_settings();
        self.status = if self.settings.remote_symbols {
            "在线符号匹配已开启；仅请求仓库，不上传镜像".into()
        } else {
            "离线模式：使用本地 ISF 和已下载缓存".into()
        };
    }
    /// Space on the resource page.
    pub(super) fn select_asset(&mut self) {
        if self.section == AssetSection::Remote {
            if self.image.is_none() {
                self.status = "请先用 Space 选用镜像；远程 w 可独立下载".into();
            } else if let Some(candidate) = self
                .remote_list()
                .get(self.asset_rows[2])
                .map(|m| (*m).clone())
            {
                self.start_work(Work::Download(candidate));
            }
            return;
        }
        if self.use_selected_asset() {
            if self.section == AssetSection::Images {
                self.symbol_source = AssetSection::Symbols;
                self.prepare_selected_image();
            }
            self.enter_when_ready = true;
            self.resolve_enter_intent();
        }
    }
    pub(super) fn delete_asset(&mut self) {
        if self.section == AssetSection::Remote {
            self.status = "远程索引条目无需移出；w 可下载到本地库".into();
            return;
        }
        if self.job.is_some() {
            self.status = "任务执行中；Esc 取消后再移出资产".into();
            return;
        }
        let Some(asset) = self.selected_asset() else {
            self.status = "没有选中的资产".into();
            return;
        };
        match self.registry.remove(&asset.path, &self.cache) {
            Ok(()) => {
                if self
                    .image
                    .as_ref()
                    .is_some_and(|p| same_path(p, &asset.path))
                {
                    self.invalidate_source();
                    self.image = None;
                } else if same_path(&self.symbols, &asset.path) {
                    self.invalidate_source();
                    self.symbols = PathBuf::new();
                }
                self.refresh_assets();
                self.status = "已移出项目清单，原文件保留".into();
            }
            Err(e) => self.status = format!("清单保存失败: {e:#}"),
        }
    }
    /// `r` refreshes whatever the active section is showing: the remote index,
    /// the exact-match lookup, or the local asset registry.
    pub(super) fn refresh_asset_list(&mut self) {
        if self.section == AssetSection::Remote {
            if self.remote_catalog {
                self.start_work(Work::Catalog(
                    self.asset_queries[2].clone(),
                    self.settings.remote_symbols,
                ));
            } else {
                self.start_work(Work::RefreshLookup);
            }
            return;
        }
        self.asset_details.clear();
        self.refresh_assets();
        self.status = "资产清单已刷新".into();
    }
    pub(super) fn toggle_source(&mut self) {
        self.switch_section(if self.symbol_source == AssetSection::Symbols {
            AssetSection::Remote
        } else {
            AssetSection::Symbols
        });
    }
    pub(super) fn fetch_index(&mut self) {
        if self.section != AssetSection::Remote {
            return;
        }
        self.set_section(AssetSection::Remote);
        self.remote_catalog = true;
        self.asset_queries[2].clear();
        self.start_work(Work::Catalog(String::new(), false));
    }
    pub(super) fn download_candidate(&mut self) {
        if self.section != AssetSection::Remote {
            return;
        }
        if let Some(candidate) = self
            .remote_list()
            .get(self.asset_rows[2])
            .map(|m| (*m).clone())
        {
            self.start_work(Work::CatalogDownload(candidate));
        }
    }
    pub(super) fn show_remote_view(&mut self, catalog: bool) {
        self.set_section(AssetSection::Remote);
        self.remote_catalog = catalog;
        self.asset_rows[2] = 0;
        self.asset_states.borrow_mut()[2] = ListState::default();
        if self.job.is_some() {
            return;
        }
        if catalog {
            if !self.remote_loaded {
                self.remote_loaded = true;
                self.start_work(Work::SavedCatalog(self.asset_queries[2].clone()));
            } else {
                self.status = format!(
                    "全部索引 · {} 项；/ 搜索，z 切换到镜像匹配",
                    self.remote_total
                );
            }
        } else if self.image.is_none() {
            self.remote_matches = Some(Vec::new());
            self.status = "镜像匹配需要先选用镜像；z 返回全部索引".into();
        } else if self.remote_matches.is_none() {
            self.start_work(Work::RefreshLookup);
        } else {
            self.status = format!(
                "镜像匹配 · {} 项；z 切换到全部索引",
                self.remote_matches.as_ref().map_or(0, Vec::len)
            );
        }
    }
    pub(super) fn toggle_match_filter(&mut self) {
        if self.section == AssetSection::Remote {
            self.show_remote_view(!self.remote_catalog);
            return;
        }
        if self.section != AssetSection::Symbols {
            return;
        }
        self.local_only_matches = !self.local_only_matches;
        self.asset_rows[1] = 0;
    }
    /// Esc is layered: close the inspector, then clear the content filter, then
    /// cancel the task. One implementation for both pages, so the order cannot
    /// diverge between them.
    pub(super) fn cancel_context(&mut self) {
        if self.inspector {
            self.inspector = false;
            if self.focus == Focus::Detail {
                self.focus = Focus::Content;
            }
            return;
        }
        if self.page == Page::Analysis && !self.query.is_empty() {
            self.query.clear();
            self.row = 0;
            self.status = "已清除内容筛选".into();
            return;
        }
        self.cancel();
    }
    /// Enter on the analysis page: the target depends on the focused region.
    pub(super) fn enter_focused(&mut self) {
        if self.focus == Focus::Detail {
            self.open_detail();
        } else if self.focus == Focus::Context {
            self.open_files(InputKind::Image);
        } else if self.focus == Focus::Navigation {
            match self.menu {
                index if index == self.menu_items().len() - 1 => {
                    self.open_dump(Plugin::Procdump, false)
                }
                index => {
                    let plugin = self.navigation_plugins()[index];
                    self.activate_plugin(plugin);
                }
            }
        } else if self.plugin.is_tree()
            && self.history.is_none()
            && let Some(row) = self.visible().get(self.row)
        {
            let pid = row[0].clone();
            if !self.collapsed.remove(&pid) {
                self.collapsed.insert(pid);
            }
        } else {
            self.open_detail();
        }
    }
    /// Availability for a [`Command`], decided by identity rather than by key.
    pub(super) fn command_disabled(&self, command: Command) -> Option<&'static str> {
        if self.page == Page::Assets && !command_applies(command, self.section) {
            return Some("当前资源区不适用该操作");
        }
        let busy = self.job.is_some();
        match command {
            Command::KernelDiagnostics if self.job.is_some() && self.kernel_report.is_none() => {
                Some("任务执行中，请等待或取消")
            }
            Command::GenerateSymbols if self.windows => Some("Windows 请使用 M 获取精确 PDB 符号"),
            Command::EnterAnalysis
            | Command::MatchLocal
            | Command::MatchRemote
            | Command::Identify
            | Command::VerifyImage
            | Command::KernelDiagnostics
                if self.image.is_none() =>
            {
                Some("请先选用镜像")
            }
            // Enter on a highlighted image selects it first, so it only needs a
            // row; every other section needs an image already in hand.
            Command::SelectAndEnter
                if self.section != AssetSection::Remote
                    && self.image.is_none()
                    && (self.section != AssetSection::Images || self.asset_list().is_empty()) =>
            {
                Some("请先选用镜像")
            }
            Command::ImportCurrent if self.section == AssetSection::Remote => {
                Some("远程符号请使用下载")
            }
            Command::Download
                if self.section != AssetSection::Remote
                    || self.remote_list().get(self.asset_rows[2]).is_none() =>
            {
                Some("请先选择远程符号")
            }
            Command::Select | Command::AssetDetail | Command::DeleteAsset => {
                let empty = if self.section == AssetSection::Remote {
                    self.remote_list().is_empty()
                } else {
                    self.asset_list().is_empty()
                };
                empty.then_some("列表为空，请导入或搜索")
            }
            Command::Export | Command::Sort | Command::Rows if self.result().is_none() => {
                Some("尚无结果；先运行插件")
            }
            Command::Run
            | Command::Rerun
            | Command::MatchLocal
            | Command::MatchRemote
            | Command::Identify
            | Command::VerifyImage
            | Command::ImportCurrent
            | Command::FetchIndex
            | Command::Download
            | Command::RefreshAssets
            | Command::ToggleOnline
            | Command::ImportImage
            | Command::ImportSymbols
            | Command::CacheClear
            | Command::CacheDelete
            | Command::CacheOpen
            | Command::CacheRefresh
                if busy =>
            {
                Some("任务执行中，请等待或取消")
            }
            _ => None,
        }
    }
}
