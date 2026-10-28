use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Focus {
    Context,
    Navigation,
    Content,
    Detail,
}
/// Which regions the current layout actually draws.
///
/// Focus must stay inside this set: a focus on a region that is not on screen
/// looks like the keys have stopped working, because every action is routed to
/// a pane the user cannot see.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Visible {
    /// The analysis page's inspector column, or the assets page's detail panel.
    pub(super) detail: bool,
    /// The analysis page's header line, which is also a focus target.
    pub(super) header: bool,
}
impl Focus {
    pub(super) fn next(self, back: bool, visible: Visible) -> Self {
        let regions = Self::cycle(visible);
        if regions.len() <= 1 {
            return regions[0];
        }
        let current = regions.iter().position(|f| *f == self).unwrap_or(0);
        let step = if back {
            (current + regions.len() - 1) % regions.len()
        } else {
            (current + 1) % regions.len()
        };
        regions[step]
    }
    /// The focus order for the regions on screen.
    fn cycle(visible: Visible) -> &'static [Focus] {
        const ALL: [Focus; 4] = [
            Focus::Context,
            Focus::Navigation,
            Focus::Content,
            Focus::Detail,
        ];
        const NO_DETAIL: [Focus; 3] = [Focus::Context, Focus::Navigation, Focus::Content];
        const NO_HEADER_NO_DETAIL: [Focus; 2] = [Focus::Navigation, Focus::Content];
        const NO_HEADER: [Focus; 3] = [Focus::Navigation, Focus::Content, Focus::Detail];
        match (visible.header, visible.detail) {
            (true, true) => &ALL,
            (true, false) => &NO_DETAIL,
            (false, true) => &NO_HEADER,
            (false, false) => &NO_HEADER_NO_DETAIL,
        }
    }
    /// Move `self` into the visible set, keeping it if already valid.
    pub(super) fn clamp(self, visible: Visible) -> Self {
        let regions = Self::cycle(visible);
        if regions.contains(&self) {
            self
        } else {
            regions[0]
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Preparation {
    ChooseImage,
    Matching,
    ChooseSystem,
    MissingSymbols,
    ChooseSymbols,
    Ready,
    Cancelled,
}
#[derive(Clone)]
pub(super) struct Execution {
    pub(super) plugin: Plugin,
    pub(super) key: String,
    pub(super) parameters: String,
    pub(super) snapshot: ExecutionSnapshot,
}
#[derive(Clone)]
pub(super) struct EventSender {
    pub(super) sender: mpsc::Sender<WorkerEvent>,
    pub(super) id: u64,
    pub(super) version: u64,
}
impl EventSender {
    pub(super) fn send(&self, event: WorkerEvent) -> bool {
        self.sender
            .send(WorkerEvent::Tagged(self.id, self.version, Box::new(event)))
            .is_ok()
    }
}
impl App {
    pub(super) fn parameter_summary(&self) -> String {
        format!(
            "PID={} · hive={} · key={} · arch={:?} · pagefile={:?} · swapfile={:?}",
            self.analysis_options
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "全部".into()),
            self.analysis_options
                .hive
                .map(|p| format!("{p:#x}"))
                .unwrap_or_default(),
            self.analysis_options.key,
            self.analysis_options.arch,
            self.analysis_options.pagefiles,
            self.analysis_options.swapfile
        )
    }
    pub(super) fn request_key(&self) -> String {
        format!(
            "{}:{:?}:{:?}",
            self.plugin.name(),
            self.analysis_options,
            self.dump_options
        )
    }
    pub(super) fn enter_workbench(&mut self) -> bool {
        if self.image.is_none() {
            self.status = "请先用 Space 选用镜像，再按 Enter 进入分析控制台".into();
            return false;
        }
        self.dialog = None;
        self.back_dialog = None;
        self.switch_page(Page::Analysis);
        self.select_plugin(if self.windows {
            Plugin::WinPslist
        } else {
            Plugin::Pslist
        });
        self.focus = if self.plugins_collapsed {
            Focus::Content
        } else {
            Focus::Navigation
        };
        self.status = "已进入分析控制台；点击插件立即分析，运行时验证页表".into();
        true
    }
    pub(super) fn apply_local_preparation(&mut self) {
        self.preparation_candidates = self
            .local_matches
            .iter()
            .flat_map(|(path, labels)| labels.iter().map(|label| (path.clone(), label.clone())))
            .collect();
        self.preparation_candidates.sort();
        let identified = self
            .results
            .get("banners")
            .is_some_and(|r| !r.rows.is_empty());
        if !identified && self.analysis_options.os == crate::analysis::Os::Auto {
            self.preparation = Preparation::ChooseSystem;
            self.status = "系统识别不明确；S 选择 Linux／Windows 后重试".into();
            return;
        }
        self.prepared_stamp = Some(self.local_stamp());
        match self.preparation_candidates.as_slice() {
            [] => {
                self.preparation = Preparation::MissingSymbols;
                self.status = "没有本地精确匹配；M 在线获取匹配符号，y 导入本地符号".into();
            }
            [(path, label)] => {
                self.symbols = path.clone();
                self.choice = Some(label.clone());
                self.preparation = Preparation::Ready;
                self.status = "唯一精确匹配已选用；可开始分析，运行时验证页表".into();
            }
            candidates => {
                self.preparation = Preparation::ChooseSymbols;
                self.status = "多个精确匹配；请选择符号（ZIP 内候选分别列出）".into();
                if self.page == Page::Assets {
                    self.dialog = Some(Dialog::Symbols {
                        labels: candidates.iter().map(|(_, label)| label.clone()).collect(),
                        selected: 0,
                    });
                }
            }
        }
    }
}

impl App {
    pub(super) fn parameter_fields(&self, advanced: bool) -> Vec<usize> {
        let mut fields = Vec::new();
        if self.plugin == Plugin::WinPrintkey {
            fields.extend([0, 1]);
        }
        if matches!(self.plugin, Plugin::Vmayarascan | Plugin::WinVadyarascan) {
            fields.push(7);
        }
        if self.plugin.descriptor().columns.contains(&"PID") {
            fields.push(2);
        }
        if self.windows && advanced {
            fields.extend([3, 4, 5]);
        }
        if self.plugin == Plugin::LinuxPslist {
            fields.extend([8, 9]);
        }
        if self.plugin == Plugin::Modxview {
            fields.push(10);
        }
        fields.push(6);
        fields
    }
}

impl App {
    fn view_key(&self) -> String {
        if self.history.is_some()
            && let Some(source) = &self.history_source
        {
            format!("history:{}", source.display())
        } else {
            self.request_key()
        }
    }
    pub(super) fn save_view(&mut self) {
        self.views.insert(
            self.view_key(),
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
    }
    pub(super) fn restore_view(&mut self) {
        let view = self.views.remove(&self.view_key()).unwrap_or_default();
        self.query = view.query;
        self.sort = view.sort;
        self.descending = view.descending;
        self.row = view.row;
        self.collapsed = view.collapsed;
        self.horizontal = view.horizontal;
        *self.table_state.borrow_mut() = view.state;
    }
}

impl App {
    pub(super) fn initialize(&mut self, options: crate::analysis::Options) {
        self.windows = options.os == crate::analysis::Os::Windows;
        self.analysis_options = options;
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
        if self.image.is_some() {
            self.page = Page::Analysis;
            self.focus = Focus::Content;
            self.prepare_selected_image();
        }
    }
}

#[derive(Clone)]
pub(super) struct ExecutionSnapshot {
    pub(super) force: bool,
    pub(super) plugin: Plugin,
    pub(super) options: crate::analysis::Options,
    pub(super) dump: Option<(Plugin, DumpOptions)>,
}

impl App {
    pub(super) fn start_snapshot(&mut self, request: ExecutionSnapshot) {
        let active_tab = self.active_tab;
        let viewing = ExecutionSnapshot {
            force: false,
            plugin: self.plugin,
            options: self.analysis_options.clone(),
            dump: self.dump_options.clone(),
        };
        self.plugin = request.plugin;
        self.analysis_options = request.options;
        self.dump_options = request.dump;
        self.start_work(Work::Analyze(request.force));
        self.active_tab = active_tab;
        self.plugin = viewing.plugin;
        self.analysis_options = viewing.options;
        self.dump_options = viewing.dump;
    }
}
