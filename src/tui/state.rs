use super::*;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum InputKind {
    Image,
    Symbols,
    Search,
    AssetsSearch,
    Export,
    DiagnosticExport,
    History,
    ImageDirectory,
    SymbolsDirectory,
    ExportDirectory,
    PageSize,
    SymbolRepository,
    InspectAddress,
    InspectStruct,
}
#[derive(Clone)]
pub(super) enum Dialog {
    Quit {
        confirm: bool,
    },
    GenerateSymbols {
        automatic: bool,
        fields: [String; 3],
        field: usize,
        cursor: usize,
        selected: bool,
        error: String,
    },
    KernelPackages {
        packages: Vec<crate::prepare::KernelPackage>,
        selected: usize,
    },
    Dump {
        mode: Plugin,
        fields: [String; 4],
        field: usize,
        cursor: usize,
        selected: bool,
        force: bool,
        error: String,
    },
    Files {
        kind: InputKind,
        root: PathBuf,
        entries: Vec<crate::browser::Entry>,
        selected: usize,
    },
    Settings {
        selected: usize,
    },
    System {
        selected: usize,
    },
    Commands {
        query: String,
        selected: usize,
    },
    WindowsParameters {
        advanced: bool,
        fields: Box<[String; 34]>,
        field: usize,
        cursor: usize,
        selected: bool,
        error: String,
    },
    Plugins {
        query: String,
        selected: usize,
    },
    Links {
        matches: Vec<RemoteMatch>,
        selected: usize,
    },
    AssetDetail {
        read_only: bool,
        asset: Asset,
        scroll: usize,
    },
    RemoteDetail {
        candidate: RemoteMatch,
        scroll: usize,
    },
    KernelDiagnostics {
        scroll: usize,
    },
    MemoryInspector {
        tab: workbench::InspectorTab,
        scroll: usize,
        selected_field: usize,
    },
    Detail {
        title: &'static str,
        text: String,
        scroll: usize,
    },
    Input {
        kind: InputKind,
        text: String,
        original: String,
        cursor: usize,
        selected: bool,
    },
    Sort {
        column: usize,
    },
    Symbols {
        labels: Vec<String>,
        selected: usize,
    },
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Page {
    #[default]
    Assets,
    Analysis,
    Cache,
}
impl Page {
    pub(super) const ALL: [Self; 3] = [Self::Assets, Self::Analysis, Self::Cache];
    pub(super) fn index(self) -> usize {
        match self {
            Self::Assets => 0,
            Self::Analysis => 1,
            Self::Cache => 2,
        }
    }
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Assets => "资源库",
            Self::Analysis => "分析",
            Self::Cache => "缓存",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum AssetSection {
    Images,
    #[default]
    Symbols,
    Remote,
}
impl AssetSection {
    pub(super) fn slot(self) -> usize {
        match self {
            Self::Images => 0,
            Self::Symbols => 1,
            Self::Remote => 2,
        }
    }
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Images => "镜像",
            Self::Symbols => "本地符号",
            Self::Remote => "远程符号",
        }
    }
}
#[derive(Clone)]
pub(super) enum Work {
    KernelDiagnostic,
    Dossier(u32),
    Triage(crate::dossier::TriagePlaybook),
    Inspect(workbench::InspectorQuery, workbench::InspectorTab),
    ExportDiagnostic(PathBuf, Arc<crate::kernel_diagnostics::Report>),
    SavedCatalog(String),
    Inventory,
    RemoveCache(Vec<PathBuf>),
    Record(String),
    History(PathBuf),
    /// The result and view settings captured when the user confirms export.
    Export {
        path: PathBuf,
        result: Arc<Results>,
        query: String,
        sort: Option<usize>,
        descending: bool,
    },
    Verify,
    Clear(Vec<cache::Scope>),
    FindKernelPackages(bool),
    PrepareKernel(crate::prepare::KernelPackage),
    GenerateSymbols([PathBuf; 3]),
    /// Derive symbols from the selected image's own BTF and kallsyms.
    GenerateFromImage,
    Identify,
    PreviewImage(PathBuf),
    InspectSymbols(PathBuf),
    RefreshLookup,
    Analyze(bool),
    FetchMatched,
    MatchLocal(Vec<PathBuf>, String),
    Download(RemoteMatch),
    Catalog(String, bool),
    CatalogDownload(RemoteMatch),
}
pub(super) enum SymbolRetry {
    Analysis(Box<ExecutionSnapshot>),
    Work(Box<Work>),
}

pub(super) enum WorkerEvent {
    ChooseWorkSymbols(Vec<String>, Work),
    KernelPackages(Vec<crate::prepare::KernelPackage>),
    KernelDiagnosed(crate::kernel_diagnostics::Report),
    Dossier(Box<crate::dossier::DossierReport>),
    Triage(Box<crate::dossier::TriageReport>),
    Inspected(Box<crate::inspector::InspectReport>),
    DiagnosticExported(PathBuf),
    SavedCatalog(Option<symbols::CatalogPage>),
    Inventory(crate::engine_service::Inventory),
    Opened(PathBuf, Results),
    Exported(PathBuf, usize, Option<String>),
    Verified(crate::engine_service::Verified),
    Tagged(u64, u64, Box<WorkerEvent>),
    Cleared(cache::Report),
    Identified(Results),
    IndexRefreshed,
    CatalogPage(symbols::CatalogPage),
    CatalogDownloaded(PathBuf),
    ImagePreviewed(PathBuf),
    SymbolDetails(PathBuf, String),
    LocalMatched(symbols::LocalMatches, String, Results),
    Links(Vec<RemoteMatch>),
    Downloaded(PathBuf),
    Progress(String),
    Done(Outcome),
    Failed(String),
}
#[derive(Clone, Default)]
pub(super) struct HitMap {
    pub(super) scrollbars: Vec<scrollbars::Scrollbar>,
    pub(super) asset_rows: Vec<(Rect, AssetSection, usize)>,
    pub(super) result_tabs: Vec<(Rect, Rect, usize)>,
    pub(super) result_tab_steps: Vec<(Rect, usize)>,
    pub(super) plugin_toggle: Rect,
    pub(super) cache_scopes: Rect,
    pub(super) cache_items: Rect,
    pub(super) cache_offset: usize,
    pub(super) header: Rect,
    /// Clickable header fields: image on the first row, symbol on the second
    /// when the header has one.
    pub(super) header_image: Rect,
    pub(super) header_symbol: Rect,
    pub(super) tabs: Vec<(Rect, Page)>,
    pub(super) systems: Vec<(Rect, crate::analysis::Os)>,
    pub(super) regions: Vec<(Rect, Focus)>,
    pub(super) sources: Vec<(Rect, AssetSection)>,
    pub(super) remote_views: Vec<(Rect, bool)>,
    pub(super) asset_lists: Vec<(Rect, AssetSection, usize)>,
    pub(super) asset_buttons: Vec<(Rect, AssetSection, KeyCode)>,
    pub(super) asset_searches: Vec<(Rect, AssetSection)>,
    pub(super) dump_fields: Vec<(Rect, usize)>,
    pub(super) dump_modes: Vec<(Rect, Plugin)>,
    pub(super) assets: Rect,
    pub(super) asset_offset: usize,
    pub(super) asset_detail: Rect,
    pub(super) search: Rect,
    pub(super) menu: Rect,
    pub(super) result: Rect,
    pub(super) workbench: Rect,
    pub(super) inspector: Rect,
    pub(super) popup: Rect,
    pub(super) menu_offset: usize,
    pub(super) row_offset: usize,
    pub(super) popup_offset: usize,
    pub(super) popup_list: Rect,
    pub(super) columns: Vec<Rect>,
    /// Drag handles on the header separator after each visible column.
    pub(super) column_grips: Vec<ColumnGrip>,
    /// Whether the result table header is currently visible and unobstructed
    /// (false when covered by the narrow full-width inspector or no table is drawn).
    pub(super) result_header_visible: bool,
    /// Width each result column was laid out with, before clipping.
    pub(super) drawn_widths: Vec<u16>,
    pub(super) buttons: Vec<(Rect, KeyCode)>,
    pub(super) console_tab: Rect,
    pub(super) console_methods: Vec<(Rect, usize)>,
}
/// Everything `asset_list_for` filters on. When all of it is unchanged the
/// previous index is still valid.
/// Cached filtered indices for one asset section.
pub(super) type AssetIndex = Option<(AssetIndexKey, Vec<usize>)>;
/// Identity of the remote list plus the query. Derived from the buffer address
/// and length, so replacing the vector invalidates the cache even when the new
/// list has the same size — no write site has to remember to bump a counter.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RemoteIndexKey {
    pub(super) identity: usize,
    pub(super) len: usize,
    pub(super) query: String,
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct AssetIndexKey {
    /// Buffer address and length of the asset vector: replacing it invalidates
    /// the cache even when the new list has the same size.
    pub(super) identity: usize,
    pub(super) len: usize,
    pub(super) query: String,
    pub(super) local_only: bool,
    pub(super) hidden: usize,
    pub(super) matches: usize,
}
#[derive(Default)]
pub(super) struct View {
    pub(super) query: String,
    pub(super) sort: Option<usize>,
    pub(super) descending: bool,
    pub(super) row: usize,
    pub(super) collapsed: HashSet<String>,
    pub(super) state: TableState,
    pub(super) horizontal: usize,
    pub(super) column_widths: HashMap<ColumnKey, u16>,
}
pub struct App {
    pub(super) terminal_size: std::cell::Cell<Option<(u16, u16)>>,
    pub(super) drag: Option<scrollbars::Drag>,
    /// Header separator being dragged to resize a result column.
    pub(super) column_drag: Option<ColumnDrag>,
    /// Last completed non-dragged click on a header separator, to recognise a double click.
    pub(super) grip_click: Option<GripClick>,
    pub(super) open_tabs: Vec<OpenTab>,
    pub(super) active_tab: Option<usize>,
    pub(super) tab_offset: std::cell::Cell<usize>,
    pub(super) tab_layout: std::cell::Cell<Option<(Option<usize>, u16)>>,
    pub(super) plugins_collapsed: bool,
    pub(super) kernel_report: Option<Arc<crate::kernel_diagnostics::Report>>,
    pub(super) diagnosis_running: bool,
    pub(super) inspector_report: Option<Arc<crate::inspector::InspectReport>>,
    pub(super) inspector_query: Option<workbench::InspectorQuery>,
    pub(super) inspector_history: Vec<(workbench::InspectorQuery, workbench::InspectorTab)>,
    pub(super) inspector_running: bool,
    pub(super) cache_page: cache_page::CachePage,
    pub(super) page: Page,
    pub(super) section: AssetSection,
    pub(super) symbol_source: AssetSection,
    pub(super) root: PathBuf,
    pub(super) registry: Registry,
    pub(super) assets: Vec<Asset>,
    pub(super) asset_rows: PerSection<usize>,
    pub(super) image_preview: Option<PathBuf>,
    pub(super) asset_scroll: PerSection<usize>,
    pub(super) asset_queries: PerSection<String>,
    pub(super) asset_states: RefCell<PerSection<ListState>>,
    pub(super) asset_details: HashMap<PathBuf, String>,
    pub(super) asset_identities: HashMap<PathBuf, crate::image::BoundIdentity>,
    pub(super) asset_digests: HashMap<PathBuf, String>,
    pub(super) remote: Vec<RemoteMatch>,
    pub(super) remote_matches: Option<Vec<RemoteMatch>>,
    pub(super) remote_loaded: bool,
    pub(super) remote_total: usize,
    pub(super) remote_index_cache: RefCell<Option<(RemoteIndexKey, Vec<usize>)>>,
    pub(super) remote_catalog: bool,
    pub(super) download_url: Option<String>,
    pub(super) downloads: HashMap<String, PathBuf>,
    pub(super) hidden_cache_copies: HashSet<PathBuf>,
    pub(super) local_matches: HashMap<PathBuf, Vec<String>>,
    pub(super) local_match_stamp: Option<String>,
    pub(super) prepared_stamp: Option<String>,
    pub(super) verified: Option<crate::engine_service::Verified>,
    pub(super) result_origins: HashMap<String, String>,
    pub(super) local_match_errors: Vec<String>,
    pub(super) local_only_matches: bool,
    pub(super) image: Option<PathBuf>,
    pub(super) symbols: PathBuf,
    pub(super) cache: PathBuf,
    pub(super) settings: Settings,
    pub(super) hits: RefCell<HitMap>,
    /// Canonical root and per-input display paths. Both are filled lazily from
    /// `&self` and dropped when the asset list is rebuilt.
    pub(super) root_cached: std::cell::OnceCell<PathBuf>,
    pub(super) path_cache: RefCell<HashMap<PathBuf, String>>,
    /// Canonical form of each path compared while drawing, so asset rows do
    /// not resolve symlinks on every frame. Dropped with `path_cache`.
    pub(super) canonical_cache: RefCell<HashMap<PathBuf, Option<PathBuf>>>,
    /// Filtered asset indices per section, keyed by the state that produced
    /// them. `asset_list_for` runs several times per frame.
    pub(super) asset_index_cache: RefCell<PerSection<AssetIndex>>,
    pub(super) table_state: RefCell<TableState>,
    pub(super) focus: Focus,
    pub(super) menu: usize,
    /// First menu row drawn. `hits` is rebuilt every frame, so the scroll
    /// position has to live on the app or the list snaps back to the top.
    /// A `Cell` because the renderer holds `&self`.
    pub(super) menu_scroll: std::cell::Cell<usize>,
    pub(super) plugin: Plugin,
    pub(super) windows: bool,
    pub(super) analysis_options: crate::analysis::Options,
    pub(super) results: ResultStore,
    pub(super) view_cache: RefCell<Option<CachedView>>,
    /// Background index build for a large result; see `App::view_index`.
    pub(super) view_job: RefCell<Option<ViewJob>>,
    /// When `refresh_assets` last rescanned the asset directories.
    pub(super) assets_scanned: Option<Instant>,
    /// Wrapped detail text of the last drawn inspector or detail tab.
    pub(super) detail_cache: RefCell<Option<DetailCache>>,
    /// Shown while a large result's first index is still being built.
    pub(super) empty_view: std::rc::Rc<crate::result_view::Index>,
    /// Natural column widths for the row index and header they were measured
    /// from. Holding the `Rc` keeps its address from being reused.
    pub(super) width_cache: RefCell<Option<ColumnWidths>>,
    pub(super) history_revision: u64,
    pub(super) history: Option<Arc<Results>>,
    pub(super) history_source: Option<PathBuf>,
    pub(super) query: String,
    pub(super) sort: Option<usize>,
    pub(super) descending: bool,
    pub(super) row: usize,
    pub(super) collapsed: HashSet<String>,
    pub(super) status: String,
    pub(super) logs: VecDeque<String>,
    pub(super) started: Option<Instant>,
    pub(super) progress: Option<u16>,
    pub(super) dialog: Option<Dialog>,
    pub(super) choice: Option<String>,
    pub(super) dump_options: Option<(Plugin, DumpOptions)>,
    pub(super) receiver: Option<mpsc::Receiver<WorkerEvent>>,
    pub(super) job: Option<Job>,
    pub(super) worker: Option<thread::JoinHandle<()>>,
    pub(super) session: Arc<Mutex<linux::Session>>,
    pub(super) last_error: Option<String>,
    pub(super) back_dialog: Option<Box<Dialog>>,
    pub(super) pending_work: Option<Work>,
    pub(super) pending_path: Option<(InputKind, PathBuf)>,
    pub(super) pending_execution: Option<ExecutionSnapshot>,
    pub(super) preparation: Preparation,
    pub(super) preparation_candidates: Vec<(PathBuf, String)>,
    pub(super) task_id: u64,
    pub(super) object_version: u64,
    pub(super) active_request: Option<Execution>,
    pub(super) symbol_retry: Option<SymbolRetry>,
    pub(super) preparation_lookup: bool,
    pub(super) parameter_drafts: HashMap<String, crate::analysis::Options>,
    /// The execution shown when returning to a completed result tab.
    pub(super) tab_requests: HashMap<&'static str, ExecutionSnapshot>,
    /// Live display selection, independent of the editable analysis options.
    pub(super) displayed_request: Option<String>,
    pub(super) result_requests: HashMap<String, String>,
    pub(super) pending_os: Option<crate::analysis::Os>,
    pub(super) horizontal: usize,
    /// Widths the user dragged, by column name and duplicate-header occurrence;
    /// unset columns keep their measured width. Saved per view like the horizontal scroll.
    pub(super) column_widths: HashMap<ColumnKey, u16>,
    pub(super) inspector: bool,
    pub(super) detail_scroll: usize,
    pub(super) views: HashMap<String, View>,
    /// Enter on a not-yet-selected asset: open the analysis page once matching is ready.
    pub(super) enter_when_ready: bool,
    /// The resource page shows the symbol-generation console instead of a list.
    pub(super) asset_console: bool,
    pub(super) console: super::console::Console,
}

/// Session results by request key and by plugin name.
///
/// Both keys of a finished run share one `Arc`, so storing a result never
/// copies its rows on the UI thread; exports and background view builds take
/// another reference instead of a deep copy.
#[derive(Default)]
pub(super) struct ResultStore {
    pub(super) values: HashMap<String, Arc<Results>>,
    /// Bumped by anything that may edit a stored result in place.
    pub(super) revision: u64,
}
impl ResultStore {
    pub(super) fn get(&self, key: &str) -> Option<&Results> {
        self.values.get(key).map(|r| &**r)
    }
    pub(super) fn shared(&self, key: &str) -> Option<&Arc<Results>> {
        self.values.get(key)
    }
    pub(super) fn insert(
        &mut self,
        key: String,
        value: impl Into<Arc<Results>>,
    ) -> Option<Arc<Results>> {
        self.values.insert(key, value.into())
    }
    /// In-place edit; copies only when the result is also referenced elsewhere.
    #[cfg(test)]
    pub(super) fn get_mut(&mut self, key: &str) -> Option<&mut Results> {
        self.revision += 1;
        self.values.get_mut(key).map(Arc::make_mut)
    }
    #[cfg(test)]
    pub(super) fn remove(&mut self, key: &str) -> Option<Results> {
        self.values.remove(key).map(Arc::unwrap_or_clone)
    }
}
impl std::ops::Deref for ResultStore {
    type Target = HashMap<String, Arc<Results>>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl std::ops::DerefMut for ResultStore {
    /// Map-level edits (`retain`, `clear`) only add or drop whole results,
    /// which changes their identity; in-place edits go through `get_mut`.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}
#[derive(PartialEq, Eq, Clone)]
/// Inputs to the filtered/sorted row index.
///
/// The collapse set and query are fingerprinted rather than cloned: this key is
/// rebuilt on every `visible()` call, which happens several times per frame.
pub(super) struct ViewKey {
    pub(super) revision: u64,
    pub(super) identity: usize,
    pub(super) history_revision: u64,
    pub(super) query: String,
    pub(super) sort: Option<usize>,
    pub(super) descending: bool,
    pub(super) tree: Option<crate::result_view::TreeColumns>,
    pub(super) collapsed: u64,
}
/// The last finished row index and the result it was built from. The weak
/// handle pins the result's address, so `identity` cannot be reused by a later
/// allocation while this entry exists.
/// What a wrapped detail text was built from. Each variant holds a strong
/// reference, so its address identifies the content for as long as it is cached:
/// a row index is never edited after it is built, and a tab's text never changes.
pub(super) enum DetailSource {
    Row(std::rc::Rc<crate::result_view::Index>, usize),
    Tab(std::rc::Rc<str>),
}
impl DetailSource {
    pub(super) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Row(a, x), Self::Row(b, y)) => std::rc::Rc::ptr_eq(a, b) && x == y,
            (Self::Tab(a), Self::Tab(b)) => std::rc::Rc::ptr_eq(a, b),
            _ => false,
        }
    }
}
pub(super) struct DetailCache {
    pub(super) source: DetailSource,
    pub(super) width: u16,
    pub(super) lines: std::rc::Rc<Vec<String>>,
}
/// Plugin activation rescans asset directories at most this often; edits to
/// already listed files are detected on every activation by re-`stat`ing them.
pub(super) const ASSET_RESCAN_INTERVAL: Duration = Duration::from_secs(5);
/// Results with more cells than this are indexed off the UI thread.
pub(super) const SYNC_VIEW_CELLS: usize = 200_000;
pub(super) struct CachedView {
    pub(super) key: ViewKey,
    pub(super) source: std::sync::Weak<Results>,
    pub(super) index: std::rc::Rc<crate::result_view::Index>,
}
/// An index being built off the UI thread. Dropping it cancels the build.
pub(super) struct ViewJob {
    pub(super) key: ViewKey,
    pub(super) cancel: Arc<std::sync::atomic::AtomicBool>,
    pub(super) receiver: mpsc::Receiver<crate::result_view::Index>,
}
impl Drop for ViewJob {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
/// A header separator: the cell drawn as `│`, the wider area that grabs it
/// (one cell either side, kept off the panel border and scrollbar), the
/// column on its left and that column's unclipped width.
#[derive(Clone, Copy, Debug)]
pub(super) struct ColumnGrip {
    pub(super) cell: Rect,
    pub(super) hit: Rect,
    pub(super) index: usize,
    pub(super) width: u16,
}
/// Identifies a column within a result table by header name and its 0-based
/// occurrence among identically named headers (e.g. CSV `PID,PID`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct ColumnKey {
    pub(super) name: String,
    pub(super) occurrence: usize,
}
impl ColumnKey {
    #[cfg(test)]
    pub(super) fn new(name: impl Into<String>, occurrence: usize) -> Self {
        Self {
            name: name.into(),
            occurrence,
        }
    }
    pub(super) fn for_index(columns: &[String], index: usize) -> Option<Self> {
        let name = columns.get(index)?;
        let occurrence = columns
            .get(..index)
            .map_or(0, |prefix| prefix.iter().filter(|c| *c == name).count());
        Some(Self {
            name: name.clone(),
            occurrence,
        })
    }
    pub(super) fn all(columns: &[String]) -> Vec<Self> {
        let mut counts: HashMap<&str, usize> = HashMap::with_capacity(columns.len());
        columns
            .iter()
            .map(|name| {
                let entry = counts.entry(name.as_str()).or_insert(0);
                let occurrence = *entry;
                *entry += 1;
                Self {
                    name: name.clone(),
                    occurrence,
                }
            })
            .collect()
    }
    pub(super) fn find_in(&self, columns: &[String]) -> Option<usize> {
        let mut seen = 0usize;
        for (index, name) in columns.iter().enumerate() {
            if *name == self.name {
                if seen == self.occurrence {
                    return Some(index);
                }
                seen += 1;
            }
        }
        None
    }
}
/// A column resize in progress: the view, column, pointer position and width
/// at press time, plus whether the pointer moved and whether a release without
/// movement completes a double-click reset.
#[derive(Clone, Debug)]
pub(super) struct ColumnDrag {
    pub(super) view: String,
    pub(super) column: ColumnKey,
    pub(super) origin: u16,
    pub(super) width: u16,
    pub(super) moved: bool,
    pub(super) double_click: bool,
}
/// Completed non-dragged click on a header separator, bound to its view and column.
#[derive(Clone, Debug)]
pub(super) struct GripClick {
    pub(super) view: String,
    pub(super) column: ColumnKey,
    pub(super) at: Instant,
}
pub(super) type ColumnWidths = (
    std::rc::Rc<crate::result_view::Index>,
    Vec<String>,
    Vec<u16>,
);
pub(super) struct IndexedRows<'a> {
    pub(super) result: Option<&'a Results>,
    pub(super) index: std::rc::Rc<crate::result_view::Index>,
}
/// A borrowed table row plus the single cell a tree decoration replaces.
pub(super) type BorrowedRow<'a> = (&'a [String], Option<(usize, String)>);
impl<'a> IndexedRows<'a> {
    pub(super) fn len(&self) -> usize {
        self.index.visible.len()
    }
    pub(super) fn get(&self, position: usize) -> Option<Vec<String>> {
        self.index.row(self.result?, position)
    }
    /// Borrowed rows for rendering, so drawing a frame does not clone the
    /// visible page out of the result set. The index is shared by reference
    /// rather than cloned per row.
    pub(super) fn sample(
        &'a self,
        start: usize,
        count: usize,
    ) -> impl Iterator<Item = BorrowedRow<'a>> + Clone + 'a {
        let end = start.saturating_add(count).min(self.len());
        (start..end).filter_map(move |i| self.index.cells(self.result?, i))
    }
}
/// One table row, substituting the decorated cell when the row is part of a
/// collapsed or expanded tree.
pub(super) fn cells_to_line((cells, decoration): BorrowedRow<'_>) -> Vec<Line<'static>> {
    cells
        .iter()
        .enumerate()
        .map(|(i, cell)| {
            let text = match decoration.as_ref() {
                Some((column, decorated)) if *column == i => decorated,
                _ => cell,
            };
            Line::from(escaped(text))
        })
        .collect()
}

/// One value per asset section. Indexing is total: the slots are 0, 1 and 2, and the
/// last section takes anything larger.
#[derive(Default)]
pub(super) struct PerSection<T>(pub(super) [T; 3]);
impl<T> std::ops::Index<usize> for PerSection<T> {
    type Output = T;
    fn index(&self, slot: usize) -> &T {
        let [images, symbols, remote] = &self.0;
        match slot {
            0 => images,
            1 => symbols,
            _ => remote,
        }
    }
}
impl<T> std::ops::IndexMut<usize> for PerSection<T> {
    fn index_mut(&mut self, slot: usize) -> &mut T {
        let [images, symbols, remote] = &mut self.0;
        match slot {
            0 => images,
            1 => symbols,
            _ => remote,
        }
    }
}
