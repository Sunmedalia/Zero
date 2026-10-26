#[derive(Clone, Copy, PartialEq, Eq)]
enum InputKind {
    Image,
    Symbols,
    Search,
    AssetsSearch,
    Export,
    History,
    ImageDirectory,
    SymbolsDirectory,
    ExportDirectory,
    PageSize,
    SymbolRepository,
}
#[derive(Clone)]
enum Dialog {
    GenerateSymbols {
        automatic: bool,
        fields: [String; 3],
        field: usize,
        cursor: usize,
        selected: bool,
        error: String,
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
        fields: [String; 8],
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
    Detail {
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
enum Page {
    #[default]
    Assets,
    Analysis,
    Cache,
}
impl Page {
    const ALL: [Self; 3] = [Self::Assets, Self::Analysis, Self::Cache];
    fn index(self) -> usize {
        match self {
            Self::Assets => 0,
            Self::Analysis => 1,
            Self::Cache => 2,
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::Assets => "资源库",
            Self::Analysis => "分析",
            Self::Cache => "缓存",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum AssetSection {
    Images,
    #[default]
    Symbols,
    Remote,
}
impl AssetSection {
    fn slot(self) -> usize {
        match self {
            Self::Images => 0,
            Self::Symbols => 1,
            Self::Remote => 2,
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::Images => "镜像",
            Self::Symbols => "本地符号",
            Self::Remote => "远程符号",
        }
    }
}
#[derive(Clone)]
enum Work {
    SavedCatalog(String),
    Inventory,
    RemoveCache(Vec<PathBuf>),
    Record(String),
    History(PathBuf),
    Export(PathBuf, Results, Vec<Vec<String>>),
    Verify,
    Clear(Vec<cache::Scope>),
    PrepareKali,
    GenerateSymbols([PathBuf; 3]),
    Identify,
    InspectSymbols(PathBuf),
    RefreshLookup,
    Analyze(bool),
    FetchMatched,
    MatchLocal(Vec<PathBuf>, String),
    Download(RemoteMatch),
    Catalog(String, bool),
    CatalogDownload(RemoteMatch),
}
enum WorkerEvent {
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
    SymbolDetails(PathBuf, String),
    LocalMatched(symbols::LocalMatches, String, Results),
    Links(Vec<RemoteMatch>),
    Downloaded(PathBuf),
    Progress(String),
    Done(Outcome),
    Failed(String),
}
#[derive(Clone, Default)]
struct HitMap {
    scrollbars: Vec<scrollbars::Scrollbar>,
    asset_rows: Vec<(Rect, AssetSection, usize)>,
    result_tabs: Vec<(Rect, Rect, usize)>,
    result_tab_steps: Vec<(Rect, usize)>,
    plugin_toggle: Rect,
    cache_scopes: Rect,
    cache_items: Rect,
    cache_offset: usize,
    header: Rect,
    /// Clickable header fields: image on the first row, symbol on the second
    /// when the header has one.
    header_image: Rect,
    header_symbol: Rect,
    tabs: Vec<(Rect, Page)>,
    systems: Vec<(Rect, crate::analysis::Os)>,
    regions: Vec<(Rect, Focus)>,
    sources: Vec<(Rect, AssetSection)>,
    remote_views: Vec<(Rect, bool)>,
    asset_lists: Vec<(Rect, AssetSection, usize)>,
    asset_buttons: Vec<(Rect, AssetSection, KeyCode)>,
    asset_searches: Vec<(Rect, AssetSection)>,
    dump_fields: Vec<(Rect, usize)>,
    dump_modes: Vec<(Rect, Plugin)>,
    assets: Rect,
    asset_offset: usize,
    asset_detail: Rect,
    search: Rect,
    menu: Rect,
    result: Rect,
    workbench: Rect,
    inspector: Rect,
    popup: Rect,
    menu_offset: usize,
    row_offset: usize,
    popup_offset: usize,
    popup_list: Rect,
    columns: Vec<Rect>,
    buttons: Vec<(Rect, KeyCode)>,
}
/// Everything `asset_list_for` filters on. When all of it is unchanged the
/// previous index is still valid.
/// Cached filtered indices for one asset section.
type AssetIndex = Option<(AssetIndexKey, Vec<usize>)>;
/// Identity of the remote list plus the query. Derived from the buffer address
/// and length, so replacing the vector invalidates the cache even when the new
/// list has the same size — no write site has to remember to bump a counter.
#[derive(Clone, PartialEq, Eq)]
struct RemoteIndexKey {
    identity: usize,
    len: usize,
    query: String,
}
#[derive(Clone, PartialEq, Eq)]
struct AssetIndexKey {
    /// Buffer address and length of the asset vector: replacing it invalidates
    /// the cache even when the new list has the same size.
    identity: usize,
    len: usize,
    query: String,
    local_only: bool,
    hidden: usize,
    matches: usize,
}
#[derive(Default)]
struct View {
    query: String,
    sort: Option<usize>,
    descending: bool,
    row: usize,
    collapsed: HashSet<String>,
    state: TableState,
    horizontal: usize,
}
pub struct App {
    terminal_size: std::cell::Cell<Option<(u16, u16)>>,
    drag: Option<scrollbars::Drag>,
    open_tabs: Vec<OpenTab>,
    active_tab: Option<usize>,
    tab_offset: std::cell::Cell<usize>,
    tab_layout: std::cell::Cell<Option<(Option<usize>, u16)>>,
    plugins_collapsed: bool,
    cache_page: cache_page::CachePage,
    page: Page,
    section: AssetSection,
    symbol_source: AssetSection,
    root: PathBuf,
    registry: Registry,
    assets: Vec<Asset>,
    asset_rows: [usize; 3],
    asset_scroll: [usize; 3],
    asset_queries: [String; 3],
    asset_states: RefCell<[ListState; 3]>,
    asset_details: HashMap<PathBuf, String>,
    asset_identities: HashMap<PathBuf, crate::image::BoundIdentity>,
    asset_digests: HashMap<PathBuf, String>,
    remote: Vec<RemoteMatch>,
    remote_matches: Option<Vec<RemoteMatch>>,
    remote_loaded: bool,
    remote_total: usize,
    remote_index_cache: RefCell<Option<(RemoteIndexKey, Vec<usize>)>>,
    remote_catalog: bool,
    download_url: Option<String>,
    downloads: HashMap<String, PathBuf>,
    hidden_cache_copies: HashSet<PathBuf>,
    local_matches: HashMap<PathBuf, Vec<String>>,
    local_match_stamp: Option<String>,
    prepared_stamp: Option<String>,
    verified: Option<crate::engine_service::Verified>,
    result_origins: HashMap<String, String>,
    local_match_errors: Vec<String>,
    local_only_matches: bool,
    image: Option<PathBuf>,
    symbols: PathBuf,
    cache: PathBuf,
    settings: Settings,
    hits: RefCell<HitMap>,
    /// Canonical root and per-input display paths. Both are filled lazily from
    /// `&self` and dropped when the asset list is rebuilt.
    root_cached: std::cell::OnceCell<PathBuf>,
    path_cache: RefCell<HashMap<PathBuf, String>>,
    /// Filtered asset indices per section, keyed by the state that produced
    /// them. `asset_list_for` runs several times per frame.
    asset_index_cache: RefCell<[AssetIndex; 3]>,
    table_state: RefCell<TableState>,
    focus: Focus,
    menu: usize,
    /// First menu row drawn. `hits` is rebuilt every frame, so the scroll
    /// position has to live on the app or the list snaps back to the top.
    /// A `Cell` because the renderer holds `&self`.
    menu_scroll: std::cell::Cell<usize>,
    plugin: Plugin,
    windows: bool,
    analysis_options: crate::analysis::Options,
    results: ResultStore,
    view_cache: RefCell<Option<(ViewKey, std::rc::Rc<crate::result_view::Index>)>>,
    history_revision: u64,
    history: Option<Arc<Results>>,
    history_source: Option<PathBuf>,
    query: String,
    sort: Option<usize>,
    descending: bool,
    row: usize,
    collapsed: HashSet<String>,
    status: String,
    logs: VecDeque<String>,
    started: Option<Instant>,
    progress: Option<u16>,
    dialog: Option<Dialog>,
    choice: Option<String>,
    dump_options: Option<(Plugin, DumpOptions)>,
    receiver: Option<mpsc::Receiver<WorkerEvent>>,
    job: Option<Job>,
    worker: Option<thread::JoinHandle<()>>,
    session: Arc<Mutex<linux::Session>>,
    last_error: Option<String>,
    back_dialog: Option<Box<Dialog>>,
    pending_work: Option<Work>,
    pending_path: Option<(InputKind, PathBuf)>,
    pending_execution: Option<ExecutionSnapshot>,
    preparation: Preparation,
    preparation_candidates: Vec<(PathBuf, String)>,
    task_id: u64,
    object_version: u64,
    active_request: Option<Execution>,
    symbol_retry: Option<ExecutionSnapshot>,
    preparation_lookup: bool,
    parameter_drafts: HashMap<String, crate::analysis::Options>,
    result_requests: HashMap<String, String>,
    pending_os: Option<crate::analysis::Os>,
    horizontal: usize,
    inspector: bool,
    detail_scroll: usize,
    views: HashMap<String, View>,
    /// Enter on a not-yet-selected asset: open the analysis page once matching is ready.
    enter_when_ready: bool,
    /// First `q` during a running task only arms the quit.
    quit_armed: bool,
}

#[derive(Default)]
struct ResultStore {
    values: HashMap<String, Results>,
    revision: u64,
}
impl std::ops::Deref for ResultStore {
    type Target = HashMap<String, Results>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
impl std::ops::DerefMut for ResultStore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.revision += 1;
        &mut self.values
    }
}
#[derive(PartialEq, Eq)]
/// Inputs to the filtered/sorted row index.
///
/// The collapse set and query are fingerprinted rather than cloned: this key is
/// rebuilt on every `visible()` call, which happens several times per frame.
struct ViewKey {
    revision: u64,
    identity: usize,
    history_revision: u64,
    query: String,
    sort: Option<usize>,
    descending: bool,
    tree: Option<(usize, usize)>,
    collapsed: u64,
}
struct IndexedRows<'a> {
    result: Option<&'a Results>,
    index: std::rc::Rc<crate::result_view::Index>,
}
/// A borrowed table row plus the single cell a tree decoration replaces.
type BorrowedRow<'a> = (&'a [String], Option<(usize, String)>);
impl<'a> IndexedRows<'a> {
    fn len(&self) -> usize {
        self.index.visible.len()
    }
    fn get(&self, position: usize) -> Option<Vec<String>> {
        self.index.row(self.result?, position)
    }
    /// Borrowed rows for rendering, so drawing a frame does not clone the
    /// visible page out of the result set. The index is shared by reference
    /// rather than cloned per row.
    fn sample(
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
fn cells_to_line((cells, decoration): BorrowedRow<'_>) -> Vec<Line<'static>> {
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
