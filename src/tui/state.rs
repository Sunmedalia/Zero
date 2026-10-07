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
    Cache {
        entries: Vec<cache::Entry>,
        scopes: Vec<cache::Scope>,
        selected: usize,
        confirm: bool,
    },
    Commands {
        query: String,
        selected: usize,
    },
    WindowsParameters {
        advanced: bool,
        fields: [String; 6],
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
}
impl Page {
    const ALL: [Self; 2] = [Self::Assets, Self::Analysis];
    fn index(self) -> usize {
        match self {
            Self::Assets => 0,
            Self::Analysis => 1,
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::Assets => "资源库",
            Self::Analysis => "分析",
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
    Tagged(u64, u64, Box<WorkerEvent>),
    Cleared(cache::Report),
    Identified(Results),
    IndexRefreshed,
    CatalogLinks(Vec<RemoteMatch>),
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
    header: Rect,
    tabs: Vec<(Rect, Page)>,
    systems: Vec<(Rect, crate::analysis::Os)>,
    regions: Vec<(Rect, Focus)>,
    sources: Vec<(Rect, AssetSection)>,
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
    columns: Vec<Rect>,
    buttons: Vec<(Rect, KeyCode)>,
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
    remote: Vec<RemoteMatch>,
    remote_catalog: bool,
    download_url: Option<String>,
    downloads: HashMap<String, PathBuf>,
    hidden_cache_copies: HashSet<PathBuf>,
    local_matches: HashMap<PathBuf, Vec<String>>,
    local_match_stamp: Option<String>,
    prepared_stamp: Option<String>,
    local_match_errors: Vec<String>,
    local_only_matches: bool,
    image: Option<PathBuf>,
    symbols: PathBuf,
    cache: PathBuf,
    settings: Settings,
    hits: RefCell<HitMap>,
    table_state: RefCell<TableState>,
    focus: Focus,
    menu: usize,
    plugin: Plugin,
    windows: bool,
    analysis_options: crate::analysis::Options,
    results: ResultStore,
    view_cache: RefCell<Option<(ViewKey, std::rc::Rc<crate::result_view::Index>)>>,
    history_revision: u64,
    history: Option<Results>,
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
struct ViewKey {
    revision: u64,
    identity: usize,
    history_revision: u64,
    query: String,
    sort: Option<usize>,
    descending: bool,
    tree: Option<(usize, usize)>,
    collapsed: HashSet<String>,
}
struct IndexedRows<'a> {
    result: Option<&'a Results>,
    index: std::rc::Rc<crate::result_view::Index>,
}
impl IndexedRows<'_> {
    fn len(&self) -> usize {
        self.index.visible.len()
    }
    fn get(&self, position: usize) -> Option<Vec<String>> {
        self.index.row(self.result?, position)
    }
    fn range(&self, start: usize, count: usize) -> Vec<Vec<String>> {
        (start..start.saturating_add(count).min(self.len()))
            .filter_map(|i| self.get(i))
            .collect()
    }
}
