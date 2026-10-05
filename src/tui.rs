use crate::{
    Job, cache,
    dump::{DumpOptions, parse_address},
    linux::{self, Outcome, PLUGINS, Plugin},
    store::{self, Results, Settings},
    symbols::{self, RemoteMatch},
    workspace::{self, Asset, Kind, Registry},
};
use anyhow::{Context, Result};
use crossterm::{
    cursor::Show,
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
        MouseEventKind,
    },
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Flex, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, StatefulWidget,
        Table, TableState, Wrap,
    },
};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, atomic::Ordering, mpsc},
    thread,
    time::{Duration, Instant},
};

const ACCENT: Color = Color::Rgb(72, 201, 184);
const FOCUS: Color = Color::Rgb(243, 178, 92);
const SELECTED_BG: Color = Color::Rgb(31, 54, 61);
const SURFACE: Color = Color::Rgb(17, 25, 31);

fn plugin_label(plugin: Plugin) -> &'static str {
    if plugin.is_dump() {
        "dump"
    } else {
        plugin.name()
    }
}
fn plugin_matches(query: &str) -> Vec<Plugin> {
    let query = query.to_lowercase();
    let mut plugins: Vec<_> = PLUGINS
        .iter()
        .filter(|d| !d.plugin.is_dump() && d.name.contains(&query))
        .map(|d| d.plugin)
        .collect();
    if "dump".contains(&query) {
        plugins.push(Plugin::Procdump);
    }
    plugins
}
fn edit_input(text: &mut String, cursor: &mut usize, selected: &mut bool, key: KeyEvent) {
    let previous =
        |text: &str, cursor: usize| text[..cursor].char_indices().last().map_or(0, |(i, _)| i);
    let next = |text: &str, cursor: usize| {
        text[cursor..]
            .chars()
            .next()
            .map_or(cursor, |c| cursor + c.len_utf8())
    };
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char('a') if control => {
            *selected = true;
            *cursor = text.len();
        }
        KeyCode::Char('u') if control => {
            text.clear();
            *cursor = 0;
            *selected = false;
        }
        KeyCode::Left => {
            *selected = false;
            *cursor = previous(text, *cursor);
        }
        KeyCode::Right => {
            *selected = false;
            *cursor = next(text, *cursor);
        }
        KeyCode::Home => {
            *selected = false;
            *cursor = 0;
        }
        KeyCode::End => {
            *selected = false;
            *cursor = text.len();
        }
        KeyCode::Backspace | KeyCode::Delete if *selected => {
            text.clear();
            *cursor = 0;
            *selected = false;
        }
        KeyCode::Backspace if *cursor > 0 => {
            let start = previous(text, *cursor);
            text.replace_range(start..*cursor, "");
            *cursor = start;
        }
        KeyCode::Delete if *cursor < text.len() => {
            text.replace_range(*cursor..next(text, *cursor), "");
        }
        KeyCode::Char(c) if !control => {
            if *selected {
                text.clear();
                *cursor = 0;
                *selected = false;
            }
            text.insert(*cursor, c);
            *cursor += c.len_utf8();
        }
        _ => {}
    }
}
fn navigation_plugins() -> Vec<Plugin> {
    let categories = [
        "Process",
        "System",
        "Memory",
        "Files",
        "Network",
        "Integrity",
    ];
    categories
        .into_iter()
        .flat_map(|category| {
            PLUGINS
                .iter()
                .filter(move |d| !d.plugin.is_dump() && d.plugin.category() == category)
                .map(|d| d.plugin)
        })
        .collect()
}
fn menu_items() -> Vec<String> {
    [
        vec!["image [i]".into(), "symbols [y]".into()],
        navigation_plugins()
            .iter()
            .map(|p| p.name().to_string())
            .collect(),
        vec!["dump".into()],
    ]
    .concat()
}
fn escaped(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn banner_candidates(result: &Results) -> Vec<&Vec<String>> {
    let clean = result
        .rows
        .iter()
        .filter(|row| {
            row.get(1).is_some_and(|banner| {
                let banner = banner.trim_end_matches(['\n', '\0']);
                banner.len() <= 512
                    && banner.starts_with("Linux version ")
                    && banner.contains('#')
                    && (banner.contains("gcc") || banner.contains("clang"))
                    && !banner.chars().any(char::is_control)
            })
        })
        .collect::<Vec<_>>();
    if clean.is_empty() {
        result.rows.iter().collect()
    } else {
        clean
    }
}
fn compare_values(a: &str, b: &str) -> std::cmp::Ordering {
    let number = |v: &str| {
        v.strip_prefix("0x").map_or_else(
            || v.parse::<u64>().ok(),
            |v| u64::from_str_radix(v, 16).ok(),
        )
    };
    match (number(a), number(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        _ => a.cmp(b),
    }
}
fn table_widths(columns: &[String], rows: &[Vec<String>]) -> Vec<u16> {
    columns
        .iter()
        .enumerate()
        .map(|(i, column)| {
            let header = Span::raw(column).width();
            let data = rows
                .iter()
                .take(200)
                .filter_map(|r| r.get(i))
                .map(|v| Span::raw(escaped(v)).width())
                .max()
                .unwrap_or(0);
            header.max(data.min(60)).clamp(3, 120) as u16
        })
        .collect()
}
fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    a == b
        || a.canonicalize()
            .ok()
            .zip(b.canonicalize().ok())
            .is_some_and(|(a, b)| a == b)
}
fn detail_lines(text: &str, width: u16) -> Vec<String> {
    let width = width.max(1) as usize;
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut used = 0;
        for c in paragraph.chars() {
            let n = Span::raw(c.to_string()).width();
            if used + n > width && !line.is_empty() {
                lines.push(std::mem::take(&mut line));
                used = 0;
            }
            line.push(c);
            used += n;
        }
        lines.push(line);
    }
    lines
}
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
    Analysis,
    Assets,
}
impl Page {
    const ALL: [Self; 2] = [Self::Analysis, Self::Assets];
    fn index(self) -> usize {
        usize::from(self == Self::Assets)
    }
    fn title(self) -> &'static str {
        match self {
            Self::Analysis => "分析",
            Self::Assets => "镜像与符号",
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
    Identify,
    InspectSymbols(PathBuf),
    RefreshLookup,
    Analyze(bool),
    Lookup,
    MatchLocal(Vec<PathBuf>, String),
    Download(RemoteMatch),
    Catalog(String, bool),
    CatalogDownload(RemoteMatch),
}
enum WorkerEvent {
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
fn asset_actions(section: AssetSection) -> Vec<(&'static str, KeyCode)> {
    let mut actions = match section {
        AssetSection::Images => vec![
            ("选用镜像 Enter", KeyCode::Enter),
            ("导入镜像 a", KeyCode::Char('a')),
        ],
        AssetSection::Symbols => vec![
            ("选用符号 Enter", KeyCode::Enter),
            ("导入符号 a", KeyCode::Char('a')),
            ("全部／匹配 z", KeyCode::Char('z')),
        ],
        AssetSection::Remote => vec![
            ("查看详情 Enter", KeyCode::Enter),
            ("下载到 symbols w", KeyCode::Char('w')),
            ("获取完整索引 g", KeyCode::Char('g')),
        ],
    };
    actions.extend([
        ("搜索 /", KeyCode::Char('/')),
        ("完整详情 d", KeyCode::Char('d')),
        ("本地匹配 m", KeyCode::Char('m')),
        ("远程匹配 M", KeyCode::Char('M')),
        ("识别内核 b", KeyCode::Char('b')),
        ("刷新 r", KeyCode::Char('r')),
        ("开始分析 x", KeyCode::Char('x')),
        ("本地／远程 t", KeyCode::Char('t')),
        ("在线／离线 o", KeyCode::Char('o')),
    ]);
    if section != AssetSection::Remote {
        actions.push(("移出清单 Delete", KeyCode::Delete));
    }
    actions
}
const COMMANDS: &[(&str, KeyCode)] = &[
    ("获取远程符号索引", KeyCode::Char('g')),
    ("搜索远程符号", KeyCode::Char('f')),
    ("打开镜像与符号", KeyCode::F(3)),
    ("打开分析页", KeyCode::F(2)),
    ("打开镜像", KeyCode::Char('i')),
    ("选择本地符号", KeyCode::Char('y')),
    ("搜索插件", KeyCode::Char('p')),
    ("Dump 导出进程／地址范围／ELF", KeyCode::Char('D')),
    ("当前镜像 → 本地符号匹配", KeyCode::Char('m')),
    ("当前镜像 → 远程精确匹配", KeyCode::Char('M')),
    ("识别内核候选", KeyCode::Char('b')),
    ("管理缓存 cache [c]", KeyCode::Char('c')),
    ("生成 Kali ARM64 精确符号", KeyCode::Char('g')),
    ("搜索当前列表／内容", KeyCode::Char('/')),
    ("排序", KeyCode::Char('s')),
    ("导出结果", KeyCode::Char('e')),
    ("显示详情", KeyCode::Char('d')),
    ("查看诊断", KeyCode::Char('v')),
    ("历史导出记录", KeyCode::Char('h')),
    ("目录与分页设置", KeyCode::Char(',')),
    ("任务日志", KeyCode::Char('l')),
    ("每页行数", KeyCode::Char('n')),
    ("前一页", KeyCode::Char('[')),
    ("后一页", KeyCode::Char(']')),
    ("导入当前资产", KeyCode::Char('a')),
    ("刷新当前资产", KeyCode::Char('r')),
    ("重新分析", KeyCode::Char('r')),
    ("在线／离线模式", KeyCode::Char('o')),
    ("帮助", KeyCode::F(1)),
];
fn command_matches(query: &str, page: Page, focus: usize) -> Vec<usize> {
    COMMANDS
        .iter()
        .enumerate()
        .filter(|(_, (label, key))| {
            let result_action = matches!(key, KeyCode::Char('e' | 's' | 'v'));
            let analysis_only = result_action
                || label.contains("重新分析")
                || label.contains("搜索插件")
                || matches!(key, KeyCode::Char('n' | '[' | ']'));
            let assets_only = label.contains("当前资产");
            (!analysis_only || page == Page::Analysis)
                && (!assets_only || page != Page::Analysis)
                && (!result_action || focus >= 2)
                && label.contains(query)
                && if page == Page::Assets {
                    !label.contains("生成 Kali")
                } else {
                    !label.contains("远程符号")
                }
        })
        .map(|(i, _)| i)
        .collect()
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
    download_analyzes: bool,
    lookup_dialog: bool,
    download_url: Option<String>,
    downloads: HashMap<String, PathBuf>,
    hidden_cache_copies: HashSet<PathBuf>,
    local_matches: HashMap<PathBuf, Vec<String>>,
    local_match_stamp: Option<String>,
    local_match_errors: Vec<String>,
    local_only_matches: bool,
    image: Option<PathBuf>,
    symbols: PathBuf,
    cache: PathBuf,
    settings: Settings,
    hits: RefCell<HitMap>,
    table_state: RefCell<TableState>,
    focus: usize,
    menu: usize,
    plugin: Plugin,
    results: HashMap<String, Results>,
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
    pending_plugin: Option<Plugin>,
    pending_cache: bool,
    horizontal: usize,
    inspector: bool,
    detail_scroll: usize,
    views: HashMap<String, View>,
}
impl App {
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
            page: Page::Analysis,
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
            download_analyzes: false,
            lookup_dialog: false,
            download_url: None,
            downloads: HashMap::new(),
            hidden_cache_copies: HashSet::new(),
            local_matches: HashMap::new(),
            local_match_stamp: None,
            local_match_errors: Vec::new(),
            local_only_matches: false,
            image,
            symbols,
            cache,
            settings,
            hits: RefCell::new(HitMap::default()),
            table_state: RefCell::new(TableState::default()),
            focus: 1,
            menu: 2,
            plugin: Plugin::Pslist,
            results: HashMap::new(),
            history: None,
            query: String::new(),
            sort: None,
            descending: false,
            row: 0,
            collapsed: HashSet::new(),
            status: "选择分析并按 Enter；i 镜像 / y 符号".into(),
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
            pending_plugin: None,
            pending_cache: false,
            horizontal: 0,
            inspector: false,
            detail_scroll: 0,
            views: HashMap::new(),
        }
    }
    fn switch_page(&mut self, page: Page) {
        self.page = page;
        self.focus = 1;
        if page != Page::Analysis {
            self.refresh_assets();
        }
    }
    fn switch_section(&mut self, section: AssetSection) {
        self.page = Page::Assets;
        self.section = section;
        if section != AssetSection::Images {
            self.symbol_source = section;
        }
        self.focus = 1;
        self.refresh_assets();
    }
    fn local_work(&self) -> Work {
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
        Work::MatchLocal(paths, self.local_stamp())
    }
    fn prepare_selected_image(&mut self) {
        if self.job.is_some() {
            return;
        }
        if self.local_match_stamp.as_ref() == Some(&self.local_stamp()) {
            self.local_only_matches = true;
            self.status = "复用内核识别与本地符号匹配；选用符号后开始分析".into();
        } else {
            self.start_work(self.local_work());
        }
    }
    fn available_commands(&self, query: &str) -> Vec<(&'static str, KeyCode)> {
        if self.page == Page::Analysis {
            command_matches(query, self.page, self.focus)
                .into_iter()
                .map(|i| COMMANDS[i])
                .collect()
        } else {
            let mut commands = asset_actions(self.section);
            commands.extend([
                ("打开分析页 F2", KeyCode::F(2)),
                ("打开镜像与符号 F3", KeyCode::F(3)),
                ("目录设置 ,", KeyCode::Char(',')),
                ("缓存管理 c", KeyCode::Char('c')),
                ("任务日志 l", KeyCode::Char('l')),
                ("帮助 F1", KeyCode::F(1)),
                ("取消任务 Esc", KeyCode::Esc),
            ]);
            commands
                .into_iter()
                .filter(|(label, _)| label.contains(query))
                .collect()
        }
    }
    fn asset_disabled(&self, section: AssetSection, key: KeyCode) -> Option<&'static str> {
        let busy = self.job.is_some();
        if matches!(key, KeyCode::Char('m' | 'M' | 'b' | 'x')) && self.image.is_none() {
            return Some("请先选用镜像");
        }
        if key == KeyCode::Char('x')
            && self.plugin != Plugin::Banners
            && self.symbols.as_os_str().is_empty()
        {
            return Some("请先选用本地符号");
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
        if matches!(key, KeyCode::Enter | KeyCode::Delete | KeyCode::Char('d')) {
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
                KeyCode::Char('a' | 'm' | 'M' | 'b' | 'x' | 'w' | 'g' | 'r' | 'o')
                    | KeyCode::Delete
            )
        {
            return Some("任务执行中，请等待或取消");
        }
        if busy && key == KeyCode::Enter && section != AssetSection::Remote {
            return Some("任务执行中，请等待或取消");
        }
        None
    }
    fn remote_detail_text(&self, candidate: &RemoteMatch) -> String {
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
    fn open_asset_detail(&mut self) {
        if self.section == AssetSection::Remote {
            if let Some(candidate) = self
                .remote_list()
                .get(self.asset_rows[2])
                .map(|m| (*m).clone())
            {
                self.dialog = Some(Dialog::RemoteDetail {
                    candidate,
                    scroll: 0,
                });
            }
        } else if let Some(asset) = self.selected_asset() {
            self.dialog = Some(Dialog::AssetDetail {
                asset: asset.clone(),
                scroll: 0,
            });
            if asset.kind == Kind::Symbols
                && !asset.directory
                && !self.asset_details.contains_key(&asset.path)
                && self.job.is_none()
            {
                self.start_work(Work::InspectSymbols(asset.path));
            }
        }
    }

    fn refresh_assets(&mut self) {
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
    fn invalidate_source(&mut self) {
        self.local_matches.clear();
        self.local_match_stamp = None;
        self.local_match_errors.clear();
        self.local_only_matches = false;
        self.dump_options = None;
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
    fn invalidate_symbols(&mut self) {
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
    fn local_stamp(&self) -> String {
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
    fn symbol_target(&mut self, remote: bool) {
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
            self.start_work(Work::Lookup);
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
    fn focus_asset(&mut self, kind: Kind, path: &std::path::Path) {
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
    fn page_rows(&self) -> usize {
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
    fn display_path(&self, path: &std::path::Path) -> String {
        let root = self.root.canonicalize().unwrap_or(self.root.clone());
        let path = path.canonicalize().unwrap_or(path.to_path_buf());
        path.strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
    }
    fn asset_list(&self) -> Vec<&Asset> {
        self.asset_list_for(self.section)
    }
    fn asset_list_for(&self, section: AssetSection) -> Vec<&Asset> {
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
    fn remote_cached(&self, candidate: &RemoteMatch) -> bool {
        self.downloads
            .get(&candidate.url)
            .is_some_and(|p| p.is_file())
            || symbols::cache_filename(&candidate.path)
                .is_ok_and(|name| self.cache.join("symbols/isf").join(name).is_file())
    }
    fn remote_list(&self) -> Vec<&RemoteMatch> {
        let query = self.asset_queries[2].to_lowercase();
        self.remote
            .iter()
            .filter(|m| {
                let text = format!("{} {} {}", m.path, m.banner, m.url).to_lowercase();
                query.split_whitespace().all(|word| text.contains(word))
            })
            .collect()
    }
    fn asset_count(&self) -> usize {
        if self.section == AssetSection::Remote {
            self.remote_list().len()
        } else {
            self.asset_list().len()
        }
    }
    fn selected_asset(&self) -> Option<Asset> {
        self.asset_list()
            .get(self.asset_rows[self.section.slot()])
            .map(|a| (*a).clone())
    }
    fn asset_text(&self) -> String {
        if self.section == AssetSection::Remote {
            return self.remote_list().get(self.asset_rows[2]).map(|m|format!("远程符号索引\n\n完整 banner: {}\n\n仓库路径: {}\n\n下载链接: {}\n\n下载前校验索引路径和 ISF。手动获取的符号会加入本地库，选用后再验证镜像。",escaped(&m.banner),escaped(&m.path),escaped(&m.url)))
                .unwrap_or_else(||"g 获取或刷新完整符号索引。\n/ 输入关键词筛选；选中条目后按 Enter 查看详情，w 下载。\nM 按当前镜像 banner 精确匹配。".into());
        }
        let Some(asset) = self.selected_asset() else {
            return "按 a 导入路径，或将文件放入配置的 images／symbols 目录。\n\nEnter 选用；Delete 移出清单，原文件保留。".into();
        };
        self.local_asset_text(&asset)
    }
    fn local_asset_text(&self, asset: &Asset) -> String {
        let mut text = format!(
            "{}\n\n路径: {}\n格式: {}\n大小: {:.2} MiB\n来源: {}\n状态: {}\n\nEnter 选用 · Delete 移出清单（保留文件）",
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
                    "\n\n完整 banner 匹配: {} 个 ISF\n{}\nEnter 选用；x 开始分析并验证页表。",
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
                text.push_str("\n\nd 读取完整 banner、符号摘要和架构配置。");
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
    fn use_selected_asset(&mut self) -> bool {
        if self.job.is_some() {
            self.status = "任务执行中；Esc 取消后再切换资产".into();
            return false;
        }
        let Some(asset) = self.selected_asset() else {
            self.status = "没有选中的资产；按 a 导入路径".into();
            return false;
        };
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
        self.status = "已选用；b 识别、m 匹配、x 进入分析".into();
        true
    }
    fn asset_key(&mut self, key: KeyEvent) -> bool {
        if self.focus == 2 && self.hits.borrow().asset_detail.height == 0 {
            self.focus = 1;
        }
        let slot = self.section.slot();
        if self.focus == 2
            && matches!(
                key.code,
                KeyCode::Up
                    | KeyCode::Down
                    | KeyCode::Char('j')
                    | KeyCode::Char('k')
                    | KeyCode::PageUp
                    | KeyCode::PageDown
                    | KeyCode::Home
                    | KeyCode::End
            )
        {
            let rect = self.hits.borrow().asset_detail;
            let maximum = detail_lines(&self.asset_text(), rect.width.saturating_sub(2))
                .len()
                .saturating_sub(rect.height.saturating_sub(2) as usize);
            self.asset_scroll[slot] = match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.asset_scroll[slot].saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => (self.asset_scroll[slot] + 1).min(maximum),
                KeyCode::PageUp => self.asset_scroll[slot].saturating_sub(10),
                KeyCode::PageDown => (self.asset_scroll[slot] + 10).min(maximum),
                KeyCode::Home => 0,
                _ => maximum,
            };
            return false;
        }
        if let Some(reason) = self.asset_disabled(self.section, key.code) {
            self.status = reason.into();
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => self.cancel(),
            KeyCode::Tab | KeyCode::BackTab => {
                let detail = self.hits.borrow().asset_detail.height > 0;
                let current = if self.focus == 2 {
                    2
                } else if self.section == AssetSection::Images {
                    0
                } else {
                    1
                };
                let count = if detail { 3 } else { 2 };
                let next = (current
                    + if key.code == KeyCode::BackTab {
                        count - 1
                    } else {
                        1
                    })
                    % count;
                self.focus = if next == 2 { 2 } else { 1 };
                if next != 2 {
                    self.section = if next == 0 {
                        AssetSection::Images
                    } else {
                        self.symbol_source
                    };
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.asset_rows[slot] = self.asset_rows[slot].saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.asset_rows[slot] =
                    (self.asset_rows[slot] + 1).min(self.asset_count().saturating_sub(1))
            }
            KeyCode::PageUp => self.asset_rows[slot] = self.asset_rows[slot].saturating_sub(10),
            KeyCode::PageDown => {
                self.asset_rows[slot] =
                    (self.asset_rows[slot] + 10).min(self.asset_count().saturating_sub(1))
            }
            KeyCode::Home => self.asset_rows[slot] = 0,
            KeyCode::End => self.asset_rows[slot] = self.asset_count().saturating_sub(1),
            KeyCode::Char('/') => self.open_input(InputKind::AssetsSearch),
            KeyCode::Char('a') => self.open_files(if self.section == AssetSection::Images {
                InputKind::Image
            } else {
                InputKind::Symbols
            }),
            KeyCode::Enter if self.section == AssetSection::Remote => self.open_asset_detail(),
            KeyCode::Char('w') => {
                if let Some(candidate) = self
                    .remote_list()
                    .get(self.asset_rows[2])
                    .map(|m| (*m).clone())
                {
                    self.start_work(Work::CatalogDownload(candidate));
                }
            }
            KeyCode::Enter => {
                let selected = self.use_selected_asset();
                if selected && self.section == AssetSection::Images {
                    self.symbol_source = AssetSection::Symbols;
                    self.prepare_selected_image();
                }
            }
            KeyCode::Delete if self.section != AssetSection::Remote => {
                if self.job.is_some() {
                    self.status = "任务执行中；Esc 取消后再移出资产".into();
                } else if let Some(asset) = self.selected_asset() {
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
            }
            KeyCode::Char('d') => self.open_asset_detail(),
            KeyCode::Char('b') => {
                self.start_work(Work::Identify);
            }
            KeyCode::Char('m') => self.symbol_target(false),
            KeyCode::Char('M') => self.symbol_target(true),
            KeyCode::Char('z') if self.section == AssetSection::Symbols => {
                self.local_only_matches = !self.local_only_matches;
                self.asset_rows[1] = 0;
            }
            KeyCode::Char('r') if self.section == AssetSection::Remote => {
                if self.remote_catalog {
                    self.start_work(Work::Catalog(
                        self.asset_queries[2].clone(),
                        self.settings.remote_symbols,
                    ));
                } else {
                    self.start_work(Work::RefreshLookup);
                }
            }
            KeyCode::Char('r') => {
                self.asset_details.clear();
                self.refresh_assets();
                self.status = "资产清单已刷新".into();
            }
            KeyCode::Char('g') => {
                self.switch_section(AssetSection::Remote);
                self.remote_catalog = true;
                self.asset_queries[2].clear();
                self.start_work(Work::Catalog(String::new(), self.settings.remote_symbols));
            }
            KeyCode::Char('t') => {
                self.switch_section(if self.symbol_source == AssetSection::Symbols {
                    AssetSection::Remote
                } else {
                    AssetSection::Symbols
                });
            }
            KeyCode::Char('x') => {
                self.switch_page(Page::Analysis);
                self.start();
            }
            KeyCode::Char('c') => self.open_cache(),
            KeyCode::Char('p') => {
                self.dialog = Some(Dialog::Plugins {
                    query: String::new(),
                    selected: 0,
                })
            }
            KeyCode::Char('o') if self.job.is_none() => {
                self.settings.remote_symbols = !self.settings.remote_symbols;
                self.status = if self.settings.remote_symbols {
                    "在线匹配已开启"
                } else {
                    "离线模式：仅使用已缓存索引和符号"
                }
                .into();
            }
            KeyCode::Char('v') | KeyCode::F(8) => self.diagnostics(),
            KeyCode::Char('?') => {
                self.dialog = Some(Dialog::Commands {
                    query: String::new(),
                    selected: 0,
                });
            }
            KeyCode::F(1) => self.help(),
            _ => {}
        }
        false
    }
    fn draw_tabs(&self, frame: &mut Frame, area: Rect) {
        let mut x = area.x;
        for (i, page) in Page::ALL.iter().enumerate() {
            let label = format!(" F{} {} ", i + 2, page.title());
            let width = Span::raw(&label).width() as u16;
            let rect = Rect::new(
                x,
                area.y,
                width.min(area.right().saturating_sub(x)),
                area.height,
            );
            frame.render_widget(
                Paragraph::new(label).style(if self.page.index() == page.index() {
                    Style::default()
                        .bg(SELECTED_BG)
                        .fg(FOCUS)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(ACCENT)
                }),
                rect,
            );
            self.hits.borrow_mut().tabs.push((rect, *page));
            x = x.saturating_add(width + 1);
        }
        if let Some(started) = self.started {
            let pulses = ["●··", "·●·", "··●", "·●·"];
            let pulse =
                pulses[(started.elapsed().as_millis() / 180 % pulses.len() as u128) as usize];
            let label = format!("SCAN {pulse} ");
            let width = Span::raw(&label).width() as u16;
            if area.width > width + 4 {
                frame.render_widget(
                    Paragraph::new(label).style(Style::default().fg(ACCENT)),
                    Rect::new(area.right() - width - 1, area.y, width, area.height),
                );
            }
        }
    }
    fn draw_search(
        &self,
        frame: &mut Frame,
        rect: Rect,
        query: &str,
        kind: InputKind,
        title: &str,
    ) {
        self.hits.borrow_mut().search = rect;
        let editing = match &self.dialog {
            Some(Dialog::Input {
                kind: active,
                cursor,
                ..
            }) if *active == kind => Some(*cursor),
            _ => None,
        };
        let cursor_width = editing
            .map(|cursor| Span::raw(escaped(&query[..cursor])).width())
            .unwrap_or(0);
        let controls = if editing.is_some() && rect.width >= 30 {
            14
        } else {
            0
        };
        let width = rect.width.saturating_sub(2 + controls).max(1) as usize;
        let scroll = cursor_width.saturating_sub(width.saturating_sub(1));
        frame.render_widget(
            Paragraph::new(escaped(query))
                .scroll((0, scroll.min(u16::MAX as usize) as u16))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(title)
                        .border_style(Style::default().fg(if editing.is_some() {
                            FOCUS
                        } else {
                            Color::DarkGray
                        })),
                ),
            rect,
        );
        if controls > 0 && rect.height > 1 {
            let confirm = Rect::new(rect.right() - 15, rect.y + 1, 6, 1);
            let cancel = Rect::new(rect.right() - 8, rect.y + 1, 6, 1);
            frame.render_widget(
                Paragraph::new("[确认]").style(Style::default().fg(FOCUS)),
                confirm,
            );
            frame.render_widget(
                Paragraph::new("[撤销]").style(Style::default().fg(ACCENT)),
                cancel,
            );
            self.hits
                .borrow_mut()
                .buttons
                .extend([(confirm, KeyCode::Enter), (cancel, KeyCode::Esc)]);
        }
        if editing.is_some() && rect.height > 1 && rect.width > 2 {
            frame.set_cursor_position((
                rect.x + 1 + (cursor_width - scroll).min(width - 1) as u16,
                rect.y + 1,
            ));
        }
    }
    fn footer_actions(&self) -> Vec<(&'static str, KeyCode)> {
        let mut actions = if self.page == Page::Analysis {
            match self.focus {
                0 => vec![
                    ("i镜像", KeyCode::Char('i')),
                    ("y符号", KeyCode::Char('y')),
                    ("b识别", KeyCode::Char('b')),
                    ("m本地匹配", KeyCode::Char('m')),
                ],
                1 => vec![
                    ("Enter运行", KeyCode::Enter),
                    ("p插件", KeyCode::Char('p')),
                    ("Tab内容", KeyCode::Tab),
                    ("D Dump", KeyCode::Char('D')),
                    ("r重跑", KeyCode::Char('r')),
                ],
                3 => vec![
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
        } else if self.focus == 2 && self.hits.borrow().asset_detail.height > 0 {
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
        if self.job.is_some() {
            actions.insert(0, ("Esc取消", KeyCode::Esc));
        }
        actions.push(("?更多", KeyCode::Char('?')));
        actions
    }
    fn draw_asset_buttons(
        &self,
        frame: &mut Frame,
        area: Rect,
        section: AssetSection,
        keys: &[KeyCode],
    ) {
        let mut x = area.x;
        let mut y = area.y;
        for (label, key) in asset_actions(section)
            .into_iter()
            .filter(|(_, key)| keys.contains(key))
        {
            let text = format!(" {label} ");
            let width = Span::raw(&text).width() as u16;
            if width > area.width {
                continue;
            }
            if x + width > area.right() {
                x = area.x;
                y += 1;
            }
            if y >= area.bottom() {
                break;
            }
            let rect = Rect::new(x, y, width, 1);
            let disabled = self.asset_disabled(section, key);
            frame.render_widget(
                Paragraph::new(text).style(if disabled.is_some() {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default().fg(FOCUS).bg(SELECTED_BG)
                }),
                rect,
            );
            if disabled.is_none() {
                self.hits
                    .borrow_mut()
                    .asset_buttons
                    .push((rect, section, key));
            }
            x += width + 1;
        }
    }
    fn draw_asset_pane(&self, frame: &mut Frame, area: Rect, section: AssetSection) {
        if area.height == 0 || area.width < 3 {
            return;
        }
        let parts = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(if frame.area().width >= 100 { 2 } else { 1 }),
            Constraint::Min(3),
        ])
        .split(area);
        let query = &self.asset_queries[section.slot()];
        if self.section == section {
            self.draw_search(
                frame,
                parts[0],
                query,
                InputKind::AssetsSearch,
                "搜索 / · Enter 确认",
            );
        } else {
            frame.render_widget(
                Paragraph::new(escaped(query))
                    .block(Block::default().borders(Borders::ALL).title("搜索 /")),
                parts[0],
            );
        }
        self.hits
            .borrow_mut()
            .asset_searches
            .push((parts[0], section));
        self.draw_asset_buttons(
            frame,
            parts[1],
            section,
            &[
                KeyCode::Enter,
                KeyCode::Char('a'),
                KeyCode::Char('w'),
                KeyCode::Char('g'),
                KeyCode::Char('z'),
                KeyCode::Char('d'),
            ],
        );
        let rows = if section == AssetSection::Remote {
            self.remote_list()
                .iter()
                .map(|m| {
                    ListItem::new(format!(
                        "{} {}",
                        if self.downloads.get(&m.url).is_some_and(|p| p.is_file()) {
                            "[已保存]"
                        } else if self.remote_cached(m) {
                            "[缓存]"
                        } else {
                            "[待下载]"
                        },
                        escaped(&m.path)
                    ))
                })
                .collect::<Vec<_>>()
        } else {
            self.asset_list_for(section)
                .iter()
                .map(|a| {
                    let active = if a.kind == Kind::Image {
                        self.image.as_ref().is_some_and(|p| same_path(p, &a.path))
                    } else {
                        same_path(&self.symbols, &a.path)
                    };
                    ListItem::new(format!(
                        "{} {} · #{} · {}{}",
                        if active {
                            "●已选用"
                        } else if self.local_matches.contains_key(&a.path) {
                            "✓匹配"
                        } else {
                            " "
                        },
                        escaped(&self.display_path(&a.path)),
                        a.id(),
                        a.format(),
                        if a.available { "" } else { " · 缺失" }
                    ))
                })
                .collect::<Vec<_>>()
        };
        let count = rows.len();
        let mut states = self.asset_states.borrow_mut();
        let state = &mut states[section.slot()];
        state.select(
            (count > 0).then_some(self.asset_rows[section.slot()].min(count.saturating_sub(1))),
        );
        let mode = match section {
            AssetSection::Symbols if self.local_only_matches => " · 完整 banner 匹配",
            AssetSection::Remote if !self.remote_catalog => " · 镜像精确匹配",
            _ => " · 全部",
        };
        frame.render_stateful_widget(
            List::new(rows)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("{}{} · {} 项", section.title(), mode, count))
                        .border_style(Style::default().fg(
                            if self.section == section && self.focus == 1 {
                                ACCENT
                            } else {
                                Color::DarkGray
                            },
                        )),
                )
                .highlight_symbol("› ")
                .highlight_style(Style::default().bg(SELECTED_BG).fg(FOCUS)),
            parts[2],
            state,
        );
        self.hits
            .borrow_mut()
            .asset_lists
            .push((parts[2], section, state.offset()));
        if self.section == section {
            self.hits.borrow_mut().assets = parts[2];
            self.hits.borrow_mut().asset_offset = state.offset();
        }
        if count == 0 {
            let text = match section {
                AssetSection::Images => "没有镜像 · a 导入镜像",
                AssetSection::Symbols if self.local_only_matches => {
                    "无本地匹配 · M 远程匹配 · z 查看全部"
                }
                AssetSection::Symbols => "没有符号 · a 导入符号",
                AssetSection::Remote => "没有远程条目 · g 获取索引 · / 搜索 · M 精确匹配",
            };
            frame.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .style(Style::default().fg(Color::DarkGray)),
                parts[2].inner(ratatui::layout::Margin::new(1, 1)),
            );
        }
    }
    fn draw_assets(&self, frame: &mut Frame, area: Rect) {
        let regions = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Min(2),
        ])
        .split(area);
        let kernel = self
            .results
            .get("banners")
            .and_then(|r| {
                banner_candidates(r)
                    .first()
                    .and_then(|row| row.get(1))
                    .map(|v| v.split_whitespace().nth(2).unwrap_or("未知").to_owned())
            })
            .unwrap_or_else(|| "尚未识别".into());
        let image = self
            .image
            .as_ref()
            .map(|p| self.display_path(p))
            .unwrap_or_else(|| "未选用镜像".into());
        let symbol = if self.symbols.as_os_str().is_empty() {
            "未选用符号".into()
        } else {
            self.display_path(&self.symbols)
        };
        frame.render_widget(
            Paragraph::new(format!(
                "镜像: {image} · 内核: {kernel}\n符号: {symbol} · 本地匹配 {} 项 · 分析时验证页表",
                self.local_matches.len()
            ))
            .style(Style::default().fg(ACCENT)),
            regions[0],
        );
        self.draw_asset_buttons(
            frame,
            regions[1],
            self.section,
            &[
                KeyCode::Char('m'),
                KeyCode::Char('M'),
                KeyCode::Char('b'),
                KeyCode::Char('x'),
            ],
        );
        let mut x = regions[2].x;
        for (label, section) in [
            (" 镜像 ", AssetSection::Images),
            (" 本地库 ", AssetSection::Symbols),
            (" 远程索引 ", AssetSection::Remote),
        ] {
            let width = Span::raw(label).width() as u16;
            if x + width > regions[2].right() {
                break;
            }
            let rect = Rect::new(x, regions[2].y, width, regions[2].height);
            frame.render_widget(
                Paragraph::new(label).style(if self.section == section {
                    Style::default().fg(FOCUS).bg(SELECTED_BG)
                } else {
                    Style::default().fg(ACCENT)
                }),
                rect,
            );
            self.hits.borrow_mut().sources.push((rect, section));
            x += width + 1;
        }
        let mut body = regions[3];
        if area.width >= 100 && area.height >= 24 {
            let rows = Layout::vertical([Constraint::Min(9), Constraint::Length(8)]).split(body);
            body = rows[0];
            self.hits.borrow_mut().asset_detail = rows[1];
            frame.render_widget(
                Paragraph::new(self.asset_text())
                    .wrap(Wrap { trim: false })
                    .scroll((
                        self.asset_scroll[self.section.slot()].min(u16::MAX as usize) as u16,
                        0,
                    ))
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("详情 · d 完整内容 · Tab 聚焦")
                            .border_style(Style::default().fg(if self.focus == 2 {
                                ACCENT
                            } else {
                                Color::DarkGray
                            })),
                    ),
                rows[1],
            );
        }
        if area.height < 16 {
            self.draw_asset_pane(frame, body, self.section);
        } else {
            let panes = if area.width >= 100 {
                Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
                    .split(body)
            } else {
                Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(body)
            };
            self.draw_asset_pane(frame, panes[0], AssetSection::Images);
            self.draw_asset_pane(frame, panes[1], self.symbol_source);
        }
    }

    fn result(&self) -> Option<&Results> {
        self.history
            .as_ref()
            .or_else(|| self.results.get(self.plugin.name()))
    }
    fn rows(&self) -> Vec<Vec<String>> {
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
    fn visible(&self) -> Vec<Vec<String>> {
        let rows = self.rows();
        if self.history.is_some() || self.plugin != Plugin::Pstree {
            return rows;
        }
        tree_rows(rows, &self.collapsed)
    }
    fn picker_filter(kind: InputKind) -> crate::browser::Filter {
        use crate::browser::Filter;
        match kind {
            InputKind::Image | InputKind::Symbols => Filter::Files,
            InputKind::History => Filter::Exports,
            _ => Filter::Directories,
        }
    }
    fn open_files(&mut self, kind: InputKind) {
        let base = match kind {
            InputKind::Image | InputKind::ImageDirectory => &self.settings.image_dir,
            InputKind::Symbols | InputKind::SymbolsDirectory => &self.settings.symbols,
            _ => &self.settings.export_dir,
        };
        let mut root = store::expand_home(base);
        if root.is_file() {
            root = root.parent().unwrap_or(&self.root).to_path_buf();
        }
        if !root.is_dir() {
            self.open_input(kind);
            self.status = format!(
                "配置目录不可用: {}；输入路径或按 , 修改目录",
                root.display()
            );
            return;
        }
        self.browse(kind, root);
    }
    fn browse(&mut self, kind: InputKind, root: PathBuf) {
        match crate::browser::entries(&root, Self::picker_filter(kind)) {
            Ok(entries) => {
                self.dialog = Some(Dialog::Files {
                    kind,
                    root,
                    entries,
                    selected: 0,
                })
            }
            Err(e) => self.status = format!("读取目录失败: {e:#}；p 手动输入路径"),
        }
    }
    fn accept_path(&mut self, kind: InputKind, path: PathBuf) {
        let kind = if path.is_file() && matches!(kind, InputKind::Image | InputKind::Symbols) {
            match crate::browser::file_kind(&path) {
                crate::browser::FileKind::Image => InputKind::Image,
                crate::browser::FileKind::Symbols => InputKind::Symbols,
                crate::browser::FileKind::Other => kind,
            }
        } else {
            kind
        };
        self.open_input(kind);
        if let Some(Dialog::Input {
            text,
            cursor,
            selected,
            ..
        }) = &mut self.dialog
        {
            *text = path.display().to_string();
            *cursor = text.len();
            *selected = false;
        }
        self.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    }
    fn settings_labels(&self) -> Vec<String> {
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
    fn persist_settings(&mut self) {
        match store::save_settings(&self.cache, &self.settings) {
            Ok(()) => self.status = "设置已保存".into(),
            Err(e) => {
                self.status = format!("设置保存失败: {e:#}");
                self.last_error = Some(self.status.clone());
            }
        }
    }
    fn open_input(&mut self, kind: InputKind) {
        let text = match kind {
            InputKind::Image => self
                .image
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            InputKind::Symbols => self.symbols.display().to_string(),
            InputKind::Search => self.query.clone(),
            InputKind::AssetsSearch => self.asset_queries[self.section.slot()].clone(),
            InputKind::Export => store::expand_home(&self.settings.export_dir)
                .join(format!("{}.csv", self.plugin.name()))
                .display()
                .to_string(),
            InputKind::PageSize => {
                if self.settings.page_size == 0 {
                    "auto".into()
                } else {
                    self.settings.page_size.to_string()
                }
            }
            InputKind::ImageDirectory => self.settings.image_dir.clone(),
            InputKind::SymbolsDirectory => self.settings.symbols.clone(),
            InputKind::ExportDirectory => self.settings.export_dir.clone(),
            InputKind::History => {
                store::history_paths(&store::expand_home(&self.settings.history_dir))
                    .first()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| self.settings.history_dir.clone())
            }
        };
        self.dialog = Some(Dialog::Input {
            kind,
            original: text.clone(),
            cursor: text.len(),
            selected: !matches!(kind, InputKind::Search | InputKind::AssetsSearch),
            text,
        });
    }
    fn start(&mut self) {
        self.request_analysis(false);
    }
    fn request_analysis(&mut self, force: bool) {
        if self.plugin.is_dump() {
            self.open_dump(self.plugin, force);
        } else {
            self.start_work(Work::Analyze(force));
        }
    }
    fn open_dump(&mut self, mode: Plugin, force: bool) {
        if self.job.is_some() {
            self.status = "任务执行中；Esc 取消后设置转储参数".into();
            return;
        }
        let previous = self
            .dump_options
            .as_ref()
            .filter(|(p, _)| *p == mode)
            .map(|(_, o)| o);
        let pid = previous
            .map(|o| o.pid.to_string())
            .or_else(|| {
                let result = self.result()?;
                let column = result.columns.iter().position(|s| s == "PID")?;
                self.visible().get(self.row)?.get(column).cloned()
            })
            .unwrap_or_default();
        let fields = [
            pid,
            previous
                .and_then(|o| o.start)
                .map(|a| format!("{a:#x}"))
                .unwrap_or_default(),
            previous
                .and_then(|o| o.end)
                .map(|a| format!("{a:#x}"))
                .unwrap_or_default(),
            previous
                .map(|o| o.directory.display().to_string())
                .unwrap_or_else(|| {
                    store::expand_home(&self.settings.export_dir)
                        .join("dumps")
                        .display()
                        .to_string()
                }),
        ];
        let cursor = fields[0].len();
        self.dialog = Some(Dialog::Dump {
            mode,
            fields,
            field: 0,
            cursor,
            selected: true,
            force,
            error: String::new(),
        });
    }
    fn start_work(&mut self, work: Work) {
        if let Work::Analyze(force) = work
            && self.plugin.is_dump()
            && self
                .dump_options
                .as_ref()
                .is_none_or(|(p, _)| *p != self.plugin)
        {
            self.request_analysis(force);
            return;
        }
        if self.job.is_some() {
            self.status = "任务正在执行；Esc 取消后可重新运行".into();
            return;
        }
        let image = self.image.clone().or_else(|| {
            matches!(
                work,
                Work::Clear(_)
                    | Work::InspectSymbols(_)
                    | Work::RefreshLookup
                    | Work::Catalog(_, _)
                    | Work::CatalogDownload(_)
            )
            .then(PathBuf::new)
        });
        let Some(image) = image else {
            self.pending_work = Some(work);
            self.open_files(InputKind::Image);
            return;
        };
        let (tx, rx) = mpsc::channel();
        let progress = tx.clone();
        let job = Job::new(move |s| {
            let _ = progress.send(WorkerEvent::Progress(s));
        });
        let worker_job = job.clone();
        let symbols = if self.symbols.as_os_str().is_empty() {
            store::expand_home(&self.settings.symbols)
        } else {
            self.symbols.clone()
        };
        let cache = self.cache.clone();
        let choice = self.choice.clone();
        let plugin = self.plugin;
        let dump = self
            .dump_options
            .as_ref()
            .filter(|(p, _)| *p == plugin)
            .map(|(_, o)| o.clone());
        let enabled = self.settings.enable_cache;
        let network = self.settings.remote_symbols;
        let saved_download = self
            .downloads
            .get(match &work {
                Work::CatalogDownload(candidate) => candidate.url.as_str(),
                _ => "",
            })
            .filter(|p| p.is_file())
            .cloned();
        let local_library = store::expand_home(&self.settings.symbols);
        let local_library = if local_library.extension().is_some() && !local_library.is_dir() {
            self.root.join("symbols")
        } else {
            local_library
        };
        let session = self.session.clone();
        if matches!(
            work,
            Work::Analyze(_) | Work::Download(_) | Work::PrepareKali
        ) {
            self.history = None;
        }
        self.last_error = None;
        self.job = Some(job);
        self.receiver = Some(rx);
        self.download_url = match &work {
            Work::Download(candidate) | Work::CatalogDownload(candidate) => {
                Some(candidate.url.clone())
            }
            _ => None,
        };
        self.lookup_dialog = self.page == Page::Analysis && matches!(work, Work::Lookup);
        self.download_analyzes =
            self.page == Page::Analysis && matches!(work, Work::Download(_) | Work::PrepareKali);
        self.status = "任务启动中".into();
        self.started = Some(Instant::now());
        self.progress = None;
        self.worker = Some(thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut session = session
                    .lock()
                    .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?;
                match work {
                    Work::Catalog(query, refresh) => {
                        if refresh {
                            anyhow::ensure!(network, "离线模式不能刷新索引；按 o 开启在线");
                            symbols::refresh_index(&cache, &worker_job)?;
                        }
                        symbols::catalog_search(&cache, &query, network, &worker_job)
                            .map(WorkerEvent::CatalogLinks)
                    }
                    Work::CatalogDownload(candidate) => {
                        if let Some(path) = saved_download {
                            anyhow::ensure!(
                                candidate.url == symbols::repository_url(&candidate.path)?,
                                "下载链接不属于指定符号仓库"
                            );
                            let valid = symbols::inspect(&path, &worker_job).is_ok_and(|isfs| {
                                isfs.len() == 1
                                    && String::from_utf8_lossy(&isfs[0].banner)
                                        .trim_end_matches(['\0', '\n'])
                                        == candidate.banner
                            });
                            worker_job.check()?;
                            if valid {
                                return Ok(WorkerEvent::CatalogDownloaded(path));
                            }
                        }
                        let isf =
                            symbols::download_catalog(&candidate, &cache, network, &worker_job)?;
                        worker_job.check()?;
                        std::fs::create_dir_all(&local_library)?;
                        let stem = candidate
                            .path
                            .rsplit('/')
                            .next()
                            .unwrap_or("symbol.json.xz")
                            .trim_end_matches(".json.xz");
                        let target = local_library.join(format!(
                            "{}-{}.json.xz",
                            stem.chars().take(100).collect::<String>(),
                            isf.digest
                        ));
                        let bytes = std::fs::read(&isf.label)?;
                        if target.exists() {
                            anyhow::ensure!(
                                std::fs::read(&target)? == bytes,
                                "同名本地符号内容不同，拒绝覆盖: {}",
                                target.display()
                            );
                        } else {
                            store::atomic_write(&target, &bytes)?;
                        }
                        worker_job.check()?;
                        store::atomic_write(
                            &target.with_extension("source.json"),
                            &serde_json::to_vec_pretty(&candidate)?,
                        )?;
                        Ok(WorkerEvent::CatalogDownloaded(target.canonicalize()?))
                    }
                    Work::Identify => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        linux::banner_result(&image, &worker_job).map(WorkerEvent::Identified)
                    }
                    Work::InspectSymbols(path) => workspace::inspect_symbols(&path, &worker_job)
                        .map(|text| WorkerEvent::SymbolDetails(path, text)),
                    Work::RefreshLookup => {
                        if network {
                            symbols::refresh_index(&cache, &worker_job)?;
                        } else {
                            anyhow::ensure!(
                                cache.join("symbols/banners_plain.json").is_file(),
                                "离线模式且没有索引缓存；按 o 开启在线模式后按 r"
                            );
                        }
                        if image.as_os_str().is_empty() {
                            return Ok(WorkerEvent::IndexRefreshed);
                        }
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        symbols::remote_matches(&image, &cache, network, &worker_job)
                            .map(WorkerEvent::Links)
                    }
                    Work::PrepareKali => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        crate::prepare::prepare_kali(&image, &cache, network, &worker_job)
                            .map(WorkerEvent::Downloaded)
                    }
                    Work::Clear(scopes) => {
                        session.clear();
                        cache::clear_with_job(&cache, &scopes, &worker_job)
                            .map(WorkerEvent::Cleared)
                    }
                    Work::Analyze(force) => session
                        .analyze_with_dump(
                            &linux::Request {
                                image: &image,
                                symbols: &symbols,
                                choice: choice.as_deref(),
                                plugin,
                                cache: &cache,
                                use_cache: enabled && !force,
                                network,
                            },
                            dump.as_ref(),
                            &worker_job,
                        )
                        .map(WorkerEvent::Done),
                    Work::MatchLocal(paths, stamp) => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        let banner = linux::banner_result(&image, &worker_job)?;
                        let report = symbols::match_local_files(&paths, &image, &worker_job)?;
                        Ok(WorkerEvent::LocalMatched(report, stamp, banner))
                    }
                    Work::Lookup => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        symbols::remote_matches(&image, &cache, network, &worker_job)
                            .map(WorkerEvent::Links)
                    }
                    Work::Download(candidate) => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        let isf =
                            symbols::download(&candidate, &image, &cache, network, &worker_job)?;
                        Ok(WorkerEvent::Downloaded(PathBuf::from(isf.label)))
                    }
                }
            }));
            let event = match outcome {
                Ok(Ok(event)) => event,
                Ok(Err(error)) => WorkerEvent::Failed(format!("{error:#}")),
                Err(_) => WorkerEvent::Failed("分析线程 panic；任务已终止".into()),
            };
            let _ = tx.send(event);
        }));
    }
    fn cancel(&mut self) {
        self.pending_plugin = None;
        self.pending_cache = false;
        if let Some(job) = &self.job {
            job.cancel.store(true, Ordering::Relaxed);
            self.status = "正在取消…".into();
        }
    }
    fn drain(&mut self) -> bool {
        let events: Vec<_> = self
            .receiver
            .as_ref()
            .map(|r| r.try_iter().collect())
            .unwrap_or_default();
        let changed = !events.is_empty();
        for event in events {
            let progress_event = matches!(&event, WorkerEvent::Progress(_));
            match event {
                WorkerEvent::LocalMatched(report, stamp, banner) => {
                    self.finish_worker();
                    self.results.insert("banners".into(), banner);
                    self.local_matches = report.matched;
                    self.local_match_errors = report.diagnostics;
                    self.local_match_stamp = Some(stamp);
                    self.local_only_matches = true;
                    self.asset_rows[1] = 0;
                    self.status = format!(
                        "本地完整 banner 匹配：{} 个文件 · {} 条诊断；Enter 选用，t 远程，z 全部",
                        self.local_matches.len(),
                        self.local_match_errors.len()
                    );
                    if !self.local_match_errors.is_empty() {
                        self.last_error = Some(self.local_match_errors.join("\n"));
                    }
                }
                WorkerEvent::CatalogLinks(matches) => {
                    self.finish_worker();
                    self.status =
                        format!("远程索引：{} 项；可输入多个关键词缩小范围", matches.len());
                    self.remote = matches;
                    self.remote_catalog = true;
                    self.asset_rows[2] =
                        self.asset_rows[2].min(self.remote_list().len().saturating_sub(1));
                }
                WorkerEvent::CatalogDownloaded(path) => {
                    self.finish_worker();
                    if let Some(url) = self.download_url.take() {
                        self.downloads.insert(url, path.clone());
                    }
                    if let Err(e) = self.registry.register(&path, Kind::Symbols, &self.cache) {
                        self.last_error = Some(format!("下载成功但清单保存失败: {e:#}"));
                    }
                    self.refresh_assets();
                    self.status = format!("已保存到 {}；在本地库定位后可选用", path.display());
                }
                WorkerEvent::IndexRefreshed => {
                    self.finish_worker();
                    self.status = "远程索引已刷新；选择镜像后按 M 精确匹配".into();
                }
                WorkerEvent::Identified(result) => {
                    self.finish_worker();
                    self.status = format!("识别到 {} 个候选；尚未验证页表", result.rows.len());
                    self.results.insert("banners".into(), result);
                }
                WorkerEvent::SymbolDetails(path, text) => {
                    self.finish_worker();
                    self.asset_details.insert(path, text);
                    self.status = "符号详情已读取；选用后通过镜像验证匹配".into();
                }
                WorkerEvent::Cleared(report) => {
                    self.finish_worker();
                    self.results.clear();
                    self.views.clear();
                    self.refresh_assets();
                    self.status = format!(
                        "已清理 {} 个文件 · 释放 {:.1} MiB · {} 项失败",
                        report.removed,
                        report.bytes as f64 / 1048576.0,
                        report.failures.len()
                    );
                    if !report.failures.is_empty() {
                        self.last_error = Some(report.failures.join("\n"));
                    }
                }
                WorkerEvent::Links(matches) => {
                    self.finish_worker();
                    self.status = format!(
                        "{} 个完整 banner 匹配 · Enter 查看详情 · w 下载到 symbols",
                        matches.len()
                    );
                    self.remote = matches.clone();
                    self.asset_rows[2] = 0;
                    self.asset_states.borrow_mut()[2] = ListState::default();
                    if matches.is_empty() {
                        self.status =
                            "仓库没有完整 banner 匹配；t 切换本地，g 获取索引，/ 手动搜索".into();
                    } else if self.lookup_dialog && self.page == Page::Analysis {
                        self.dialog = Some(Dialog::Links {
                            matches,
                            selected: 0,
                        });
                    }
                }
                WorkerEvent::Downloaded(path) => {
                    self.finish_worker();
                    if let Some(url) = self.download_url.take() {
                        self.downloads.insert(url, path.clone());
                    }
                    self.symbols = path.clone();
                    self.choice = None;
                    let banner = self.results.get("banners").cloned();
                    self.results.clear();
                    if let Some(banner) = banner {
                        self.results.insert("banners".into(), banner);
                    }
                    self.views.clear();
                    self.history = None;
                    self.query.clear();
                    self.sort = None;
                    self.row = 0;
                    self.horizontal = 0;
                    self.collapsed.clear();
                    if let Err(e) = self.registry.import(&path, Kind::Symbols, &self.cache) {
                        self.last_error = Some(format!("下载成功但清单保存失败: {e:#}"));
                    }
                    self.refresh_assets();
                    self.focus_asset(Kind::Symbols, &path);
                    self.status = format!("符号已选用: {}；x 进入分析", path.display());
                    if self.download_analyzes && self.pending_plugin.is_none() {
                        self.page = Page::Analysis;
                        self.start();
                    }
                }
                WorkerEvent::Progress(s) => {
                    self.progress = s
                        .split_whitespace()
                        .find_map(|v| v.strip_suffix('%').and_then(|v| v.parse::<u16>().ok()))
                        .map(|p| p.min(100));
                    self.logs.push_back(s.clone());
                    if self.logs.len() > 200 {
                        self.logs.pop_front();
                    }
                    self.status = if let Some(plugin) = self.pending_plugin {
                        format!("正在切换到 {}…", plugin.name())
                    } else {
                        s
                    }
                }
                WorkerEvent::Failed(s) => {
                    self.last_error = Some(s.clone());
                    self.status = s;
                    self.finish_worker();
                }
                WorkerEvent::Done(outcome) => {
                    self.finish_worker();
                    match outcome {
                        Outcome::Choose(labels) => {
                            self.status = "多个匹配 ISF，必须选择".into();
                            self.dialog = Some(Dialog::Symbols {
                                labels,
                                selected: 0,
                            });
                        }
                        Outcome::Ready(result) => {
                            self.last_error = None;
                            self.status = format!(
                                "{} · {} 条 · {}{}",
                                result.plugin,
                                result.rows.len(),
                                if result.complete {
                                    "完整"
                                } else {
                                    "部分结果 / 未缓存"
                                },
                                if result.diagnostics.is_empty() {
                                    String::new()
                                } else {
                                    format!(" · {} 条诊断（v 查看）", result.diagnostics.len())
                                }
                            );
                            self.results.insert(result.plugin.clone(), result);
                            self.row = 0;
                            self.focus = 2;
                        }
                    }
                }
            }
            if !progress_event {
                self.logs.push_back(self.status.clone());
                if self.logs.len() > 200 {
                    self.logs.pop_front();
                }
            }
        }
        if self.job.is_none() && self.pending_cache {
            self.pending_cache = false;
            self.open_cache();
        }
        if self.job.is_none()
            && let Some(plugin) = self.pending_plugin.take()
        {
            self.dialog = None;
            self.select_plugin(plugin);
        }
        changed
    }
    fn finish_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.receiver = None;
        self.job = None;
        self.started = None;
        self.progress = None;
    }
    fn resize(&mut self, width: u16, height: u16) {
        if self.page == Page::Assets && self.focus == 2 && (width < 100 || height < 28) {
            self.focus = 1;
        }
        if width < 140 && self.focus == 3 {
            self.focus = 2;
        }
    }
    fn select_plugin(&mut self, plugin: Plugin) {
        if self.job.is_some() {
            self.cancel();
            self.pending_plugin = Some(plugin);
            self.status = format!("正在切换到 {}…", plugin.name());
            return;
        }
        self.views.insert(
            self.plugin.name().into(),
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
        self.plugin = plugin;
        self.last_error = None;
        self.menu = if plugin.is_dump() {
            menu_items().len() - 1
        } else {
            navigation_plugins()
                .iter()
                .position(|p| *p == plugin)
                .unwrap()
                + 2
        };
        self.history = None;
        self.query.clear();
        self.sort = None;
        self.row = 0;
        self.collapsed.clear();
        let view = self.views.remove(plugin.name()).unwrap_or_default();
        self.query = view.query;
        self.sort = view.sort;
        self.descending = view.descending;
        self.row = view.row;
        self.collapsed = view.collapsed;
        self.horizontal = view.horizontal;
        *self.table_state.borrow_mut() = view.state;
        self.detail_scroll = 0;
        if let Some(result) = self.results.get(plugin.name()) {
            self.focus = 2;
            self.status = format!(
                "{} · {} 条 · {} · {} 条诊断（v）",
                plugin.name(),
                result.rows.len(),
                if result.complete { "完整" } else { "部分" },
                result.diagnostics.len()
            );
        } else {
            self.start();
        }
    }
    fn open_cache(&mut self) {
        if self.job.is_some() {
            self.cancel();
            self.pending_cache = true;
            self.status = "正在停止分析，随后打开缓存管理…".into();
            return;
        }
        match cache::inventory(&self.cache) {
            Ok(entries) => {
                self.dialog = Some(Dialog::Cache {
                    entries,
                    scopes: vec![cache::Scope::Results, cache::Scope::Identification],
                    selected: 0,
                    confirm: false,
                })
            }
            Err(e) => {
                self.status = format!("缓存清单失败: {e:#}");
                self.last_error = Some(self.status.clone());
            }
        }
    }
    fn paste(&mut self, value: &str) {
        if let Some(Dialog::Files { kind, .. }) = &self.dialog {
            let kind = *kind;
            self.open_input(kind);
        }
        match self.dialog.as_mut() {
            Some(Dialog::Dump {
                fields,
                field,
                cursor,
                selected,
                ..
            }) if *field < 4 => {
                if *selected {
                    fields[*field].clear();
                    *cursor = 0;
                    *selected = false;
                }
                fields[*field].insert_str(*cursor, value);
                *cursor += value.len();
            }
            Some(Dialog::Input {
                kind,
                text,
                cursor,
                selected,
                ..
            }) => {
                if *selected {
                    text.clear();
                    *cursor = 0;
                    *selected = false;
                }
                text.insert_str(*cursor, value);
                *cursor += value.len();
                if *kind == InputKind::Search {
                    self.query = text.clone();
                    self.row = 0;
                } else if *kind == InputKind::AssetsSearch {
                    self.asset_queries[self.section.slot()] = text.clone();
                    self.asset_rows[self.section.slot()] = 0;
                }
            }
            Some(Dialog::Plugins { query, selected })
            | Some(Dialog::Commands { query, selected }) => {
                query.push_str(value);
                *selected = 0;
            }
            _ => {}
        }
    }
    fn help(&mut self) {
        let mut text = "ZERO 取证工作台\n\nF2 分析 · F3 镜像与符号 · Ctrl+←/→ 切换页面\nTab / Shift+Tab 切换区域；↑↓ 或 j/k 导航；PgUp/PgDn/Home/End 翻页\n\n镜像与符号：\n选用镜像后自动识别内核并匹配本地；选用符号后按 x 开始分析。\n远程下载只保存，完成后仍需在本地库选用。\n".to_owned();
        for section in [
            AssetSection::Images,
            AssetSection::Symbols,
            AssetSection::Remote,
        ] {
            text.push_str(&format!("\n{}：\n", section.title()));
            text.push_str(
                &asset_actions(section)
                    .iter()
                    .map(|(label, _)| *label)
                    .collect::<Vec<_>>()
                    .join(" · "),
            );
            text.push('\n');
        }
        text.push_str("\n远程详情：w 下载到 symbols · L 在本地库定位 · c 取消下载 · Esc 返回\n\n分析：i 镜像 · y 符号 · p/F4 插件 · Enter 执行 · D Dump\n/ 搜索 · s 排序 · e 导出 · d 详情 · n 行数 · [/] 翻页\nr/F5 重跑 · v/F8 诊断 · Alt+←/→ 横向滚动\n分析页 g 生成 Kali ARM64 符号\n\nCtrl+P / ? 命令面板 · , 目录设置 · c 缓存 · l 日志 · h 历史\nEsc 关闭弹窗；无弹窗时取消任务 · q / Ctrl+C 退出\n文件弹窗：Enter 选用 · ← 上级 · Tab 切换目录 · p 输入路径\nDump：F2/F3/F4 切换模式 · Tab 字段 · Ctrl+Enter 运行\n");
        self.dialog = Some(Dialog::Detail { text, scroll: 0 });
    }
    fn diagnostics(&mut self) {
        if let Some(error) = &self.last_error {
            self.dialog = Some(Dialog::Detail {
                text: escaped(error),
                scroll: 0,
            });
            return;
        }
        if let Some(r) = self.result() {
            self.dialog = Some(Dialog::Detail {
                scroll: 0,
                text: if r.diagnostics.is_empty() {
                    "没有诊断；结果完整。".into()
                } else {
                    r.diagnostics
                        .iter()
                        .map(|s| escaped(s))
                        .collect::<Vec<_>>()
                        .join("\n\n")
                },
            });
        }
    }
    fn key(&mut self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        if self.dialog.is_some() {
            self.dialog_key(key);
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p') {
            self.dialog = Some(Dialog::Commands {
                query: String::new(),
                selected: 0,
            });
            return false;
        }
        if self.page == Page::Assets
            && !matches!(
                key.code,
                KeyCode::F(1..=3) | KeyCode::Char(',' | 'h' | 'l' | '?' | 'c')
            )
            && !key.modifiers.contains(KeyModifiers::CONTROL)
        {
            return self.asset_key(key);
        }
        match key.code {
            KeyCode::Char('M') => {
                self.symbol_target(true);
                return false;
            }
            KeyCode::Char('m') => {
                self.symbol_target(false);
                return false;
            }
            KeyCode::Char('D') => {
                self.open_dump(
                    if self.plugin.is_dump() {
                        self.plugin
                    } else {
                        Plugin::Procdump
                    },
                    false,
                );
                return false;
            }
            KeyCode::Char('n') => {
                self.open_input(InputKind::PageSize);
                return false;
            }
            KeyCode::Char(',') => {
                self.dialog = Some(Dialog::Settings { selected: 0 });
                return false;
            }
            KeyCode::Char('h') => {
                self.open_files(InputKind::History);
                return false;
            }
            KeyCode::Char('l') => {
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
                return false;
            }
            KeyCode::Char('?') => {
                self.dialog = Some(Dialog::Commands {
                    query: String::new(),
                    selected: 0,
                });
                return false;
            }
            KeyCode::F(1) => {
                self.help();
                return false;
            }
            _ => {}
        }
        if matches!(key.code, KeyCode::F(2) | KeyCode::F(3)) {
            self.switch_page(if key.code == KeyCode::F(2) {
                Page::Analysis
            } else {
                Page::Assets
            });
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(
                key.code,
                KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab
            )
        {
            let back = matches!(key.code, KeyCode::Left | KeyCode::BackTab)
                || key.modifiers.contains(KeyModifiers::SHIFT);
            self.switch_page(
                Page::ALL[(self.page.index() + if back { Page::ALL.len() - 1 } else { 1 })
                    % Page::ALL.len()],
            );
            return false;
        }
        if self.page != Page::Analysis {
            return self.asset_key(key);
        }
        if key.modifiers.contains(KeyModifiers::ALT)
            && matches!(key.code, KeyCode::Left | KeyCode::Right)
        {
            self.horizontal = if key.code == KeyCode::Left {
                self.horizontal.saturating_sub(12)
            } else {
                (self.horizontal + 12).min(2048)
            };
            return false;
        }
        if self.focus == 3
            && matches!(
                key.code,
                KeyCode::Up
                    | KeyCode::Down
                    | KeyCode::Char('j')
                    | KeyCode::Char('k')
                    | KeyCode::PageUp
                    | KeyCode::PageDown
                    | KeyCode::Home
                    | KeyCode::End
            )
        {
            let rect = self.hits.borrow().inspector;
            let max = detail_lines(&self.detail_text(), rect.width.saturating_sub(2))
                .len()
                .saturating_sub(rect.height.saturating_sub(2) as usize);
            self.detail_scroll = match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.detail_scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => (self.detail_scroll + 1).min(max),
                KeyCode::PageUp => self.detail_scroll.saturating_sub(10),
                KeyCode::PageDown => (self.detail_scroll + 10).min(max),
                KeyCode::Home => 0,
                _ => max,
            };
            return false;
        }
        match key.code {
            KeyCode::Char('c') => self.open_cache(),
            KeyCode::Char('g') => self.start_work(Work::PrepareKali),
            KeyCode::Char('q') => return true,
            KeyCode::Esc if self.inspector => {
                self.inspector = false;
                if self.focus == 3 {
                    self.focus = 2;
                }
            }
            KeyCode::Esc => self.cancel(),
            KeyCode::Tab => {
                self.focus = (self.focus + 1)
                    % if self.hits.borrow().inspector.width > 0 {
                        4
                    } else {
                        3
                    }
            }
            KeyCode::BackTab => {
                let n = if self.hits.borrow().inspector.width > 0 {
                    4
                } else {
                    3
                };
                self.focus = (self.focus + n - 1) % n;
            }
            KeyCode::Char('i') => self.open_files(InputKind::Image),
            KeyCode::Char('y') => self.open_files(InputKind::Symbols),
            KeyCode::Char('h') => self.open_input(InputKind::History),
            KeyCode::Char('/') => self.open_input(InputKind::Search),
            KeyCode::Char('e') if self.result().is_some() => {
                self.open_input(InputKind::Export);
            }
            KeyCode::Char('s') if self.result().is_some() => {
                self.dialog = Some(Dialog::Sort {
                    column: self.sort.unwrap_or(0),
                });
            }
            KeyCode::Char('[') => {
                self.row = self.row.saturating_sub(self.page_rows());
            }
            KeyCode::Char(']') => {
                self.row =
                    (self.row + self.page_rows()).min(self.visible().len().saturating_sub(1));
            }
            KeyCode::Char('r') | KeyCode::F(5) => self.request_analysis(true),
            KeyCode::Char('p') | KeyCode::F(4) => {
                self.dialog = Some(Dialog::Plugins {
                    query: String::new(),
                    selected: 0,
                })
            }
            KeyCode::Char('b') => self.select_plugin(Plugin::Banners),
            KeyCode::Char('v') | KeyCode::F(8) => self.diagnostics(),
            KeyCode::Char('o') if self.job.is_none() => {
                self.settings.remote_symbols = !self.settings.remote_symbols;
                self.status = if self.settings.remote_symbols {
                    "在线符号匹配已开启；仅请求仓库，不上传镜像"
                } else {
                    "离线模式：使用本地 ISF 和已下载缓存"
                }
                .into();
            }
            KeyCode::Char('d')
                if self.hits.borrow().inspector.width > 0
                    || self.hits.borrow().result.right() >= 140 =>
            {
                self.inspector = !self.inspector;
                self.detail_scroll = 0;
            }
            KeyCode::Char('d') => self.open_detail(),
            KeyCode::Up | KeyCode::Char('k') => {
                if self.focus == 1 {
                    self.menu = self.menu.saturating_sub(1);
                } else if self.focus == 2 {
                    self.row = self.row.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.focus == 1 {
                    self.menu = (self.menu + 1).min(menu_items().len() - 1);
                } else if self.focus == 2 {
                    self.row = (self.row + 1).min(self.visible().len().saturating_sub(1));
                }
            }
            KeyCode::PageUp => {
                if self.focus == 1 {
                    self.menu = self.menu.saturating_sub(10);
                } else {
                    self.row = self.row.saturating_sub(self.page_rows());
                }
            }
            KeyCode::PageDown => {
                if self.focus == 1 {
                    self.menu = (self.menu + 10).min(menu_items().len() - 1);
                } else {
                    self.row =
                        (self.row + self.page_rows()).min(self.visible().len().saturating_sub(1));
                }
            }
            KeyCode::Home => {
                if self.focus == 1 {
                    self.menu = 0;
                } else {
                    self.row = 0;
                }
            }
            KeyCode::End => {
                if self.focus == 1 {
                    self.menu = menu_items().len() - 1;
                } else {
                    self.row = self.visible().len().saturating_sub(1);
                }
            }
            KeyCode::Left | KeyCode::Right if self.focus == 2 && self.plugin == Plugin::Pstree => {
                if let Some(row) = self.visible().get(self.row) {
                    if key.code == KeyCode::Left {
                        self.collapsed.insert(row[0].clone());
                    } else {
                        self.collapsed.remove(&row[0]);
                    }
                }
            }
            KeyCode::Enter => {
                if self.focus == 3 {
                    self.open_detail();
                } else if self.focus == 0 {
                    self.open_files(InputKind::Image);
                } else if self.focus == 1 {
                    match self.menu {
                        0 => self.open_files(InputKind::Image),
                        1 => self.open_files(InputKind::Symbols),

                        index if index == menu_items().len() - 1 => {
                            self.open_dump(Plugin::Procdump, false)
                        }
                        index => {
                            self.select_plugin(navigation_plugins()[index - 2]);
                        }
                    }
                } else if self.plugin == Plugin::Pstree
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
            _ => {}
        }
        false
    }
    fn detail_text(&self) -> String {
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
    fn open_detail(&mut self) {
        if self.result().is_some() {
            self.dialog = Some(Dialog::Detail {
                text: self.detail_text(),
                scroll: 0,
            });
        }
    }
    fn mouse(&mut self, mouse: MouseEvent) -> bool {
        let hits = self.hits.borrow().clone();
        let point = Position::new(mouse.column, mouse.row);
        let click = mouse.kind == MouseEventKind::Down(MouseButton::Left);
        if mouse.kind == MouseEventKind::Down(MouseButton::Right) {
            return self.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        }
        let scroll = match mouse.kind {
            MouseEventKind::ScrollUp => Some(KeyCode::Up),
            MouseEventKind::ScrollDown => Some(KeyCode::Down),
            _ => None,
        };
        if !click && scroll.is_none() {
            return false;
        }
        if matches!(
            self.dialog,
            Some(Dialog::Input {
                kind: InputKind::Search | InputKind::AssetsSearch,
                ..
            })
        ) {
            if click
                && let Some((_, key)) = hits.buttons.iter().find(|(rect, key)| {
                    rect.contains(point) && matches!(key, KeyCode::Enter | KeyCode::Esc)
                })
            {
                self.dialog_key(KeyEvent::new(*key, KeyModifiers::NONE));
                return false;
            }
            if click && !hits.search.contains(point) {
                self.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                return self.mouse(mouse);
            }
            return false;
        }
        if self.dialog.is_none() {
            if click
                && let Some((_, page)) = hits.tabs.iter().find(|(rect, _)| rect.contains(point))
            {
                self.switch_page(*page);
                return false;
            }
            if click && hits.header.contains(point) {
                self.focus = 0;
                if point.y == hits.header.y + 1 {
                    self.open_files(InputKind::Image);
                } else if point.y == hits.header.y + 2 {
                    self.open_files(InputKind::Symbols);
                }
                return false;
            }
            if click
                && let Some((_, page)) = hits.sources.iter().find(|(rect, _)| rect.contains(point))
            {
                self.switch_section(*page);
                return false;
            }
            if self.page == Page::Assets
                && click
                && let Some((_, section)) = hits
                    .asset_searches
                    .iter()
                    .find(|(rect, _)| rect.contains(point))
            {
                self.section = *section;
                self.focus = 1;
                self.open_input(InputKind::AssetsSearch);
                return false;
            }
            if click && hits.search.contains(point) {
                self.focus = if self.page == Page::Analysis { 2 } else { 1 };
                self.open_input(if self.page == Page::Analysis {
                    InputKind::Search
                } else {
                    InputKind::AssetsSearch
                });
                return false;
            }
            if self.page == Page::Assets {
                if click
                    && let Some((_, section, key)) = hits
                        .asset_buttons
                        .iter()
                        .find(|(rect, _, _)| rect.contains(point))
                {
                    self.section = *section;
                    if *section != AssetSection::Images {
                        self.symbol_source = *section;
                    }
                    return self.asset_key(KeyEvent::new(*key, KeyModifiers::NONE));
                }
                if click
                    && let Some((_, key)) =
                        hits.buttons.iter().find(|(rect, _)| rect.contains(point))
                {
                    return self.key(KeyEvent::new(*key, KeyModifiers::NONE));
                }
                if hits.asset_detail.contains(point) {
                    self.focus = 2;
                    if let Some(key) = scroll {
                        for _ in 0..3 {
                            self.asset_key(KeyEvent::new(key, KeyModifiers::NONE));
                        }
                    }
                    return false;
                }
                if let Some((rect, section, offset)) = hits
                    .asset_lists
                    .iter()
                    .find(|(rect, _, _)| rect.contains(point))
                {
                    self.section = *section;
                    self.focus = 1;
                    if let Some(key) = scroll {
                        for _ in 0..3 {
                            self.asset_key(KeyEvent::new(key, KeyModifiers::NONE));
                        }
                    } else if click && point.y > rect.y && point.y < rect.bottom().saturating_sub(1)
                    {
                        let index = offset + (point.y - rect.y - 1) as usize;
                        if index < self.asset_count() {
                            self.asset_rows[section.slot()] = index;
                            self.asset_scroll[section.slot()] = 0;
                            if *section == AssetSection::Remote {
                                self.open_asset_detail();
                            }
                        }
                    }
                }
                return false;
            }
        }
        if self.dialog.is_some() {
            if !hits.popup.contains(point) {
                return false;
            }
            if click
                && let Some(index) = hits
                    .dump_fields
                    .iter()
                    .find(|(rect, _)| rect.contains(point))
                    .map(|(_, index)| *index)
                && let Some(Dialog::Dump {
                    fields,
                    field,
                    cursor,
                    selected,
                    ..
                }) = self.dialog.as_mut()
            {
                *field = index;
                *cursor = fields[index].len();
                *selected = true;
                return false;
            }
            if click
                && let Some((_, key)) = hits.buttons.iter().find(|(rect, _)| rect.contains(point))
            {
                if *key == KeyCode::Enter
                    && let Some(Dialog::Dump { field, .. }) = self.dialog.as_mut()
                {
                    *field = 4;
                }
                self.dialog_key(KeyEvent::new(*key, KeyModifiers::NONE));
                return false;
            }
            if let Some(key) = scroll {
                if !matches!(self.dialog, Some(Dialog::Input { .. })) {
                    for _ in 0..3 {
                        self.dialog_key(KeyEvent::new(key, KeyModifiers::NONE));
                    }
                }
            } else if click
                && point.y > hits.popup.y
                && point.y < hits.popup.bottom().saturating_sub(1)
            {
                let index = hits.popup_offset + (point.y - hits.popup.y - 1) as usize;
                let count = self.result_column_count();
                let command_count = match self.dialog.as_ref() {
                    Some(Dialog::Commands { query, .. }) => self.available_commands(query).len(),
                    _ => 0,
                };
                let selected = match self.dialog.as_mut() {
                    Some(Dialog::Files {
                        entries, selected, ..
                    }) if index < entries.len() => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Settings { selected }) if index < 5 => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Plugins { query, selected })
                        if index < plugin_matches(query).len() =>
                    {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Cache {
                        selected, confirm, ..
                    }) if index < cache::SCOPES.len() => {
                        *selected = index;
                        *confirm = false;
                        true
                    }
                    Some(Dialog::Commands { selected, .. }) if index < command_count => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Links { matches, selected }) if index < matches.len() => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Sort { column }) if index < count => {
                        *column = index;
                        true
                    }
                    Some(Dialog::Symbols { labels, selected }) if index < labels.len() => {
                        *selected = index;
                        true
                    }
                    _ => false,
                };
                if selected {
                    let code = if matches!(self.dialog, Some(Dialog::Cache { .. })) {
                        KeyCode::Char(' ')
                    } else {
                        KeyCode::Enter
                    };
                    self.dialog_key(KeyEvent::new(code, KeyModifiers::NONE));
                }
            }
            return false;
        }
        if click && let Some((_, key)) = hits.buttons.iter().find(|(rect, _)| rect.contains(point))
        {
            return self.key(KeyEvent::new(*key, KeyModifiers::NONE));
        }
        if hits.inspector.contains(point) {
            self.focus = 3;
            if let Some(key) = scroll {
                self.key(KeyEvent::new(key, KeyModifiers::NONE));
            }
            return false;
        }
        if hits.menu.contains(point) {
            self.focus = 1;
            if let Some(key) = scroll {
                for _ in 0..3 {
                    self.key(KeyEvent::new(key, KeyModifiers::NONE));
                }
            } else if click
                && point.y > hits.menu.y
                && point.y < hits.menu.bottom().saturating_sub(1)
            {
                let index = hits.menu_offset + (point.y - hits.menu.y - 1) as usize;
                if index < menu_items().len() {
                    self.menu = index;
                    self.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                }
            }
        } else if hits.result.contains(point) {
            self.focus = 2;
            if let Some(key) = scroll {
                for _ in 0..3 {
                    self.key(KeyEvent::new(key, KeyModifiers::NONE));
                }
            } else if click {
                if point.y == hits.result.y + 1 {
                    if let Some(column) = hits
                        .columns
                        .iter()
                        .position(|rect| rect.x <= point.x && point.x < rect.right())
                    {
                        self.descending = self.sort == Some(column) && !self.descending;
                        self.sort = Some(column);
                        self.row = 0;
                    }
                } else if point.y > hits.result.y + 1
                    && point.y < hits.result.bottom().saturating_sub(1)
                {
                    let index = hits.row_offset + (point.y - hits.result.y - 2) as usize;
                    if index < self.visible().len() {
                        self.row = index;
                        if self.plugin == Plugin::Pstree
                            && self.history.is_none()
                            && hits
                                .columns
                                .get(3)
                                .is_some_and(|rect| rect.x <= point.x && point.x < rect.right())
                        {
                            self.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                        }
                    }
                }
            }
        } else if click && hits.header.contains(point) {
            self.focus = 0;
            if point.y == hits.header.y + 2 {
                self.open_files(InputKind::Symbols);
            } else if point.y == hits.header.y + 1 {
                self.open_files(InputKind::Image);
            }
        }
        false
    }
    fn result_column_count(&self) -> usize {
        self.result().map_or(0, |r| r.columns.len())
    }
    fn dialog_key(&mut self, key: KeyEvent) {
        let Some(mut dialog) = self.dialog.take() else {
            return;
        };
        if key.code == KeyCode::Esc {
            self.pending_work = None;
            if matches!(dialog, Dialog::Detail { .. } | Dialog::RemoteDetail { .. })
                && let Some(back) = self.back_dialog.take()
            {
                self.dialog = Some(*back);
                return;
            }
            if let Dialog::Input { kind, original, .. } = dialog {
                if kind == InputKind::Search {
                    self.query = original;
                    self.row = 0;
                } else if kind == InputKind::AssetsSearch {
                    self.asset_queries[self.section.slot()] = original;
                    self.asset_rows[self.section.slot()] = 0;
                }
            }
            return;
        }
        match &mut dialog {
            Dialog::Dump {
                mode,
                fields,
                field,
                cursor,
                selected,
                force,
                error,
            } => {
                if let KeyCode::F(n @ 2..=4) = key.code {
                    *mode = [Plugin::Procdump, Plugin::Memdump, Plugin::Elfdump][n as usize - 2];
                    if *mode == Plugin::Elfdump {
                        fields[1].clear();
                        fields[2].clear();
                    }
                    error.clear();
                    self.dialog = Some(dialog);
                    return;
                }
                if key.code == KeyCode::Enter
                    && (*field == 4 || key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    let parsed = (|| -> Result<DumpOptions> {
                        let pid = fields[0].trim().parse::<u32>().context("请输入有效 PID")?;
                        let address = |text: &str| -> Result<Option<u64>> {
                            if text.trim().is_empty() {
                                Ok(None)
                            } else {
                                Ok(Some(parse_address(text).map_err(anyhow::Error::msg)?))
                            }
                        };
                        let options = DumpOptions {
                            pid,
                            directory: store::expand_home(fields[3].trim()),
                            start: address(&fields[1])?,
                            end: address(&fields[2])?,
                        };
                        options.validate(*mode)?;
                        Ok(options)
                    })();
                    match parsed {
                        Ok(options) => {
                            self.dump_options = Some((*mode, options));
                            self.plugin = *mode;
                            self.page = Page::Analysis;
                            self.menu = menu_items().len() - 1;
                            self.history = None;
                            self.query.clear();
                            self.sort = None;
                            self.row = 0;
                            self.start_work(Work::Analyze(*force));
                            return;
                        }
                        Err(e) => *error = e.to_string(),
                    }
                } else if matches!(
                    key.code,
                    KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down | KeyCode::Enter
                ) {
                    *field = (*field
                        + if matches!(key.code, KeyCode::BackTab | KeyCode::Up) {
                            4
                        } else {
                            1
                        })
                        % 5;
                    *cursor = fields.get(*field).map_or(0, String::len);
                    *selected = true;
                } else if *field < 4 {
                    edit_input(&mut fields[*field], cursor, selected, key);
                    error.clear();
                }
            }
            Dialog::Files {
                kind,
                root,
                entries,
                selected,
            } => match key.code {
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => *selected = (*selected + 1).min(entries.len().saturating_sub(1)),
                KeyCode::PageUp => *selected = selected.saturating_sub(10),
                KeyCode::PageDown => {
                    *selected = (*selected + 10).min(entries.len().saturating_sub(1))
                }
                KeyCode::Home => *selected = 0,
                KeyCode::End => *selected = entries.len().saturating_sub(1),
                KeyCode::Tab | KeyCode::BackTab
                    if matches!(kind, InputKind::Image | InputKind::Symbols) =>
                {
                    self.open_files(if *kind == InputKind::Image {
                        InputKind::Symbols
                    } else {
                        InputKind::Image
                    });
                    return;
                }
                KeyCode::Char('w') if matches!(kind, InputKind::Image | InputKind::Symbols) => {
                    self.open_files(*kind);
                    return;
                }
                KeyCode::Left | KeyCode::Backspace => {
                    self.browse(*kind, root.parent().unwrap_or(root).to_path_buf());
                    return;
                }
                KeyCode::Char('p') => {
                    self.open_input(*kind);
                    return;
                }
                KeyCode::Char(' ')
                    if matches!(
                        kind,
                        InputKind::Symbols
                            | InputKind::ImageDirectory
                            | InputKind::SymbolsDirectory
                            | InputKind::ExportDirectory
                    ) =>
                {
                    self.accept_path(*kind, root.clone());
                    return;
                }
                KeyCode::Enter | KeyCode::Right => {
                    if let Some(entry) = entries.get(*selected) {
                        if entry.directory {
                            self.browse(*kind, entry.path.clone());
                        } else {
                            self.accept_path(*kind, entry.path.clone());
                        }
                        return;
                    }
                }
                _ => {}
            },
            Dialog::Settings { selected } => match key.code {
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => *selected = (*selected + 1).min(4),
                KeyCode::Enter => {
                    match selected {
                        0 => self.open_files(InputKind::ImageDirectory),
                        1 => self.open_files(InputKind::SymbolsDirectory),
                        2 => self.open_files(InputKind::ExportDirectory),
                        3 => {
                            self.open_input(InputKind::PageSize);
                            return;
                        }
                        _ => {
                            self.settings.remote_symbols = !self.settings.remote_symbols;
                            self.persist_settings();
                        }
                    }
                    if *selected < 3 {
                        return;
                    }
                }
                _ => {}
            },
            Dialog::Cache {
                entries,
                scopes,
                selected,
                confirm,
            } => {
                match key.code {
                    KeyCode::Up => {
                        *selected = selected.saturating_sub(1);
                        *confirm = false;
                    }
                    KeyCode::Down => {
                        *selected = (*selected + 1).min(cache::SCOPES.len() - 1);
                        *confirm = false;
                    }
                    KeyCode::Char(' ') => {
                        let scope = cache::SCOPES[*selected];
                        if scopes.contains(&scope) {
                            scopes.retain(|v| *v != scope);
                        } else {
                            scopes.push(scope);
                        }
                        *confirm = false;
                    }
                    KeyCode::Enter if !*confirm => {
                        *confirm = true;
                    }
                    KeyCode::Enter => {
                        if !scopes.is_empty() {
                            let chosen = scopes.clone();
                            self.start_work(Work::Clear(chosen));
                        }
                        return;
                    }
                    _ => {}
                }
                let _ = entries;
            }
            Dialog::Commands { query, selected } => match key.code {
                KeyCode::Char(c) => {
                    query.push(c);
                    *selected = 0;
                }
                KeyCode::Backspace => {
                    query.pop();
                    *selected = 0;
                }
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => {
                    *selected =
                        (*selected + 1).min(self.available_commands(query).len().saturating_sub(1))
                }
                KeyCode::Enter => {
                    if let Some((_, key)) = self.available_commands(query).get(*selected) {
                        self.key(KeyEvent::new(*key, KeyModifiers::NONE));
                    }
                    return;
                }
                _ => {}
            },
            Dialog::Plugins { query, selected } => {
                let count = plugin_matches(query).len();
                match key.code {
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        query.push(c);
                        *selected = 0;
                    }
                    KeyCode::Backspace => {
                        query.pop();
                        *selected = 0;
                    }
                    KeyCode::Up => *selected = selected.saturating_sub(1),
                    KeyCode::Down => *selected = (*selected + 1).min(count.saturating_sub(1)),
                    KeyCode::Enter => {
                        if let Some(plugin) = plugin_matches(query).get(*selected) {
                            if plugin.is_dump() {
                                self.open_dump(*plugin, false);
                            } else {
                                self.select_plugin(*plugin);
                            }
                        }
                        return;
                    }
                    _ => {}
                }
            }
            Dialog::Links { matches, selected } => match key.code {
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => *selected = (*selected + 1).min(matches.len().saturating_sub(1)),
                KeyCode::Enter => {
                    if let Some(candidate) = matches.get(*selected) {
                        self.start_work(Work::Download(candidate.clone()));
                    }
                    return;
                }
                KeyCode::Char('d') => {
                    if let Some(m) = matches.get(*selected) {
                        self.back_dialog = Some(Box::new(Dialog::Links {
                            matches: matches.clone(),
                            selected: *selected,
                        }));
                        self.dialog = Some(Dialog::RemoteDetail {
                            candidate: m.clone(),
                            scroll: 0,
                        });
                    }
                    return;
                }
                _ => {}
            },
            Dialog::AssetDetail { asset, scroll } => {
                let popup = self.hits.borrow().popup;
                let maximum =
                    detail_lines(&self.local_asset_text(asset), popup.width.saturating_sub(2))
                        .len()
                        .saturating_sub(popup.height.saturating_sub(2) as usize);
                match key.code {
                    KeyCode::Up => *scroll = scroll.saturating_sub(1),
                    KeyCode::Down => *scroll = scroll.saturating_add(1).min(maximum),
                    KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                    KeyCode::PageDown => *scroll = scroll.saturating_add(10).min(maximum),
                    KeyCode::Home => *scroll = 0,
                    KeyCode::End => *scroll = maximum,
                    _ => {}
                }
            }
            Dialog::RemoteDetail { candidate, scroll } => {
                let popup = self.hits.borrow().popup;
                let maximum = detail_lines(
                    &self.remote_detail_text(candidate),
                    popup.width.saturating_sub(2),
                )
                .len()
                .saturating_sub(popup.height.saturating_sub(5) as usize);
                match key.code {
                    KeyCode::Char('w') => {
                        self.start_work(Work::CatalogDownload(candidate.clone()));
                    }
                    KeyCode::Char('L') => {
                        if self.job.is_some() {
                            self.status = "任务执行中，请等待或取消".into();
                        } else if let Some(path) = self
                            .downloads
                            .get(&candidate.url)
                            .filter(|p| p.is_file())
                            .cloned()
                        {
                            self.local_only_matches = false;
                            self.switch_section(AssetSection::Symbols);
                            self.focus_asset(Kind::Symbols, &path);
                            self.back_dialog = None;
                            return;
                        }
                    }
                    KeyCode::Char('c') => self.cancel(),
                    KeyCode::Up => *scroll = scroll.saturating_sub(1),
                    KeyCode::Down => *scroll = scroll.saturating_add(1).min(maximum),
                    KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                    KeyCode::PageDown => *scroll = scroll.saturating_add(10).min(maximum),
                    KeyCode::Home => *scroll = 0,
                    KeyCode::End => *scroll = maximum,
                    _ => {}
                }
            }
            Dialog::Detail { text, scroll } => {
                let popup = self.hits.borrow().popup;
                let maximum = detail_lines(text, popup.width.saturating_sub(2))
                    .len()
                    .saturating_sub(popup.height.saturating_sub(2) as usize);
                match key.code {
                    KeyCode::Up => *scroll = scroll.saturating_sub(1),
                    KeyCode::Down => *scroll = scroll.saturating_add(1).min(maximum),
                    KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                    KeyCode::PageDown => *scroll = scroll.saturating_add(10).min(maximum),
                    KeyCode::Home => *scroll = 0,
                    KeyCode::End => *scroll = maximum,
                    _ => {}
                }
            }
            Dialog::Input {
                kind,
                text,
                cursor,
                selected,
                ..
            } => {
                if key.code == KeyCode::Enter {
                    let value = text.trim().to_string();
                    if value.is_empty()
                        && !matches!(kind, InputKind::Search | InputKind::AssetsSearch)
                    {
                        self.status = "路径不能为空".into();
                        self.dialog = Some(dialog);
                        return;
                    }
                    let path = store::expand_home(&value);
                    match kind {
                        InputKind::Image | InputKind::Symbols => {
                            if self.job.is_some() {
                                self.status = "请先关闭弹窗，按 Esc 取消任务".into();
                                return;
                            }
                            if !path.exists() {
                                self.status = format!("路径不存在: {}", path.display());
                                self.dialog = Some(dialog);
                                return;
                            }
                            let asset_kind = if *kind == InputKind::Image {
                                Kind::Image
                            } else {
                                Kind::Symbols
                            };
                            let path = match self.registry.import(&path, asset_kind, &self.cache) {
                                Ok(path) => path,
                                Err(e) => {
                                    self.status = format!("导入失败: {e:#}");
                                    self.dialog = Some(dialog);
                                    return;
                                }
                            };
                            if *kind == InputKind::Image {
                                self.invalidate_source();
                            } else {
                                self.invalidate_symbols();
                            }
                            if *kind == InputKind::Image {
                                self.symbols = PathBuf::new();
                                self.choice = None;
                                self.image = Some(path.clone());
                            } else {
                                self.symbols = path.clone();
                            }
                            self.refresh_assets();
                            self.focus_asset(asset_kind, &path);
                            self.status = if self.page == Page::Analysis {
                                "路径已加载；选择分析并按 Enter"
                            } else {
                                "路径已加载并选用；x 进入分析"
                            }
                            .into();
                            if let Some(work) = self.pending_work.take() {
                                if matches!(work, Work::MatchLocal(_, _)) {
                                    self.symbol_target(false);
                                } else {
                                    self.start_work(work);
                                }
                            } else if *kind == InputKind::Image {
                                if self.page == Page::Assets {
                                    self.symbol_source = AssetSection::Symbols;
                                    self.prepare_selected_image();
                                } else {
                                    self.start_work(Work::Identify);
                                }
                            }
                        }
                        InputKind::PageSize => {
                            match value.parse::<usize>().ok().filter(|n| *n <= 10000).or_else(
                                || {
                                    (value.eq_ignore_ascii_case("auto") || value == "自动")
                                        .then_some(0)
                                },
                            ) {
                                Some(n) => {
                                    self.settings.page_size = n;
                                    self.row = 0;
                                    self.persist_settings();
                                }
                                None => {
                                    self.status = "请输入 auto、0 或 1–10000 的行数".into();
                                    self.dialog = Some(dialog);
                                }
                            }
                        }
                        InputKind::ImageDirectory
                        | InputKind::SymbolsDirectory
                        | InputKind::ExportDirectory => {
                            if let Err(e) = std::fs::create_dir_all(&path) {
                                self.status = format!("创建目录失败: {e}");
                                self.dialog = Some(dialog);
                                return;
                            }
                            let value = path.canonicalize().unwrap_or(path).display().to_string();
                            match kind {
                                InputKind::ImageDirectory => self.settings.image_dir = value,
                                InputKind::SymbolsDirectory => self.settings.symbols = value,
                                _ => {
                                    self.settings.export_dir = value.clone();
                                    self.settings.history_dir = value;
                                }
                            }
                            self.persist_settings();
                            self.refresh_assets();
                        }
                        InputKind::Search => {
                            self.query = value;
                            self.row = 0;
                        }
                        InputKind::AssetsSearch => {
                            self.asset_queries[self.section.slot()] = value.clone();
                            if self.section == AssetSection::Remote
                                && self.remote_catalog
                                && self.remote.is_empty()
                            {
                                self.remote_catalog = true;
                                self.start_work(Work::Catalog(String::new(), false));
                            }
                            self.asset_rows[self.section.slot()] = 0;
                        }
                        InputKind::Export => {
                            if let Some(result) = self.result() {
                                self.status = match store::export(&path, result, self.rows()) {
                                    Ok(()) => format!(
                                        "已导出 {} 条: {}{}",
                                        self.rows().len(),
                                        path.display(),
                                        if result.complete {
                                            ""
                                        } else {
                                            " (部分/历史结果)"
                                        }
                                    ),
                                    Err(e) => format!("导出失败: {e:#}"),
                                };
                            }
                        }
                        InputKind::History => {
                            if self.job.is_some() {
                                self.status = "请先取消任务".into();
                                return;
                            }
                            match store::exported(&path) {
                                Ok(result) => {
                                    self.history = Some(result);
                                    self.page = Page::Analysis;
                                    self.query.clear();
                                    self.sort = None;
                                    self.row = 0;
                                    self.focus = 2;
                                    self.status = "导出记录：历史内容，未重新验证镜像".into();
                                }
                                Err(e) => self.status = format!("历史加载失败: {e:#}"),
                            };
                        }
                    }
                    return;
                }
                edit_input(text, cursor, selected, key);
                if *kind == InputKind::Search {
                    self.query = text.clone();
                    self.row = 0;
                } else if *kind == InputKind::AssetsSearch {
                    self.asset_queries[self.section.slot()] = text.clone();
                    self.asset_rows[self.section.slot()] = 0;
                }
            }
            Dialog::Sort { column } => {
                let count = self.result().map(|r| r.columns.len()).unwrap_or(0);
                match key.code {
                    KeyCode::Up => *column = column.saturating_sub(1),
                    KeyCode::Down => *column = (*column + 1).min(count.saturating_sub(1)),
                    KeyCode::Enter => {
                        self.descending = self.sort == Some(*column) && !self.descending;
                        self.sort = Some(*column);
                        self.row = 0;
                        return;
                    }
                    _ => {}
                }
            }
            Dialog::Symbols { labels, selected } => match key.code {
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => *selected = (*selected + 1).min(labels.len().saturating_sub(1)),
                KeyCode::Enter => {
                    self.choice = Some(labels[*selected].clone());
                    self.start();
                    return;
                }
                _ => {}
            },
        }
        self.dialog = Some(dialog);
    }
    pub fn draw(&self, frame: &mut Frame) {
        *self.hits.borrow_mut() = HitMap::default();
        frame.render_widget(
            Block::default().style(Style::default().bg(SURFACE)),
            frame.area(),
        );
        let [tabs, area] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(frame.area());
        self.draw_tabs(frame, tabs);
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if self.page == Page::Analysis { 5 } else { 0 }),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(area);
        self.hits.borrow_mut().header = parts[0];
        let selected = |focus| {
            if self.focus == focus {
                Style::default().fg(ACCENT)
            } else {
                Style::default().fg(Color::DarkGray)
            }
        };
        let image = self
            .image
            .as_ref()
            .map(|p| self.display_path(p))
            .unwrap_or_else(|| "未加载；按 i 输入路径".into());
        let kernel = self
            .result()
            .filter(|r| !r.historical)
            .or_else(|| self.results.get("banners"))
            .map(|r| {
                if r.page_table == 0 {
                    format!(
                        "内核候选（尚未验证页表）: {}",
                        banner_candidates(r)
                            .first()
                            .and_then(|r| r.get(1))
                            .unwrap_or(&r.banner)
                            .trim_end()
                    )
                } else {
                    format!(
                        "镜像已读取 → 完整 banner 匹配 → 页表已验证 {:#x} · {}",
                        r.page_table, r.banner
                    )
                }
            })
            .unwrap_or_else(|| "镜像 → 内核候选 → 符号匹配 → 页表验证 · Ctrl+P 命令".into());
        frame.render_widget(
            Paragraph::new(format!(
                "镜像: {}\n符号: {}\n{}",
                escaped(&image),
                escaped(
                    &self
                        .result()
                        .filter(|r| !r.symbol.is_empty())
                        .map(|r| r.symbol.clone())
                        .unwrap_or_else(|| {
                            if self.symbols.as_os_str().is_empty() {
                                "未选择 · F3 镜像与符号".into()
                            } else {
                                self.display_path(&self.symbols)
                            }
                        })
                ),
                escaped(&kernel)
            ))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(
                        " ZERO · {} · {} ",
                        if self.settings.remote_symbols {
                            "在线符号"
                        } else {
                            "离线"
                        },
                        self.plugin.name()
                    ))
                    .border_style(selected(0)),
            ),
            parts[0],
        );
        if self.page != Page::Analysis {
            self.draw_assets(frame, parts[1]);
        } else {
            let mut main = if area.width >= 80 {
                let columns = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Length(20), Constraint::Min(20)])
                    .split(parts[1]);
                self.draw_menu(frame, columns[0], selected(1));
                columns[1]
            } else if self.focus == 1 {
                self.draw_menu(frame, parts[1], selected(1));
                Rect::default()
            } else {
                parts[1]
            };
            if area.width >= 140 && self.inspector {
                let columns =
                    Layout::horizontal([Constraint::Min(50), Constraint::Length(42)]).split(main);
                main = columns[0];
                self.hits.borrow_mut().inspector = columns[1];
                let text = self.detail_text();
                let lines = detail_lines(&text, columns[1].width.saturating_sub(2));
                frame.render_widget(
                    Paragraph::new(
                        lines
                            .into_iter()
                            .skip(self.detail_scroll)
                            .map(Line::raw)
                            .collect::<Vec<_>>(),
                    )
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("详情 · Tab 聚焦 · d 关闭")
                            .border_style(selected(3)),
                    ),
                    columns[1],
                );
            }
            if main.width > 0 {
                let regions =
                    Layout::vertical([Constraint::Length(3), Constraint::Min(2)]).split(main);
                self.draw_search(
                    frame,
                    regions[0],
                    &self.query,
                    InputKind::Search,
                    "内容搜索 · / 编辑 · Enter 确认 · Esc 撤销",
                );
                main = regions[1];
            }
            self.hits.borrow_mut().result = main;
            if main.width > 0 {
                let rows = self.visible();
                let result = self.result();
                let title = match result {
                    Some(r) => format!(
                        " {} · {} / {} 条 · {} · 第 {} / {} 页 ",
                        r.plugin,
                        self.rows().len(),
                        r.rows.len(),
                        if r.historical {
                            "历史"
                        } else if r.complete {
                            "完整"
                        } else {
                            "部分"
                        },
                        self.row / self.page_rows() + 1,
                        self.visible().len().div_ceil(self.page_rows()).max(1)
                    ),
                    None => format!(" {} ", self.plugin.name()),
                };
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(selected(2));
                if let Some(result) = result {
                    let columns = result
                        .columns
                        .iter()
                        .enumerate()
                        .map(|(i, c)| {
                            if self.sort == Some(i) {
                                format!(
                                    "{} {}",
                                    escaped(c),
                                    if self.descending { "↓" } else { "↑" }
                                )
                            } else {
                                escaped(c)
                            }
                        })
                        .collect::<Vec<_>>();
                    let natural = table_widths(&columns, &rows);
                    let widths: Vec<_> = natural.iter().copied().map(Constraint::Length).collect();
                    let total = natural.iter().map(|n| *n as u32).sum::<u32>()
                        + natural.len().saturating_sub(1) as u32
                        + 4;
                    let virtual_width = (total.min(4096) as u16).max(main.width);
                    let scroll = self
                        .horizontal
                        .min(virtual_width.saturating_sub(main.width) as usize)
                        as u16;
                    let render_area = Rect::new(main.x, main.y, virtual_width, main.height);
                    let page_size = self.page_rows();
                    let page_start = self.row / page_size * page_size;
                    let rows: Vec<_> = rows.into_iter().skip(page_start).take(page_size).collect();
                    let row_count = rows.len();
                    let viewport_block = block.clone();
                    let inner = block.inner(render_area);
                    let [_, columns_area] = Layout::horizontal([
                        Constraint::Length(if row_count > 0 { 2 } else { 0 }),
                        Constraint::Fill(0),
                    ])
                    .areas(Rect::new(inner.x, inner.y, inner.width, 1));
                    self.hits.borrow_mut().columns = Layout::horizontal(widths.clone())
                        .flex(Flex::Start)
                        .spacing(1)
                        .split(columns_area)
                        .to_vec();
                    let table = Table::new(
                        rows.into_iter().map(|row| {
                            Row::new(row.iter().map(|v| escaped(v)).collect::<Vec<_>>())
                        }),
                        widths,
                    )
                    .header(
                        Row::new(columns)
                            .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
                    )
                    .block(block)
                    .row_highlight_style(Style::default().bg(SELECTED_BG))
                    .highlight_symbol("› ");
                    let mut state = self.table_state.borrow_mut();
                    state.select(
                        (row_count > 0).then_some(
                            self.row
                                .saturating_sub(page_start)
                                .min(row_count.saturating_sub(1)),
                        ),
                    );
                    if virtual_width == main.width {
                        frame.render_stateful_widget(table, main, &mut state);
                    } else {
                        let mut buffer = ratatui::buffer::Buffer::empty(render_area);
                        StatefulWidget::render(table, render_area, &mut buffer, &mut state);
                        for y in main.y..main.bottom() {
                            for x in main.x..main.right() {
                                let source = x + scroll;
                                frame.buffer_mut()[(x, y)] = buffer[(source, y)].clone();
                            }
                        }
                        // Preserve viewport borders when the data scrolls horizontally.
                        frame.render_widget(viewport_block, main);
                        for rect in &mut self.hits.borrow_mut().columns {
                            let left = (rect.x as i32 - scroll as i32).max(main.x as i32 + 1);
                            let right =
                                (rect.right() as i32 - scroll as i32).min(main.right() as i32 - 1);
                            *rect = Rect::new(
                                left as u16,
                                rect.y,
                                (right - left).max(0) as u16,
                                rect.height,
                            );
                        }
                    }
                    self.hits.borrow_mut().row_offset = page_start + state.offset();
                } else {
                    frame.render_widget(
                    Paragraph::new(
                        "选择左侧分析项后按 Enter\n缺少符号时按完整 banner 自动匹配；M 查看远程匹配
按 p 搜索插件 · ? 查看快捷键 · o 切换离线",
                    )
                    .block(block),
                    main,
                );
                }
            }
        }
        let footer = parts[2];
        frame.render_widget(
            Block::default().borders(Borders::TOP).title(format!(
                " {} · {} · Tab 切换区域 ",
                self.page.title(),
                if self.page == Page::Analysis {
                    match self.focus {
                        0 => "镜像信息",
                        1 => "插件",
                        3 => "详情",
                        _ => "内容",
                    }
                } else if self.focus == 2 {
                    "详情"
                } else {
                    self.section.title()
                }
            )),
            footer,
        );
        let status = Rect::new(
            footer.x,
            footer.y + 1,
            footer.width,
            u16::from(footer.height > 1),
        );
        if let (Some(progress), Some(started)) = (self.progress, self.started) {
            frame.render_widget(
                Gauge::default()
                    .percent(progress)
                    .label(format!(
                        "{progress}% · {}s · {}",
                        started.elapsed().as_secs(),
                        escaped(&self.status)
                    ))
                    .gauge_style(Style::default().fg(ACCENT)),
                status,
            );
        } else {
            let message = self
                .started
                .map(|started| {
                    format!(
                        "{} · {}s · Esc 取消",
                        escaped(&self.status),
                        started.elapsed().as_secs()
                    )
                })
                .unwrap_or_else(|| escaped(&self.status));
            frame.render_widget(Paragraph::new(message), status);
        }
        let buttons = self.footer_actions();
        let more_width = Span::raw(" ?更多 ").width() as u16;
        let mut x = footer.x;
        for (label, key) in buttons {
            let text = format!(" {label} ");
            let width = Span::raw(&text).width() as u16;
            let more = key == KeyCode::Char('?');
            if footer.height < 3 {
                break;
            }
            if !more && x + width + more_width > footer.right() {
                continue;
            }
            if more && x + width > footer.right() {
                continue;
            }
            let rect = Rect::new(x, footer.y + 2, width, 1);
            frame.render_widget(
                Paragraph::new(text).style(
                    Style::default()
                        .fg(Color::Rgb(144, 203, 195))
                        .bg(Color::Rgb(27, 42, 48)),
                ),
                rect,
            );
            if self.page != Page::Assets || self.asset_disabled(self.section, key).is_none() {
                self.hits.borrow_mut().buttons.push((rect, key));
            } else {
                frame.render_widget(
                    Paragraph::new(format!(" {label} "))
                        .style(Style::default().fg(Color::DarkGray)),
                    rect,
                );
            }
            x += width;
        }
        if matches!(
            self.dialog,
            Some(Dialog::Input {
                kind: InputKind::AssetsSearch | InputKind::Search,
                ..
            })
        ) {
            return;
        }
        if let Some(dialog) = &self.dialog {
            let popup = centered(
                area,
                area.width.saturating_sub(6).min(90),
                match dialog {
                    Dialog::Dump { .. } => 12,
                    Dialog::Input { .. } => 6,
                    _ => 12,
                },
            );
            self.hits.borrow_mut().popup = popup;
            self.hits.borrow_mut().buttons.clear();
            frame.render_widget(Clear, popup);
            match dialog {
                Dialog::Dump {
                    mode,
                    fields,
                    field,
                    cursor,
                    selected,
                    error,
                    ..
                } => {
                    let labels = [
                        "PID (必填)",
                        "Start (0x / 十进制)",
                        "End (不包含)",
                        "转储目录 (必填)",
                    ];
                    frame.render_widget(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(ACCENT))
                            .title("DUMP · Tab 字段 · Ctrl+Enter 运行 · Esc 取消"),
                        popup,
                    );
                    let hint = match mode {
                        Plugin::Memdump => "指定 PID、Start 和 End；读取该进程的用户虚拟地址范围",
                        Plugin::Elfdump => "指定 PID；导出含 ELF 头的可读映射（不重建磁盘 ELF）",
                        _ => "指定 PID；导出可读 VMA；Start / End 可限制范围",
                    };
                    frame.render_widget(
                        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
                        Rect::new(popup.x + 2, popup.y + 1, popup.width.saturating_sub(4), 1),
                    );
                    let mut x = popup.x + 2;
                    for (label, plugin, n) in [
                        ("F2 Process", Plugin::Procdump, 2),
                        ("F3 Range", Plugin::Memdump, 3),
                        ("F4 ELF", Plugin::Elfdump, 4),
                    ] {
                        let width = Span::raw(label).width() as u16 + 2;
                        let rect = Rect::new(
                            x,
                            popup.y + 2,
                            width.min(popup.right().saturating_sub(x + 1)),
                            1,
                        );
                        frame.render_widget(
                            Paragraph::new(format!(" {label} ")).style(if *mode == plugin {
                                Style::default().fg(FOCUS).bg(SELECTED_BG)
                            } else {
                                Style::default().fg(ACCENT)
                            }),
                            rect,
                        );
                        self.hits.borrow_mut().dump_modes.push((rect, plugin));
                        self.hits.borrow_mut().buttons.push((rect, KeyCode::F(n)));
                        x += width;
                    }
                    let compact = popup.height < 11;
                    for (i, text) in fields.iter().enumerate() {
                        if compact && i != (*field).min(3) {
                            continue;
                        }
                        let rect = Rect::new(
                            popup.x + 2,
                            popup.y + if compact { 3 } else { 3 + i as u16 },
                            popup.width.saturating_sub(4),
                            1,
                        )
                        .intersection(popup);
                        frame.render_widget(
                            Paragraph::new(format!("{}: {}", labels[i], escaped(text))).style(
                                if *field == i {
                                    Style::default().fg(FOCUS).bg(SELECTED_BG)
                                } else {
                                    Style::default()
                                },
                            ),
                            rect,
                        );
                        self.hits.borrow_mut().dump_fields.push((rect, i));
                        if *field == i && !selected {
                            let x = rect.x
                                + Span::raw(format!("{}: {}", labels[i], escaped(&text[..*cursor])))
                                    .width() as u16;
                            if x < rect.right() {
                                frame.set_cursor_position((x, rect.y));
                            }
                        }
                    }
                    let y = popup.bottom().saturating_sub(2);
                    frame.render_widget(
                        Paragraph::new(error.as_str()).style(Style::default().fg(FOCUS)),
                        Rect::new(
                            popup.x + 2,
                            y.saturating_sub(1),
                            popup.width.saturating_sub(4),
                            1,
                        ),
                    );
                    let run = Rect::new(popup.x + 2, y, 14.min(popup.width.saturating_sub(4)), 1);
                    frame.render_widget(
                        Paragraph::new("[开始转储]").style(
                            Style::default().fg(FOCUS).bg(if *field == 4 {
                                SELECTED_BG
                            } else {
                                SURFACE
                            }),
                        ),
                        run,
                    );
                    let cancel = Rect::new(
                        run.right() + 1,
                        y,
                        8.min(popup.right().saturating_sub(run.right() + 2)),
                        1,
                    );
                    frame.render_widget(Paragraph::new("[取消]"), cancel);
                    self.hits
                        .borrow_mut()
                        .buttons
                        .extend([(run, KeyCode::Enter), (cancel, KeyCode::Esc)]);
                }
                Dialog::Files {
                    kind,
                    root,
                    entries,
                    selected,
                } => {
                    let title = format!(
                        "{} · Enter 选用 · ← 上级 · Tab 切换目录 · p 路径",
                        match kind {
                            InputKind::Image => "选择镜像",
                            InputKind::Symbols => "选择符号",
                            InputKind::History => "导出记录",
                            _ => "选择目录",
                        }
                    );
                    let mut labels = entries
                        .iter()
                        .map(|e| {
                            format!(
                                "{} {}",
                                if e.directory {
                                    "DIR"
                                } else {
                                    match crate::browser::file_kind(&e.path) {
                                        crate::browser::FileKind::Image => "IMG",
                                        crate::browser::FileKind::Symbols => "ISF",
                                        crate::browser::FileKind::Other => "FILE",
                                    }
                                },
                                escaped(&e.path.file_name().unwrap_or_default().to_string_lossy())
                            )
                        })
                        .collect::<Vec<_>>();
                    if labels.is_empty() {
                        labels.push("目录中没有匹配文件；← 上级，p 输入路径".into());
                    }
                    let mut state = ListState::default()
                        .with_selected((!entries.is_empty()).then_some(*selected));
                    frame.render_stateful_widget(
                        List::new(labels)
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title(title)
                                    .title_bottom(format!(
                                        "目录: {}",
                                        escaped(&self.display_path(root))
                                    )),
                            )
                            .highlight_symbol("› ")
                            .highlight_style(Style::default().fg(ACCENT)),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                    let _ = kind;
                }
                Dialog::Settings { selected } => {
                    let mut state = ListState::default().with_selected(Some(*selected));
                    frame.render_stateful_widget(
                        List::new(self.settings_labels())
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title("目录与分页设置 · Enter 修改 · Esc 关闭"),
                            )
                            .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                }
                Dialog::Cache {
                    entries,
                    scopes,
                    selected,
                    confirm,
                } => {
                    let items = cache::SCOPES
                        .iter()
                        .map(|scope| {
                            let files: Vec<_> =
                                entries.iter().filter(|e| e.scope == *scope).collect();
                            let size: u64 = files.iter().map(|e| e.bytes).sum();
                            format!(
                                "[{}] {} · {} 个文件 · {:.1} MiB",
                                if scopes.contains(scope) { "x" } else { " " },
                                scope.label(),
                                files.len(),
                                size as f64 / 1048576.0
                            )
                        })
                        .collect::<Vec<_>>();
                    let mut state = ListState::default().with_selected(Some(*selected));
                    frame.render_stateful_widget(
                        List::new(items)
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title("缓存管理 · Space 勾选 · Enter 预览／清理"),
                            )
                            .highlight_symbol("› ")
                            .highlight_style(Style::default().fg(ACCENT)),
                        popup,
                        &mut state,
                    );
                    let button = Rect::new(
                        popup.x + 2,
                        popup.bottom().saturating_sub(3),
                        popup.width.saturating_sub(4),
                        1,
                    );
                    frame.render_widget(
                        Paragraph::new(if *confirm {
                            "[确认清理]"
                        } else {
                            "[预览清理]"
                        })
                        .style(Style::default().fg(FOCUS)),
                        button,
                    );
                    self.hits
                        .borrow_mut()
                        .buttons
                        .push((button, KeyCode::Enter));
                    let files = cache::selected(entries, scopes);
                    let size: u64 = files.iter().map(|e| e.bytes).sum();
                    frame.render_widget(
                        Paragraph::new(format!(
                            "{} {} 个文件 / {:.1} MiB\n保留原镜像、导出、配置和迁移备份",
                            if *confirm {
                                "再次 Enter 清理："
                            } else {
                                "已选："
                            },
                            files.len(),
                            size as f64 / 1048576.0
                        )),
                        Rect::new(popup.x + 2, popup.y + 6, popup.width.saturating_sub(4), 3),
                    );
                }
                Dialog::Commands { query, selected } => {
                    let mut state = ListState::default().with_selected(Some(*selected));
                    frame.render_stateful_widget(
                        List::new(
                            self.available_commands(query)
                                .iter()
                                .map(|(label, _)| *label),
                        )
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(format!("命令 · {} · Enter 执行", escaped(query))),
                        )
                        .highlight_symbol("› ")
                        .highlight_style(Style::default().fg(ACCENT)),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
                Dialog::Plugins { query, selected } => {
                    let plugins = plugin_matches(query);
                    let mut state = ListState::default()
                        .with_selected((!plugins.is_empty()).then_some(*selected));
                    frame.render_stateful_widget(
                        List::new(plugins.iter().map(|p| plugin_label(*p)))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title(format!("插件搜索: {} · Enter 执行", escaped(query))),
                            )
                            .highlight_style(Style::default().fg(ACCENT))
                            .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
                Dialog::Links { matches, selected } => {
                    let mut state = ListState::default().with_selected(Some(*selected));
                    frame.render_stateful_widget(
                        List::new(matches.iter().map(|m| escaped(&m.path)))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title("匹配的 ISF · Enter 下载并分析 · d 完整 URL"),
                            )
                            .highlight_style(Style::default().fg(ACCENT))
                            .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
                Dialog::AssetDetail { asset, scroll } => {
                    let lines =
                        detail_lines(&self.local_asset_text(asset), popup.width.saturating_sub(2));
                    let maximum = lines
                        .len()
                        .saturating_sub(popup.height.saturating_sub(2) as usize);
                    frame.render_widget(
                        Paragraph::new(
                            lines
                                .into_iter()
                                .skip((*scroll).min(maximum))
                                .map(Line::raw)
                                .collect::<Vec<_>>(),
                        )
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("资产详情 · ↑↓ / PgUp PgDn · Esc 关闭"),
                        ),
                        popup,
                    );
                }
                Dialog::RemoteDetail { candidate, scroll } => {
                    frame.render_widget(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(ACCENT))
                            .title("远程符号详情 · ↑↓ 滚动 · Esc 返回"),
                        popup,
                    );
                    let content = Rect::new(
                        popup.x + 1,
                        popup.y + 1,
                        popup.width.saturating_sub(2),
                        popup.height.saturating_sub(5),
                    );
                    let text = self.remote_detail_text(candidate);
                    let lines = detail_lines(&text, content.width);
                    let maximum = lines.len().saturating_sub(content.height as usize);
                    frame.render_widget(
                        Paragraph::new(
                            lines
                                .into_iter()
                                .skip((*scroll).min(maximum))
                                .map(Line::raw)
                                .collect::<Vec<_>>(),
                        ),
                        content,
                    );
                    let mut x = popup.x + 1;
                    let y = popup.bottom().saturating_sub(3);
                    for (label, key, enabled) in [
                        ("下载到 symbols w", KeyCode::Char('w'), self.job.is_none()),
                        (
                            "本地库定位 L",
                            KeyCode::Char('L'),
                            self.job.is_none()
                                && self
                                    .downloads
                                    .get(&candidate.url)
                                    .is_some_and(|p| p.is_file()),
                        ),
                        ("取消下载 c", KeyCode::Char('c'), self.job.is_some()),
                    ] {
                        let text = format!("[{label}]");
                        let width = Span::raw(&text).width() as u16;
                        if x + width >= popup.right() || popup.height < 5 {
                            continue;
                        }
                        let rect = Rect::new(x, y, width, 1);
                        frame.render_widget(
                            Paragraph::new(text).style(Style::default().fg(if enabled {
                                FOCUS
                            } else {
                                Color::DarkGray
                            })),
                            rect,
                        );
                        if enabled {
                            self.hits.borrow_mut().buttons.push((rect, key));
                        }
                        x += width + 1;
                    }
                }
                Dialog::Detail { text, scroll } => {
                    let lines = detail_lines(text, popup.width.saturating_sub(2));
                    let maximum = lines
                        .len()
                        .saturating_sub(popup.height.saturating_sub(2) as usize);
                    frame.render_widget(
                        Paragraph::new(
                            lines
                                .into_iter()
                                .skip((*scroll).min(maximum))
                                .map(Line::raw)
                                .collect::<Vec<_>>(),
                        )
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("详情 · ↑↓ / PgUp PgDn · Esc 关闭"),
                        ),
                        popup,
                    );
                }
                Dialog::Input {
                    kind,
                    text,
                    cursor,
                    selected,
                    ..
                } => {
                    let title = match kind {
                        InputKind::Image => "镜像路径 · RAW / LiME / gzip",
                        InputKind::Symbols => "符号路径 · JSON / JSON.XZ / ZIP / 目录",
                        InputKind::Search => "全文搜索",
                        InputKind::AssetsSearch => "资产筛选 · Enter 确认 / Esc 撤销",
                        InputKind::Export => "导出当前筛选 · .csv / .json",
                        InputKind::History => "导出记录 · CSV / JSON 路径",
                        InputKind::ImageDirectory => "镜像存放目录",
                        InputKind::SymbolsDirectory => "符号存放目录",
                        InputKind::ExportDirectory => "导出存放目录",
                        InputKind::PageSize => "每页行数 · auto 自动填满 / 0 / 1–10000",
                    };
                    frame.render_widget(
                        Paragraph::new(Line::from(Span::styled(
                            escaped(text),
                            if *selected {
                                Style::default().bg(SELECTED_BG).fg(Color::White)
                            } else {
                                Style::default()
                            },
                        )))
                        .wrap(Wrap { trim: false })
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(title)
                                .border_style(Style::default().fg(ACCENT)),
                        ),
                        popup,
                    );
                    let width = popup.width.saturating_sub(2).max(1);
                    let n = Span::raw(escaped(&text[..*cursor])).width() as u16;
                    let y_cursor = popup.y + 1 + n / width;
                    if y_cursor < popup.bottom().saturating_sub(2) {
                        frame.set_cursor_position(Position::new(popup.x + 1 + n % width, y_cursor));
                    }
                    let y = popup.bottom().saturating_sub(2);
                    let buttons = Rect::new(popup.x + 1, y, popup.width.saturating_sub(2), 1);
                    frame.render_widget(Clear, buttons);
                    frame.render_widget(
                        Paragraph::new("[确认] [取消] Ctrl+u 清空 · ←→ 编辑")
                            .style(Style::default().fg(ACCENT)),
                        buttons,
                    );
                    self.hits.borrow_mut().buttons.extend([
                        (
                            Rect::new(buttons.x, y, 6.min(buttons.width), 1),
                            KeyCode::Enter,
                        ),
                        (
                            Rect::new(buttons.x + 7, y, 6.min(buttons.width.saturating_sub(7)), 1),
                            KeyCode::Esc,
                        ),
                    ]);
                }
                Dialog::Sort { column } => {
                    let labels = self.result().map(|r| r.columns.clone()).unwrap_or_default();
                    let mut state = ListState::default().with_selected(Some(*column));
                    frame.render_stateful_widget(
                        List::new(labels)
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title("排序列 · 再选同列反转 · Esc 取消"),
                            )
                            .highlight_style(Style::default().fg(ACCENT))
                            .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
                Dialog::Symbols { labels, selected } => {
                    let mut state = ListState::default().with_selected(Some(*selected));
                    frame.render_stateful_widget(
                        List::new(
                            labels
                                .iter()
                                .map(|label| escaped(label))
                                .collect::<Vec<_>>(),
                        )
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("多个完整 banner 匹配 · 请选择 ISF"),
                        )
                        .highlight_style(Style::default().fg(ACCENT))
                        .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
            }
            if !matches!(dialog, Dialog::Input { .. } | Dialog::Dump { .. }) {
                let cancel = Rect::new(
                    popup.right().saturating_sub(8).max(popup.x),
                    popup.bottom().saturating_sub(1),
                    8.min(popup.width),
                    1,
                );
                frame.render_widget(Paragraph::new("[取消]"), cancel);
                self.hits.borrow_mut().buttons.push((cancel, KeyCode::Esc));
            }
        }
    }
    fn draw_menu(&self, frame: &mut Frame, area: Rect, style: Style) {
        let mut state = ListState::default().with_selected(Some(self.menu));
        frame.render_stateful_widget(
            List::new(menu_items().into_iter().map(ListItem::new))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Plugins · p 搜索")
                        .border_style(style),
                )
                .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
                .highlight_symbol("› "),
            area,
            &mut state,
        );
        let mut hits = self.hits.borrow_mut();
        hits.menu = area;
        hits.menu_offset = state.offset();
    }
}
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}
fn tree_rows(rows: Vec<Vec<String>>, collapsed: &HashSet<String>) -> Vec<Vec<String>> {
    let ids: HashSet<_> = rows.iter().map(|r| r[0].as_str()).collect();
    let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        if row[2] == "0" || !ids.contains(row[2].as_str()) || row[0] == row[2] {
            roots.push(i);
        } else {
            children.entry(&row[2]).or_default().push(i);
        }
    }
    let mut visited = HashSet::new();
    let mut output = Vec::new();
    // Each remaining node is a fallback root for malformed parent cycles.
    for root in roots.into_iter().chain(0..rows.len()) {
        if visited.contains(&root) {
            continue;
        }
        let mut stack = vec![(root, 0usize, false)];
        while let Some((index, depth, hidden)) = stack.pop() {
            if !visited.insert(index) {
                continue;
            }
            let row = &rows[index];
            if !hidden {
                let mut shown = row.clone();
                let has_children = children.contains_key(row[0].as_str());
                shown[3] = format!(
                    "{}{} {}",
                    "  ".repeat(depth.min(64)),
                    if has_children {
                        if collapsed.contains(&row[0]) {
                            "▸"
                        } else {
                            "▾"
                        }
                    } else {
                        "·"
                    },
                    row[3]
                );
                output.push(shown);
            }
            if let Some(kids) = children.get(row[0].as_str()) {
                for child in kids.iter().rev() {
                    stack.push((*child, depth + 1, hidden || collapsed.contains(&row[0])));
                }
            }
        }
    }
    output
}
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}
fn restore() {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(
        std::io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        Show
    );
}
pub fn run(
    image: Option<PathBuf>,
    symbols: PathBuf,
    cache: PathBuf,
    settings: Settings,
) -> Result<()> {
    terminal::enable_raw_mode().context("TUI 需要真实终端；批处理请使用 analyze")?;
    let _guard = TerminalGuard;
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let previous = std::panic::take_hook();
    let ui_thread = thread::current().id();
    std::panic::set_hook(Box::new(move |info| {
        if thread::current().id() == ui_thread {
            restore();
            previous(info);
        }
        // Worker panics are caught and reported through the event channel.
    }));
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut app = App::new(image, symbols, cache, settings);
    if app.image.is_some() {
        app.start_work(Work::Identify);
    }
    let outcome = (|| -> Result<()> {
        let mut dirty = true;
        let mut last_tick = Instant::now();
        loop {
            if app.job.is_some() && last_tick.elapsed() >= Duration::from_millis(280) {
                dirty = true;
                last_tick = Instant::now();
            }
            dirty |= app.drain();
            if dirty {
                terminal.draw(|f| app.draw(f))?;
                dirty = false;
            }
            if event::poll(Duration::from_millis(80))? {
                let next = event::read()?;
                dirty = !matches!(
                    next,
                    Event::Mouse(MouseEvent {
                        kind: MouseEventKind::Moved,
                        ..
                    })
                );
                let quit = match next {
                    Event::Key(key) => app.key(key),
                    Event::Mouse(mouse) => app.mouse(mouse),
                    Event::Resize(width, height) => {
                        app.resize(width, height);
                        false
                    }
                    Event::Paste(text) => {
                        app.paste(&text);
                        false
                    }
                    _ => false,
                };
                if quit {
                    break;
                }
            }
        }
        Ok(())
    })();
    app.cancel();
    app.finish_worker();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    fn app() -> App {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            None,
            "symbols".into(),
            dir.path().join("cache"),
            Settings::default(),
        );
        app.results.insert(
            "pslist".into(),
            Results {
                plugin: "pslist".into(),
                columns: vec!["PID", "TGID", "PPID", "Name", "Address"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                rows: vec![
                    vec!["10", "10", "0", "zsh", "0x1000"],
                    vec!["2", "2", "0", "init", "0x2000"],
                ]
                .into_iter()
                .map(|r| r.into_iter().map(String::from).collect())
                .collect(),
                complete: true,
                diagnostics: vec![],
                banner: String::new(),
                symbol: String::new(),
                page_table: 0,
                historical: false,
            },
        );
        app
    }
    #[test]
    fn asset_tabs_import_filter_selection_and_non_destructive_removal() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("sample.raw");
        let symbols = dir.path().join("exact.json.xz");
        std::fs::write(&image, b"image").unwrap();
        std::fs::write(&symbols, b"symbols").unwrap();
        let image = image.canonicalize().unwrap();
        let symbols = symbols.canonicalize().unwrap();
        let cache = dir.path().join("cache");
        let mut app = App::new(None, "missing".into(), cache.clone(), Settings::default());
        app.root = dir.path().into();
        app.settings.symbols = symbols.display().to_string();
        app.settings.image_dir = dir.path().join("images").display().to_string();
        app.key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        app.paste(&image.display().to_string());
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.image.as_ref(), Some(&image));
        assert_eq!(
            Registry::load(&cache).unwrap().selected(Kind::Image),
            Some(image.as_path())
        );
        assert_eq!(app.asset_count(), 1);
        assert!(app.job.is_some()); // importing an image starts banner identification
        app.finish_worker();

        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.paste("absent");
        assert_eq!(app.asset_count(), 0);
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.asset_count(), 1);
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.paste("sample");
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.asset_queries[0].is_empty());
        app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert!(image.exists());
        assert!(app.image.is_none());
        assert_eq!(app.asset_count(), 0);
        assert!(
            Registry::load(&cache)
                .unwrap()
                .selected(Kind::Image)
                .is_none()
        );
        app.switch_section(AssetSection::Symbols);
        assert_eq!(app.section, AssetSection::Symbols);
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.symbols, symbols);
        assert_eq!(
            Registry::load(&cache).unwrap().selected(Kind::Symbols),
            Some(symbols.as_path())
        );
        assert!(app.results.is_empty());
        app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert!(symbols.exists());
        assert!(app.symbols.as_os_str().is_empty());
        assert!(Registry::load(&cache).unwrap().excluded(&symbols));

        app.switch_section(AssetSection::Images);
        app.key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        assert!(app.job.is_none());
        assert!(app.dialog.is_none()); // no selected image must not silently use the old one
    }
    #[test]
    fn remote_tabs_mouse_scrolling_full_links_events_and_cancellation() {
        let mut app = app();
        app.switch_section(AssetSection::Remote);
        app.remote = (0..50)
            .map(|i| RemoteMatch {
                banner: format!("Linux version exact-{i}\tcomplete"),
                path: format!("Linux/sample-{i}.json.xz"),
                url: format!(
                    "https://example.test/{}-{i}.json.xz",
                    "long-path/".repeat(100)
                ),
            })
            .collect();
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert!(hits.asset_offset > 0);
        click(&mut app, hits.assets.x + 2, hits.assets.y + 1);
        assert_eq!(app.asset_rows[2], hits.asset_offset);
        assert!(app.job.is_none()); // row selection never triggers download
        let Some(Dialog::RemoteDetail { candidate, .. }) = &app.dialog else {
            panic!("detail missing")
        };
        let text = app.remote_detail_text(candidate);
        assert!(text.contains(&app.remote[hits.asset_offset].url));
        assert!(text.contains("\\t"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.focus = 2;
        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert!(app.asset_scroll[2] > 0);
        let job = Job::default();
        app.job = Some(job.clone());
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(job.cancel.load(Ordering::Relaxed));
        app.job = None;
        let (tx, rx) = mpsc::channel();
        tx.send(WorkerEvent::Links(app.remote.clone())).unwrap();
        app.receiver = Some(rx);
        app.drain();
        assert!(app.dialog.is_none());
        assert_eq!(app.remote.len(), 50);
        terminal.draw(|f| app.draw(f)).unwrap();
        let rect = app.hits.borrow().tabs[1].0;
        click(&mut app, rect.x, rect.y);
        assert_eq!(app.section, AssetSection::Remote); // Switching a top-level tab preserves the region.
        app.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Analysis);
    }
    #[test]
    fn downloaded_symbols_are_registered_without_starting_analysis_in_manager() {
        let dir = tempfile::tempdir().unwrap();
        let symbols = dir.path().join("download.json.xz");
        std::fs::write(&symbols, b"validated worker output").unwrap();
        let symbols = symbols.canonicalize().unwrap();
        let cache = dir.path().join("cache");
        let settings = Settings {
            image_dir: dir.path().join("images").display().to_string(),
            symbols: dir.path().join("symbols").display().to_string(),
            ..Settings::default()
        };
        let mut app = App::new(None, "absent".into(), cache.clone(), settings);
        app.root = dir.path().into();
        app.switch_section(AssetSection::Remote);
        app.download_url = Some("https://example.test/exact.json.xz".into());
        let (tx, rx) = mpsc::channel();
        tx.send(WorkerEvent::Downloaded(symbols.clone())).unwrap();
        app.receiver = Some(rx);
        app.drain();
        assert_eq!(app.section, AssetSection::Remote);
        assert!(app.job.is_none());
        assert_eq!(app.symbols, symbols);
        assert_eq!(app.downloads.len(), 1);
        app.switch_section(AssetSection::Symbols);
        assert!(app.asset_list().iter().any(|a| a.path == symbols));
        assert_eq!(
            Registry::load(&cache).unwrap().selected(Kind::Symbols),
            Some(symbols.as_path())
        );
    }
    #[test]
    fn all_asset_pages_render_on_wide_narrow_and_tiny_terminals() {
        let mut app = app();
        for (w, h) in [(170, 32), (80, 24), (45, 16), (20, 8), (1, 1)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            for page in Page::ALL {
                app.switch_page(page);
                terminal.draw(|f| app.draw(f)).unwrap();
            }
        }
    }
    #[test]
    fn compact_columns_mixed_numeric_sort_and_paginated_mouse_rows() {
        let columns = vec!["PID".into(), "Name".into(), "Path".into()];
        let rows = vec![vec!["2".into(), "sh".into(), "/very/long/path".into()]];
        assert_eq!(table_widths(&columns, &rows), vec![3, 4, 15]);
        let mut mixed = vec!["2", "10", "1a", "0x3", ""];
        mixed.sort_by(|a, b| compare_values(a, b));
        assert_eq!(mixed, vec!["2", "0x3", "10", "", "1a"]);
        let mut app = app();
        let result = app.results.get_mut("pslist").unwrap();
        result.rows = (0..20)
            .map(|i| {
                vec![
                    i.to_string(),
                    i.to_string(),
                    "0".into(),
                    "sh".into(),
                    "0x1000".into(),
                ]
            })
            .collect();
        app.settings.page_size = 2;
        app.focus = 2;
        app.key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE));
        assert_eq!(app.row, 2);
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hit = app.hits.borrow().clone();
        assert_eq!(hit.row_offset, 2);
        click(&mut app, hit.result.x + 2, hit.result.y + 2);
        assert_eq!(app.row, 2);
        assert_eq!(app.rows().len(), 20); // page does not limit export
        app.key(KeyEvent::new(KeyCode::Char('['), KeyModifiers::NONE));
        assert_eq!(app.row, 0);
        assert_eq!(menu_items().len(), navigation_plugins().len() + 3);
        assert!(!menu_items().iter().any(|i| i.contains("CSV")));
    }
    #[test]
    fn directory_configuration_picker_navigation_and_export_history() {
        let dir = tempfile::tempdir().unwrap();
        let images = dir.path().join("images");
        let nested = images.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("one.raw"), b"image").unwrap();
        let mut app = App::new(
            None,
            "missing".into(),
            dir.path().join("cache"),
            Settings::default(),
        );
        app.accept_path(InputKind::ImageDirectory, images.clone());
        assert_eq!(
            store::settings(&app.cache).unwrap().image_dir,
            images.canonicalize().unwrap().display().to_string()
        );
        app.open_files(InputKind::Image);
        assert!(matches!(app.dialog, Some(Dialog::Files { .. })));
        if let Some(Dialog::Files {
            entries,
            selected,
            root,
            ..
        }) = &mut app.dialog
        {
            assert!(same_path(root, &images));
            assert!(entries.iter().any(|e| e.path.ends_with("nested")));
            *selected = entries
                .iter()
                .position(|e| e.directory && same_path(&e.path, &nested))
                .unwrap();
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            matches!(&app.dialog, Some(Dialog::Files { root, .. }) if root.ends_with("nested"))
        );
        app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert!(
            matches!(&app.dialog, Some(Dialog::Files { root, .. }) if root.ends_with("images"))
        );
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        assert!(matches!(
            app.dialog,
            Some(Dialog::Files {
                kind: InputKind::History,
                ..
            })
        ));
        let result = super::tests::app().results.remove("pslist").unwrap();
        let json = dir.path().join("history.json");
        store::export(&json, &result, result.rows.clone()).unwrap();
        app.accept_path(InputKind::History, json);
        assert!(app.result().unwrap().historical);
        assert_eq!(app.rows().len(), 2);
    }
    #[test]
    fn refresh_without_image_does_not_prompt_and_offline_error_is_actionable() {
        let mut app = app();
        app.settings.remote_symbols = false;
        app.switch_section(AssetSection::Remote);
        app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert!(app.dialog.is_none());
        for _ in 0..100 {
            app.drain();
            if app.job.is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.job.is_none());
        assert!(app.status.contains("按 o"));
        assert!(app.logs.iter().any(|s| s.contains("离线")));
    }
    #[test]
    fn imported_image_automatically_identifies_banner_and_renders_progress() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.raw");
        let mut bytes = vec![0; 8192];
        let banner = b"Linux version 3.2.0-test (test@test) (gcc version 4.6.3) #1 SMP test\n\0";
        bytes[256..256 + banner.len()].copy_from_slice(banner);
        std::fs::write(&path, bytes).unwrap();
        let mut app = App::new(
            None,
            "missing".into(),
            dir.path().join("cache"),
            Settings::default(),
        );
        app.accept_path(InputKind::Image, path);
        assert!(app.job.is_some());
        for _ in 0..100 {
            app.drain();
            if app.job.is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(app.results["banners"].rows.len(), 1);
        let candidate = app.results.get_mut("banners").unwrap();
        candidate.rows.insert(
            0,
            vec![
                "0x1".into(),
                format!(
                    "Linux version 4.4.0 #1 SMP {}",
                    "embedded application data".repeat(40)
                ),
            ],
        );
        assert!(banner_candidates(candidate)[0][1].contains("3.2.0-test"));
        assert_eq!(candidate.rows.len(), 2); // full banner output is retained
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(rendered.contains("Linux version 3.2.0-test"));
        app.started = Some(Instant::now());
        app.progress = Some(42);
        terminal.draw(|f| app.draw(f)).unwrap();
        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(rendered.contains("42%"));
    }
    #[test]
    fn layouts_and_popup() {
        for (w, h) in [(80, 24), (120, 32), (45, 16), (20, 8)] {
            let mut app = app();
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            app.focus = 2;
            terminal.draw(|f| app.draw(f)).unwrap();
            app.open_input(InputKind::Export);
            terminal.draw(|f| app.draw(f)).unwrap();
            use unicode_width::UnicodeWidthStr;
            let mut text = String::new();
            for row in terminal.backend().buffer().content.chunks(w as usize) {
                let mut x = 0;
                while x < row.len() {
                    let symbol = row[x].symbol();
                    text.push_str(symbol);
                    x += symbol.width().max(1);
                }
            }
            assert!(text.contains("导出当前筛选") || w < 45, "{w}x{h}: {text:?}");
        }
    }
    fn screen(terminal: &Terminal<TestBackend>, width: usize) -> String {
        use unicode_width::UnicodeWidthStr;
        let mut text = String::new();
        for row in terminal.backend().buffer().content.chunks(width) {
            let mut x = 0;
            while x < row.len() {
                let symbol = row[x].symbol();
                text.push_str(symbol);
                x += symbol.width().max(1);
            }
            text.push('\n');
        }
        text
    }
    #[test]
    fn closing_popup_restores_results() {
        let mut app = app();
        app.focus = 2;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let before = screen(&terminal, 80);
        app.open_input(InputKind::Export);
        terminal.draw(|f| app.draw(f)).unwrap();
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(screen(&terminal, 80), before);
    }
    fn mouse_event(kind: MouseEventKind, x: u16, y: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        }
    }
    fn click(app: &mut App, x: u16, y: u16) -> bool {
        app.mouse(mouse_event(MouseEventKind::Down(MouseButton::Left), x, y))
    }
    #[test]
    fn mouse_menu_header_and_modal() {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let header = app.hits.borrow().header;
        assert!(!click(&mut app, 5, header.y + 2));
        assert!(matches!(
            app.dialog,
            Some(Dialog::Files {
                kind: InputKind::Symbols,
                ..
            })
        ));
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        // Modal clicks must not activate the underlying menu.
        click(&mut app, 0, 0);
        assert!(app.dialog.is_some());
        let cancel = hits
            .buttons
            .iter()
            .find(|(_, key)| *key == KeyCode::Esc)
            .unwrap()
            .0;
        click(&mut app, cancel.x, cancel.y);
        assert!(app.dialog.is_none());
        terminal.draw(|f| app.draw(f)).unwrap();
        let menu = app.hits.borrow().menu;
        click(&mut app, 5, menu.y + 2);
        assert!(matches!(
            app.dialog,
            Some(Dialog::Files {
                kind: InputKind::Symbols,
                ..
            })
        ));
        app.mouse(mouse_event(MouseEventKind::Down(MouseButton::Right), 5, 7));
        assert!(app.dialog.is_none());
        terminal.draw(|f| app.draw(f)).unwrap();
        let menu = app.hits.borrow().menu;
        click(&mut app, 5, menu.y + 3);
        assert_eq!(app.plugin, Plugin::Pslist);
        assert_eq!(app.focus, 2);
    }
    #[test]
    fn mouse_scrolled_rows_sort_and_wheel() {
        let mut app = app();
        let template = app.result().unwrap().rows[0].clone();
        app.results.get_mut("pslist").unwrap().rows = (0..40)
            .map(|i| {
                let mut r = template.clone();
                r[0] = i.to_string();
                r
            })
            .collect();
        app.row = 25;
        app.focus = 2;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert!(hits.row_offset > 0);
        click(&mut app, hits.result.x + 3, hits.result.y + 2);
        assert_eq!(app.row, hits.row_offset);
        app.mouse(mouse_event(
            MouseEventKind::ScrollDown,
            hits.result.x + 3,
            hits.result.y + 2,
        ));
        assert_eq!(app.row, hits.row_offset + 3);
        let col = hits.columns[0];
        click(&mut app, col.x, hits.result.y + 1);
        assert_eq!(app.sort, Some(0));
        assert!(!app.descending);
        click(&mut app, col.x, hits.result.y + 1);
        assert!(app.descending);
        let focus = app.focus;
        app.mouse(mouse_event(MouseEventKind::Moved, 5, 8));
        assert_eq!(app.focus, focus);
    }
    #[test]
    fn mouse_tree_and_sort_popup() {
        let mut app = app();
        let mut result = app.result().unwrap().clone();
        result.plugin = "pstree".into();
        result.rows[1][2] = "10".into();
        app.results.insert("pstree".into(), result);
        app.plugin = Plugin::Pstree;
        app.focus = 2;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        click(&mut app, hits.columns[3].x, hits.result.y + 2);
        assert_eq!(app.visible().len(), 1);
        terminal.draw(|f| app.draw(f)).unwrap();
        click(&mut app, hits.columns[3].x, hits.result.y + 2);
        assert_eq!(app.visible().len(), 2);
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        let popup = app.hits.borrow().popup;
        click(&mut app, popup.x + 2, popup.y + 2);
        assert_eq!(app.sort, Some(1));
        assert!(app.dialog.is_none());
    }
    #[test]
    fn mouse_narrow_pages_and_footer_actions() {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(45, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert_eq!(hits.result.width, 0);
        let tab = hits
            .buttons
            .iter()
            .find(|(_, key)| *key == KeyCode::Tab)
            .unwrap()
            .0;
        click(&mut app, tab.x, tab.y);
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(app.hits.borrow().result.width > 0);
        let search = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(_, key)| *key == KeyCode::Char('/'))
            .unwrap()
            .0;
        click(&mut app, search.x, search.y);
        assert!(matches!(
            app.dialog,
            Some(Dialog::Input {
                kind: InputKind::Search,
                ..
            })
        ));
    }
    #[test]
    fn mouse_input_confirm_and_symbol_candidates() {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        app.open_input(InputKind::Search);
        app.dialog_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        let confirm = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(_, key)| *key == KeyCode::Enter)
            .unwrap()
            .0;
        click(&mut app, confirm.x, confirm.y);
        assert!(app.dialog.is_none());
        assert_eq!(app.rows().len(), 1);
        app.dialog = Some(Dialog::Symbols {
            labels: (0..20).map(|i| format!("symbol-{i}")).collect(),
            selected: 15,
        });
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert!(hits.popup_offset > 0);
        click(&mut app, hits.popup.x + 2, hits.popup.y + 1);
        assert_eq!(app.choice, Some(format!("symbol-{}", hits.popup_offset)));
        // No image is loaded, so selecting a candidate asks for the image.
        assert!(matches!(
            app.dialog,
            Some(Dialog::Files {
                kind: InputKind::Image,
                ..
            })
        ));
    }
    #[test]
    fn search_sort_cancel() {
        let mut app = app();
        app.sort = Some(0);
        assert_eq!(app.rows()[0][0], "2");
        app.descending = true;
        assert_eq!(app.rows()[0][0], "10");
        app.open_input(InputKind::Search);
        app.dialog_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.rows().len(), 1);
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.rows().len(), 2);
    }
    #[test]
    fn tree_expansion_and_cycle() {
        let rows = vec![
            vec!["1", "1", "0", "init", "0"],
            vec!["2", "2", "1", "child", "0"],
            vec!["3", "3", "2", "leaf", "0"],
        ]
        .into_iter()
        .map(|r| r.into_iter().map(String::from).collect())
        .collect::<Vec<_>>();
        assert_eq!(tree_rows(rows.clone(), &HashSet::new()).len(), 3);
        assert_eq!(tree_rows(rows, &HashSet::from(["1".into()])).len(), 1);
    }
    #[test]
    fn new_plugin_menu_mouse_details_and_raw_export() {
        let mut app = app();
        for d in PLUGINS {
            let mut r = app.results["pslist"].clone();
            r.plugin = d.plugin.name().into();
            r.columns = d.columns.iter().map(|s| (*s).into()).collect();
            r.rows = (0..40)
                .map(|n| {
                    d.columns
                        .iter()
                        .enumerate()
                        .map(|(index, c)| {
                            if index == 0 {
                                format!("item-{n:03}")
                            } else {
                                format!("{c}\n\x1b{}", "长".repeat(500))
                            }
                        })
                        .collect()
                })
                .collect();
            app.results.insert(d.plugin.name().into(), r);
        }
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        for d in PLUGINS.iter().skip(3).filter(|d| !d.plugin.is_dump()) {
            app.focus = 1;
            app.menu = navigation_plugins()
                .iter()
                .position(|p| *p == d.plugin)
                .unwrap()
                + 2;
            terminal.draw(|f| app.draw(f)).unwrap();
            let h = app.hits.borrow().clone();
            let y = h.menu.y + 1 + (app.menu - h.menu_offset) as u16;
            click(&mut app, h.menu.x + 2, y);
            assert_eq!(app.plugin, d.plugin);
            assert_eq!(app.focus, 2);
            app.row = 25;
            terminal.draw(|f| app.draw(f)).unwrap();
            let h = app.hits.borrow().clone();
            click(&mut app, h.result.x + 3, h.result.y + 2);
            assert_eq!(app.row, h.row_offset);
            app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            terminal.draw(|f| app.draw(f)).unwrap();
            assert!(matches!(app.dialog, Some(Dialog::Detail { .. })));
            assert!(screen(&terminal, 80).contains("\\n\\u{1b}"));
            app.dialog_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
            terminal.draw(|f| app.draw(f)).unwrap();
            assert!(matches!(app.dialog,Some(Dialog::Detail {scroll,..}) if scroll>0));
            app.mouse(mouse_event(MouseEventKind::Down(MouseButton::Right), 0, 0));
            assert!(app.dialog.is_none());
            terminal.draw(|f| app.draw(f)).unwrap();
            let h = app.hits.borrow().clone();
            let button = h
                .buttons
                .iter()
                .find(|(_, k)| *k == KeyCode::Char('d'))
                .unwrap()
                .0;
            click(&mut app, button.x, button.y);
            assert!(app.dialog.is_some());
            app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
            app.query = "item-025".into();
            assert_eq!(app.rows().len(), 1);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("result.json");
            store::export(&path, app.result().unwrap(), app.rows()).unwrap();
            let exported: Results = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert!(exported.rows[0][1].contains('\x1b'));
            app.query.clear();
        }
        assert!(detail_lines(&"x".repeat(1024 * 1024), 10).len() > u16::MAX as usize);
    }
    #[test]
    fn searchable_picker_context_navigation_and_help() {
        let mut app = app();
        app.focus = 1;
        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert_eq!(app.menu, menu_items().len() - 1);
        app.key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        assert_eq!(app.menu, 0);
        app.key(KeyEvent::new(KeyCode::F(4), KeyModifiers::NONE));
        app.paste("pscred");
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 80).contains("pscred"));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.plugin, Plugin::Pscred);
        assert!(matches!(
            app.dialog,
            Some(Dialog::Files {
                kind: InputKind::Image,
                ..
            })
        ));
        assert!(matches!(app.pending_work, Some(Work::Analyze(false))));
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.pending_work.is_none());
        app.key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));
        assert!(!app.settings.remote_symbols);
        app.key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 80).contains("取证工作台"));
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.last_error = Some("download failed\nurl detail".into());
        app.key(KeyEvent::new(KeyCode::F(8), KeyModifiers::NONE));
        assert!(
            matches!(&app.dialog,Some(Dialog::Detail {text,..}) if text.contains("url detail"))
        );
    }
    #[test]
    fn editable_inputs_paste_and_link_detail_back_navigation() {
        let mut app = app();
        app.open_input(InputKind::Export);
        app.paste("/tmp/路径.json");
        assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="/tmp/路径.json"));
        app.dialog_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        app.dialog_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
        assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="X/tmp/路径.json"));
        app.dialog_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        app.dialog_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        app.dialog_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="Xtmp/路径.jso"));
        app.dialog_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
        app.paste("替换");
        assert!(
            matches!(&app.dialog,Some(Dialog::Input {text,cursor,..}) if text=="替换" && *cursor==6)
        );
        app.dialog_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        app.dialog_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="换"));
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        let candidate = RemoteMatch {
            banner: "Linux version fixture".into(),
            path: "Debian/amd64/a.json.xz".into(),
            url: symbols::repository_url("Debian/amd64/a.json.xz").unwrap(),
        };
        app.dialog = Some(Dialog::Links {
            matches: vec![candidate.clone()],
            selected: 0,
        });
        app.dialog_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(
            matches!(&app.dialog,Some(Dialog::RemoteDetail {candidate: shown,..}) if shown.url == candidate.url)
        );
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(app.dialog, Some(Dialog::Links { .. })));
        app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(app.pending_work, Some(Work::Download(_))));
    }
    #[test]
    fn switching_busy_plugin_cancels_and_resumes_without_extra_confirmation() {
        let mut app = app();
        let mut result = app.results["pslist"].clone();
        result.plugin = "pstree".into();
        app.results.insert("pstree".into(), result);
        let old = Job::default();
        app.job = Some(old.clone());
        app.select_plugin(Plugin::Pstree);
        assert!(old.cancel.load(Ordering::Relaxed));
        assert_eq!(app.pending_plugin, Some(Plugin::Pstree));
        let (tx, rx) = mpsc::channel();
        app.receiver = Some(rx);
        tx.send(WorkerEvent::Failed("cancelled".into())).unwrap();
        assert!(app.drain());
        assert_eq!(app.plugin, Plugin::Pstree);
        assert!(app.job.is_none());
        assert!(app.last_error.is_none());
        assert_eq!(app.focus, 2);
        app.job = Some(Job::default());
        app.select_plugin(Plugin::Pscred);
        app.cancel();
        assert!(app.pending_plugin.is_none());
    }
    #[test]
    fn workstation_palette_views_and_responsive_inspector() {
        let mut app = app();
        let mut result = app.results["pslist"].clone();
        result.plugin = "psaux".into();
        result.columns = vec![
            "PID".into(),
            "Name".into(),
            "CommandLine".into(),
            "Status".into(),
        ];
        result.rows = vec![vec![
            "1".into(),
            "bash".into(),
            "长命令行".repeat(200),
            "OK".into(),
        ]];
        app.results.insert("psaux".into(), result);
        app.query = "10".into();
        app.sort = Some(0);
        app.descending = true;
        app.horizontal = 24;
        app.select_plugin(Plugin::Psaux);
        assert!(app.query.is_empty());
        assert_eq!(app.horizontal, 0);
        app.select_plugin(Plugin::Pslist);
        assert_eq!(app.query, "10");
        assert_eq!(app.sort, Some(0));
        assert!(app.descending);
        assert_eq!(app.horizontal, 24);
        app.select_plugin(Plugin::Psaux);
        let mut terminal = Terminal::new(TestBackend::new(170, 32)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(app.hits.borrow().inspector.width > 0);
        assert!(app.dialog.is_none());
        let inspector = app.hits.borrow().inspector;
        click(&mut app, inspector.x + 2, inspector.y + 2);
        assert_eq!(app.focus, 3);
        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert!(app.detail_scroll > 0);
        app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::ALT));
        assert_eq!(app.horizontal, 12);
        terminal.draw(|f| app.draw(f)).unwrap();
        terminal.backend_mut().resize(80, 24);
        app.resize(80, 24);
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(app.focus, 2);
        assert_eq!(app.hits.borrow().inspector.width, 0);
        app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(matches!(app.dialog, Some(Dialog::Detail { .. })));
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        app.paste("cache");
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 80).contains("缓存"));
        app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.dialog,
            Some(Dialog::Cache { confirm: false, .. })
        ));
        app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            app.dialog,
            Some(Dialog::Cache { confirm: true, .. })
        ));
        // Cancelling the concrete preview must never start deletion.
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.pending_work.is_none());
        assert!(app.dialog.is_none());
    }
    #[test]
    fn automatic_rows_fill_viewport_and_custom_rows_persist() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app();
        app.cache = dir.path().join("cache");
        app.results.get_mut("pslist").unwrap().rows = (1..=200)
            .map(|i| {
                vec![
                    i.to_string(),
                    i.to_string(),
                    "0".into(),
                    format!("row{i}"),
                    "0x1000".into(),
                ]
            })
            .collect();
        app.focus = 2;
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let result = app.hits.borrow().result;
        assert_eq!(app.page_rows(), usize::from(result.height - 3));
        let bottom = result.bottom() - 2;
        let bottom_text: String = (result.x + 1..result.right() - 1)
            .map(|x| terminal.backend().buffer()[(x, bottom)].symbol())
            .collect();
        assert!(bottom_text.contains(&format!("row{}", app.page_rows())));
        let initial_rows = app.page_rows();
        terminal.backend_mut().resize(100, 50);
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(app.page_rows(), initial_rows + 10);
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        app.paste("17");
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.page_rows(), 17);
        assert_eq!(crate::store::settings(&app.cache).unwrap().page_size, 17);
        app.key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE));
        assert_eq!(app.row, 17);
        terminal.backend_mut().resize(80, 24);
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(
            app.page_rows(),
            usize::from(app.hits.borrow().result.height - 3)
        );
        assert!(app.page_rows() < 17);
        assert_eq!(app.settings.page_size, 17); // Desired size is preserved for a larger screen.
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        app.paste("auto");
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.settings.page_size, 0);
        assert_eq!(app.row, 0);
    }
    #[test]
    fn unified_symbol_manager_has_inline_search_and_analysis_only_header() {
        let mut app = app();
        let dir = tempfile::tempdir().unwrap();
        app.root = dir.path().into();
        std::fs::create_dir_all(dir.path().join("images")).unwrap();
        let image = dir.path().join("images/capture.raw");
        std::fs::write(&image, b"image").unwrap();
        app.image = Some(image.clone());
        assert_eq!(app.display_path(&image), "images/capture.raw");
        assert!(
            std::path::Path::new(&app.display_path(std::path::Path::new("/tmp"))).is_absolute()
        );
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 100).contains("镜像: images/capture.raw"));
        app.switch_section(AssetSection::Symbols);
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert_eq!(hits.tabs.len(), 2);
        assert_eq!(hits.header.height, 0);
        assert_eq!(hits.search.height, 3);
        assert!(screen(&terminal, 100).contains("镜像: images/capture.raw"));
        click(&mut app, hits.search.x + 2, hits.search.y + 1);
        app.paste("test symbol");
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(app.hits.borrow().popup.height, 0);
        assert!(screen(&terminal, 100).contains("test symbol"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.asset_queries[1].is_empty());
        app.key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.section, AssetSection::Remote);
        app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL));
        assert_eq!(app.page, Page::Analysis);
    }
    #[test]
    fn manual_catalog_download_preserves_analysis_context() {
        let mut app = app();
        let dir = tempfile::tempdir().unwrap();
        app.cache = dir.path().join("cache");
        let downloaded = app.cache.join("symbols/isf/example.json");
        std::fs::create_dir_all(downloaded.parent().unwrap()).unwrap();
        std::fs::write(&downloaded, b"{}").unwrap();
        let selected = app.symbols.clone();
        app.switch_section(AssetSection::Remote);
        app.remote_catalog = true;
        app.download_url = Some("https://example.test/example.json".into());
        let (tx, rx) = mpsc::channel();
        app.receiver = Some(rx);
        tx.send(WorkerEvent::CatalogDownloaded(downloaded.clone()))
            .unwrap();
        app.drain();
        assert_eq!(app.symbols, selected);
        assert!(app.image.is_none());
        assert_eq!(app.results["pslist"].rows.len(), 2);
        assert!(
            app.assets
                .iter()
                .any(|asset| same_path(&asset.path, &downloaded))
        );
        assert_eq!(app.section, AssetSection::Remote);
        assert!(app.status.contains("已保存到"));
        assert!(app.job.is_none());
    }
    #[test]
    fn horizontally_scrolled_headers_keep_mouse_column_identity() {
        let mut app = app();
        let d = Plugin::Sockstat.descriptor();
        let mut result = app.results["pslist"].clone();
        result.plugin = "sockstat".into();
        result.columns = d.columns.iter().map(|s| (*s).into()).collect();
        result.rows = vec![d.columns.iter().map(|s| (*s).into()).collect()];
        app.results.insert("sockstat".into(), result);
        app.select_plugin(Plugin::Sockstat);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let before = app.hits.borrow().columns.clone();
        for _ in 0..3 {
            app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::ALT));
        }
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert_ne!(hits.columns, before);
        let (index, rect) = hits
            .columns
            .iter()
            .enumerate()
            .find(|(_, r)| r.width >= 3)
            .unwrap();
        click(&mut app, rect.x + 1, hits.result.y + 1);
        assert_eq!(app.sort, Some(index));
        assert_eq!(
            terminal.backend().buffer()[(hits.result.x, hits.result.y)].symbol(),
            "┌"
        );
        assert_eq!(
            terminal.backend().buffer()[(hits.result.right() - 1, hits.result.y)].symbol(),
            "┐"
        );
    }
    #[test]
    fn contextual_footer_and_symbol_sources_follow_focus() {
        let mut app = app();
        let has = |app: &App, code| app.footer_actions().iter().any(|(_, key)| *key == code);
        app.focus = 1;
        assert!(has(&app, KeyCode::Enter));
        assert!(!has(&app, KeyCode::Char('n')));
        app.focus = 2;
        assert!(has(&app, KeyCode::Char('n')));
        assert!(has(&app, KeyCode::Char(']')));
        assert!(!has(&app, KeyCode::Enter));
        app.switch_section(AssetSection::Symbols);
        assert!(has(&app, KeyCode::Char('a')));
        assert!(!has(&app, KeyCode::Char('g')));
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let source = app.hits.borrow().sources[2].0;
        click(&mut app, source.x, source.y);
        assert_eq!(app.section, AssetSection::Remote);
        assert!(has(&app, KeyCode::Char('g')));
        assert!(!has(&app, KeyCode::Char('a')));
        app.focus = 2;
        assert!(!has(&app, KeyCode::Enter));
        assert!(has(&app, KeyCode::PageDown));
        assert!(command_matches("导出结果", Page::Assets, 1).is_empty());
        assert!(command_matches("导出结果", Page::Analysis, 1).is_empty());
        assert!(!command_matches("导出结果", Page::Analysis, 2).is_empty());
        assert!(menu_items().iter().skip(2).all(|item| !item.contains(' ')));
        for width in [30, 80, 160] {
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            assert!(
                app.hits
                    .borrow()
                    .buttons
                    .iter()
                    .any(|(_, key)| *key == KeyCode::Char('?'))
            );
        }
    }
    #[test]
    fn inline_content_search_has_mouse_confirmation_and_reversible_filter() {
        let mut app = app();
        app.focus = 2;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let search = app.hits.borrow().search;
        let result = app.hits.borrow().result;
        assert_eq!(search.bottom(), result.y);
        click(&mut app, search.x + 2, search.y + 1);
        app.paste("init");
        assert_eq!(app.rows().len(), 1);
        terminal.draw(|f| app.draw(f)).unwrap();
        let confirm = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(r, key)| *key == KeyCode::Enter && r.y == search.y + 1)
            .unwrap()
            .0;
        click(&mut app, confirm.x, confirm.y);
        assert!(app.dialog.is_none());
        app.open_input(InputKind::Search);
        app.paste(&"x".repeat(200));
        terminal.draw(|f| app.draw(f)).unwrap();
        let position = terminal.get_cursor_position().unwrap();
        assert!(position.x < search.right() - 1);
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.query, "init");
    }
    #[test]
    fn dump_form_requires_target_range_and_explicit_run() {
        let mut app = app();
        app.select_plugin(Plugin::Memdump);
        assert!(app.job.is_none());
        assert!(matches!(app.dialog, Some(Dialog::Dump { .. })));
        app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
        assert!(matches!(&app.dialog,Some(Dialog::Dump{error,..}) if error.contains("PID")));
        app.paste("12");
        app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        app.paste("0x4000");
        app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        app.paste("0x5000");
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let directory = app
            .hits
            .borrow()
            .dump_fields
            .iter()
            .find(|(_, i)| *i == 3)
            .unwrap()
            .0;
        click(&mut app, directory.x, directory.y);
        app.paste("exports/targeted");
        assert!(app.job.is_none());
        for size in [(40, 10), (80, 24), (160, 40)] {
            let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            assert!(!app.hits.borrow().dump_fields.is_empty());
        }
        terminal.draw(|f| app.draw(f)).unwrap();
        let run = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(_, key)| *key == KeyCode::Enter)
            .unwrap()
            .0;
        click(&mut app, run.x, run.y);
        let (_, options) = app.dump_options.as_ref().unwrap();
        assert_eq!(options.pid, 12);
        assert_eq!(options.start, Some(0x4000));
        assert_eq!(options.end, Some(0x5000));
        assert_eq!(options.directory, PathBuf::from("exports/targeted"));
        assert!(app.job.is_none()); // No image: ask for it only after validating the parameters.
        assert!(matches!(
            app.dialog,
            Some(Dialog::Files {
                kind: InputKind::Image,
                ..
            })
        ));
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.start();
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.dialog.is_none());
        assert!(app.job.is_none());
    }
    #[test]
    fn managed_symbol_library_hides_cache_duplicates_and_survives_cache_removal() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("library/exact.json.xz");
        let cached = dir.path().join("cache/symbols/isf/exact.json.xz");
        for path in [&local, &cached] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"validated-symbol").unwrap();
            store::atomic_write(
                &path.with_extension("source.json"),
                &serde_json::to_vec(&RemoteMatch {
                    banner: "Linux version exact".into(),
                    path: "Debian/exact.json.xz".into(),
                    url: "https://example.test/exact".into(),
                })
                .unwrap(),
            )
            .unwrap();
        }
        let settings = || Settings {
            symbols: local.parent().unwrap().display().to_string(),
            ..Settings::default()
        };
        let mut app = App::new(
            None,
            local.parent().unwrap().into(),
            dir.path().join("cache"),
            settings(),
        );
        app.root = dir.path().into();
        app.switch_section(AssetSection::Symbols);
        assert!(app.asset_list().iter().any(|a| same_path(&a.path, &local)));
        assert!(!app.asset_list().iter().any(|a| same_path(&a.path, &cached)));
        app.focus_asset(Kind::Symbols, &local);
        assert!(same_path(&app.selected_asset().unwrap().path, &local));
        assert!(cached.is_file()); // The duplicate is hidden, not deleted.
        std::fs::remove_file(&cached).unwrap();
        let mut restored = App::new(
            None,
            local.parent().unwrap().into(),
            dir.path().join("cache"),
            settings(),
        );
        restored.root = dir.path().into();
        restored.switch_section(AssetSection::Symbols);
        assert!(
            restored
                .asset_list()
                .iter()
                .any(|a| same_path(&a.path, &local))
        );
        restored.focus_asset(Kind::Symbols, &local);
        assert!(restored.use_selected_asset());
        assert!(local.is_file());
        assert_eq!(
            restored.downloads.get("https://example.test/exact"),
            Some(&local.canonicalize().unwrap())
        );
    }
    #[test]
    fn startup_does_not_load_saved_choices_and_pickers_show_cross_directory_samples() {
        let dir = tempfile::tempdir().unwrap();
        let images = dir.path().join("images");
        let symbols = dir.path().join("symbols");
        std::fs::create_dir_all(&images).unwrap();
        std::fs::create_dir_all(&symbols).unwrap();
        let kali = images.join("kali.raw");
        let kali_isf = symbols.join("kali.json.xz");
        let sample = symbols.join("linux-sample-1.bin.gz");
        let zip = images.join("linux.zip");
        for file in [&kali, &kali_isf, &sample, &zip] {
            std::fs::write(file, b"read-only-fixture").unwrap();
        }
        let cache = dir.path().join("cache");
        let mut registry = Registry::default();
        registry.import(&kali, Kind::Image, &cache).unwrap();
        registry.import(&kali_isf, Kind::Symbols, &cache).unwrap();
        let downloaded = cache.join("symbols/isf");
        std::fs::create_dir_all(&downloaded).unwrap();
        for n in 0..20 {
            std::fs::write(downloaded.join(format!("cached-{n}.json.xz")), b"cached").unwrap();
        }
        let before = std::fs::read(cache.join("workspace.json")).unwrap();
        let settings = Settings {
            image_dir: images.display().to_string(),
            symbols: symbols.display().to_string(),
            ..Settings::default()
        };
        let mut app = App::new(None, PathBuf::new(), cache.clone(), settings);
        app.root = dir.path().into();
        assert!(app.image.is_none());
        assert!(app.symbols.as_os_str().is_empty());
        assert!(app.job.is_none());
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 120).contains("未加载"));
        assert!(screen(&terminal, 120).contains("未选择"));
        let archive = images.join("another-capture.zip");
        let notes = images.join("notes.txt");
        std::fs::write(&archive, b"archive").unwrap();
        std::fs::write(&notes, b"notes").unwrap();
        std::fs::write(dir.path().join("unrelated.raw"), b"outside").unwrap();
        app.open_files(InputKind::Image);
        let Some(Dialog::Files { root, entries, .. }) = &app.dialog else {
            panic!("missing image picker")
        };
        assert!(same_path(root, &images));
        for file in [&kali, &zip, &archive, &notes] {
            assert!(entries.iter().any(|e| same_path(&e.path, file)));
        }
        assert!(!entries.iter().any(|e| same_path(&e.path, &sample)));
        assert!(!entries.iter().any(|e| e.path.ends_with("unrelated.raw")));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 120).contains("linux.zip"));
        app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        let Some(Dialog::Files {
            root,
            entries,
            kind,
            ..
        }) = &app.dialog
        else {
            panic!("missing symbol picker")
        };
        assert!(*kind == InputKind::Symbols);
        assert!(same_path(root, &symbols));
        for file in [&kali_isf, &sample] {
            assert!(entries.iter().any(|e| same_path(&e.path, file)));
        }
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 120).contains("linux-sample-1.bin.gz"));
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.image.is_none());
        assert!(app.symbols.as_os_str().is_empty());
        assert_eq!(std::fs::read(cache.join("workspace.json")).unwrap(), before);
        for file in [kali, kali_isf, sample, zip] {
            assert_eq!(std::fs::read(file).unwrap(), b"read-only-fixture");
        }
    }
    #[test]
    fn unified_dump_modes_cancel_and_mouse_selection() {
        let mut app = app();
        let previous = app.plugin;
        app.row = 1;
        app.key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));
        assert_eq!(app.plugin, previous);
        assert!(matches!(
            &app.dialog,
            Some(Dialog::Dump {
                mode: Plugin::Procdump,
                ..
            })
        ));
        app.dialog_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
        assert!(matches!(
            &app.dialog,
            Some(Dialog::Dump {
                mode: Plugin::Memdump,
                ..
            })
        ));
        if let Some(Dialog::Dump { fields, .. }) = &mut app.dialog {
            fields[1] = "0x4000".into();
            fields[2] = "0x5000".into();
        }
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let elf = app
            .hits
            .borrow()
            .dump_modes
            .iter()
            .find(|(_, mode)| *mode == Plugin::Elfdump)
            .unwrap()
            .0;
        click(&mut app, elf.x, elf.y);
        assert!(
            matches!(&app.dialog, Some(Dialog::Dump { mode: Plugin::Elfdump, fields, .. })
            if fields[1].is_empty() && fields[2].is_empty())
        );
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.plugin, previous);
        assert_eq!(app.results["pslist"].rows.len(), 2);
        assert!(app.job.is_none());
        assert_eq!(menu_items().iter().filter(|s| **s == "dump").count(), 1);
        assert_eq!(plugin_matches("dump"), vec![Plugin::Procdump]);
        app.dialog = Some(Dialog::Plugins {
            query: "dump".into(),
            selected: 0,
        });
        app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(&app.dialog, Some(Dialog::Dump { .. })));
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.plugin, previous);
    }
    #[test]
    fn local_matches_stay_in_manager_and_reuse_image_context() {
        let dir = tempfile::tempdir().unwrap();
        let images = dir.path().join("images");
        let symbols = dir.path().join("symbols");
        std::fs::create_dir_all(&images).unwrap();
        std::fs::create_dir_all(&symbols).unwrap();
        let image = images.join("test.raw");
        let exact = symbols.join("exact.json");
        let wrong = symbols.join("wrong.json");
        for file in [&image, &exact, &wrong] {
            std::fs::write(file, b"fixture").unwrap();
        }
        let settings = Settings {
            image_dir: images.display().to_string(),
            symbols: symbols.display().to_string(),
            ..Settings::default()
        };
        let mut app = App::new(
            Some(image.clone()),
            PathBuf::new(),
            dir.path().join("cache"),
            settings,
        );
        app.root = dir.path().into();
        app.switch_section(AssetSection::Symbols);
        let exact = exact.canonicalize().unwrap();
        let mut banner = super::tests::app().results.remove("pslist").unwrap();
        banner.plugin = "banners".into();
        let mut report = symbols::LocalMatches::default();
        report
            .matched
            .insert(exact.clone(), vec!["exact-candidate".into()]);
        let stamp = app.local_stamp();
        let (tx, rx) = mpsc::channel();
        app.receiver = Some(rx);
        tx.send(WorkerEvent::LocalMatched(report, stamp, banner.clone()))
            .unwrap();
        app.drain();
        assert_eq!(app.asset_list().len(), 1);
        assert!(same_path(&app.selected_asset().unwrap().path, &exact));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.page, Page::Assets);
        assert!(same_path(&app.symbols, &exact));
        assert_eq!(app.choice.as_deref(), Some("exact-candidate"));
        assert_eq!(app.results["banners"], banner);
        assert!(app.job.is_none());
        app.key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
        assert_eq!(app.section, AssetSection::Symbols);
        assert!(app.job.is_none());
        assert!(app.status.contains("复用"));
        app.key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.asset_list().len(), 2);
        app.invalidate_source();
        assert!(app.local_match_stamp.is_none());
        assert!(app.local_matches.is_empty());
    }
    #[test]
    fn fetch_during_matching_keeps_remote_source_mode() {
        let mut app = app();
        app.switch_section(AssetSection::Remote);
        app.remote_catalog = false;
        app.job = Some(Job::default());
        app.key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert!(!app.remote_catalog);
        assert!(app.status.contains("任务执行中"));
        assert!(app.dialog.is_none());
    }
    fn fixture_isf(banner: &str, variant: u8) -> Vec<u8> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        serde_json::to_vec(&serde_json::json!({
            "base_types": { "pointer": { "size": 8 } },
            "symbols": { "linux_banner": { "address": 256,
                "constant_data": STANDARD.encode(format!("{banner}\n\0")) } },
            "metadata": { "variant": variant }
        }))
        .unwrap()
    }
    fn finish_test_job(app: &mut App) {
        if let Some(worker) = app.worker.take() {
            worker.join().unwrap();
        }
        app.drain();
        assert!(app.job.is_none());
    }
    fn cache_fixture(app: &App, candidate: &RemoteMatch, bytes: &[u8]) -> PathBuf {
        use std::io::Write;
        let path = app
            .cache
            .join("symbols/isf")
            .join(symbols::cache_filename(&candidate.path).unwrap());
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
        encoder.write_all(bytes).unwrap();
        store::atomic_write(&path, &encoder.finish().unwrap()).unwrap();
        path
    }
    #[test]
    fn remote_detail_download_button_saves_offline_without_selecting_or_navigating() {
        for catalog in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let mut app = app();
            app.cache = dir.path().join("cache");
            app.root = dir.path().into();
            app.settings.symbols = dir.path().join("library").display().to_string();
            app.settings.image_dir = dir.path().join("images").display().to_string();
            app.settings.remote_symbols = false;
            app.history = app.results.get("pslist").cloned();
            app.query = "init".into();
            let previous_symbols = app.symbols.clone();
            let history = app.history.clone();
            app.switch_section(AssetSection::Remote);
            let candidate = RemoteMatch {
                banner: "Linux version fixture".into(),
                path: "Debian/amd64/fixture.json.xz".into(),
                url: symbols::repository_url("Debian/amd64/fixture.json.xz").unwrap(),
            };
            let cached = cache_fixture(&app, &candidate, &fixture_isf(&candidate.banner, 0));
            app.remote = vec![candidate.clone()];
            app.remote_catalog = catalog;
            app.asset_queries[2] = "fixture".into();
            let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            let list = app.hits.borrow().assets;
            click(&mut app, list.x + 1, list.y + 1);
            assert!(
                matches!(&app.dialog, Some(Dialog::RemoteDetail { candidate: detail, .. }) if detail.url == candidate.url)
            );
            assert!(app.job.is_none());
            terminal.draw(|f| app.draw(f)).unwrap();
            let button = app
                .hits
                .borrow()
                .buttons
                .iter()
                .find(|(_, k)| *k == KeyCode::Char('w'))
                .unwrap()
                .0;
            if catalog {
                click(&mut app, button.x, button.y);
            } else {
                app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
            }
            finish_test_job(&mut app);
            let saved = app.downloads[&candidate.url].clone();
            assert!(saved.starts_with(dir.path().join("library").canonicalize().unwrap()));
            assert!(saved.is_file());
            assert!(saved.with_extension("source.json").is_file());
            assert_eq!(app.page, Page::Assets);
            assert_eq!(app.section, AssetSection::Remote);
            assert_eq!(app.remote_catalog, catalog);
            assert_eq!(app.asset_queries[2], "fixture");
            assert_eq!(app.symbols, previous_symbols);
            assert_eq!(app.history, history);
            assert_eq!(app.query, "init");
            assert!(
                Registry::load(&app.cache)
                    .unwrap()
                    .selected(Kind::Symbols)
                    .is_none()
            );
            assert!(matches!(app.dialog, Some(Dialog::RemoteDetail { .. })));
            assert!(
                app.remote_detail_text(&candidate)
                    .contains(&saved.display().to_string())
            );
            // Durable copies work without the regenerable cache and do not create duplicates.
            std::fs::remove_file(cached).unwrap();
            app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
            finish_test_job(&mut app);
            assert_eq!(app.downloads[&candidate.url], saved);
            assert!(app.last_error.is_none());
            assert_eq!(
                app.asset_list_for(AssetSection::Symbols)
                    .iter()
                    .filter(|a| a.path == saved)
                    .count(),
                1
            );
            app.key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
            assert_eq!(app.section, AssetSection::Symbols);
            assert!(same_path(&app.selected_asset().unwrap().path, &saved));
            assert_eq!(app.symbols, previous_symbols);
            assert!(app.dialog.is_none());
        }
    }
    #[test]
    fn remote_detail_failed_download_retains_candidate_and_allows_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app();
        app.cache = dir.path().join("cache");
        app.settings.symbols = dir.path().join("library").display().to_string();
        app.settings.image_dir = dir.path().join("images").display().to_string();
        app.settings.remote_symbols = false;
        app.switch_section(AssetSection::Remote);
        let path = "Debian/amd64/fixture.json.xz";
        let candidate = RemoteMatch {
            banner: "Linux version fixture".into(),
            path: path.into(),
            url: symbols::repository_url(path).unwrap(),
        };
        app.remote = vec![candidate.clone()];
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        // No cache: failure is actionable and does not register a local file.
        app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert!(app.last_error.as_deref().unwrap().contains("离线"));
        assert!(app.downloads.is_empty());
        assert!(matches!(app.dialog, Some(Dialog::RemoteDetail { .. })));
        // Wrong banner must not be copied into the durable library.
        cache_fixture(&app, &candidate, &fixture_isf("Linux version wrong", 0));
        app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert!(app.last_error.as_deref().unwrap().contains("banner"));
        assert!(app.downloads.is_empty());
        // A corrected cache can be retried directly from the same detail.
        cache_fixture(&app, &candidate, &fixture_isf(&candidate.banner, 0));
        app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert!(app.last_error.is_none());
        let saved = app.downloads[&candidate.url].clone();
        std::fs::remove_file(&saved).unwrap();
        app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert!(saved.is_file());
    }
    #[test]
    fn manager_automatically_matches_images_and_requires_explicit_symbol_selection() {
        let dir = tempfile::tempdir().unwrap();
        let images = dir.path().join("images");
        let library = dir.path().join("symbols");
        std::fs::create_dir_all(&images).unwrap();
        std::fs::create_dir_all(&library).unwrap();
        let first = images.join("first.raw");
        let second = images.join("second.raw");
        for (path, banner) in [
            (&first, "Linux version fixture"),
            (&second, "Linux version other"),
        ] {
            let mut bytes = vec![0; 4096];
            let banner = format!("{banner}\n\0");
            bytes[256..256 + banner.len()].copy_from_slice(banner.as_bytes());
            std::fs::write(path, bytes).unwrap();
        }
        for (name, banner, variant) in [
            ("one.json", "Linux version fixture", 0),
            ("two.json", "Linux version fixture", 1),
            ("other.json", "Linux version other", 0),
        ] {
            std::fs::write(library.join(name), fixture_isf(banner, variant)).unwrap();
        }
        let settings = Settings {
            image_dir: images.display().to_string(),
            symbols: library.display().to_string(),
            remote_symbols: false,
            ..Settings::default()
        };
        let mut app = App::new(
            None,
            library.join("other.json"),
            dir.path().join("cache"),
            settings,
        );
        app.switch_section(AssetSection::Images);
        app.focus_asset(Kind::Image, &first);
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert_eq!(app.page, Page::Assets);
        assert!(app.symbols.as_os_str().is_empty());
        assert_eq!(app.local_matches.len(), 2);
        assert_eq!(app.asset_list_for(AssetSection::Symbols).len(), 2);
        assert_eq!(app.results["banners"].rows.len(), 1);
        assert!(
            Registry::load(&app.cache)
                .unwrap()
                .selected(Kind::Symbols)
                .is_none()
        );
        // A highlighted image must not replace the selected target when matching.
        app.focus_asset(Kind::Image, &second);
        app.key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
        assert!(same_path(app.image.as_ref().unwrap(), &first));
        assert!(app.job.is_none());
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!app.symbols.as_os_str().is_empty());
        assert_eq!(app.page, Page::Assets);
        app.switch_section(AssetSection::Images);
        app.focus_asset(Kind::Image, &second);
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.symbols.as_os_str().is_empty());
        finish_test_job(&mut app);
        assert_eq!(app.local_matches.len(), 1);
        assert!(app.local_matches.keys().all(|p| p.ends_with("other.json")));
    }
    #[test]
    fn manager_cancel_stops_preparation_and_detail_download_without_followup_actions() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app();
        app.cache = dir.path().join("cache");
        app.settings.image_dir = dir.path().join("images").display().to_string();
        app.settings.symbols = dir.path().join("symbols").display().to_string();
        app.settings.remote_symbols = false;
        let path = "Debian/amd64/fixture.json.xz";
        let candidate = RemoteMatch {
            banner: "Linux version fixture".into(),
            path: path.into(),
            url: symbols::repository_url(path).unwrap(),
        };
        cache_fixture(&app, &candidate, &fixture_isf(&candidate.banner, 0));
        app.switch_section(AssetSection::Remote);
        app.remote = vec![candidate];
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let session = app.session.clone();
        let guard = session.lock().unwrap();
        app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
        drop(guard);
        finish_test_job(&mut app);
        assert!(app.downloads.is_empty());
        assert!(matches!(app.dialog, Some(Dialog::RemoteDetail { .. })));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        let image = dir.path().join("fixture.raw");
        std::fs::write(&image, vec![0; 4096]).unwrap();
        app.image = Some(image);
        let guard = session.lock().unwrap();
        app.prepare_selected_image();
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        drop(guard);
        finish_test_job(&mut app);
        assert!(app.local_match_stamp.is_none());
        assert!(app.local_matches.is_empty());
        assert!(app.dialog.is_none());
        assert_eq!(app.page, Page::Assets);
    }
    #[test]
    fn combined_manager_layout_focus_and_actions_work_at_supported_sizes() {
        let mut app = app();
        app.switch_section(AssetSection::Images);
        for (w, h) in [(160, 40), (100, 32), (80, 24), (60, 18)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            let hits = app.hits.borrow().clone();
            assert_eq!(hits.tabs.len(), 2);
            assert_eq!(hits.asset_lists.len(), if h < 20 { 1 } else { 2 });
            if h >= 20 {
                assert!(hits.asset_lists.iter().all(|(r, _, _)| r.height >= 3));
            }
            assert_eq!(hits.asset_detail.height > 0, w >= 100 && h >= 28);
            assert!(
                hits.asset_buttons
                    .iter()
                    .all(|(rect, _, _)| rect.right() <= w && rect.bottom() <= h)
            );
            app.section = AssetSection::Images;
            app.focus = 1;
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
            assert_eq!(app.section, AssetSection::Symbols);
            app.key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
            assert_eq!(app.section, AssetSection::Images);
            assert!(
                app.asset_disabled(AssetSection::Images, KeyCode::Char('x'))
                    .is_some()
            );
            assert!(
                app.available_commands("开始分析")
                    .iter()
                    .any(|(_, k)| *k == KeyCode::Char('x'))
            );
        }
        app.key(KeyEvent::new(KeyCode::F(9), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Assets); // Old page shortcuts have been removed.
        app.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Analysis);
        app.key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Assets);
    }
}
