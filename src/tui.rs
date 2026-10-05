use crate::{
    Job, cache,
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

fn plugin_matches(query: &str) -> Vec<Plugin> {
    let query = query.to_lowercase();
    PLUGINS
        .iter()
        .filter(|d| d.label.to_lowercase().contains(&query) || d.name.contains(&query))
        .map(|d| d.plugin)
        .collect()
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
    let categories = ["进程", "系统", "内存", "文件", "网络", "异常检查"];
    categories
        .into_iter()
        .flat_map(|category| {
            PLUGINS
                .iter()
                .filter(move |d| d.plugin.category() == category)
                .map(|d| d.plugin)
        })
        .collect()
}
fn menu_items() -> Vec<String> {
    [
        vec!["打开镜像 [i]".into(), "选择符号 [y]".into()],
        navigation_plugins()
            .iter()
            .map(|p| format!("{} · {}", p.category(), p.name()))
            .collect(),
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
    Images,
    Symbols,
    Remote,
}
impl Page {
    const ALL: [Self; 3] = [Self::Analysis, Self::Images, Self::Symbols];
    fn index(self) -> usize {
        if self == Self::Remote {
            2
        } else {
            Self::ALL.iter().position(|p| *p == self).unwrap()
        }
    }
    fn slot(self) -> usize {
        if self == Self::Remote {
            2
        } else {
            self.index().saturating_sub(1)
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::Analysis => "分析",
            Self::Images => "镜像",
            Self::Symbols => "符号管理",
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
const COMMANDS: &[(&str, KeyCode)] = &[
    ("打开镜像", KeyCode::Char('i')),
    ("选择本地符号", KeyCode::Char('y')),
    ("搜索插件", KeyCode::Char('p')),
    ("匹配／下载符号", KeyCode::Char('u')),
    ("识别内核候选", KeyCode::Char('b')),
    ("管理缓存 cache [c]", KeyCode::Char('c')),
    ("生成 Kali ARM64 精确符号", KeyCode::Char('g')),
    ("全文筛选", KeyCode::Char('/')),
    ("排序", KeyCode::Char('s')),
    ("导出结果", KeyCode::Char('e')),
    ("显示详情", KeyCode::Char('d')),
    ("查看诊断", KeyCode::Char('v')),
    ("历史导出记录", KeyCode::Char('h')),
    ("目录与分页设置", KeyCode::Char(',')),
    ("任务日志", KeyCode::Char('l')),
    ("重新分析", KeyCode::Char('r')),
    ("在线／离线模式", KeyCode::Char('o')),
    ("帮助", KeyCode::Char('?')),
];
fn command_matches(query: &str) -> Vec<usize> {
    COMMANDS
        .iter()
        .enumerate()
        .filter(|(_, (label, _))| label.contains(query))
        .map(|(i, _)| i)
        .collect()
}
pub struct App {
    page: Page,
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
    download_url: Option<String>,
    downloads: HashMap<String, PathBuf>,
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
            root,
            registry,
            assets,
            asset_rows: [asset_rows[0], asset_rows[1], 0],
            asset_scroll: [0; 3],
            asset_queries: Default::default(),
            asset_states: RefCell::new(Default::default()),
            asset_details: HashMap::new(),
            remote: vec![],
            remote_catalog: false,
            download_analyzes: false,
            download_url: None,
            downloads: HashMap::new(),
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
                for asset in &self.assets {
                    let side = asset.path.with_extension("source.json");
                    if asset.kind == Kind::Symbols
                        && side.metadata().is_ok_and(|m| m.len() <= 1024 * 1024)
                        && let Ok(bytes) = std::fs::read(side)
                        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                        && let Some(url) = value["url"].as_str()
                    {
                        self.downloads.insert(url.into(), asset.path.clone());
                    }
                }
            }
            Err(e) => {
                self.status = format!("资产清单读取失败: {e:#}");
                self.last_error = Some(self.status.clone());
            }
        }
        if self.page != Page::Analysis {
            self.asset_rows[self.page.slot()] =
                self.asset_rows[self.page.slot()].min(self.asset_count().saturating_sub(1));
        }
    }
    fn invalidate_source(&mut self) {
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
    fn focus_asset(&mut self, kind: Kind, path: &std::path::Path) {
        let slot = usize::from(kind == Kind::Symbols);
        self.asset_queries[slot].clear();
        self.asset_rows[slot] = self
            .assets
            .iter()
            .filter(|a| a.kind == kind)
            .position(|a| same_path(&a.path, path))
            .unwrap_or(0);
        self.asset_scroll[slot] = 0;
        self.asset_states.borrow_mut()[slot] = ListState::default();
    }
    fn page_rows(&self) -> usize {
        if self.settings.page_size == 0 {
            self.hits.borrow().result.height.saturating_sub(3).max(1) as usize
        } else {
            self.settings.page_size
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
        let kind = if self.page == Page::Images {
            Kind::Image
        } else {
            Kind::Symbols
        };
        let query = self.asset_queries[self.page.slot()].to_lowercase();
        self.assets
            .iter()
            .filter(|a| a.kind == kind && a.path.to_string_lossy().to_lowercase().contains(&query))
            .collect()
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
        if self.page == Page::Remote {
            self.remote_list().len()
        } else {
            self.asset_list().len()
        }
    }
    fn selected_asset(&self) -> Option<Asset> {
        self.asset_list()
            .get(self.asset_rows[self.page.slot()])
            .map(|a| (*a).clone())
    }
    fn asset_text(&self) -> String {
        if self.page == Page::Remote {
            return self.remote_list().get(self.asset_rows[2]).map(|m|format!("符号索引项（选用时校验镜像）\n\n仓库路径: {}\n\n完整 banner: {}\n\n下载链接: {}\n\n下载后校验 ISF 与完整 banner；进入分析时继续验证页表。",escaped(&m.path),escaped(&m.banner),escaped(&m.url)))
                .unwrap_or_else(||"按 m 匹配当前镜像，r 刷新远程索引。\n\n仅使用完整 banner 精确匹配；没有候选时可导入本地 ISF，或用 g 准备指定 Kali 符号。\n\n下载成功后自动选用符号；x 进入分析。".into());
        }
        let Some(asset) = self.selected_asset() else {
            return "按 a 导入路径，或将测试镜像放入项目根目录／images，符号放入 symbols。\n\nEnter 选用；Backspace 移出清单，原文件保留。".into();
        };
        let mut text = format!(
            "{}\n\n路径: {}\n格式: {}\n大小: {:.2} MiB\n来源: {}\n状态: {}\n\nEnter 选用 · Backspace 移出清单（保留文件）",
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
        if self.page == Page::Symbols {
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
                text.push_str("\n\nb 识别内核候选；m 获取远程符号匹配。");
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
            self.invalidate_source();
        }
        if asset.kind == Kind::Image {
            self.image = Some(asset.path);
        } else {
            self.symbols = asset.path;
        }
        self.status = "已选用；b 识别、m 匹配、x 进入分析".into();
        true
    }
    fn asset_key(&mut self, key: KeyEvent) -> bool {
        let slot = self.page.slot();
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
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => self.cancel(),
            KeyCode::Tab | KeyCode::BackTab => self.focus = if self.focus == 1 { 2 } else { 1 },
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
            KeyCode::Char('i') | KeyCode::F(2) => self.open_files(InputKind::Image),
            KeyCode::Char('y') | KeyCode::F(3) => self.open_files(InputKind::Symbols),
            KeyCode::Char('a') => self.open_files(if self.page == Page::Images {
                InputKind::Image
            } else {
                InputKind::Symbols
            }),
            KeyCode::Enter if self.page == Page::Remote => {
                if let Some(candidate) = self
                    .remote_list()
                    .get(self.asset_rows[2])
                    .map(|m| (*m).clone())
                {
                    self.start_work(if self.remote_catalog {
                        Work::CatalogDownload(candidate)
                    } else {
                        Work::Download(candidate)
                    });
                } else {
                    self.status = "没有选中的符号；f 搜索索引，m 精确匹配镜像".into();
                }
            }
            KeyCode::Enter => {
                let selected = self.use_selected_asset();
                if selected && self.page == Page::Images {
                    self.start_work(Work::Identify);
                }
            }
            KeyCode::Backspace if self.page != Page::Remote => {
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
            KeyCode::Char('d') => {
                if self.page == Page::Symbols
                    && let Some(asset) = self.selected_asset()
                    && !self.asset_details.contains_key(&asset.path)
                {
                    self.start_work(Work::InspectSymbols(asset.path));
                } else {
                    self.dialog = Some(Dialog::Detail {
                        text: self.asset_text(),
                        scroll: 0,
                    });
                }
            }
            KeyCode::Char('b') | KeyCode::F(7) => {
                if self.page == Page::Images && !self.use_selected_asset() {
                    return false;
                }
                self.start_work(Work::Identify);
            }
            KeyCode::Char('m') | KeyCode::Char('u') | KeyCode::F(6) => {
                if self.page == Page::Images && !self.use_selected_asset() {
                    return false;
                }
                self.remote_catalog = false;
                self.asset_queries[2].clear();
                self.switch_page(Page::Remote);
                self.start_work(Work::Lookup);
            }
            KeyCode::Char('r') | KeyCode::F(5) if self.page == Page::Remote => {
                if self.remote_catalog {
                    self.start_work(Work::Catalog(self.asset_queries[2].clone(), true));
                } else {
                    self.start_work(Work::RefreshLookup);
                }
            }
            KeyCode::Char('r') | KeyCode::F(5) => {
                self.asset_details.clear();
                self.refresh_assets();
                self.status = "资产清单已刷新".into();
            }
            KeyCode::Char('g') => self.start_work(Work::PrepareKali),
            KeyCode::Char('x') => {
                self.switch_page(Page::Analysis);
                self.start();
            }
            KeyCode::Char('c') => self.open_cache(),
            KeyCode::Char('p') | KeyCode::F(4) => {
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
            KeyCode::Char('?') | KeyCode::F(1) => self.help(),
            _ => {}
        }
        false
    }
    fn draw_tabs(&self, frame: &mut Frame, area: Rect) {
        let mut x = area.x;
        for (i, page) in Page::ALL.iter().enumerate() {
            let label = format!(" F{} {} ", i + 9, page.title());
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
                        .bg(Color::Rgb(35, 48, 60))
                        .fg(Color::Rgb(216, 170, 97))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Rgb(116, 180, 210))
                }),
                rect,
            );
            self.hits.borrow_mut().tabs.push((rect, *page));
            x = x.saturating_add(width + 1);
        }
    }
    fn draw_assets(&self, frame: &mut Frame, area: Rect) {
        let area = if matches!(self.page, Page::Symbols | Page::Remote) {
            let regions = Layout::vertical([Constraint::Length(3), Constraint::Min(2)]).split(area);
            self.hits.borrow_mut().search = regions[0];
            let query = &self.asset_queries[self.page.slot()];
            frame.render_widget(
                Paragraph::new(escaped(query)).block(Block::default().borders(Borders::ALL).title(
                    if self.page == Page::Remote {
                        "远程索引搜索 · / 输入 · Enter 搜索 · t 本地库"
                    } else {
                        "本地符号搜索 · / 输入 · t 远程下载 · f 搜索索引"
                    },
                )),
                regions[0],
            );
            if let Some(Dialog::Input {
                kind: InputKind::AssetsSearch,
                cursor,
                ..
            }) = &self.dialog
            {
                let x = regions[0].x
                    + 1
                    + Span::raw(&query[..(*cursor).min(query.len())]).width() as u16;
                if x < regions[0].right().saturating_sub(1) && regions[0].height > 1 {
                    frame.set_cursor_position((x, regions[0].y + 1));
                }
            }
            regions[1]
        } else {
            area
        };
        let panes = if area.width >= 100 {
            Layout::horizontal([Constraint::Percentage(45), Constraint::Min(30)]).split(area)
        } else {
            Layout::vertical([Constraint::Percentage(50), Constraint::Min(3)]).split(area)
        };
        let rows = if self.page == Page::Remote {
            self.remote_list()
                .iter()
                .map(|m| {
                    ListItem::new(format!(
                        "{} {}",
                        if self.downloads.get(&m.url).is_some_and(|p| p.is_file()) {
                            "[已缓存]"
                        } else {
                            "[待下载]"
                        },
                        escaped(&m.path)
                    ))
                })
                .collect::<Vec<_>>()
        } else {
            self.asset_list()
                .iter()
                .map(|asset| {
                    let active = if asset.kind == Kind::Image {
                        self.image
                            .as_ref()
                            .is_some_and(|p| same_path(p, &asset.path))
                    } else {
                        same_path(&self.symbols, &asset.path)
                    };
                    ListItem::new(format!(
                        "{} {} · #{} · {} · {:.1} MiB{}",
                        if active { "●" } else { " " },
                        escaped(&self.display_path(&asset.path)),
                        asset.id(),
                        asset.format(),
                        asset.bytes as f64 / 1048576.0,
                        if asset.available { "" } else { " · 缺失" }
                    ))
                })
                .collect::<Vec<_>>()
        };
        let count = rows.len();
        let slot = self.page.slot();
        let mut states = self.asset_states.borrow_mut();
        let state = &mut states[slot];
        state.select((count > 0).then_some(self.asset_rows[slot].min(count.saturating_sub(1))));
        frame.render_stateful_widget(
            List::new(rows)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("{} · {} 项 · / 筛选", self.page.title(), count))
                        .border_style(Style::default().fg(Color::Rgb(116, 180, 210))),
                )
                .highlight_symbol("› ")
                .highlight_style(
                    Style::default()
                        .bg(Color::Rgb(35, 48, 60))
                        .fg(Color::Rgb(216, 170, 97)),
                ),
            panes[0],
            state,
        );
        self.hits.borrow_mut().assets = panes[0];
        self.hits.borrow_mut().asset_offset = state.offset();
        if count == 0 {
            frame.render_widget(
                Paragraph::new(if self.page == Page::Remote {
                    if self.remote_catalog {
                        "没有匹配的索引项\nf 或 / 修改关键词；r 刷新索引"
                    } else {
                        "f 手动搜索索引（无需镜像）\nm 精确匹配镜像；r 刷新索引"
                    }
                } else {
                    "没有匹配的资产\na 导入 · r 刷新 · / 更改筛选"
                })
                .style(Style::default().fg(Color::DarkGray)),
                Rect::new(
                    panes[0].x + 1,
                    panes[0].y + 1,
                    panes[0].width.saturating_sub(2),
                    panes[0].height.saturating_sub(2),
                ),
            );
        }
        self.hits.borrow_mut().asset_detail = panes[1];
        let lines = detail_lines(&self.asset_text(), panes[1].width.saturating_sub(2));
        let maximum = lines
            .len()
            .saturating_sub(panes[1].height.saturating_sub(2) as usize);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((
                    self.asset_scroll[slot].min(maximum).min(u16::MAX as usize) as u16,
                    0,
                ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("详情 · Tab 切换 · ↑↓ 滚动 · d 完整内容")
                        .border_style(if self.focus == 2 {
                            Style::default().fg(Color::Rgb(116, 180, 210))
                        } else {
                            Style::default().fg(Color::DarkGray)
                        }),
                ),
            panes[1],
        );
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
            InputKind::Image => Filter::Images,
            InputKind::Symbols => Filter::Symbols,
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
            root = self.root.clone();
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
            InputKind::AssetsSearch => self.asset_queries[self.page.slot()].clone(),
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
        self.start_work(Work::Analyze(false));
    }
    fn start_work(&mut self, work: Work) {
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
            self.open_input(InputKind::Image);
            return;
        };
        let (tx, rx) = mpsc::channel();
        let progress = tx.clone();
        let job = Job::new(move |s| {
            let _ = progress.send(WorkerEvent::Progress(s));
        });
        let worker_job = job.clone();
        let symbols = self.symbols.clone();
        let cache = self.cache.clone();
        let choice = self.choice.clone();
        let plugin = self.plugin;
        let enabled = self.settings.enable_cache;
        let network = self.settings.remote_symbols;
        let session = self.session.clone();
        self.history = None;
        self.job = Some(job);
        self.receiver = Some(rx);
        self.download_url = match &work {
            Work::Download(candidate) | Work::CatalogDownload(candidate) => {
                Some(candidate.url.clone())
            }
            _ => None,
        };
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
                        symbols::download_catalog(&candidate, &cache, network, &worker_job)
                            .map(|s| WorkerEvent::CatalogDownloaded(PathBuf::from(s.label)))
                    }
                    Work::Identify => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        linux::banner_result(&image, &worker_job).map(WorkerEvent::Identified)
                    }
                    Work::InspectSymbols(path) => workspace::inspect_symbols(&path, &worker_job)
                        .map(|text| WorkerEvent::SymbolDetails(path, text)),
                    Work::RefreshLookup => {
                        anyhow::ensure!(
                            network,
                            "离线模式不能刷新远程索引；按 o 开启在线模式后按 r"
                        );
                        symbols::refresh_index(&cache, &worker_job)?;
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
                        .analyze(
                            &linux::Request {
                                image: &image,
                                symbols: &symbols,
                                choice: choice.as_deref(),
                                plugin,
                                cache: &cache,
                                use_cache: enabled && !force,
                                network,
                            },
                            &worker_job,
                        )
                        .map(WorkerEvent::Done),
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
                WorkerEvent::CatalogLinks(matches) => {
                    self.finish_worker();
                    self.status = format!(
                        "远程搜索：{} 项（最多 2000 项；可输入多个关键词缩小范围）",
                        matches.len()
                    );
                    self.remote = matches;
                    self.remote_catalog = true;
                    self.asset_rows[2] = 0;
                }
                WorkerEvent::CatalogDownloaded(path) => {
                    self.finish_worker();
                    if let Some(url) = self.download_url.take() {
                        self.downloads.insert(url, path.clone());
                    }
                    self.refresh_assets();
                    self.status = "符号已下载到本地库；t 切换本地，Enter 选用时再与镜像验证".into();
                    self.focus_asset(Kind::Symbols, &path);
                }
                WorkerEvent::IndexRefreshed => {
                    self.finish_worker();
                    self.status = "远程索引已刷新；选择镜像后按 m 精确匹配".into();
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
                        "{} 个完整 banner 匹配 · Enter 下载选用 · x 分析",
                        matches.len()
                    );
                    self.remote = matches.clone();
                    self.asset_rows[2] = 0;
                    self.asset_states.borrow_mut()[2] = ListState::default();
                    if matches.is_empty() {
                        self.status =
                            "仓库没有完整匹配；选用本地 ISF，或 g 准备指定 Kali 符号".into();
                    } else if self.page == Page::Analysis {
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
                    self.results.clear();
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
    fn resize(&mut self, width: u16) {
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
        self.menu = navigation_plugins()
            .iter()
            .position(|p| *p == plugin)
            .unwrap()
            + 2;
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
                    self.asset_queries[self.page.slot()] = text.clone();
                    self.asset_rows[self.page.slot()] = 0;
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
        self.dialog=Some(Dialog::Detail {scroll:0,text:"ZERO 取证工作台\n\nF9 分析 · F10 镜像 · F11 符号管理；t 本地／远程，F12 直接进入远程\nCtrl+←/→ 切换页面；Tab 切换页内区域\n资产页：a 导入 · Enter 选用 · Backspace 移出清单\nn 自定义每页行数；auto 自动填满窗口\n符号管理：/ 搜索本地；t 远程，f 手动搜索索引\n远程：m 按镜像匹配 · r 刷新 · Enter 下载\nx 进入分析；任务中可切换页面，Esc 取消\n\nCtrl+P 统一命令 · c 缓存管理 · g Kali ARM64 符号生成\nAlt+←/→ 表格横向滚动 · 宽屏 d 展开详情面板\n\np / F4  搜索插件，输入名称或中文说明，Enter 执行\nb / F7  无需符号即可扫描内核 banner\nu / F6  按镜像完整 banner 获取符号候选与下载链接\ny / F3  选择本地 ISF；o 切换在线／离线模式\ni / F2  打开镜像；相同镜像切换插件复用符号与页表\n\nTab / Shift+Tab  切换区域；↑↓ 或 j/k 导航\nPageUp / PageDown / Home / End  当前区域滚动\nEnter  执行插件、展开树或打开行详情\n/  筛选；s 排序；e 导出所有筛选行；d 行详情\nv / F8  全部诊断；r / F5 重跑（跳过结果缓存）\nEsc  关闭弹窗或取消任务；q / Ctrl+C  退出\n\n符号候选：Enter 下载并分析，d 查看完整 URL\n目录弹窗：Enter 打开；← 上级；Space 选择目录；p 手动输入\n, 目录设置；h 历史 CSV／JSON；l 任务日志\n[ / ] 结果翻页；e 导出全部筛选结果\n输入框：Ctrl+u 清空；Esc 撤销；Enter 确认\n详情：↑↓ / PageUp / PageDown / Home / End；右键关闭\n\n共享凭据只是核查线索，不能单凭共享判定入侵。".into()});
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
        match key.code {
            KeyCode::Char('n') => {
                self.open_input(InputKind::PageSize);
                return false;
            }
            KeyCode::Char('t') if matches!(self.page, Page::Symbols | Page::Remote) => {
                self.switch_page(if self.page == Page::Symbols {
                    Page::Remote
                } else {
                    Page::Symbols
                });
                return false;
            }
            KeyCode::Char('f') if matches!(self.page, Page::Symbols | Page::Remote) => {
                self.switch_page(Page::Remote);
                self.open_input(InputKind::AssetsSearch);
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
            _ => {}
        }
        if matches!(
            key.code,
            KeyCode::F(9) | KeyCode::F(10) | KeyCode::F(11) | KeyCode::F(12)
        ) {
            let index = match key.code {
                KeyCode::F(n) => n.saturating_sub(9) as usize,
                _ => 0,
            };
            self.switch_page(if index == 3 {
                Page::Remote
            } else {
                Page::ALL[index]
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
                Page::ALL[(self.page.index() + if back { 2 } else { 1 }) % Page::ALL.len()],
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
            KeyCode::Char('r') | KeyCode::F(5) => self.start_work(Work::Analyze(true)),
            KeyCode::Char('p') | KeyCode::F(4) => {
                self.dialog = Some(Dialog::Plugins {
                    query: String::new(),
                    selected: 0,
                })
            }
            KeyCode::Char('u') | KeyCode::F(6) => {
                self.remote_catalog = false;
                self.asset_queries[2].clear();
                self.switch_page(Page::Remote);
                self.start_work(Work::Lookup);
            }
            KeyCode::Char('b') | KeyCode::F(7) => self.select_plugin(Plugin::Banners),
            KeyCode::Char('?') | KeyCode::F(1) => self.help(),
            KeyCode::Char('v') | KeyCode::F(8) => self.diagnostics(),
            KeyCode::F(2) => self.open_files(InputKind::Image),
            KeyCode::F(3) => self.open_files(InputKind::Symbols),
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
        if self.dialog.is_none() {
            if click
                && let Some((_, page)) = hits.tabs.iter().find(|(rect, _)| rect.contains(point))
            {
                self.switch_page(*page);
                return false;
            }
            if click && hits.header.contains(point) {
                if point.y == hits.header.y + 1 {
                    self.open_files(InputKind::Image);
                } else if point.y == hits.header.y + 2 {
                    self.open_files(InputKind::Symbols);
                }
                return false;
            }
            if click && hits.search.contains(point) {
                self.open_input(InputKind::AssetsSearch);
                return false;
            }
            if self.page != Page::Analysis {
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
                if hits.assets.contains(point) {
                    self.focus = 1;
                    if let Some(key) = scroll {
                        for _ in 0..3 {
                            self.asset_key(KeyEvent::new(key, KeyModifiers::NONE));
                        }
                    } else if click
                        && point.y > hits.assets.y
                        && point.y < hits.assets.bottom().saturating_sub(1)
                    {
                        let index = hits.asset_offset + (point.y - hits.assets.y - 1) as usize;
                        if index < self.asset_count() {
                            self.asset_rows[self.page.slot()] = index;
                            self.asset_scroll[self.page.slot()] = 0;
                            self.focus = 1;
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
                && let Some((_, key)) = hits.buttons.iter().find(|(rect, _)| rect.contains(point))
            {
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
                    }) if index < 4 => {
                        *selected = index;
                        *confirm = false;
                        true
                    }
                    Some(Dialog::Commands { query, selected })
                        if index < command_matches(query).len() =>
                    {
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
            if matches!(dialog, Dialog::Detail { .. })
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
                    self.asset_queries[self.page.slot()] = original;
                    self.asset_rows[self.page.slot()] = 0;
                }
            }
            return;
        }
        match &mut dialog {
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
                KeyCode::Left | KeyCode::Backspace => {
                    let parent = root.parent().unwrap_or(root).to_path_buf();
                    self.browse(*kind, parent);
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
                        *selected = (*selected + 1).min(3);
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
                    *selected = (*selected + 1).min(command_matches(query).len().saturating_sub(1))
                }
                KeyCode::Enter => {
                    if let Some(i) = command_matches(query).get(*selected) {
                        self.key(KeyEvent::new(COMMANDS[*i].1, KeyModifiers::NONE));
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
                            self.select_plugin(*plugin);
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
                        self.dialog = Some(Dialog::Detail {
                            text: format!(
                                "完整 banner: {}\n\nISF: {}\n\n下载链接: {}\n\nEsc 返回候选列表后，按 Enter 下载并分析",
                                escaped(&m.banner),
                                escaped(&m.path),
                                escaped(&m.url)
                            ),
                            scroll: 0,
                        });
                    }
                    return;
                }
                _ => {}
            },
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
                            self.invalidate_source();
                            if *kind == InputKind::Image {
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
                                self.start_work(work);
                            } else if *kind == InputKind::Image {
                                self.start_work(Work::Identify);
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
                            self.asset_queries[self.page.slot()] = value.clone();
                            if self.page == Page::Remote {
                                self.remote_catalog = true;
                                self.start_work(Work::Catalog(value, false));
                            }
                            self.asset_rows[self.page.slot()] = 0;
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
                    self.asset_queries[self.page.slot()] = text.clone();
                    self.asset_rows[self.page.slot()] = 0;
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
                Style::default().fg(Color::Rgb(116, 180, 210))
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
                                "未选择 · F11 管理符号".into()
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
                    .constraints([
                        Constraint::Length(if area.width >= 100 { 30 } else { 22 }),
                        Constraint::Min(20),
                    ])
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
                        Row::new(columns).style(
                            Style::default()
                                .fg(Color::Rgb(116, 180, 210))
                                .add_modifier(Modifier::BOLD),
                        ),
                    )
                    .block(block)
                    .row_highlight_style(Style::default().bg(Color::Rgb(35, 48, 60)))
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
                        "选择左侧分析项后按 Enter\n缺少符号时按完整 banner 自动匹配；u 查看下载链接
按 p 搜索插件 · ? 查看快捷键 · o 切换离线",
                    )
                    .block(block),
                    main,
                );
                }
            }
        }
        let footer = parts[2];
        frame.render_widget(Block::default().borders(Borders::TOP), footer);
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
                    .gauge_style(Style::default().fg(Color::Rgb(116, 180, 210))),
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
        let mut buttons = if self.page == Page::Analysis {
            vec![
                ("/搜索", KeyCode::Char('/')),
                ("p插件", KeyCode::Char('p')),
                ("e导出", KeyCode::Char('e')),
                ("d详情", KeyCode::Char('d')),
                ("上页", KeyCode::Char('[')),
                ("下页", KeyCode::Char(']')),
                ("n行数", KeyCode::Char('n')),
                ("?更多", KeyCode::Char('?')),
                ("q退出", KeyCode::Char('q')),
            ]
        } else if matches!(self.page, Page::Symbols | Page::Remote) {
            vec![
                ("t切换", KeyCode::Char('t')),
                ("/搜索", KeyCode::Char('/')),
                ("f索引", KeyCode::Char('f')),
                ("m匹配", KeyCode::Char('m')),
                ("r刷新", KeyCode::Char('r')),
                ("Enter操作", KeyCode::Enter),
                ("?更多", KeyCode::Char('?')),
            ]
        } else {
            vec![
                ("a导入", KeyCode::Char('a')),
                ("Enter选用", KeyCode::Enter),
                ("m匹配", KeyCode::Char('m')),
                ("x分析", KeyCode::Char('x')),
                ("d详情", KeyCode::Char('d')),
                ("?更多", KeyCode::Char('?')),
            ]
        };
        if self.page == Page::Analysis && frame.area().width < 80 {
            buttons.insert(0, ("Tab区域", KeyCode::Tab));
        }
        let mut x = footer.x;
        for (label, key) in buttons {
            let text = format!("[{label}] ");
            let width = Span::raw(&text).width() as u16;
            if x + width > footer.right() || footer.height < 3 {
                break;
            }
            let rect = Rect::new(x, footer.y + 2, width, 1);
            frame.render_widget(
                Paragraph::new(text).style(Style::default().fg(Color::Rgb(116, 180, 210))),
                rect,
            );
            self.hits.borrow_mut().buttons.push((rect, key));
            x += width;
        }
        if matches!(self.page, Page::Symbols | Page::Remote)
            && matches!(
                self.dialog,
                Some(Dialog::Input {
                    kind: InputKind::AssetsSearch,
                    ..
                })
            )
        {
            return;
        }
        if let Some(dialog) = &self.dialog {
            let popup = centered(
                area,
                area.width.saturating_sub(6).min(90),
                match dialog {
                    Dialog::Input { .. } => 6,
                    _ => 12,
                },
            );
            self.hits.borrow_mut().popup = popup;
            self.hits.borrow_mut().buttons.clear();
            frame.render_widget(Clear, popup);
            match dialog {
                Dialog::Files {
                    kind,
                    root,
                    entries,
                    selected,
                } => {
                    let title = format!(
                        "{} · ← 上级 · Enter 打开 · Space 目录 · p 路径",
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
                                if e.directory { "▸" } else { " " },
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
                                        escaped(&root.display().to_string())
                                    )),
                            )
                            .highlight_symbol("› ")
                            .highlight_style(Style::default().fg(Color::Rgb(116, 180, 210))),
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
                            .highlight_style(Style::default().fg(Color::Rgb(116, 180, 210))),
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
                        .style(Style::default().fg(Color::Rgb(216, 170, 97))),
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
                        List::new(command_matches(query).iter().map(|i| COMMANDS[*i].0))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title(format!("命令 · {} · Enter 执行", escaped(query))),
                            )
                            .highlight_symbol("› ")
                            .highlight_style(Style::default().fg(Color::Rgb(116, 180, 210))),
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
                        List::new(plugins.iter().map(|p| p.descriptor().label))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .title(format!("插件搜索: {} · Enter 执行", escaped(query))),
                            )
                            .highlight_style(Style::default().fg(Color::Rgb(116, 180, 210)))
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
                            .highlight_style(Style::default().fg(Color::Rgb(116, 180, 210)))
                            .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
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
                                Style::default().bg(Color::Rgb(44, 72, 92)).fg(Color::White)
                            } else {
                                Style::default()
                            },
                        )))
                        .wrap(Wrap { trim: false })
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(title)
                                .border_style(Style::default().fg(Color::Rgb(116, 180, 210))),
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
                            .style(Style::default().fg(Color::Rgb(116, 180, 210))),
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
                            .highlight_style(Style::default().fg(Color::Rgb(116, 180, 210)))
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
                        .highlight_style(Style::default().fg(Color::Rgb(116, 180, 210)))
                        .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
            }
            if !matches!(dialog, Dialog::Input { .. }) {
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
                        .title("插件分类 · p 搜索")
                        .border_style(style),
                )
                .highlight_style(
                    Style::default()
                        .fg(Color::Rgb(116, 180, 210))
                        .add_modifier(Modifier::BOLD),
                )
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
            if app.job.is_some() && last_tick.elapsed() >= Duration::from_secs(1) {
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
                    Event::Resize(width, _) => {
                        app.resize(width);
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
        app.key(KeyEvent::new(KeyCode::F(10), KeyModifiers::NONE));
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
        app.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(image.exists());
        assert!(app.image.is_none());
        assert_eq!(app.asset_count(), 0);
        assert!(
            Registry::load(&cache)
                .unwrap()
                .selected(Kind::Image)
                .is_none()
        );
        app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL));
        assert_eq!(app.page, Page::Symbols);
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.symbols, symbols);
        assert_eq!(
            Registry::load(&cache).unwrap().selected(Kind::Symbols),
            Some(symbols.as_path())
        );
        assert!(app.results.is_empty());
        app.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(symbols.exists());
        assert!(app.symbols.as_os_str().is_empty());
        assert!(Registry::load(&cache).unwrap().excluded(&symbols));

        app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL));
        app.key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        assert!(app.job.is_none());
        assert!(app.dialog.is_none()); // no selected image must not silently use the old one
    }
    #[test]
    fn remote_tabs_mouse_scrolling_full_links_events_and_cancellation() {
        let mut app = app();
        app.switch_page(Page::Remote);
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
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert!(hits.asset_offset > 0);
        click(&mut app, hits.assets.x + 2, hits.assets.y + 1);
        assert_eq!(app.asset_rows[2], hits.asset_offset);
        assert!(app.job.is_none()); // row selection never triggers download
        app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        let Some(Dialog::Detail { text, .. }) = &app.dialog else {
            panic!("detail missing")
        };
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
        assert_eq!(app.page, Page::Images);
        app.key(KeyEvent::new(KeyCode::F(9), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Analysis);
    }
    #[test]
    fn downloaded_symbols_are_registered_without_starting_analysis_in_manager() {
        let dir = tempfile::tempdir().unwrap();
        let symbols = dir.path().join("download.json.xz");
        std::fs::write(&symbols, b"validated worker output").unwrap();
        let symbols = symbols.canonicalize().unwrap();
        let cache = dir.path().join("cache");
        let mut app = App::new(None, "absent".into(), cache.clone(), Settings::default());
        app.root = dir.path().into();
        app.switch_page(Page::Remote);
        app.download_url = Some("https://example.test/exact.json.xz".into());
        let (tx, rx) = mpsc::channel();
        tx.send(WorkerEvent::Downloaded(symbols.clone())).unwrap();
        app.receiver = Some(rx);
        app.drain();
        assert_eq!(app.page, Page::Remote);
        assert!(app.job.is_none());
        assert_eq!(app.symbols, symbols);
        assert_eq!(app.downloads.len(), 1);
        app.switch_page(Page::Symbols);
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
        assert_eq!(menu_items().len(), PLUGINS.len() + 2);
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
        app.switch_page(Page::Remote);
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
            Some(Dialog::Input {
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
                                n.to_string()
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
        for d in PLUGINS.iter().skip(3) {
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
            app.query = "25".into();
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
            Some(Dialog::Input {
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
            matches!(&app.dialog,Some(Dialog::Detail {text,..}) if text.contains(&candidate.url))
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
        app.resize(80);
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
        app.switch_page(Page::Symbols);
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert_eq!(hits.tabs.len(), 3);
        assert_eq!(hits.header.height, 0);
        assert_eq!(hits.search.height, 3);
        assert!(!screen(&terminal, 100).contains("镜像: images/capture.raw"));
        click(&mut app, hits.search.x + 2, hits.search.y + 1);
        app.paste("test symbol");
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(app.hits.borrow().popup.height, 0);
        assert!(screen(&terminal, 100).contains("test symbol"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.asset_queries[1].is_empty());
        app.key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.page, Page::Remote);
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
        app.switch_page(Page::Remote);
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
        assert!(app.status.contains("选用时再与镜像验证"));
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
}
