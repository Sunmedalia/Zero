// One action table drives keyboard dispatch, availability, the command palette,
// the resource toolbar, the analysis footer and the help text.
//
// Every user-invokable action has exactly one `Command`, one label and one
// binding. Surfaces select from this table by placement, so a binding can no
// longer exist in the palette but be missing from the toolbar, or be
// implemented twice with drifting status text.

/// Identity of an action, independent of the key that triggers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Command {
    // Global
    Quit,
    Help,
    Palette,
    Settings,
    Cache,
    TaskLog,
    History,
    Diagnostics,
    PageAssets,
    PageAnalysis,
    SystemSelect,
    ToggleOnline,
    Cancel,
    CacheRefresh,
    CacheToggle,
    CacheOpen,
    CacheDelete,
    CacheClear,
    // Image and symbol intake, valid on both pages.
    ImportImage,
    ImportSymbols,
    MatchLocal,
    MatchRemote,
    Identify,
    VerifyImage,
    // Resource library
    ImportCurrent,
    Select,
    SelectAndEnter,
    AssetDetail,
    DeleteAsset,
    RefreshAssets,
    SearchAssets,
    EnterAnalysis,
    ToggleSource,
    GenerateSymbols,
    FetchIndex,
    Download,
    ToggleMatchFilter,
    // Analysis
    Run,
    Rerun,
    Plugins,
    Parameters,
    Dump,
    Export,
    Sort,
    Rows,
    PrevPage,
    NextPage,
    Detail,
    SearchContent,
    Enter,
}

/// Which page an action belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    Anywhere,
    Assets,
    Analysis,
    Cache,
}

/// Where an action is offered. Zero means "reachable by key only".
const PALETTE: u8 = 1;
const TOOLBAR: u8 = 2;
const FOOTER: u8 = 4;

const CONTEXT_FOCUS: u8 = 1;
const NAV_FOCUS: u8 = 2;
const CONTENT_FOCUS: u8 = 4;
const DETAIL_FOCUS: u8 = 8;
const ANY_FOCUS: u8 = 0xF;

const IMAGES: u8 = 1;
const SYMBOLS: u8 = 2;
const REMOTE: u8 = 4;
const ALL_SECTIONS: u8 = 7;

pub(super) struct Action {
    pub(super) command: Command,
    pub(super) label: &'static str,
    pub(super) key: KeyCode,
    pub(super) scope: Scope,
    placement: u8,
    sections: u8,
    palette_focus: u8,
    footer_focus: u8,
}

const fn action(
    command: Command,
    label: &'static str,
    key: KeyCode,
    scope: Scope,
    placement: u8,
) -> Action {
    Action {
        command,
        label,
        key,
        scope,
        placement,
        sections: ALL_SECTIONS,
        palette_focus: ANY_FOCUS,
        footer_focus: 0,
    }
}

/// English aliases so the palette matches the words users already know
/// (`cache`, `dump`, `pid`) in addition to the Chinese label.
fn keywords(command: Command) -> &'static str {
    match command {
        Command::Quit => "quit exit",
        Command::Help => "help f1",
        Command::Palette => "command palette",
        Command::Settings => "settings directory page size",
        Command::Cache => "cache inventory",
        Command::CacheRefresh => "cache refresh",
        Command::CacheToggle => "cache scope toggle",
        Command::CacheOpen => "cache record open group",
        Command::CacheDelete => "cache delete remove",
        Command::CacheClear => "cache clear scopes",
        Command::TaskLog => "log task",
        Command::History => "history export",
        Command::Diagnostics => "diagnostics partial",
        Command::PageAssets => "assets library resource",
        Command::PageAnalysis => "analysis console",
        Command::SystemSelect => "os system linux windows auto",
        Command::ToggleOnline => "offline online network",
        Command::Cancel => "cancel abort",
        Command::ImportImage => "image raw lime import",
        Command::ImportSymbols => "symbols isf json zip import",
        Command::MatchLocal => "match local symbol",
        Command::MatchRemote => "match remote pdb download",
        Command::VerifyImage => "verify image sha256 digest hash checksum",
        Command::Identify => "identify banner kernel",
        Command::ImportCurrent => "import asset",
        Command::Select => "select use",
        Command::SelectAndEnter => "select enter analysis",
        Command::AssetDetail => "detail info",
        Command::DeleteAsset => "remove delete registry",
        Command::RefreshAssets => "refresh reload",
        Command::SearchAssets => "search filter",
        Command::EnterAnalysis => "enter analysis console",
        Command::ToggleSource => "local remote source",
        Command::GenerateSymbols => "generate symbols dwarf2json kali",
        Command::FetchIndex => "index catalog fetch",
        Command::Download => "download save",
        Command::ToggleMatchFilter => "filter matched",
        Command::Run => "run plugin",
        Command::Rerun => "rerun force",
        Command::Plugins => "plugins search",
        Command::Parameters => "parameters options pid hive key arch pagefile",
        Command::Dump => "dump procdump memdump elfdump pedump",
        Command::Export => "export csv json",
        Command::Sort => "sort order",
        Command::Rows => "rows page size",
        Command::PrevPage => "previous page",
        Command::NextPage => "next page",
        Command::Detail => "detail inspector",
        Command::SearchContent => "search content filter",
        Command::Enter => "enter open",
    }
}

pub(super) const ACTIONS: &[Action] = &[
    action(
        Command::CacheRefresh,
        "刷新 r",
        KeyCode::Char('r'),
        Scope::Cache,
        PALETTE | FOOTER,
    ),
    action(
        Command::CacheToggle,
        "勾选范围 Space",
        KeyCode::Char(' '),
        Scope::Cache,
        PALETTE | FOOTER,
    ),
    action(
        Command::CacheOpen,
        "打开／折叠 Enter",
        KeyCode::Enter,
        Scope::Cache,
        PALETTE | FOOTER,
    ),
    action(
        Command::CacheDelete,
        "删除条目 Delete",
        KeyCode::Delete,
        Scope::Cache,
        PALETTE | FOOTER,
    ),
    action(
        Command::CacheClear,
        "清理已勾选 x",
        KeyCode::Char('x'),
        Scope::Cache,
        PALETTE | FOOTER,
    ),
    // Global actions, valid on all pages.
    action(
        Command::Quit,
        "退出 q",
        KeyCode::Char('q'),
        Scope::Anywhere,
        PALETTE,
    ),
    action(
        Command::Help,
        "帮助 H",
        KeyCode::Char('H'),
        Scope::Anywhere,
        PALETTE,
    ),
    action(
        Command::Palette,
        "命令面板 ?",
        KeyCode::Char('?'),
        Scope::Anywhere,
        PALETTE | TOOLBAR,
    ),
    action(
        Command::Settings,
        "目录与分页设置 ,",
        KeyCode::Char(','),
        Scope::Anywhere,
        PALETTE | TOOLBAR,
    ),
    action(
        Command::Cache,
        "管理缓存 c",
        KeyCode::Char('c'),
        Scope::Anywhere,
        PALETTE,
    ),
    action(
        Command::TaskLog,
        "任务日志 l",
        KeyCode::Char('l'),
        Scope::Anywhere,
        PALETTE,
    ),
    action(
        Command::History,
        "历史导出记录 h",
        KeyCode::Char('h'),
        Scope::Anywhere,
        PALETTE,
    ),
    action(
        Command::Diagnostics,
        "查看诊断 v",
        KeyCode::Char('v'),
        Scope::Anywhere,
        PALETTE,
    ),
    action(
        Command::PageAssets,
        "打开资源库 1",
        KeyCode::Char('1'),
        Scope::Anywhere,
        PALETTE,
    ),
    action(
        Command::PageAnalysis,
        "打开分析页 2",
        KeyCode::Char('2'),
        Scope::Anywhere,
        PALETTE,
    ),
    Action {
        footer_focus: ANY_FOCUS,
        ..action(
            Command::SystemSelect,
            "选择分析系统 S",
            KeyCode::Char('S'),
            Scope::Anywhere,
            PALETTE | FOOTER,
        )
    },
    action(
        Command::ToggleOnline,
        "在线／离线 o",
        KeyCode::Char('o'),
        Scope::Anywhere,
        PALETTE | TOOLBAR,
    ),
    action(
        Command::Cancel,
        "取消 Esc",
        KeyCode::Esc,
        Scope::Anywhere,
        TOOLBAR,
    ),
    // Intake actions, valid on both pages.
    Action {
        footer_focus: CONTEXT_FOCUS,
        ..action(
            Command::ImportImage,
            "打开镜像 i",
            KeyCode::Char('i'),
            Scope::Anywhere,
            PALETTE | FOOTER,
        )
    },
    Action {
        footer_focus: CONTEXT_FOCUS,
        ..action(
            Command::ImportSymbols,
            "选择本地符号 y",
            KeyCode::Char('y'),
            Scope::Anywhere,
            PALETTE | FOOTER,
        )
    },
    Action {
        footer_focus: CONTEXT_FOCUS,
        ..action(
            Command::MatchLocal,
            "当前镜像 → 本地匹配 m",
            KeyCode::Char('m'),
            Scope::Anywhere,
            PALETTE | TOOLBAR | FOOTER,
        )
    },
    Action {
        footer_focus: CONTEXT_FOCUS,
        ..action(
            Command::MatchRemote,
            "当前镜像 → 远程匹配 M",
            KeyCode::Char('M'),
            Scope::Anywhere,
            PALETTE | TOOLBAR,
        )
    },
    Action {
        footer_focus: CONTEXT_FOCUS,
        ..action(
            Command::Identify,
            "识别内核候选 b",
            KeyCode::Char('b'),
            Scope::Anywhere,
            PALETTE | FOOTER,
        )
    },
    action(
        Command::VerifyImage,
        "校验镜像 SHA256 V",
        KeyCode::Char('V'),
        Scope::Anywhere,
        PALETTE,
    ),
    // Resource library actions.
    action(
        Command::ImportCurrent,
        "导入当前资产 a",
        KeyCode::Char('a'),
        Scope::Assets,
        PALETTE | TOOLBAR,
    ),
    action(
        Command::Select,
        "选用 Space",
        KeyCode::Char(' '),
        Scope::Assets,
        PALETTE | TOOLBAR,
    ),
    action(
        Command::SelectAndEnter,
        "选用并分析 Enter",
        KeyCode::Enter,
        Scope::Assets,
        PALETTE,
    ),
    action(
        Command::AssetDetail,
        "详情 d",
        KeyCode::Char('d'),
        Scope::Assets,
        PALETTE | TOOLBAR,
    ),
    Action {
        sections: IMAGES | SYMBOLS,
        ..action(
            Command::DeleteAsset,
            "移出清单 Delete",
            KeyCode::Delete,
            Scope::Assets,
            PALETTE,
        )
    },
    action(
        Command::RefreshAssets,
        "刷新资产 r",
        KeyCode::Char('r'),
        Scope::Assets,
        PALETTE,
    ),
    action(
        Command::SearchAssets,
        "搜索列表 /",
        KeyCode::Char('/'),
        Scope::Assets,
        PALETTE,
    ),
    action(
        Command::EnterAnalysis,
        "进入分析 x",
        KeyCode::Char('x'),
        Scope::Assets,
        PALETTE | TOOLBAR,
    ),
    action(
        Command::ToggleSource,
        "本地／远程 t",
        KeyCode::Char('t'),
        Scope::Assets,
        PALETTE,
    ),
    action(
        Command::GenerateSymbols,
        "生成当前镜像符号表 K",
        KeyCode::Char('K'),
        Scope::Anywhere,
        PALETTE,
    ),
    Action {
        sections: REMOTE,
        ..action(
            Command::FetchIndex,
            "获取索引 g",
            KeyCode::Char('g'),
            Scope::Assets,
            PALETTE | TOOLBAR,
        )
    },
    Action {
        sections: REMOTE,
        ..action(
            Command::Download,
            "仅下载 w",
            KeyCode::Char('w'),
            Scope::Assets,
            PALETTE | TOOLBAR,
        )
    },
    Action {
        sections: SYMBOLS | REMOTE,
        ..action(
            Command::ToggleMatchFilter,
            "全部／匹配 z",
            KeyCode::Char('z'),
            Scope::Assets,
            PALETTE | TOOLBAR,
        )
    },
    // Analysis actions.
    Action {
        footer_focus: NAV_FOCUS,
        ..action(
            Command::Run,
            "运行插件 R",
            KeyCode::Char('R'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        footer_focus: NAV_FOCUS,
        ..action(
            Command::Rerun,
            "重新分析 r",
            KeyCode::Char('r'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        footer_focus: NAV_FOCUS,
        ..action(
            Command::Plugins,
            "搜索插件 p",
            KeyCode::Char('p'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    action(
        Command::Parameters,
        "编辑适用参数 P",
        KeyCode::Char('P'),
        Scope::Analysis,
        PALETTE,
    ),
    Action {
        footer_focus: NAV_FOCUS | CONTENT_FOCUS,
        ..action(
            Command::Dump,
            "Dump 导出进程／地址范围／ELF",
            KeyCode::Char('D'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        palette_focus: CONTENT_FOCUS | DETAIL_FOCUS,
        footer_focus: CONTENT_FOCUS,
        ..action(
            Command::Export,
            "导出结果 e",
            KeyCode::Char('e'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        palette_focus: CONTENT_FOCUS | DETAIL_FOCUS,
        footer_focus: CONTENT_FOCUS,
        ..action(
            Command::Sort,
            "排序 s",
            KeyCode::Char('s'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        palette_focus: CONTENT_FOCUS | DETAIL_FOCUS,
        footer_focus: CONTENT_FOCUS,
        ..action(
            Command::Rows,
            "每页行数 n",
            KeyCode::Char('n'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        palette_focus: CONTENT_FOCUS | DETAIL_FOCUS,
        footer_focus: CONTENT_FOCUS,
        ..action(
            Command::PrevPage,
            "前一页 [",
            KeyCode::Char('['),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        palette_focus: CONTENT_FOCUS | DETAIL_FOCUS,
        footer_focus: CONTENT_FOCUS,
        ..action(
            Command::NextPage,
            "后一页 ]",
            KeyCode::Char(']'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        palette_focus: CONTENT_FOCUS | DETAIL_FOCUS,
        footer_focus: CONTENT_FOCUS,
        ..action(
            Command::Detail,
            "详情 d",
            KeyCode::Char('d'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    Action {
        footer_focus: CONTENT_FOCUS,
        ..action(
            Command::SearchContent,
            "搜索内容 /",
            KeyCode::Char('/'),
            Scope::Analysis,
            PALETTE | FOOTER,
        )
    },
    // Enter is key-only: its meaning depends on the focused region.
    action(
        Command::Enter,
        "打开 Enter",
        KeyCode::Enter,
        Scope::Analysis,
        0,
    ),
];

/// Toolbar order is presentation, not identity: the primary action leads, then
/// the section's own actions, then the cross-section ones.
const TOOLBAR_ORDER: &[Command] = &[
    Command::EnterAnalysis,
    Command::ImportCurrent,
    Command::Select,
    Command::AssetDetail,
    Command::ToggleMatchFilter,
    Command::FetchIndex,
    Command::Download,
    Command::MatchLocal,
    Command::MatchRemote,
    Command::ToggleOnline,
    Command::Settings,
    Command::Palette,
];

fn action_of(command: Command) -> &'static Action {
    ACTIONS
        .iter()
        .find(|action| action.command == command)
        .expect("every command has a table entry")
}
fn focus_bit(focus: Focus) -> u8 {
    1 << focus as u8
}
fn section_bit(section: AssetSection) -> u8 {
    match section {
        AssetSection::Images => IMAGES,
        AssetSection::Symbols => SYMBOLS,
        AssetSection::Remote => REMOTE,
    }
}
/// Whether `command` applies to `section` at all. Section-specific actions
/// (`g`, `w`, `z`, `Delete`) are filtered here instead of by a key guard.
fn command_applies(command: Command, section: AssetSection) -> bool {
    action_of(command).sections & section_bit(section) != 0
}
/// Actions offered on the resource toolbar for `section`. A running task adds
/// the cancellation entry last so it is always the reachable way out.
fn toolbar_commands(section: AssetSection, busy: bool) -> Vec<Command> {
    let mut commands = TOOLBAR_ORDER
        .iter()
        .copied()
        .filter(|command| {
            let action = action_of(*command);
            action.placement & TOOLBAR != 0 && action.sections & section_bit(section) != 0
        })
        .collect::<Vec<_>>();
    if busy {
        // Cancellation leads when a task is running: it is the way out, so it
        // must survive the row cap rather than being the first action dropped.
        commands.insert(0, Command::Cancel);
    }
    commands
}
fn toolbar_actions(section: AssetSection, busy: bool) -> Vec<(&'static str, KeyCode)> {
    toolbar_commands(section, busy)
        .into_iter()
        .map(|command| {
            let action = action_of(command);
            (action.label, action.key)
        })
        .collect()
}
/// Every action reachable on the resource page, for the help text.
fn asset_actions(section: AssetSection) -> Vec<(&'static str, KeyCode)> {
    ACTIONS
        .iter()
        .filter(|action| {
            matches!(action.scope, Scope::Anywhere | Scope::Assets)
                && action.sections & section_bit(section) != 0
        })
        .map(|action| (action.label, action.key))
        .collect()
}
/// Footer order is presentation: the actions used most often lead, so a narrow
/// terminal truncates the rare ones instead of the frequent ones.
const FOOTER_ORDER: &[Command] = &[
    Command::Run,
    Command::SearchContent,
    Command::Detail,
    Command::Sort,
    Command::Export,
    Command::Rows,
    Command::PrevPage,
    Command::NextPage,
    Command::Plugins,
    Command::Rerun,
    Command::Dump,
    Command::ImportImage,
    Command::ImportSymbols,
    Command::Identify,
    Command::MatchLocal,
    Command::SystemSelect,
];
fn footer_actions(focus: Focus) -> Vec<(&'static str, KeyCode)> {
    FOOTER_ORDER
        .iter()
        .filter_map(|command| {
            let action = action_of(*command);
            (action.placement & FOOTER != 0 && action.footer_focus & focus_bit(focus) != 0)
                .then_some((action.label, action.key))
        })
        .collect()
}
/// Rows a wrapped action strip needs at `width`, so the layout can reserve the
/// exact footer height before drawing.
/// Rows the resource toolbar needs at `width`, capped so the chrome cannot grow
/// past the content it describes.
///
/// An uncapped toolbar took four rows on a 60-column terminal, leaving the list
/// eight. Three rows hold every resource action at that width; anything past
/// the cap stays reachable through `更多 ?`, which the strip reserves room for.
const TOOLBAR_ROWS: u16 = 3;
fn action_rows(actions: &[(&'static str, KeyCode)], width: u16) -> u16 {
    // Mirrors the renderer: every row keeps room for `更多 ?` so the height
    // reserved here is the height actually needed.
    let more = Span::raw(" 更多 ? ").width() as u16;
    let mut rows = 1;
    let mut x = 0;
    for (label, _) in actions {
        let length = Span::raw(format!(" {label} ")).width() as u16;
        if length > width {
            continue;
        }
        if x + length + more > width {
            rows += 1;
            x = 0;
        }
        x += length + 1;
    }
    rows.min(TOOLBAR_ROWS)
}
/// Palette entries for a page, focus and — on the resource page — section.
fn command_matches(
    query: &str,
    page: Page,
    focus: Focus,
    section: Option<AssetSection>,
) -> Vec<usize> {
    ACTIONS
        .iter()
        .enumerate()
        .filter(|(_, action)| {
            action.placement & PALETTE != 0
                && match action.scope {
                    Scope::Anywhere => true,
                    Scope::Assets => page == Page::Assets,
                    Scope::Analysis => page == Page::Analysis,
                    Scope::Cache => page == Page::Cache,
                }
                && section.is_none_or(|section| action.sections & section_bit(section) != 0)
                && action.palette_focus & focus_bit(focus) != 0
                && (query_matches(action.label, query)
                    || query_matches(keywords(action.command), query))
        })
        .map(|(i, _)| i)
        .collect()
}
impl Command {
    /// Resolve a key for the active page. Keys that mean different things on the
    /// two pages (`d`, `r`, `/`, `g`) are disambiguated here instead of in two
    /// independent match blocks that drifted apart.
    fn from_key(page: Page, key: KeyCode) -> Option<Self> {
        match key {
            KeyCode::F(1) => return Some(Self::Help),
            KeyCode::F(2) => return Some(Self::PageAssets),
            KeyCode::F(3) => return Some(Self::PageAnalysis),
            KeyCode::F(5) if page == Page::Analysis => return Some(Self::Run),
            KeyCode::F(6) => return Some(Self::SystemSelect),
            KeyCode::Char('C') if page == Page::Cache => return Some(Self::CacheClear),
            KeyCode::Char('1') => return Some(Self::PageAssets),
            KeyCode::Char('2') => return Some(Self::PageAnalysis),
            KeyCode::Char('3') | KeyCode::F(4) => return Some(Self::Cache),
            KeyCode::F(8) => return Some(Self::Diagnostics),
            KeyCode::Char('g') if page == Page::Analysis => return Some(Self::GenerateSymbols),
            _ => {}
        }
        ACTIONS
            .iter()
            .find(|action| {
                action.key == key
                    && match action.scope {
                        Scope::Anywhere => true,
                        Scope::Assets => page == Page::Assets,
                        Scope::Analysis => page == Page::Analysis,
                        Scope::Cache => page == Page::Cache,
                    }
            })
            .map(|action| action.command)
    }
}
