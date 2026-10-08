fn asset_actions(section: AssetSection) -> Vec<(&'static str, KeyCode)> {
    let mut actions = match section {
        AssetSection::Images => vec![
            ("选用 Space", KeyCode::Char(' ')),
            ("选用并分析 Enter", KeyCode::Enter),
            ("导入 a", KeyCode::Char('a')),
        ],
        AssetSection::Symbols => vec![
            ("选用 Space", KeyCode::Char(' ')),
            ("选用并分析 Enter", KeyCode::Enter),
            ("导入 a", KeyCode::Char('a')),
            ("全部／匹配 z", KeyCode::Char('z')),
        ],
        AssetSection::Remote => vec![
            ("下载并选用 Space", KeyCode::Char(' ')),
            ("进入分析控制台 Enter", KeyCode::Enter),
            ("仅下载 w", KeyCode::Char('w')),
            ("获取索引 g", KeyCode::Char('g')),
        ],
    };
    actions.extend([
        ("搜索 /", KeyCode::Char('/')),
        ("详情 d", KeyCode::Char('d')),
        ("本地匹配 m", KeyCode::Char('m')),
        ("远程匹配 M", KeyCode::Char('M')),
        ("识别内核 b", KeyCode::Char('b')),
        ("刷新 r", KeyCode::Char('r')),
        ("进入分析 x", KeyCode::Char('x')),
        ("本地／远程 t", KeyCode::Char('t')),
        ("在线／离线 o", KeyCode::Char('o')),
        ("生成当前镜像符号表 K", KeyCode::Char('K')),
    ]);
    if section != AssetSection::Images {
        actions.push(("导入镜像 i", KeyCode::Char('i')));
    }
    if section != AssetSection::Symbols {
        actions.push(("导入符号 y", KeyCode::Char('y')));
    }
    if section != AssetSection::Remote {
        actions.push(("移出清单 Delete", KeyCode::Delete));
    }
    actions
}
fn asset_pane_keys(section: AssetSection) -> &'static [KeyCode] {
    match section {
        AssetSection::Images => &[KeyCode::Char('a'), KeyCode::Char(' '), KeyCode::Char('d')],
        AssetSection::Symbols => &[
            KeyCode::Char('a'),
            KeyCode::Char(' '),
            KeyCode::Char('d'),
            KeyCode::Char('z'),
        ],
        AssetSection::Remote => &[
            KeyCode::Char('g'),
            KeyCode::Char(' '),
            KeyCode::Char('w'),
            KeyCode::Char('d'),
        ],
    }
}
fn asset_action_rows(section: AssetSection, keys: &[KeyCode], width: u16) -> u16 {
    let actions = asset_actions(section);
    let mut rows = 1;
    let mut x = 0;
    for key in keys {
        if let Some((label, _)) = actions.iter().find(|(_, action)| action == key) {
            let length = Span::raw(format!(" {label} ")).width() as u16;
            if length > width {
                continue;
            }
            if x + length > width {
                rows += 1;
                x = 0;
            }
            x += length + 1;
        }
    }
    rows
}
const COMMANDS: &[(&str, KeyCode)] = &[
    ("打开资源库", KeyCode::F(2)),
    ("运行当前插件 Ctrl+R", KeyCode::F(5)),
    ("编辑适用参数 P", KeyCode::Char('P')),
    ("打开分析页", KeyCode::F(3)),
    ("选择分析系统：自动 / Linux / Windows", KeyCode::F(6)),
    ("打开镜像", KeyCode::Char('i')),
    ("选择本地符号", KeyCode::Char('y')),
    ("搜索插件", KeyCode::Char('p')),
    ("Dump 导出进程／地址范围／ELF", KeyCode::Char('D')),
    ("当前镜像 → 本地符号匹配", KeyCode::Char('m')),
    ("当前镜像 → 远程精确匹配", KeyCode::Char('M')),
    ("识别内核候选", KeyCode::Char('b')),
    ("管理缓存 cache [c]", KeyCode::Char('c')),
    ("生成当前镜像符号表 K", KeyCode::Char('K')),
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
fn command_matches(query: &str, page: Page, focus: Focus) -> Vec<usize> {
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
                && (!result_action || focus >= Focus::Content)
                && query_matches(label, query)
        })
        .map(|(i, _)| i)
        .collect()
}
