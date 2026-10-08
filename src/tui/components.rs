fn plugin_label(plugin: Plugin) -> &'static str {
    if plugin.is_dump() {
        "dump"
    } else {
        plugin
            .name()
            .strip_prefix("windows.")
            .unwrap_or(plugin.name())
    }
}
/// Case-insensitive, order-free token match: every space-separated term must appear.
fn query_matches(haystack: &str, query: &str) -> bool {
    let haystack = haystack.to_lowercase();
    query
        .to_lowercase()
        .split_whitespace()
        .all(|term| haystack.contains(term))
}
/// Plugins are found by name, short label, Chinese description or category.
fn plugin_search_hit(plugin: Plugin, query: &str) -> bool {
    let text = format!(
        "{} {} {} {}",
        plugin.name(),
        plugin_label(plugin),
        plugin_description(plugin),
        plugin.category()
    );
    query_matches(&text, query)
}
fn plugin_matches(query: &str) -> Vec<Plugin> {
    let query = query.to_lowercase();
    let mut plugins: Vec<_> = PLUGINS
        .iter()
        .filter(|d| {
            !d.plugin.is_dump() && !d.plugin.is_windows() && plugin_search_hit(d.plugin, &query)
        })
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
                .filter(move |d| {
                    !d.plugin.is_dump() && !d.plugin.is_windows() && d.plugin.category() == category
                })
                .map(|d| d.plugin)
        })
        .collect()
}
fn menu_items() -> Vec<String> {
    navigation_plugins()
        .iter()
        .map(|p| plugin_label(*p).to_string())
        .chain(std::iter::once("dump".into()))
        .collect()
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
#[cfg(test)]
fn compare_values(a: &str, b: &str) -> std::cmp::Ordering {
    crate::result_view::compare(a, b)
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
#[cfg(test)]
fn tree_rows(rows: Vec<Vec<String>>, collapsed: &HashSet<String>) -> Vec<Vec<String>> {
    tree_rows_with_columns(rows, collapsed, 2, 3)
}
#[cfg(test)]
fn tree_rows_with_columns(
    rows: Vec<Vec<String>>,
    collapsed: &HashSet<String>,
    parent: usize,
    name: usize,
) -> Vec<Vec<String>> {
    let ids: HashSet<_> = rows.iter().map(|r| r[0].as_str()).collect();
    let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        if row[parent] == "0" || !ids.contains(row[parent].as_str()) || row[0] == row[parent] {
            roots.push(i);
        } else {
            children.entry(&row[parent]).or_default().push(i);
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
                shown[name] = format!(
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
                    row[name]
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

fn plugin_description(plugin: Plugin) -> &'static str {
    use Plugin::*;
    match plugin {
        WinLdrmodules => "对照 PE 映射与三条 PEB 模块链表",
        WinHollowprocesses => "检查主程序基址及映像映射异常",
        WinSuspiciousThreads => "检查活动线程起点所在的 VAD",
        CheckExec => "检查 Linux 主程序代码映射与可执行文件",
        Pslist | WinPslist => "列出活动进程及其地址",
        Pstree | WinPstree => "按父进程关系浏览进程树",
        Psaux | WinCmdline => "读取进程命令行",
        Envars | WinEnvars => "读取进程环境变量",
        Lsmod | WinModules => "列出内核模块及地址范围",
        Maps | WinVadinfo => "查看进程虚拟内存映射",
        Lsof | WinHandles => "列出进程打开的文件或对象",
        Sockstat | Netscan | WinNetscan => "查看网络连接及端点",
        Banners => "识别完整内核身份，无需符号",
        Pwd => "读取进程工作目录",
        Pscred => "查看进程身份和凭据",
        Threads | WinThreads => "列出进程线程",
        Mountinfo => "查看文件系统挂载关系",
        CheckCreds => "检查进程凭据异常",
        Dmesg => "读取内核日志缓冲区",
        Systeminfo | WinSysteminfo => "查看系统和内核信息",
        Elfs => "识别进程中的 ELF 映射",
        Bash => "恢复内存中的 Bash 历史记录",
        Malfind | WinMalfind => "检查可疑的可执行内存映射",
        Psxview | WinPsxview => "对比多种进程发现方式",
        CheckModules | WinDrivercheck => "检查模块或驱动异常",
        CheckSyscall => "检查系统调用表",
        Iomem => "查看物理内存资源范围",
        Ioports => "查看 I/O 端口资源",
        Ptrace => "检查进程跟踪关系",
        KeyboardNotifiers => "查看键盘通知回调",
        Psstate => "查看进程状态",
        Capabilities => "查看进程能力集合",
        Fdsummary => "汇总进程文件描述符",
        WinCallbacks => "查看内核回调及模块归属",
        WinUnloadedmodules => "读取已卸载驱动记录",
        WinFilescan => "扫描文件对象",
        WinMutantscan => "扫描互斥对象",
        WinGetsids => "读取进程令牌 SID",
        WinConnscan => "扫描旧版 Windows 连接对象",
        WinSockscan => "扫描旧版 Windows 套接字对象",
        WinConsoles => "恢复控制台保存的记录",
        WinCmdscan => "扫描命令历史记录",
        WinDriverscan => "扫描驱动对象",
        WinSvcscan => "扫描 Windows 服务",
        WinCrashinfo => "读取转储容器故障信息，无需完整内核符号",
        WinAutoruns => "查看注册表自启动配置",
        WinDlllist => "列出进程加载的 DLL",
        WinHivelist => "列出注册表 hive 地址",
        WinPrintkey => "读取指定 hive 中的注册表键",
        WinPsscan => "扫描进程对象",
        Procdump | WinProcdump => "转储指定进程的可读内存",
        Memdump | WinMemdump => "转储指定进程的地址范围",
        Elfdump => "导出进程中含 ELF 头的映射",
        WinPedump => "按 PE 节表重建可读文件",
    }
}
