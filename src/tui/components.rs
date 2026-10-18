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
/// Plugin order in the navigation menu. This is a fixed property of the plugin
/// registry, so it is computed once instead of rescanning every descriptor on
/// each keystroke and frame.
fn navigation_plugins() -> &'static [Plugin] {
    static ORDER: std::sync::OnceLock<Vec<Plugin>> = std::sync::OnceLock::new();
    ORDER.get_or_init(|| {
        const CATEGORIES: [&str; 6] = [
            "Process",
            "System",
            "Memory",
            "Files",
            "Network",
            "Integrity",
        ];
        CATEGORIES
            .into_iter()
            .flat_map(|category| {
                PLUGINS
                    .iter()
                    .filter(move |d| {
                        !d.plugin.is_dump()
                            && !d.plugin.is_windows()
                            && d.plugin.category() == category
                    })
                    .map(|d| d.plugin)
            })
            .collect()
    })
}
/// Windows plugins follow the same category order as Linux so the menu layout
/// is stable when the detected system changes.
fn windows_navigation_plugins() -> &'static [Plugin] {
    static ORDER: std::sync::OnceLock<Vec<Plugin>> = std::sync::OnceLock::new();
    ORDER.get_or_init(|| {
        const CATEGORIES: [&str; 6] = [
            "Process",
            "System",
            "Memory",
            "Files",
            "Network",
            "Integrity",
        ];
        CATEGORIES
            .into_iter()
            .flat_map(|category| {
                PLUGINS
                    .iter()
                    .filter(move |d| {
                        d.plugin.is_windows()
                            && !d.plugin.is_dump()
                            && d.plugin.category() == category
                    })
                    .map(|d| d.plugin)
            })
            .collect()
    })
}
fn windows_menu_items() -> &'static [&'static str] {
    static LABELS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LABELS.get_or_init(|| {
        windows_navigation_plugins()
            .iter()
            .map(|p| plugin_label(*p))
            .chain(std::iter::once("dump"))
            .collect()
    })
}
fn menu_items() -> &'static [&'static str] {
    static LABELS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LABELS.get_or_init(|| {
        navigation_plugins()
            .iter()
            .map(|p| plugin_label(*p))
            .chain(std::iter::once("dump"))
            .collect()
    })
}

/// Render control characters as visible escapes so table cells cannot corrupt
/// the terminal. Runs on every visible cell of every frame, so it walks the
/// string once and only allocates when an escape is actually needed.
fn escaped(value: &str) -> String {
    if !value.chars().any(char::is_control) {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}
/// Lay out `label: value` pairs across `width`, dropping whole trailing pairs
/// that would not fit.
///
/// Narrow terminals used to truncate mid-field, which reads as corruption: the
/// image path would end in the middle of a filename. Stopping at a field
/// boundary keeps every visible value truthful.
fn fit<'a>(
    fields: &[(&'a str, String, Style)],
    width: u16,
) -> Vec<Span<'a>> {
    // Two rules, because the fields are not equally important:
    //
    // - A long *value* is shortened to leave room for the fields after it. A
    //   truncated path still identifies the image; a missing kernel does not.
    // - A field that cannot be shortened usefully is dropped whole, so the row
    //   never ends in a fragment like `M 匹…`.
    let width = width as usize;
    let total: usize = fields
        .iter()
        .enumerate()
        .map(|(i, (label, text, _))| {
            usize::from(i > 0) * 3 + Span::raw(*label).width() + Span::raw(text).width()
        })
        .sum();
    let shorten = total > width;
    let mut out = Vec::new();
    let mut used = 0usize;
    for (index, (label, text, style)) in fields.iter().enumerate() {
        let gap = usize::from(index > 0) * 3;
        let label_width = Span::raw(*label).width();
        let text_width = Span::raw(text).width();
        let remaining = width.saturating_sub(used + gap + label_width);
        if remaining == 0 {
            break;
        }
        if text_width <= remaining {
            used += gap + label_width + text_width;
            if index > 0 {
                out.push(Span::styled(" · ", Style::default().fg(BORDER)));
            }
            out.extend(field(label, escaped(text), *style));
            continue;
        }
        // Too long. Share the row with the fields that follow when they are
        // worth keeping, otherwise take what is left.
        let rest: usize = fields[index + 1..]
            .iter()
            .map(|(l, t, _)| 3 + Span::raw(*l).width() + Span::raw(t).width())
            .sum();
        let budget = if shorten && rest > 0 && remaining > rest + 8 {
            remaining - rest
        } else {
            remaining
        };
        if budget < 8 {
            break;
        }
        let shown = truncate_with_ellipsis(text, budget);
        if index > 0 {
            out.push(Span::styled(" · ", Style::default().fg(BORDER)));
        }
        out.extend(field(label, escaped(&shown), *style));
        // Nothing after a shortened value: it already used the shared budget.
        break;
    }
    out
}
/// Shorten a repository path for display.
///
/// These paths end in a long content hash that is the same for every candidate
/// of one kernel, so the tail is the least informative part. The directory and
/// the file name are kept and the hash is elided in the middle.
fn compact_remote_path(path: &str, width: u16) -> String {
    let budget = (width as usize).saturating_sub(12).max(16);
    if Span::raw(path).width() <= budget {
        return path.to_string();
    }
    // The file name is `<distribution>_<version>-<hash>.json.xz`; the hash is
    // 64 hex characters that are identical across candidates, so it is the part
    // worth dropping. Cut the name before the hash and keep the extension.
    if let Some((dir, file)) = path.rsplit_once('/') {
        let (stem, extension) = match file.find(".json") {
            Some(at) => (&file[..at], &file[at..]),
            None => (file, ""),
        };
        // The hash follows the last '-'; everything before it identifies the
        // build.
        let informative = stem.rsplit_once('-').map_or(stem, |(head, tail)| {
            if tail.len() >= 32 && tail.chars().all(|c| c.is_ascii_hexdigit()) {
                head
            } else {
                stem
            }
        });
        let compact = format!("{dir}/{informative}{extension}");
        if Span::raw(&compact).width() <= budget {
            return compact;
        }
        // Still too wide: shorten the directory part, which repeats across
        // candidates, and keep the informative file name.
        let name_room = budget.saturating_sub(2).max(8);
        let name = format!("{informative}{extension}");
        let name = if Span::raw(&name).width() > name_room {
            truncate_with_ellipsis(&name, name_room)
        } else {
            name
        };
        return format!("…/{name}");
    }
    truncate_with_ellipsis(path, budget)
}
/// Shorten a path to `budget` cells, keeping the end.
///
/// The tail of a path distinguishes files: six captures in the same directory
/// all truncate to the same prefix, so a front-truncated list is unreadable.
fn truncate_path(path: &str, budget: usize) -> String {
    if Span::raw(path).width() <= budget {
        return path.to_string();
    }
    if budget <= 2 {
        return "…".into();
    }
    // Walk backwards from the end, keeping whole characters. Each step adds
    // only the width of the character just taken.
    let mut kept: Vec<char> = Vec::new();
    let mut used = 1; // the leading ellipsis
    for c in path.chars().rev() {
        let mut probe = String::new();
        probe.push(c);
        let width = Span::raw(probe.as_str()).width();
        if used + width > budget {
            break;
        }
        used += width;
        kept.push(c);
    }
    let tail: String = kept.iter().rev().copied().collect();
    format!("…{tail}")
}
/// Shorten `text` to `budget` display cells, marking the cut with `…`.
fn truncate_with_ellipsis(text: &str, budget: usize) -> String {
    if budget <= 1 {
        return "…".into();
    }
    let mut out = String::new();
    for c in text.chars() {
        let mut candidate = out.clone();
        candidate.push(c);
        if Span::raw(candidate.as_str()).width() > budget - 1 {
            break;
        }
        out = candidate;
    }
    out.push('…');
    out
}
/// Trim a kernel banner to its identifying head.
///
/// A full Linux banner is ~150 characters of build metadata; the version and
/// the distribution build are what identify it, and the whole string is
/// available in the detail panel and the identification result.
fn summarise_banner(banner: &str) -> String {
    let banner = banner.trim_end_matches(['\n', '\0', ' ']);
    let mut out = String::new();
    for (i, word) in banner.split_whitespace().enumerate() {
        if i >= 6 {
            out.push_str(" …");
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
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
/// Column widths from the header and a bounded sample of the visible rows.
/// Borrows the cells so sizing does not clone the table.
fn table_widths<'a>(
    columns: &[String],
    rows: impl Iterator<Item = (&'a [String], Option<(usize, String)>)> + Clone,
) -> Vec<u16> {
    columns
        .iter()
        .enumerate()
        .map(|(i, column)| {
            let header = Span::raw(column).width();
            let data = rows
                .clone()
                .filter_map(|(cells, decoration)| {
                    let value = match decoration.as_ref() {
                        Some((column, text)) if *column == i => text.as_str(),
                        _ => cells.get(i)?.as_str(),
                    };
                    Some(Span::raw(escaped(value)).width())
                })
                .max()
                .unwrap_or(0);
            header.max(data.min(60)).clamp(3, 120) as u16
        })
        .collect()
}
/// Order-independent fingerprint of the collapsed-row set.
///
/// The index cache is keyed on this instead of a cloned `HashSet`, because the
/// key is rebuilt several times per frame. A collision would only cost one
/// extra index rebuild, never a wrong row.
fn collapsed_fingerprint(collapsed: &HashSet<String>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut xor = 0u64;
    let mut sum = 0u64;
    for value in collapsed {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        value.hash(&mut hasher);
        let hash = hasher.finish();
        xor ^= hash;
        sum = sum.wrapping_add(hash);
    }
    xor ^ sum.rotate_left(17) ^ (collapsed.len() as u64).rotate_left(31)
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
