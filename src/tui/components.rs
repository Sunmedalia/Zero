fn plugin_label(plugin: Plugin) -> &'static str {
    if plugin.is_dump() {
        "dump"
    } else if matches!(plugin, Plugin::ProcessSpoofing | Plugin::Modxview | Plugin::Kallsyms | Plugin::LinuxPsscan | Plugin::LinuxSockscan) {
        plugin.descriptor().label
    } else {
        plugin
            .name()
            .strip_prefix("windows.")
            .or_else(|| plugin.name().strip_prefix("linux."))
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
    *cursor = (*cursor).min(text.len());
    while !text.is_char_boundary(*cursor) {
        *cursor = cursor.saturating_sub(1);
    }
    use unicode_segmentation::UnicodeSegmentation;
    let previous = |text: &str, cursor: usize| {
        text[..cursor]
            .grapheme_indices(true)
            .next_back()
            .map_or(0, |(i, _)| i)
    };
    let next = |text: &str, cursor: usize| {
        text[cursor..]
            .graphemes(true)
            .next()
            .map_or(cursor, |c| cursor + c.len())
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
fn fit<'a>(fields: &[(&'a str, String, Style)], width: u16) -> Vec<Span<'a>> {
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
                out.push(Span::styled(" · ", Style::default().fg(color_border())));
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
            out.push(Span::styled(" · ", Style::default().fg(color_border())));
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
fn truncate_with_ellipsis(text: &str, budget: usize) -> String {
    if Span::raw(text).width() <= budget {
        return text.into();
    }
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
    plugin.description()
}

fn dump_modes(windows: bool) -> &'static [Plugin] {
    if windows {
        &[
            Plugin::WinProcdump,
            Plugin::WinMemdump,
            Plugin::WinPedump,
            Plugin::WinVaddump,
            Plugin::WinDlldump,
            Plugin::WinModdump,
            Plugin::WinDumpfiles,
        ]
    } else {
        &[Plugin::Procdump, Plugin::Memdump, Plugin::Elfdump, Plugin::ModuleExtract]
    }
}

fn identity_label(identity: &crate::image::BoundIdentity) -> String {
    let kernel = identity.kernels.first().map(String::as_str).unwrap_or("");
    let name = if identity.system == "linux" {
        kernel.split_whitespace().nth(2).unwrap_or(kernel)
    } else {
        kernel
            .trim_start_matches("Windows PDB ")
            .split('/')
            .next()
            .unwrap_or(kernel)
    };
    format!(
        "{} {}{}",
        if identity.system == "linux" {
            "Linux"
        } else {
            "Windows"
        },
        name,
        if identity.kernels.len() > 1 {
            format!(" 等 {} 个", identity.kernels.len())
        } else {
            String::new()
        }
    )
}

fn remote_fields(candidate: &RemoteMatch) -> Vec<(String, String)> {
    if !candidate.banner.starts_with("Linux version ") {
        return vec![];
    }
    let file = candidate
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&candidate.path)
        .trim_end_matches(".xz")
        .trim_end_matches(".json");
    let parts = file.split('_').collect::<Vec<_>>();
    let mut fields = Vec::new();
    if parts.len() >= 3 {
        fields.push(("发行版".into(), parts[0].into()));
    }
    fields.push((
        "内核版本".into(),
        candidate
            .banner
            .split_whitespace()
            .nth(2)
            .unwrap_or("")
            .into(),
    ));
    if parts.len() >= 3 {
        fields.push(("架构".into(), parts.last().unwrap().to_string()));
    }
    if let Some(start) = candidate
        .banner
        .find("(gcc")
        .or_else(|| candidate.banner.find("(clang"))
    {
        let mut depth = 0;
        for (offset, c) in candidate.banner[start..].char_indices() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    fields.push((
                        "编译器".into(),
                        candidate.banner[start + 1..start + offset].trim().into(),
                    ));
                    break;
                }
            }
        }
    }
    if let Some(start) = candidate.banner.find('#') {
        fields.push(("构建".into(), candidate.banner[start..].trim().into()));
    }
    fields
}
