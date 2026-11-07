//! Mouse hit-testing and dispatch for every page and dialog.
use super::*;

impl App {
    pub(super) fn mouse(&mut self, mouse: MouseEvent) -> bool {
        if self
            .terminal_size
            .get()
            .is_some_and(|(w, h)| w < 60 || h < 16)
        {
            return false;
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left)
            && self.dialog.is_some()
            && !matches!(
                self.dialog,
                Some(Dialog::Input {
                    kind: InputKind::Search | InputKind::AssetsSearch,
                    ..
                })
            )
            && !self
                .hits
                .borrow()
                .popup
                .contains(Position::new(mouse.column, mouse.row))
        {
            self.back_dialog = None;
            self.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
            return false;
        }
        if self.scrollbar_mouse(mouse) {
            return false;
        }
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
        if self.dialog.is_none() && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Middle))
        {
            let tab = self
                .hits
                .borrow()
                .result_tabs
                .iter()
                .find(|(r, _, _)| r.contains(point))
                .map(|(_, _, i)| *i);
            if let Some(index) = tab {
                self.close_result_tab(index);
            }
            return false;
        }
        // Mouse moves are the most frequent terminal event and nothing consumes
        // them, so reject them before copying the hit map.
        if !click && scroll.is_none() {
            return false;
        }
        let hits = self.hits.borrow().clone();
        if matches!(self.dialog, Some(Dialog::Quit { .. })) {
            if click
                && let Some((_, key)) = hits.buttons.iter().find(|(rect, _)| rect.contains(point))
            {
                return self.key(KeyEvent::new(*key, KeyModifiers::NONE));
            }
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
            if click && hits.plugin_toggle.contains(point) {
                self.toggle_plugins();
                return false;
            }
            if click
                && let Some((_, focus)) = hits.regions.iter().find(|(rect, _)| rect.contains(point))
            {
                self.focus = *focus;
                return false;
            }
            if click
                && let Some((_, os)) = hits.systems.iter().find(|(rect, _)| rect.contains(point))
            {
                if self.shown_os() != *os {
                    self.select_os(*os);
                }
                return false;
            }
            if click
                && let Some((_, page)) = hits.tabs.iter().find(|(rect, _)| rect.contains(point))
            {
                self.switch_page(*page);
                return false;
            }
            if click
                && let Some((_, index)) = hits
                    .result_tab_steps
                    .iter()
                    .find(|(r, _)| r.contains(point))
            {
                self.tab_offset.set(*index);
                return false;
            }
            if click
                && let Some((_, close, index)) =
                    hits.result_tabs.iter().find(|(r, _, _)| r.contains(point))
            {
                if close.contains(point) {
                    self.close_result_tab(*index);
                } else {
                    self.switch_result_tab(*index);
                }
                return false;
            }
            if self.page == Page::Cache {
                if click
                    && let Some((_, key)) = hits.buttons.iter().find(|(r, _)| r.contains(point))
                {
                    return self.key(KeyEvent::new(*key, KeyModifiers::NONE));
                }
                return self.cache_page_mouse(mouse);
            }
            if click
                && let Some((_, catalog)) =
                    hits.remote_views.iter().find(|(r, _)| r.contains(point))
            {
                self.show_remote_view(*catalog);
                return false;
            }
            if click && hits.header_symbol.contains(point) {
                // Only the analysis header is a focus target; on the resource
                // page these rows are labels that open a picker.
                if self.page == Page::Analysis {
                    self.focus = Focus::Context;
                }
                if self.page == Page::Analysis && !self.symbols.as_os_str().is_empty() {
                    self.view_asset_path(self.symbols.clone(), Kind::Symbols);
                    if let Some(Dialog::AssetDetail { read_only, .. }) = self.dialog.as_mut() {
                        *read_only = true;
                    }
                } else {
                    self.open_files(InputKind::Symbols);
                }
                return false;
            }
            if click && hits.header_image.contains(point) {
                if self.page == Page::Analysis {
                    self.focus = Focus::Context;
                }
                if self.page == Page::Analysis
                    && let Some(image) = self.image.clone()
                {
                    self.view_asset_path(image, Kind::Image);
                    if let Some(Dialog::AssetDetail { read_only, .. }) = self.dialog.as_mut() {
                        *read_only = true;
                    }
                } else {
                    self.open_files(InputKind::Image);
                }
                return false;
            }
            if click && self.page == Page::Assets && hits.console_tab.contains(point) {
                self.open_generation_console();
                return false;
            }
            if click
                && self.page == Page::Assets
                && self.asset_console
                && let Some((_, index)) = hits
                    .console_methods
                    .iter()
                    .find(|(rect, _)| rect.contains(point))
            {
                self.console.selected = *index;
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
                self.focus = Focus::Navigation;
                self.open_input(InputKind::AssetsSearch);
                return false;
            }
            if click && hits.search.contains(point) {
                self.focus = if self.page == Page::Analysis {
                    Focus::Content
                } else {
                    Focus::Navigation
                };
                self.open_input(if self.page == Page::Analysis {
                    InputKind::Search
                } else {
                    InputKind::AssetsSearch
                });
                return false;
            }
            if self.page == Page::Assets {
                if click
                    && let Some((_, section, row)) =
                        hits.asset_rows.iter().find(|(r, _, _)| r.contains(point))
                {
                    let mut select = self.section == *section
                        && self.asset_rows[section.slot()] == *row
                        && *section != AssetSection::Remote;
                    self.section = *section;
                    self.asset_rows[section.slot()] = *row;
                    self.focus = Focus::Navigation;
                    if *section == AssetSection::Images
                        && let Some(asset) = self.selected_asset()
                    {
                        select &= self.image_preview.as_ref() == Some(&asset.path);
                        self.image_preview = Some(asset.path.clone());
                        if !select {
                            self.asset_scroll[0] = 0;
                            if asset.available
                                && !self.asset_identities.contains_key(&asset.path)
                                && self.job.is_none()
                            {
                                self.start_work(Work::PreviewImage(asset.path));
                            }
                        }
                    }
                    if *section == AssetSection::Remote {
                        self.open_asset_detail();
                    } else if select
                        && self
                            .selected_asset()
                            .is_some_and(|a| !self.asset_active(&a))
                    {
                        self.select_asset();
                    }
                    return false;
                }
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
                    return self.key(KeyEvent::new(*key, KeyModifiers::NONE));
                }
                if click
                    && let Some((_, key)) =
                        hits.buttons.iter().find(|(rect, _)| rect.contains(point))
                {
                    return self.key(KeyEvent::new(*key, KeyModifiers::NONE));
                }
                if hits.asset_detail.contains(point) {
                    self.focus = Focus::Content;
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
                    let already_highlighted = self.section == *section
                        && self.focus == Focus::Navigation
                        && *section != AssetSection::Remote;
                    self.section = *section;
                    self.focus = Focus::Navigation;
                    if let Some(key) = scroll {
                        for _ in 0..3 {
                            self.asset_key(KeyEvent::new(key, KeyModifiers::NONE));
                        }
                    } else if click
                        && *section != AssetSection::Images
                        && point.y > rect.y
                        && point.y < rect.bottom().saturating_sub(1)
                    {
                        let index = offset + (point.y - rect.y - 1) as usize;
                        // Clicking the highlighted row again selects it (like Space).
                        if already_highlighted
                            && index == self.asset_rows[section.slot()]
                            && index < self.asset_count()
                            && self
                                .selected_asset()
                                .is_some_and(|asset| !self.asset_active(&asset))
                        {
                            return self
                                .asset_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
                        }
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
            if click
                && let Some((_, plugin)) = hits
                    .dump_modes
                    .iter()
                    .find(|(rect, _)| rect.contains(point))
            {
                if let Some(Dialog::Dump {
                    mode,
                    fields,
                    error,
                    ..
                }) = self.dialog.as_mut()
                {
                    *mode = *plugin;
                    if !matches!(
                        plugin,
                        Plugin::Memdump
                            | Plugin::WinMemdump
                            | Plugin::Procdump
                            | Plugin::WinProcdump
                    ) {
                        fields[1].clear();
                        fields[2].clear();
                    }
                    error.clear();
                }
                return false;
            }
            if !hits.popup.contains(point) {
                return false;
            }
            if click
                && let Some((_, index)) = hits.dump_fields.iter().find(|(r, _)| r.contains(point))
                && let Some(Dialog::WindowsParameters {
                    fields,
                    field,
                    cursor,
                    selected,
                    ..
                }) = self.dialog.as_mut()
            {
                *field = *index;
                *cursor = fields.get(*index).map_or(0, String::len);
                *selected = true;
                return false;
            }
            if click
                && let Some(index) = hits
                    .dump_fields
                    .iter()
                    .find(|(rect, _)| rect.contains(point))
                    .map(|(_, index)| *index)
                && let Some(Dialog::GenerateSymbols {
                    fields,
                    field,
                    cursor,
                    selected,
                    ..
                }) = self.dialog.as_mut()
            {
                *field = index;
                *cursor = fields.get(index).map_or(0, String::len);
                *selected = true;
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
                *cursor = fields.get(index).map_or(0, String::len);
                *selected = true;
                return false;
            }
            if click
                && let Some((_, key)) = hits.buttons.iter().find(|(rect, _)| rect.contains(point))
            {
                if *key == KeyCode::Enter
                    && let Some(Dialog::WindowsParameters { field, .. }) = self.dialog.as_mut()
                {
                    *field = 6;
                }
                if *key == KeyCode::Enter
                    && let Some(Dialog::Dump { field, .. }) = self.dialog.as_mut()
                {
                    *field = 4;
                }
                if *key == KeyCode::Enter
                    && let Some(Dialog::GenerateSymbols { field, .. }) = self.dialog.as_mut()
                {
                    *field = 3;
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
                let list = if matches!(self.dialog, Some(Dialog::Plugins { .. })) {
                    hits.popup_list
                } else {
                    hits.popup
                };
                if !list.contains(point)
                    || point.y <= list.y
                    || point.y >= list.bottom().saturating_sub(1)
                {
                    return false;
                }
                let index = hits.popup_offset + (point.y - list.y - 1) as usize;
                let count = self.result_column_count();
                let plugin_count = match self.dialog.as_ref() {
                    Some(Dialog::Plugins { query, .. }) => self.plugin_matches(query).len(),
                    _ => 0,
                };
                let command_count = match self.dialog.as_ref() {
                    Some(Dialog::Commands { query, .. }) => self.available_commands(query).len(),
                    _ => 0,
                };
                let settings_count = self.settings_labels().len();
                let selected = match self.dialog.as_mut() {
                    Some(Dialog::Files {
                        entries, selected, ..
                    }) if index < entries.len() => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::System { selected }) if index < 2 => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Settings { selected }) if index < settings_count => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Plugins { selected, .. }) if index < plugin_count => {
                        *selected = index;
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
                    let code = if matches!(
                        self.dialog,
                        Some(Dialog::Symbols { .. } | Dialog::Links { .. })
                    ) {
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
            self.focus = Focus::Detail;
            if let Some(key) = scroll {
                self.key(KeyEvent::new(key, KeyModifiers::NONE));
            }
            return false;
        }
        if hits.menu.contains(point) {
            self.focus = Focus::Navigation;
            if let Some(key) = scroll {
                for _ in 0..3 {
                    self.key(KeyEvent::new(key, KeyModifiers::NONE));
                }
            } else if click
                && point.y > hits.menu.y
                && point.y < hits.menu.bottom().saturating_sub(1)
            {
                let index = hits.menu_offset + (point.y - hits.menu.y - 1) as usize;
                if index < self.menu_items().len() {
                    self.menu = index;
                    if index < self.menu_items().len() - 1 {
                        if let Some(plugin) = self.navigation_plugins().get(index).copied() {
                            self.activate_plugin(plugin);
                        }
                    } else {
                        self.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                    }
                }
            }
        } else if hits.result.contains(point) {
            self.focus = Focus::Content;
            if let Some(key) = scroll {
                self.key(KeyEvent::new(key, KeyModifiers::NONE));
                let maximum = self.visible().len().saturating_sub(self.page_rows());
                let offset = self.table_state.borrow().offset();
                *self.table_state.borrow_mut().offset_mut() = if key == KeyCode::Up {
                    offset.saturating_sub(1)
                } else {
                    offset.saturating_add(1).min(maximum)
                };
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
                    if index < self.visible().len()
                        && index < hits.row_offset.saturating_add(self.page_rows())
                    {
                        self.row = index;
                        if self.plugin.is_tree()
                            && self.history.is_none()
                            && hits
                                .columns
                                .get(if self.plugin == Plugin::WinPstree {
                                    2
                                } else {
                                    3
                                })
                                .is_some_and(|rect| rect.x <= point.x && point.x < rect.right())
                        {
                            self.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                        }
                    }
                }
            }
        } else if click && hits.header.contains(point) {
            self.focus = Focus::Context;
        }
        false
    }
}
