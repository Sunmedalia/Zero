use super::*;

impl App {
    pub(super) fn system_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::System { selected } = &mut dialog else {
                return;
            };
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => *selected = selected.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *selected = (*selected + 1).min(2),
                KeyCode::Enter => {
                    self.select_os(
                        [
                            crate::analysis::Os::Auto,
                            crate::analysis::Os::Linux,
                            crate::analysis::Os::Windows,
                        ][*selected],
                    );
                    return;
                }
                _ => {}
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn windows_parameters_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::WindowsParameters {
                advanced,
                fields,
                field,
                cursor,
                selected,
                error,
            } = &mut dialog
            else {
                return;
            };
            if key.code == KeyCode::F(7) && self.windows {
                *advanced = !*advanced;
                if !*advanced && *field >= 3 {
                    *field = 6;
                }
            } else if key.code == KeyCode::Enter
                && (*field == 6 || key.modifiers.contains(KeyModifiers::CONTROL))
            {
                let parsed = (|| -> Result<crate::analysis::Options> {
                    let hive = if self.plugin != Plugin::WinPrintkey || fields[0].trim().is_empty()
                    {
                        None
                    } else {
                        Some(parse_address(fields[0].trim()).map_err(anyhow::Error::msg)?)
                    };
                    let pid = if !self.plugin.descriptor().columns.contains(&"PID")
                        || fields[2].trim().is_empty()
                    {
                        None
                    } else {
                        Some(fields[2].trim().parse::<u32>().context("PID 无效")?)
                    };
                    anyhow::ensure!(
                        self.plugin != Plugin::WinPrintkey || hive.is_some(),
                        "printkey 必须填写 hive 地址"
                    );
                    Ok(crate::analysis::Options {
                        arch: <crate::windows::Architecture as clap::ValueEnum>::from_str(
                            fields[3].trim(),
                            true,
                        )
                        .map_err(anyhow::Error::msg)?,
                        os: self.analysis_options.os,
                        pid,
                        hive,
                        key: if self.plugin == Plugin::WinPrintkey {
                            fields[1].clone()
                        } else {
                            String::new()
                        },
                        pagefiles: fields[4]
                            .split([';', '\n'])
                            .filter(|s| !s.trim().is_empty())
                            .map(|s| {
                                crate::windows::paging::parse_attachment(s.trim())
                                    .map_err(anyhow::Error::msg)
                            })
                            .collect::<Result<Vec<_>>>()?,
                        swapfile: if fields[5].trim().is_empty() {
                            None
                        } else {
                            Some(fields[5].trim().into())
                        },
                    })
                })();
                match parsed {
                    Ok(options) => {
                        self.save_view();
                        self.analysis_options = options;
                        self.restore_view();
                        self.status = "参数已保存；Ctrl+R 明确运行".into();
                        return;
                    }
                    Err(e) => *error = e.to_string(),
                }
            } else if matches!(
                key.code,
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down | KeyCode::Enter
            ) {
                let visible = self.parameter_fields(*advanced);
                let index = visible.iter().position(|f| f == field).unwrap_or(0);
                *field = visible[(index
                    + if matches!(key.code, KeyCode::BackTab | KeyCode::Up) {
                        visible.len() - 1
                    } else {
                        1
                    })
                    % visible.len()];
                *cursor = if *field < 6 { fields[*field].len() } else { 0 };
                *selected = true;
            } else if *field < 6 {
                edit_input(&mut fields[*field], cursor, selected, key);
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn dump_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Dump {
                mode,
                fields,
                field,
                cursor,
                selected,
                force,
                error,
            } = &mut dialog
            else {
                return;
            };
            if let KeyCode::F(n @ 2..=4) = key.code {
                *mode = if self.windows {
                    [Plugin::WinProcdump, Plugin::WinMemdump, Plugin::WinPedump]
                } else {
                    [Plugin::Procdump, Plugin::Memdump, Plugin::Elfdump]
                }[n as usize - 2];
                if matches!(*mode, Plugin::Elfdump | Plugin::WinPedump) {
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
                        self.menu = self.menu_items().len() - 1;
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
        self.dialog = Some(dialog);
    }
    pub(super) fn files_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Files {
                kind,
                root,
                entries,
                selected,
            } = &mut dialog
            else {
                return;
            };
            match key.code {
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
                    if *kind == InputKind::Symbols
                        && key.modifiers.contains(KeyModifiers::SHIFT) =>
                {
                    self.accept_path(*kind, root.clone());
                    return;
                }
                KeyCode::Char(' ') if matches!(kind, InputKind::Image | InputKind::Symbols) => {
                    if let Some(entry) = entries.get(*selected) {
                        if !entry.directory || *kind == InputKind::Symbols {
                            self.accept_path(*kind, entry.path.clone());
                            return;
                        }
                        self.status = "镜像目录用 Enter 打开；Space 选用镜像文件".into();
                    }
                }
                KeyCode::Char(' ')
                    if matches!(
                        kind,
                        InputKind::ImageDirectory
                            | InputKind::SymbolsDirectory
                            | InputKind::ExportDirectory
                    ) =>
                {
                    self.accept_path(*kind, root.clone());
                    return;
                }
                KeyCode::Char('d') if matches!(kind, InputKind::Image | InputKind::Symbols) => {
                    if let Some(entry) = entries.get(*selected) {
                        let path = entry.path.clone();
                        let asset_kind = if *kind == InputKind::Symbols
                            || crate::browser::file_kind(&path) == crate::browser::FileKind::Symbols
                        {
                            Kind::Symbols
                        } else {
                            Kind::Image
                        };
                        self.back_dialog = Some(Box::new(dialog.clone()));
                        self.view_asset_path(path, asset_kind);
                        return;
                    }
                }
                KeyCode::Enter | KeyCode::Right => {
                    if let Some(entry) = entries.get(*selected) {
                        let path = entry.path.clone();
                        if entry.directory {
                            self.browse(*kind, path);
                        } else if matches!(kind, InputKind::Image | InputKind::Symbols) {
                            if !self.enter_workbench() {
                                self.dialog = Some(dialog);
                            }
                        } else {
                            self.accept_path(*kind, path);
                        }
                        return;
                    }
                }
                _ => {}
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn settings_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Settings { selected } = &mut dialog else {
                return;
            };
            match key.code {
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
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn cache_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Cache {
                entries,
                scopes,
                selected,
                confirm,
            } = &mut dialog
            else {
                return;
            };
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
        self.dialog = Some(dialog);
    }
    pub(super) fn commands_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Commands { query, selected } = &mut dialog else {
                return;
            };
            match key.code {
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
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn plugins_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Plugins { query, selected } = &mut dialog else {
                return;
            };
            let count = self.plugin_matches(query).len();
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
                    if let Some(plugin) = self.plugin_matches(query).get(*selected) {
                        if plugin.is_dump() {
                            self.open_dump(*plugin, false);
                        } else {
                            self.activate_plugin(*plugin);
                        }
                    }
                    return;
                }
                _ => {}
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn links_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Links { matches, selected } = &mut dialog else {
                return;
            };
            match key.code {
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => *selected = (*selected + 1).min(matches.len().saturating_sub(1)),
                KeyCode::Char(' ') => {
                    if let Some(candidate) = matches.get(*selected) {
                        self.start_work(Work::Download(candidate.clone()));
                    }
                    return;
                }
                KeyCode::Enter => {
                    if !self.enter_workbench() {
                        self.dialog = Some(dialog);
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
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn asset_detail_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::AssetDetail { asset, scroll } = &mut dialog else {
                return;
            };
            let popup = self.hits.borrow().popup;
            let maximum =
                detail_lines(&self.local_asset_text(asset), popup.width.saturating_sub(2))
                    .len()
                    .saturating_sub(popup.height.saturating_sub(2) as usize);
            match key.code {
                KeyCode::Enter => {
                    if !self.enter_workbench() {
                        self.dialog = Some(dialog);
                    }
                    return;
                }
                KeyCode::Char(' ') => {
                    if let Some(back) = self.back_dialog.take()
                        && matches!(*back, Dialog::Symbols { .. })
                    {
                        self.dialog = Some(*back);
                        self.dialog_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
                    } else {
                        let kind = if asset.kind == Kind::Image {
                            InputKind::Image
                        } else {
                            InputKind::Symbols
                        };
                        self.accept_path(kind, asset.path.clone());
                    }
                    return;
                }
                KeyCode::Up => *scroll = scroll.saturating_sub(1),
                KeyCode::Down => *scroll = scroll.saturating_add(1).min(maximum),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                KeyCode::PageDown => *scroll = scroll.saturating_add(10).min(maximum),
                KeyCode::Home => *scroll = 0,
                KeyCode::End => *scroll = maximum,
                _ => {}
            }
        }
        self.dialog = Some(dialog);
    }
    pub(super) fn remote_detail_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::RemoteDetail { candidate, scroll } = &mut dialog else {
                return;
            };
            let popup = self.hits.borrow().popup;
            let maximum = detail_lines(
                &self.remote_detail_text(candidate),
                popup.width.saturating_sub(2),
            )
            .len()
            .saturating_sub(popup.height.saturating_sub(5) as usize);
            match key.code {
                KeyCode::Enter => {
                    if !self.enter_workbench() {
                        self.dialog = Some(dialog);
                    }
                    return;
                }
                KeyCode::Char(' ') if self.image.is_some() => {
                    self.back_dialog = None;
                    self.start_work(Work::Download(candidate.clone()));
                    return;
                }
                KeyCode::Char(' ') => self.status = "请先用 Space 选用镜像；w 可独立下载".into(),
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
        self.dialog = Some(dialog);
    }
    pub(super) fn detail_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Detail { text, scroll } = &mut dialog else {
                return;
            };
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
        self.dialog = Some(dialog);
    }
    pub(super) fn input_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Input {
                kind,
                text,
                cursor,
                selected,
                ..
            } = &mut dialog
            else {
                return;
            };
            if key.code == KeyCode::Enter {
                let value = text.trim().to_string();
                if value.is_empty() && !matches!(kind, InputKind::Search | InputKind::AssetsSearch)
                {
                    self.status = "路径不能为空".into();
                    self.dialog = Some(dialog);
                    return;
                }
                let path = store::expand_home(&value);
                match kind {
                    InputKind::Image | InputKind::Symbols => {
                        if self.job.is_some() {
                            self.cancel();
                            self.pending_path = Some((*kind, path));
                            self.status = "正在取消；随后选用新对象并重新准备".into();
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
                        self.pending_work = None;
                        self.pending_execution = None;
                        self.page = Page::Assets;
                        self.symbol_source = AssetSection::Symbols;
                        if self.image.is_some() {
                            self.prepare_selected_image();
                        }
                    }
                    InputKind::PageSize => {
                        match value
                            .parse::<usize>()
                            .ok()
                            .filter(|n| *n <= 10000)
                            .or_else(|| {
                                (value.eq_ignore_ascii_case("auto") || value == "自动").then_some(0)
                            }) {
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
                            && self.job.is_none()
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
                                self.focus = Focus::Content;
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
        self.dialog = Some(dialog);
    }
    pub(super) fn sort_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Sort { column } = &mut dialog else {
                return;
            };
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
        self.dialog = Some(dialog);
    }
    pub(super) fn symbols_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        {
            let Dialog::Symbols { labels, selected } = &mut dialog else {
                return;
            };
            match key.code {
                KeyCode::Up => *selected = selected.saturating_sub(1),
                KeyCode::Down => *selected = (*selected + 1).min(labels.len().saturating_sub(1)),
                KeyCode::Char(' ') if !labels.is_empty() => {
                    if self.choice.as_ref() != Some(&labels[*selected]) {
                        self.results.retain(|key, _| key == "banners");
                        self.result_requests.clear();
                        self.views.clear();
                        self.history = None;
                        self.query.clear();
                        self.sort = None;
                        self.row = 0;
                        self.horizontal = 0;
                        self.collapsed.clear();
                    }
                    self.object_version += 1;
                    self.choice = Some(labels[*selected].clone());
                    if let Some(request) = self.symbol_retry.take() {
                        self.start_snapshot(request);
                    } else if let Some((path, _)) = self
                        .preparation_candidates
                        .iter()
                        .find(|(_, label)| label == &labels[*selected])
                    {
                        self.symbols = path.clone();
                        self.preparation = Preparation::Ready;
                        self.status = "可开始分析，运行时验证页表".into();
                    } else {
                        self.start();
                    }
                    return;
                }
                KeyCode::Enter => {
                    if !self.enter_workbench() {
                        self.dialog = Some(dialog);
                    }
                    return;
                }
                KeyCode::Char('d') if !labels.is_empty() => {
                    let path = self
                        .preparation_candidates
                        .iter()
                        .find(|(_, label)| label == &labels[*selected])
                        .map(|(path, _)| path.clone())
                        .unwrap_or_else(|| self.symbols.clone());
                    self.back_dialog = Some(Box::new(dialog.clone()));
                    self.inspect_symbol_path(path);
                    return;
                }
                _ => {}
            }
        }
        self.dialog = Some(dialog);
    }
}
