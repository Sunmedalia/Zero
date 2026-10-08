use super::*;

impl App {
    pub(super) fn windows_parameters(&mut self) {
        self.dialog = Some(Dialog::WindowsParameters {
            advanced: false,
            fields: [
                self.analysis_options
                    .hive
                    .map(|n| format!("{n:#x}"))
                    .unwrap_or_default(),
                self.analysis_options.key.clone(),
                self.analysis_options
                    .pid
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                serde_json::to_value(self.analysis_options.arch)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .into(),
                self.analysis_options
                    .pagefiles
                    .iter()
                    .map(|f| format!("{}={}", f.index, f.path.display()))
                    .collect::<Vec<_>>()
                    .join("; "),
                self.analysis_options
                    .swapfile
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
            ],
            field: if self.plugin == Plugin::WinPrintkey {
                0
            } else if self.plugin.descriptor().columns.contains(&"PID") {
                2
            } else {
                6
            },
            cursor: 0,
            selected: true,
            error: String::new(),
        });
    }
    pub(super) fn open_asset_detail(&mut self) {
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
    pub(super) fn view_asset_path(&mut self, path: PathBuf, kind: Kind) {
        let asset = self
            .assets
            .iter()
            .find(|asset| same_path(&asset.path, &path))
            .cloned()
            .unwrap_or_else(|| {
                let metadata = std::fs::metadata(&path).ok();
                Asset {
                    path: path.clone(),
                    kind,
                    bytes: metadata.as_ref().map_or(0, |m| m.len()),
                    available: metadata.is_some(),
                    directory: metadata.as_ref().is_some_and(|m| m.is_dir()),
                    stamp: None,
                    origin: "文件浏览",
                }
            });
        self.dialog = Some(Dialog::AssetDetail { asset, scroll: 0 });
        if kind == Kind::Symbols && !self.asset_details.contains_key(&path) && self.job.is_none() {
            self.start_work(Work::InspectSymbols(path));
        }
    }
    pub(super) fn inspect_symbol_path(&mut self, path: PathBuf) {
        self.view_asset_path(path, Kind::Symbols);
    }
    pub(super) fn asset_key(&mut self, key: KeyEvent) -> bool {
        if self.focus == Focus::Content && self.hits.borrow().asset_detail.height == 0 {
            self.focus = Focus::Navigation;
        }
        let slot = self.section.slot();
        if self.focus == Focus::Content
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
            KeyCode::Char('q') => return self.request_quit(),
            KeyCode::Esc => self.cancel(),
            KeyCode::Tab | KeyCode::BackTab => {
                let detail = self.hits.borrow().asset_detail.height > 0;
                let current = if self.focus == Focus::Content {
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
                self.focus = if next == 2 {
                    Focus::Content
                } else {
                    Focus::Navigation
                };
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
            KeyCode::Char('i') => self.open_files(InputKind::Image),
            KeyCode::Char('y') => self.open_files(InputKind::Symbols),
            KeyCode::Char('a') => self.open_files(if self.section == AssetSection::Images {
                InputKind::Image
            } else {
                InputKind::Symbols
            }),
            KeyCode::Enter => self.select_and_enter(),
            KeyCode::Char('w') => {
                if let Some(candidate) = self
                    .remote_list()
                    .get(self.asset_rows[2])
                    .map(|m| (*m).clone())
                {
                    self.start_work(Work::CatalogDownload(candidate));
                }
            }
            KeyCode::Char(' ') if self.section == AssetSection::Remote => {
                if self.image.is_none() {
                    self.status = "请先用 Space 选用镜像；远程 w 可独立下载".into();
                } else if let Some(candidate) = self
                    .remote_list()
                    .get(self.asset_rows[2])
                    .map(|m| (*m).clone())
                {
                    self.start_work(Work::Download(candidate));
                }
            }
            KeyCode::Char(' ') if self.section != AssetSection::Remote => {
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
            KeyCode::Char('K') => self.open_symbol_generation(),
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
                self.enter_workbench();
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
    pub(super) fn open_files(&mut self, kind: InputKind) {
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
    pub(super) fn browse(&mut self, kind: InputKind, root: PathBuf) {
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
    pub(super) fn accept_path(&mut self, kind: InputKind, path: PathBuf) {
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
    pub(super) fn open_input(&mut self, kind: InputKind) {
        if kind == InputKind::Search {
            self.focus = Focus::Content;
        }
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
    pub(super) fn open_dump(&mut self, mode: Plugin, force: bool) {
        let mode = if self.windows {
            match mode {
                Plugin::Procdump => Plugin::WinProcdump,
                Plugin::Memdump => Plugin::WinMemdump,
                Plugin::Elfdump => Plugin::WinPedump,
                _ => mode,
            }
        } else {
            mode
        };

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
    pub(super) fn open_cache(&mut self) {
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
    pub(super) fn paste(&mut self, value: &str) {
        if let Some(Dialog::Files { kind, .. }) = &self.dialog {
            let kind = *kind;
            self.open_input(kind);
        }
        match self.dialog.as_mut() {
            Some(Dialog::WindowsParameters {
                fields,
                field,
                cursor,
                selected,
                ..
            }) if *field < 6 => {
                if *selected {
                    fields[*field].clear();
                    *cursor = 0;
                    *selected = false;
                }
                fields[*field].insert_str(*cursor, value);
                *cursor += value.len();
            }
            Some(Dialog::GenerateSymbols {
                fields,
                field,
                cursor,
                selected,
                ..
            }) if *field < 3 => {
                if *selected {
                    fields[*field].clear();
                    *cursor = 0;
                    *selected = false;
                }
                fields[*field].insert_str(*cursor, value);
                *cursor += value.len();
            }
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
    pub(super) fn help(&mut self) {
        let mut text = "ZERO 取证工作台\n\nF2 资源库 · F3 分析 · F6 自动/Linux/Windows · Ctrl+←/→ 切换页面\nTab / Shift+Tab 切换区域；↑↓ 或 j/k 导航；PgUp/PgDn/Home/End 翻页\n\n镜像与符号：\n资源库 Space 选用；Enter 选用高亮项并进入分析（匹配完成后自动进入）；再次点击高亮行等同 Space；d 查看详情。\n选用镜像后自动识别内核并匹配本地；x 进入分析；点击或 Enter 选择插件即显示已有结果或运行。\nM 使用 GitHub 完整 banner / Windows PDB 精确查询、下载并选用；多候选手动选择。独立下载 w 只保存文件。\n".to_owned();
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
        text.push_str("\n远程详情：w 下载到 symbols · L 在本地库定位 · c 取消下载 · Esc 返回\n\n分析：i 镜像 · y 符号 · p 插件（按名称、中文说明或类别搜索） · P 适用参数 · Ctrl+R 运行 · D Dump\n/ 搜索 · s 排序 · e 导出 · d 详情 · n 行数 · [/] 翻页\nr 重跑 · F5 运行 · v/F8 诊断 · Alt+←/→ 横向滚动\n资源库 K / 分析页 g 生成当前镜像符号表\n\nCtrl+P / ? 命令面板（空格分隔多个词，不区分大小写） · , 目录设置 · c 缓存 · l 日志 · h 历史\nEsc 关闭弹窗；分析页先清除筛选，再取消任务 · q 退出（任务中需按两次）· Ctrl+C 立即退出\n文件弹窗：Space 选用 · Enter 打开目录／进入分析控制台，d 详情 · Shift+Space 选用符号目录 · ← 上级 · Tab 切换目录 · p 输入路径\nDump：F2/F3/F4 切换模式 · Tab 字段 · Ctrl+Enter 运行\n");
        self.dialog = Some(Dialog::Detail { text, scroll: 0 });
    }
    pub(super) fn diagnostics(&mut self) {
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
    pub(super) fn key(&mut self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        if key.code != KeyCode::Char('q') {
            self.quit_armed = false;
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
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
            self.request_analysis(false);
            return false;
        }
        if self.page == Page::Assets
            && !matches!(
                key.code,
                KeyCode::F(1..=3) | KeyCode::F(6) | KeyCode::Char(',' | 'h' | 'l' | '?' | 'c')
            )
            && !key.modifiers.contains(KeyModifiers::CONTROL)
        {
            return self.asset_key(key);
        }
        match key.code {
            KeyCode::F(6) => {
                self.dialog = Some(Dialog::System {
                    selected: match self.analysis_options.os {
                        crate::analysis::Os::Auto => 0,
                        crate::analysis::Os::Linux => 1,
                        crate::analysis::Os::Windows => 2,
                    },
                });
                return false;
            }
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
        if let KeyCode::F(n @ 2..=3) = key.code {
            self.switch_page(Page::ALL[n as usize - 2]);
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
        if self.focus == Focus::Detail
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
            KeyCode::Char('g' | 'K') => self.open_symbol_generation(),
            KeyCode::Char('q') => return self.request_quit(),
            KeyCode::Esc if self.inspector => {
                self.inspector = false;
                if self.focus == Focus::Detail {
                    self.focus = Focus::Content;
                }
            }
            KeyCode::Esc if self.job.is_none() && !self.query.is_empty() => {
                self.query.clear();
                self.row = 0;
                self.status = "已清除内容筛选".into();
            }
            KeyCode::Esc => self.cancel(),
            KeyCode::Tab => {
                self.focus = self
                    .focus
                    .next(false, self.hits.borrow().inspector.width > 0)
            }
            KeyCode::BackTab => {
                let n = if self.hits.borrow().inspector.width > 0 {
                    4
                } else {
                    3
                };
                self.focus = self.focus.next(true, n == 4);
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
            KeyCode::Char('[') => self.move_result_page(false),
            KeyCode::Char(']') => self.move_result_page(true),
            KeyCode::Char('r') => self.request_analysis(true),
            KeyCode::F(5) => self.request_analysis(false),
            KeyCode::Char('p') => {
                self.dialog = Some(Dialog::Plugins {
                    query: String::new(),
                    selected: 0,
                })
            }
            KeyCode::Char('P') => self.windows_parameters(),
            KeyCode::Char('b') => self.start_work(Work::Identify),
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
                if self.focus == Focus::Navigation {
                    self.menu = self.menu.saturating_sub(1);
                } else if self.focus == Focus::Content {
                    self.row = self.row.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.focus == Focus::Navigation {
                    self.menu = (self.menu + 1).min(self.menu_items().len() - 1);
                } else if self.focus == Focus::Content {
                    self.row = (self.row + 1).min(self.visible().len().saturating_sub(1));
                }
            }
            KeyCode::PageUp => {
                if self.focus == Focus::Navigation {
                    self.menu = self.menu.saturating_sub(10);
                } else {
                    self.move_result_page(false);
                }
            }
            KeyCode::PageDown => {
                if self.focus == Focus::Navigation {
                    self.menu = (self.menu + 10).min(self.menu_items().len() - 1);
                } else {
                    self.move_result_page(true);
                }
            }
            KeyCode::Home => {
                if self.focus == Focus::Navigation {
                    self.menu = 0;
                } else {
                    self.row = 0;
                }
            }
            KeyCode::End => {
                if self.focus == Focus::Navigation {
                    self.menu = self.menu_items().len() - 1;
                } else {
                    self.row = self.visible().len().saturating_sub(1);
                }
            }
            KeyCode::Left | KeyCode::Right
                if self.focus == Focus::Content && self.plugin.is_tree() =>
            {
                if let Some(row) = self.visible().get(self.row) {
                    if key.code == KeyCode::Left {
                        self.collapsed.insert(row[0].clone());
                    } else {
                        self.collapsed.remove(&row[0]);
                    }
                }
            }
            KeyCode::Enter => {
                if self.focus == Focus::Detail {
                    self.open_detail();
                } else if self.focus == Focus::Context {
                    self.open_files(InputKind::Image);
                } else if self.focus == Focus::Navigation {
                    match self.menu {
                        index if index == self.menu_items().len() - 1 => {
                            self.open_dump(Plugin::Procdump, false)
                        }
                        index => {
                            let plugin = self.navigation_plugins()[index];
                            self.activate_plugin(plugin);
                        }
                    }
                } else if self.plugin.is_tree()
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
    pub(super) fn open_detail(&mut self) {
        if self.result().is_some() {
            self.dialog = Some(Dialog::Detail {
                text: self.detail_text(),
                scroll: 0,
            });
        }
    }
    pub(super) fn mouse(&mut self, mouse: MouseEvent) -> bool {
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
                && let Some((_, focus)) = hits.regions.iter().find(|(rect, _)| rect.contains(point))
            {
                self.focus = *focus;
                return false;
            }
            if click
                && let Some((_, os)) = hits.systems.iter().find(|(rect, _)| rect.contains(point))
            {
                if self.analysis_options.os != *os
                    || (*os == crate::analysis::Os::Auto && self.image.is_some())
                {
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
            if click && hits.header.contains(point) {
                self.focus = Focus::Context;
                if point.y == hits.header.y {
                    self.open_files(InputKind::Image);
                } else if point.y == hits.header.y + 1 {
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
                    } else if click && point.y > rect.y && point.y < rect.bottom().saturating_sub(1)
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
            if !hits.popup.contains(point) {
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
                *cursor = fields[index].len();
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
                let index = hits.popup_offset + (point.y - hits.popup.y - 1) as usize;
                let count = self.result_column_count();
                let plugin_count = match self.dialog.as_ref() {
                    Some(Dialog::Plugins { query, .. }) => self.plugin_matches(query).len(),
                    _ => 0,
                };
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
                    Some(Dialog::System { selected }) if index < 3 => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Settings { selected }) if index < 5 => {
                        *selected = index;
                        true
                    }
                    Some(Dialog::Plugins { selected, .. }) if index < plugin_count => {
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
                    let code = if matches!(
                        self.dialog,
                        Some(Dialog::Cache { .. } | Dialog::Symbols { .. } | Dialog::Links { .. })
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
                        self.activate_plugin(self.navigation_plugins()[index]);
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
            if point.y == hits.header.y + 2 {
                self.open_files(InputKind::Symbols);
            } else if point.y == hits.header.y + 1 {
                self.open_files(InputKind::Image);
            }
        }
        false
    }
    pub(super) fn dialog_key(&mut self, key: KeyEvent) {
        let Some(dialog) = self.dialog.take() else {
            return;
        };
        if key.code == KeyCode::Esc {
            if matches!(dialog, Dialog::Symbols { .. }) {
                self.symbol_retry = None;
                self.enter_when_ready = false;
            }
            self.pending_work = None;
            if matches!(
                dialog,
                Dialog::Detail { .. } | Dialog::RemoteDetail { .. } | Dialog::AssetDetail { .. }
            ) && let Some(back) = self.back_dialog.take()
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
        match dialog {
            Dialog::System { .. } => self.system_key(dialog, key),
            Dialog::GenerateSymbols { .. } => self.generation_key(dialog, key),
            Dialog::WindowsParameters { .. } => self.windows_parameters_key(dialog, key),
            Dialog::Dump { .. } => self.dump_key(dialog, key),
            Dialog::Files { .. } => self.files_key(dialog, key),
            Dialog::Settings { .. } => self.settings_key(dialog, key),
            Dialog::Cache { .. } => self.cache_key(dialog, key),
            Dialog::Commands { .. } => self.commands_key(dialog, key),
            Dialog::Plugins { .. } => self.plugins_key(dialog, key),
            Dialog::Links { .. } => self.links_key(dialog, key),
            Dialog::AssetDetail { .. } => self.asset_detail_key(dialog, key),
            Dialog::RemoteDetail { .. } => self.remote_detail_key(dialog, key),
            Dialog::Detail { .. } => self.detail_key(dialog, key),
            Dialog::Input { .. } => self.input_key(dialog, key),
            Dialog::Sort { .. } => self.sort_key(dialog, key),
            Dialog::Symbols { .. } => self.symbols_key(dialog, key),
        }
    }
}
