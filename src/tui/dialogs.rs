//! Every modal. `draw_dialog` picks the popup geometry, then dispatches to the
//! per-dialog renderer below.
use super::*;

impl App {
    /// Columns a dialog needs for its own content.
    ///
    /// Every modal used to be as wide as the screen minus six columns, so the
    /// three-word system picker spanned the terminal and its highlight bar
    /// stretched the full width. Width now follows the widest line the dialog
    /// draws, up to a readable maximum.
    fn dialog_width(&self, dialog: &Dialog, screen: Rect) -> u16 {
        /// Frame borders plus a one-cell margin on each side.
        const CHROME: usize = 4;
        const MAX: u16 = 90;
        let longest = match dialog {
            Dialog::System { .. } => 12,
            Dialog::Sort { .. } => self.result().map_or(0, |r| {
                r.columns
                    .iter()
                    .map(|c| c.chars().count())
                    .max()
                    .unwrap_or(0)
            }),
            Dialog::Symbols { labels, .. } => {
                labels.iter().map(|l| l.chars().count()).max().unwrap_or(0)
            }
            Dialog::Links { matches, .. } => matches
                .iter()
                .map(|m| m.path.chars().count())
                .max()
                .unwrap_or(0),
            Dialog::Commands { .. } => self
                .available_commands("")
                .iter()
                .map(|(l, _)| l.chars().count())
                .max()
                .unwrap_or(0),
            Dialog::Plugins { .. } => self
                .plugin_matches("")
                .iter()
                .map(|p| plugin_label(*p).chars().count())
                .max()
                .unwrap_or(0),
            Dialog::Settings { .. } => self
                .settings_labels()
                .iter()
                .map(|l| l.chars().count())
                .max()
                .unwrap_or(0),
            // Text dialogs hold a path or a query, which can be long and which
            // the user is editing: they get the room to show it.
            Dialog::Input { text, .. } => text.chars().count().max(40),
            // Detail text is wrapped prose; it wants width more than anything.
            Dialog::Detail { .. } => screen.width.saturating_sub(6).min(90) as usize,
            _ => 0,
        };
        // A rough cell estimate: CJK and wide glyphs take two columns.
        let estimate = longest * 3 / 2 + CHROME + 20;
        let max = screen.width.saturating_sub(6).min(MAX);
        (estimate as u16).clamp(30, max.max(30)).min(max)
    }
    /// Rows a dialog needs for its own content, including the frame and one
    /// hint row.
    ///
    /// These used to be a flat `_ => 12`, so a three-option system picker and
    /// an eight-column sort picker both claimed twelve rows and a 60x18
    /// terminal lost two thirds of its screen to a two-line list.
    fn dialog_height(&self, dialog: &Dialog, screen: Rect) -> u16 {
        /// Frame borders plus a title row.
        const CHROME: u16 = 2;
        let rows = match dialog {
            Dialog::System { .. } => 3,
            Dialog::Sort { .. } => self.result().map_or(4, |r| r.columns.len()) as u16,
            Dialog::Symbols { labels, .. } => labels.len() as u16,
            Dialog::Links { matches, .. } => matches.len() as u16,
            Dialog::Commands { .. } => self.available_commands("").len() as u16,
            Dialog::Plugins { .. } => self.plugin_matches("").len() as u16,
            Dialog::Settings { .. } => self.settings_labels().len() as u16,
            Dialog::Input { .. } => 4,
            Dialog::Detail { .. } => 12,
            Dialog::Dump { .. } => 12,
            Dialog::WindowsParameters { .. } => 18,
            Dialog::GenerateSymbols { .. } => 15,
            _ => 10,
        };
        // Cap at three quarters of the screen so the page behind the modal
        // stays visible enough to keep the user oriented.
        let cap = (screen.height * 3 / 4).max(8);
        (rows + CHROME).clamp(4, cap)
    }
    pub(super) fn draw_dialog(&self, frame: &mut Frame, area: Rect) {
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
            let popup = if (matches!(dialog, Dialog::Dump { .. })
                || (matches!(dialog, Dialog::Detail { .. }) && frame.area().width < 140))
                && self.hits.borrow().workbench.width > 0
            {
                self.hits.borrow().workbench
            } else {
                centered(
                    area,
                    self.dialog_width(dialog, area),
                    self.dialog_height(dialog, area),
                )
            };
            self.hits.borrow_mut().popup = popup;
            self.hits.borrow_mut().buttons.clear();
            frame.render_widget(Clear, popup);
            match dialog {
                Dialog::GenerateSymbols { .. } => self.draw_generation(frame, popup, dialog),
                Dialog::System { selected } => {
                    let mut state = ListState::default().with_selected(Some(*selected));
                    frame.render_stateful_widget(
                        List::new(["自动识别镜像系统", "Linux", "Windows"])
                            .block(panel().title("分析系统 · Enter 选择 · Esc 取消"))
                            .highlight_symbol("› ")
                            .highlight_style(
                                Style::default()
                                    .bg(SELECTED_BG)
                                    .fg(FOCUS)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
                Dialog::WindowsParameters {
                    advanced,
                    fields,
                    field,
                    error,
                    ..
                } => {
                    let labels = [
                        "Hive 地址",
                        "键路径（空为根）",
                        "PID 筛选（可选）",
                        "架构 auto / x86 / x64 / arm64",
                        "pagefile（索引=路径；分号分隔）",
                        "swapfile（可选路径）",
                    ];
                    let mut lines = vec![Line::raw(if self.windows {
                        "F7 展开／收起 Windows 高级配置"
                    } else {
                        "参数按插件保存草稿"
                    })];
                    for index in self.parameter_fields(*advanced) {
                        if index == 6 {
                            continue;
                        }
                        lines.push(Line::styled(
                            format!(
                                "{} {}",
                                if *field == index { "›" } else { " " },
                                labels[index]
                            ),
                            Style::default().fg(ACCENT),
                        ));
                        lines.push(Line::raw(escaped(&fields[index])));
                    }
                    lines.push(Line::raw(format!(
                        "{} 保存参数 · Tab 字段 · Ctrl+Enter 保存",
                        if *field == 6 { "›" } else { " " }
                    )));
                    lines.push(Line::raw(error.clone()));
                    frame.render_widget(
                        Paragraph::new(lines).block(panel().title("适用参数 · 保存后 Ctrl+R 运行")),
                        popup,
                    );
                }
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
                        panel()
                            .border_style(Style::default().fg(ACCENT))
                            .title("DUMP · Tab 字段 · Ctrl+Enter 运行 · Esc 取消"),
                        popup,
                    );
                    let hint = match mode {
                        Plugin::Memdump | Plugin::WinMemdump => {
                            "指定 PID、Start 和 End；读取该进程的用户虚拟地址范围"
                        }
                        Plugin::WinPedump => "指定 PID；按 PE 节表重建可读 PE",
                        Plugin::Elfdump => "指定 PID；导出含 ELF 头的可读映射（不重建磁盘 ELF）",
                        _ => "指定 PID；导出可读 VMA；Start / End 可限制范围",
                    };
                    frame.render_widget(
                        Paragraph::new(hint).style(Style::default().fg(MUTED)),
                        Rect::new(popup.x + 2, popup.y + 1, popup.width.saturating_sub(4), 1),
                    );
                    let mut x = popup.x + 2;
                    for (label, plugin, n) in [
                        (
                            "F2 Process",
                            if self.windows {
                                Plugin::WinProcdump
                            } else {
                                Plugin::Procdump
                            },
                            2,
                        ),
                        (
                            "F3 Range",
                            if self.windows {
                                Plugin::WinMemdump
                            } else {
                                Plugin::Memdump
                            },
                            3,
                        ),
                        (
                            if self.windows { "F4 PE" } else { "F4 ELF" },
                            if self.windows {
                                Plugin::WinPedump
                            } else {
                                Plugin::Elfdump
                            },
                            4,
                        ),
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
                        "{} · Space 选用 · Enter 打开／进入控制台 · d 详情 · ← 上级 · p 路径",
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
                            .block(panel().title(title).title_bottom(format!(
                                "目录: {}",
                                escaped(&self.display_path(root))
                            )))
                            .highlight_symbol("› ")
                            .highlight_style(
                                Style::default()
                                    .bg(SELECTED_BG)
                                    .fg(FOCUS)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                    if matches!(kind, InputKind::Image | InputKind::Symbols) && popup.width >= 28 {
                        let button =
                            Rect::new(popup.x + 1, popup.bottom().saturating_sub(1), 18, 1);
                        frame.render_widget(
                            Paragraph::new("[选用 Space]").style(Style::default().fg(FOCUS)),
                            button,
                        );
                        self.hits
                            .borrow_mut()
                            .buttons
                            .push((button, KeyCode::Char(' ')));
                    }
                    let _ = kind;
                }
                Dialog::Settings { selected } => {
                    let mut state = ListState::default().with_selected(Some(*selected));
                    frame.render_stateful_widget(
                        List::new(self.settings_labels())
                            .block(panel().title("目录与分页设置 · Enter 修改 · Esc 关闭"))
                            .highlight_style(
                                Style::default()
                                    .bg(SELECTED_BG)
                                    .fg(FOCUS)
                                    .add_modifier(Modifier::BOLD),
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
                            .block(panel().title("缓存管理 · Space 勾选 · Enter 预览／清理"))
                            .highlight_symbol("› ")
                            .highlight_style(
                                Style::default()
                                    .bg(SELECTED_BG)
                                    .fg(FOCUS)
                                    .add_modifier(Modifier::BOLD),
                            ),
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
                        .block(panel().title(if query.is_empty() {
                            "命令 · 输入以筛选 · Enter 执行".to_string()
                        } else {
                            format!("命令 · {} · Enter 执行", escaped(query))
                        }))
                        .highlight_symbol("› ")
                        .highlight_style(
                            Style::default()
                                .bg(SELECTED_BG)
                                .fg(FOCUS)
                                .add_modifier(Modifier::BOLD),
                        ),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
                Dialog::Plugins { query, selected } => {
                    let plugins = self.plugin_matches(query);
                    let mut state = ListState::default()
                        .with_selected((!plugins.is_empty()).then_some(*selected));
                    frame.render_stateful_widget(
                        List::new(plugins.iter().map(|p| plugin_label(*p)))
                            .block(
                                panel().title(format!("插件搜索: {} · Enter 选择", escaped(query))),
                            )
                            .highlight_style(
                                Style::default()
                                    .bg(SELECTED_BG)
                                    .fg(FOCUS)
                                    .add_modifier(Modifier::BOLD),
                            )
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
                                panel().title(
                                    "匹配符号 · Space 下载并选用 · Enter 进入控制台 · d 详情",
                                ),
                            )
                            .highlight_style(
                                Style::default()
                                    .bg(SELECTED_BG)
                                    .fg(FOCUS)
                                    .add_modifier(Modifier::BOLD),
                            )
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
                        .block(panel().title(
                            if asset.kind == Kind::Symbols {
                                "符号表分析 · ↑↓ / PgUp PgDn · Esc 返回"
                            } else {
                                "镜像详情 · ↑↓ / PgUp PgDn · Esc 返回"
                            },
                        )),
                        popup,
                    );
                    if popup.width >= 28 {
                        let button =
                            Rect::new(popup.x + 1, popup.bottom().saturating_sub(1), 18, 1);
                        frame.render_widget(
                            Paragraph::new("[选用 Space]").style(Style::default().fg(FOCUS)),
                            button,
                        );
                        self.hits
                            .borrow_mut()
                            .buttons
                            .push((button, KeyCode::Char(' ')));
                    }
                }
                Dialog::RemoteDetail { candidate, scroll } => {
                    frame.render_widget(
                        panel()
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
                                MUTED
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
                        .block(panel().title("详情 · ↑↓ / PgUp PgDn · Esc 关闭")),
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
                            panel()
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
                            .block(panel().title("排序列 · 再选同列反转 · Esc 取消"))
                            .highlight_style(
                                Style::default()
                                    .bg(SELECTED_BG)
                                    .fg(FOCUS)
                                    .add_modifier(Modifier::BOLD),
                            )
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
                            panel().title(
                                "多个完整 banner 匹配 · Space 选用 · Enter 进入控制台 · d 详情",
                            ),
                        )
                        .highlight_style(
                            Style::default()
                                .bg(SELECTED_BG)
                                .fg(FOCUS)
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol("› "),
                        popup,
                        &mut state,
                    );
                    self.hits.borrow_mut().popup_offset = state.offset();
                }
            }
            if !matches!(
                dialog,
                Dialog::Input { .. } | Dialog::Dump { .. } | Dialog::GenerateSymbols { .. }
            ) {
                let cancel = Rect::new(
                    popup.right().saturating_sub(8).max(popup.x),
                    popup.bottom().saturating_sub(1),
                    8.min(popup.width),
                    1,
                );
                frame.render_widget(
                    Paragraph::new("[取消]").style(Style::default().fg(MUTED)),
                    cancel,
                );
                self.hits.borrow_mut().buttons.push((cancel, KeyCode::Esc));
            }
            Self::frame_popup(frame, popup);
        }
    }
}
