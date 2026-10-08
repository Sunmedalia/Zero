use super::*;

impl App {
    pub(super) fn draw_system_buttons(&self, frame: &mut Frame, area: Rect) {
        let mut x = area.x;
        if area.width >= 29 {
            frame.render_widget(
                Paragraph::new(" 系统: ").style(Style::default().fg(MUTED)),
                Rect::new(x, area.y, 7, area.height),
            );
            x += 7;
        }
        for (label, os) in [
            (" Linux ", crate::analysis::Os::Linux),
            (" Windows ", crate::analysis::Os::Windows),
            (" 自动 ", crate::analysis::Os::Auto),
        ] {
            let width = Span::raw(label).width() as u16;
            if width > area.right().saturating_sub(x) {
                continue;
            }
            let rect = Rect::new(x, area.y, width, area.height);
            let active = self.analysis_options.os == os;
            frame.render_widget(
                Paragraph::new(label).style(if active {
                    Style::default()
                        .bg(SELECTED_BG)
                        .fg(FOCUS)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().bg(RAISED).fg(ACCENT)
                }),
                rect,
            );
            self.hits.borrow_mut().systems.push((rect, os));
            x += width;
        }
    }
    pub(super) fn draw_tabs(&self, frame: &mut Frame, area: Rect) {
        let mut x = area.x;
        for (i, page) in Page::ALL.iter().enumerate() {
            let label = format!(" F{} {} ", i + 2, page.title());
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
                        .bg(SELECTED_BG)
                        .fg(FOCUS)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT)
                }),
                rect,
            );
            self.hits.borrow_mut().tabs.push((rect, *page));
            x = x.saturating_add(width + 1);
        }
        if let Some(started) = self.started {
            let pulses = ["●··", "·●·", "··●", "·●·"];
            let pulse =
                pulses[(started.elapsed().as_millis() / 180 % pulses.len() as u128) as usize];
            let label = format!("SCAN {pulse} ");
            let width = Span::raw(&label).width() as u16;
            if area.width > width + 4 {
                frame.render_widget(
                    Paragraph::new(label).style(Style::default().fg(ACCENT)),
                    Rect::new(area.right() - width - 1, area.y, width, area.height),
                );
            }
        } else if area.width.saturating_sub(x.saturating_sub(area.x)) > 24 {
            let brand = Line::from(vec![
                Span::styled(
                    "ZERO",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" 内存取证 ", Style::default().fg(MUTED)),
            ]);
            let width = brand.width() as u16;
            frame.render_widget(
                Paragraph::new(brand),
                Rect::new(area.right() - width - 1, area.y, width, area.height),
            );
        }
    }
    pub(super) fn draw_search(
        &self,
        frame: &mut Frame,
        rect: Rect,
        query: &str,
        kind: InputKind,
        title: &str,
    ) {
        self.hits.borrow_mut().search = rect;
        let editing = match &self.dialog {
            Some(Dialog::Input {
                kind: active,
                cursor,
                ..
            }) if *active == kind => Some(*cursor),
            _ => None,
        };
        let cursor_width = editing
            .map(|cursor| Span::raw(escaped(&query[..cursor])).width())
            .unwrap_or(0);
        let controls = if editing.is_some() && rect.width >= 30 {
            14
        } else {
            0
        };
        let width = rect.width.saturating_sub(2 + controls).max(1) as usize;
        let scroll = cursor_width.saturating_sub(width.saturating_sub(1));
        frame.render_widget(
            Paragraph::new(escaped(query))
                .scroll((0, scroll.min(u16::MAX as usize) as u16))
                .block(panel().title(title).border_style(
                    Style::default().fg(if editing.is_some() { FOCUS } else { BORDER }),
                )),
            rect,
        );
        if controls > 0 && rect.height > 1 {
            let confirm = Rect::new(rect.right() - 15, rect.y + 1, 6, 1);
            let cancel = Rect::new(rect.right() - 8, rect.y + 1, 6, 1);
            frame.render_widget(
                Paragraph::new("[确认]").style(Style::default().fg(FOCUS)),
                confirm,
            );
            frame.render_widget(
                Paragraph::new("[撤销]").style(Style::default().fg(ACCENT)),
                cancel,
            );
            self.hits
                .borrow_mut()
                .buttons
                .extend([(confirm, KeyCode::Enter), (cancel, KeyCode::Esc)]);
        }
        if editing.is_some() && rect.height > 1 && rect.width > 2 {
            frame.set_cursor_position((
                rect.x + 1 + (cursor_width - scroll).min(width - 1) as u16,
                rect.y + 1,
            ));
        }
    }
    pub(super) fn draw_asset_buttons(
        &self,
        frame: &mut Frame,
        area: Rect,
        section: AssetSection,
        keys: &[KeyCode],
    ) {
        let mut x = area.x;
        let mut y = area.y;
        let actions = asset_actions(section);
        for key in keys.iter().copied() {
            let Some((label, _)) = actions.iter().find(|(_, action)| *action == key) else {
                continue;
            };
            let text = format!(" {label} ");
            let width = Span::raw(&text).width() as u16;
            if width > area.width {
                continue;
            }
            if x + width > area.right() {
                x = area.x;
                y += 1;
            }
            if y >= area.bottom() {
                break;
            }
            let rect = Rect::new(x, y, width, 1);
            let disabled = self.asset_disabled(section, key);
            frame.render_widget(
                Paragraph::new(text).style(if disabled.is_some() {
                    Style::default().fg(MUTED)
                } else {
                    Style::default().fg(FOCUS).bg(if key == KeyCode::Char('x') {
                        SELECTED_BG
                    } else {
                        RAISED
                    })
                }),
                rect,
            );
            if disabled.is_none() {
                self.hits
                    .borrow_mut()
                    .asset_buttons
                    .push((rect, section, key));
            }
            x += width + 1;
        }
    }
    pub(super) fn draw_asset_pane(&self, frame: &mut Frame, area: Rect, section: AssetSection) {
        if area.height == 0 || area.width < 3 {
            return;
        }
        let keys = asset_pane_keys(section);
        let button_rows =
            asset_action_rows(section, keys, area.width).min(if area.height >= 8 { 2 } else { 1 });
        let parts = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(button_rows),
            Constraint::Min(3),
        ])
        .split(area);
        let query = &self.asset_queries[section.slot()];
        if self.section == section {
            self.draw_search(
                frame,
                parts[0],
                query,
                InputKind::AssetsSearch,
                "搜索 / · Enter 确认",
            );
        } else {
            frame.render_widget(
                Paragraph::new(escaped(query)).block(panel().title("搜索 /")),
                parts[0],
            );
        }
        self.hits
            .borrow_mut()
            .asset_searches
            .push((parts[0], section));
        self.draw_asset_buttons(frame, parts[1], section, keys);
        let rows = if section == AssetSection::Remote {
            self.remote_list()
                .iter()
                .map(|m| {
                    let (tag, color) = if self.downloads.get(&m.url).is_some_and(|p| p.is_file()) {
                        ("[已保存]", SUCCESS)
                    } else if self.remote_cached(m) {
                        ("[缓存]", ACCENT)
                    } else {
                        ("[待下载]", MUTED)
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(tag, Style::default().fg(color)),
                        Span::styled(format!(" {}", escaped(&m.path)), Style::default().fg(TEXT)),
                    ]))
                })
                .collect::<Vec<_>>()
        } else {
            self.asset_list_for(section)
                .iter()
                .map(|a| {
                    let active = if a.kind == Kind::Image {
                        self.image.as_ref().is_some_and(|p| same_path(p, &a.path))
                    } else {
                        same_path(&self.symbols, &a.path)
                    };
                    let (marker, color) = if active {
                        ("●已选用", SUCCESS)
                    } else if self.local_matches.contains_key(&a.path) {
                        ("✓匹配", ACCENT)
                    } else {
                        (" ", MUTED)
                    };
                    let mut spans = vec![
                        Span::styled(
                            marker,
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" {}", escaped(&self.display_path(&a.path))),
                            Style::default().fg(if a.available { TEXT } else { MUTED }),
                        ),
                        Span::styled(
                            format!(" · #{} · {}", a.id(), a.format()),
                            Style::default().fg(MUTED),
                        ),
                    ];
                    if !a.available {
                        spans.push(Span::styled(" · 缺失", Style::default().fg(DANGER)));
                    }
                    ListItem::new(Line::from(spans))
                })
                .collect::<Vec<_>>()
        };
        let count = rows.len();
        let mut states = self.asset_states.borrow_mut();
        let state = &mut states[section.slot()];
        state.select(
            (count > 0).then_some(self.asset_rows[section.slot()].min(count.saturating_sub(1))),
        );
        let mode = match section {
            AssetSection::Symbols if self.local_only_matches => " · 完整 banner 匹配",
            AssetSection::Remote if !self.remote_catalog => " · 镜像精确匹配",
            _ => " · 全部",
        };
        frame.render_stateful_widget(
            List::new(rows)
                .block(
                    panel()
                        .title(format!("{}{} · {} 项", section.title(), mode, count))
                        .border_style(Style::default().fg(
                            if self.section == section && self.focus == Focus::Navigation {
                                ACCENT
                            } else {
                                BORDER
                            },
                        )),
                )
                .highlight_symbol("› ")
                .highlight_style(
                    Style::default()
                        .bg(SELECTED_BG)
                        .add_modifier(Modifier::BOLD),
                ),
            parts[2],
            state,
        );
        self.hits
            .borrow_mut()
            .asset_lists
            .push((parts[2], section, state.offset()));
        if self.section == section {
            self.hits.borrow_mut().assets = parts[2];
            self.hits.borrow_mut().asset_offset = state.offset();
        }
        if count == 0 {
            let text = match section {
                AssetSection::Images => "没有镜像 · a 导入镜像",
                AssetSection::Symbols if self.local_only_matches => {
                    "无本地匹配 · M 远程匹配 · z 查看全部"
                }
                AssetSection::Symbols => "没有符号 · a 导入符号",
                AssetSection::Remote => "没有远程条目 · g 获取索引 · / 搜索 · M 精确匹配",
            };
            frame.render_widget(
                Paragraph::new(text)
                    .wrap(Wrap { trim: false })
                    .style(Style::default().fg(MUTED)),
                parts[2].inner(ratatui::layout::Margin::new(1, 1)),
            );
        }
    }
    pub(super) fn draw_assets(&self, frame: &mut Frame, area: Rect) {
        let keys = [KeyCode::Char('x'), KeyCode::Char('M'), KeyCode::Char('m')];
        let regions = Layout::vertical([
            Constraint::Length(if area.height >= 20 { 4 } else { 2 }),
            Constraint::Length(asset_action_rows(self.section, &keys, area.width).min(2)),
            Constraint::Length(1),
            Constraint::Min(2),
        ])
        .split(area);
        let banner = self
            .results
            .get("banners")
            .and_then(|r| {
                banner_candidates(r)
                    .first()
                    .and_then(|row| row.get(1))
                    .cloned()
            })
            .unwrap_or_else(|| "尚未识别；选用镜像后自动识别".into());
        let image = self
            .image
            .as_ref()
            .map(|p| self.display_path(p))
            .unwrap_or_else(|| "尚未选择；i 导入或 Space 选用清单中的镜像".into());
        let symbol = if self.symbols.as_os_str().is_empty() {
            "未选用；m 本地匹配，M 匹配并获取符号".into()
        } else {
            let path = self
                .choice
                .clone()
                .unwrap_or_else(|| self.display_path(&self.symbols));
            if self.preparation == Preparation::Ready {
                path
            } else {
                format!("待匹配 {path}")
            }
        };
        let (state, state_color) = match self.preparation {
            Preparation::ChooseImage => ("选用镜像后自动识别与匹配", MUTED),
            Preparation::Matching => ("正在识别系统并匹配本地符号", ACCENT),
            Preparation::ChooseSystem => ("系统不明确；F6 手动选择", WARN),
            Preparation::MissingSymbols => ("缺少精确符号；M 获取，y 导入", WARN),
            Preparation::ChooseSymbols => ("多个精确候选；Space 选用，Enter 进入控制台", WARN),
            Preparation::Ready => ("符号已选用；x 进入分析，点击插件运行", SUCCESS),
            Preparation::Cancelled => ("匹配已取消；m 重试", DANGER),
        };
        let source = if self.windows {
            "Microsoft symbol server · 精确 PDB GUID / Age".into()
        } else {
            format!("{} · 完整 banner 精确匹配", symbols::REPOSITORY)
        };
        let (mode, mode_color) = if self.settings.remote_symbols {
            ("在线", SUCCESS)
        } else {
            ("离线（仅缓存）", WARN)
        };
        let value = Style::default().fg(TEXT);
        let separator = || Span::styled(" · ", Style::default().fg(BORDER));
        let identified = self.results.contains_key("banners");
        frame.render_widget(
            Paragraph::new(vec![
                Line::from_iter(field("镜像: ", escaped(&image), value)),
                Line::from_iter(field("符号: ", escaped(&symbol), value).into_iter().chain([
                    separator(),
                    Span::styled(state, Style::default().fg(state_color)),
                ])),
                Line::from_iter(field(
                    "内核: ",
                    escaped(&banner),
                    if identified {
                        value
                    } else {
                        Style::default().fg(MUTED)
                    },
                )),
                Line::from_iter(
                    field("来源: ", mode.into(), Style::default().fg(mode_color))
                        .into_iter()
                        .chain([
                            separator(),
                            Span::styled(source, Style::default().fg(MUTED)),
                        ]),
                ),
            ]),
            regions[0],
        );
        self.draw_asset_buttons(frame, regions[1], self.section, &keys);
        let mut x = regions[2].x;
        for (label, section) in [
            (" 镜像 ", AssetSection::Images),
            (" 本地库 ", AssetSection::Symbols),
            (" 远程索引 ", AssetSection::Remote),
        ] {
            let width = Span::raw(label).width() as u16;
            if x + width > regions[2].right() {
                break;
            }
            let rect = Rect::new(x, regions[2].y, width, regions[2].height);
            frame.render_widget(
                Paragraph::new(label).style(if self.section == section {
                    Style::default().fg(FOCUS).bg(SELECTED_BG)
                } else {
                    Style::default().fg(ACCENT)
                }),
                rect,
            );
            self.hits.borrow_mut().sources.push((rect, section));
            x += width + 1;
        }
        let mut body = regions[3];
        if area.width >= 100 && area.height >= 24 {
            let rows = Layout::vertical([Constraint::Min(9), Constraint::Length(8)]).split(body);
            body = rows[0];
            self.hits.borrow_mut().asset_detail = rows[1];
            frame.render_widget(
                Paragraph::new(self.asset_text())
                    .wrap(Wrap { trim: false })
                    .scroll((
                        self.asset_scroll[self.section.slot()].min(u16::MAX as usize) as u16,
                        0,
                    ))
                    .block(panel().title("详情 · d 完整内容 · Tab 聚焦").border_style(
                        Style::default().fg(if self.focus == Focus::Content {
                            ACCENT
                        } else {
                            BORDER
                        }),
                    )),
                rows[1],
            );
        }
        if area.height < 16 {
            self.draw_asset_pane(frame, body, self.section);
        } else {
            let panes = if area.width >= 100 {
                Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
                    .split(body)
            } else {
                Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(body)
            };
            self.draw_asset_pane(frame, panes[0], AssetSection::Images);
            self.draw_asset_pane(frame, panes[1], self.symbol_source);
        }
    }
    pub fn draw(&self, frame: &mut Frame) {
        *self.hits.borrow_mut() = HitMap::default();
        frame.render_widget(
            Block::default().style(Style::default().bg(SURFACE)),
            frame.area(),
        );
        let [tabs, systems, area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(frame.area());
        self.draw_tabs(frame, tabs);
        if self.page == Page::Analysis && (frame.area().width < 100 || frame.area().height < 20) {
            let mut x = systems.x;
            for (label, focus) in [(" 插件 ", Focus::Navigation), (" 内容 ", Focus::Content)] {
                let width =
                    (Span::raw(label).width() as u16).min(systems.right().saturating_sub(x));
                let rect = Rect::new(x, systems.y, width, systems.height);
                frame.render_widget(
                    Paragraph::new(label).style(Style::default().fg(if self.focus == focus {
                        FOCUS
                    } else {
                        ACCENT
                    })),
                    rect,
                );
                self.hits.borrow_mut().regions.push((rect, focus));
                x += width;
            }
        } else {
            self.draw_system_buttons(frame, systems);
        }
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if self.page == Page::Analysis { 2 } else { 0 }),
                Constraint::Min(3),
                Constraint::Length(3),
            ])
            .split(area);
        self.hits.borrow_mut().header = parts[0];
        let selected = |focus| {
            if self.focus == focus {
                Style::default().fg(ACCENT)
            } else {
                Style::default().fg(BORDER)
            }
        };
        let image = self
            .image
            .as_ref()
            .map(|p| self.display_path(p))
            .unwrap_or_else(|| "未加载；按 i 输入路径".into());
        let verified = self
            .results
            .values()
            .find(|r| !r.historical && r.page_table > 0)
            .map(|r| r.page_table);
        let (kernel, kernel_style) = match verified {
            Some(table) => (
                format!("页表已验证 {table:#x}"),
                Style::default().fg(SUCCESS),
            ),
            None if self.preparation == Preparation::Ready => {
                ("运行时验证页表".into(), Style::default().fg(TEXT))
            }
            None => ("尚未验证页表".into(), Style::default().fg(WARN)),
        };
        let symbol = self
            .result()
            .filter(|r| !r.historical && !r.symbol.is_empty())
            .map(|r| r.symbol.clone());
        let (symbol, symbol_style) = match symbol {
            Some(symbol) => (symbol, Style::default().fg(TEXT)),
            None if self.symbols.as_os_str().is_empty() => {
                ("未选择 · F2 资源库".into(), Style::default().fg(WARN))
            }
            None => (self.display_path(&self.symbols), Style::default().fg(TEXT)),
        };
        let value = Style::default().fg(TEXT);
        let separator = || Span::styled(" · ", Style::default().fg(BORDER));
        frame.render_widget(
            Paragraph::new(vec![
                Line::from_iter(
                    field(
                        "系统: ",
                        if self.windows { "Windows" } else { "Linux" }.into(),
                        value.add_modifier(Modifier::BOLD),
                    )
                    .into_iter()
                    .chain([separator()])
                    .chain(field("镜像: ", escaped(&image), value)),
                ),
                Line::from_iter(
                    field("验证: ", escaped(&kernel), kernel_style)
                        .into_iter()
                        .chain([separator()])
                        .chain(field("符号: ", escaped(&symbol), symbol_style)),
                ),
            ]),
            parts[0],
        );
        if self.page == Page::Assets {
            self.draw_assets(frame, parts[1]);
        } else {
            let mut main = if area.width >= 100 && frame.area().height >= 20 {
                let columns = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Length(22), Constraint::Min(20)])
                    .split(parts[1]);
                self.draw_menu(frame, columns[0], selected(Focus::Navigation));
                columns[1]
            } else if self.focus == Focus::Navigation {
                self.draw_menu(frame, parts[1], selected(Focus::Navigation));
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
                        panel()
                            .title("详情 · Tab 聚焦 · d 关闭")
                            .border_style(selected(Focus::Detail)),
                    ),
                    columns[1],
                );
            }
            self.hits.borrow_mut().workbench = main;
            if main.width > 0 {
                let regions = Layout::vertical([
                    Constraint::Length(if main.height >= 6 { 3 } else { 0 }),
                    Constraint::Min(2),
                ])
                .split(main);
                self.draw_search(
                    frame,
                    regions[0],
                    &self.query,
                    InputKind::Search,
                    "内容搜索 · / 编辑 · Enter 确认 · Esc 撤销",
                );
                main = regions[1];
            }
            self.hits.borrow_mut().result = main;
            if main.width > 0 {
                let rows = self.visible();
                let page_size = self.page_rows();
                let selected_row = self.row.min(rows.len().saturating_sub(1));
                let offset = self.table_state.borrow().offset();
                let page_start = if selected_row < offset {
                    selected_row
                } else if selected_row >= offset.saturating_add(page_size) {
                    selected_row.saturating_add(1).saturating_sub(page_size)
                } else {
                    offset
                }
                .min(rows.len().saturating_sub(page_size));
                let result = self.result();
                let title = match result {
                    Some(r) => format!(
                        " {} · {} / {} 条 · {} · 显示 {}–{} 行 ",
                        r.plugin.strip_prefix("windows.").unwrap_or(&r.plugin),
                        rows.index.filtered.len(),
                        r.rows.len(),
                        if r.historical {
                            "历史"
                        } else if r.complete {
                            "完整"
                        } else {
                            "部分"
                        },
                        if rows.index.visible.is_empty() {
                            0
                        } else {
                            page_start + 1
                        },
                        page_start.saturating_add(page_size).min(rows.len())
                    ),
                    None => format!(" {} ", plugin_label(self.plugin)),
                };
                let block = panel().title(title).border_style(selected(Focus::Content));
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
                    let natural = table_widths(&columns, &rows.range(0, 200));
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
                    let rows = rows.range(page_start, page_size);
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
                        rows.into_iter().enumerate().map(|(i, row)| {
                            Row::new(row.iter().map(|v| escaped(v)).collect::<Vec<_>>()).style(
                                Style::default().fg(TEXT).bg(if (page_start + i) % 2 == 1 {
                                    STRIPE
                                } else {
                                    SURFACE
                                }),
                            )
                        }),
                        widths,
                    )
                    .header(
                        Row::new(columns).style(
                            Style::default()
                                .fg(ACCENT)
                                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                        ),
                    )
                    .block(block)
                    .row_highlight_style(
                        Style::default()
                            .bg(SELECTED_BG)
                            .fg(FOCUS)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("› ");
                    // Render only the current window; saved state uses absolute
                    // row indices so scrolling never snaps to a page boundary.
                    let mut state = TableState::default();
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
                    let offset = page_start + state.offset();
                    self.hits.borrow_mut().row_offset = offset;
                    let mut saved = self.table_state.borrow_mut();
                    saved.select((row_count > 0).then_some(selected_row));
                    *saved.offset_mut() = offset;
                } else {
                    frame.render_widget(
                        Paragraph::new(vec![
                            Line::raw(""),
                            Line::styled(
                                "尚无结果",
                                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                            ),
                            Line::styled("浏览左侧插件或按 p 搜索", Style::default().fg(MUTED)),
                            Line::styled("点击或 Enter 选择插件即运行", Style::default().fg(MUTED)),
                            Line::styled("F2 资源库 · ? 命令面板", Style::default().fg(MUTED)),
                        ])
                        .alignment(ratatui::layout::Alignment::Center)
                        .block(block),
                        main,
                    );
                }
            }
        }
        let footer = parts[2];
        frame.render_widget(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(BORDER))
                .title_style(Style::default().fg(MUTED))
                .title(format!(
                    " {} · {} · Tab 切换区域 ",
                    self.page.title(),
                    if self.page == Page::Analysis {
                        match self.focus {
                            Focus::Context => "镜像信息",
                            Focus::Navigation => "插件",
                            Focus::Detail => "详情",
                            _ => "内容",
                        }
                    } else if self.focus == Focus::Content {
                        "详情"
                    } else {
                        self.section.title()
                    }
                )),
            footer,
        );
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
                    .use_unicode(true)
                    .gauge_style(Style::default().fg(ACCENT).bg(RAISED)),
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
            let color = if self.last_error.as_deref() == Some(self.status.as_str()) {
                DANGER
            } else if self.started.is_some() {
                ACCENT
            } else {
                TEXT
            };
            frame.render_widget(
                Paragraph::new(message).style(Style::default().fg(color)),
                status,
            );
        }
        let buttons = self.footer_actions();
        let more_width = Span::raw(" 更多 ? ").width() as u16;
        let mut x = footer.x;
        for (label, key) in buttons {
            let text = format!(" {label} ");
            let width = Span::raw(&text).width() as u16;
            let more = key == KeyCode::Char('?');
            if footer.height < 3 {
                break;
            }
            if !more && x + width + 1 + more_width > footer.right() {
                continue;
            }
            if more && x + width > footer.right() {
                continue;
            }
            let rect = Rect::new(x, footer.y + 2, width, 1);
            frame.render_widget(
                Paragraph::new(text).style(Style::default().fg(FOCUS).bg(RAISED)),
                rect,
            );
            if self.page != Page::Assets || self.asset_disabled(self.section, key).is_none() {
                self.hits.borrow_mut().buttons.push((rect, key));
            } else {
                frame.render_widget(
                    Paragraph::new(format!(" {label} ")).style(Style::default().fg(MUTED)),
                    rect,
                );
            }
            x += width + 1;
        }
        self.draw_dialog(frame, area);
    }
    fn draw_dialog(&self, frame: &mut Frame, area: Rect) {
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
                    area.width.saturating_sub(6).min(90),
                    match dialog {
                        Dialog::System { .. } => 5,
                        Dialog::Dump { .. } => 12,
                        Dialog::WindowsParameters { .. } => 18,
                        Dialog::GenerateSymbols { .. } => 15,
                        Dialog::Input { .. } => 6,
                        _ => 12,
                    },
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
    /// Accent the popup frame and cast a one-cell shadow so modals read above content.
    fn frame_popup(frame: &mut Frame, popup: Rect) {
        let bounds = frame.area();
        let buffer = frame.buffer_mut();
        let edge = |x: u16, y: u16| {
            x == popup.x || y == popup.y || x + 1 == popup.right() || y + 1 == popup.bottom()
        };
        for y in popup.top()..popup.bottom() {
            for x in popup.left()..popup.right() {
                if !edge(x, y) {
                    continue;
                }
                let cell = &mut buffer[(x, y)];
                if cell
                    .symbol()
                    .chars()
                    .next()
                    .is_some_and(|c| ('\u{2500}'..='\u{257f}').contains(&c))
                {
                    cell.set_fg(ACCENT);
                }
            }
        }
        let shadow = Color::Rgb(8, 12, 15);
        let right = popup.right();
        let bottom = popup.bottom();
        if right < bounds.right() {
            for y in popup.y + 1..bottom.min(bounds.bottom()) {
                buffer[(right, y)].set_bg(shadow);
            }
        }
        if bottom < bounds.bottom() {
            for x in popup.x + 1..(right + 1).min(bounds.right()) {
                buffer[(x, bottom)].set_bg(shadow);
            }
        }
    }
    pub(super) fn draw_menu(&self, frame: &mut Frame, area: Rect, style: Style) {
        let mut state = ListState::default().with_selected(Some(self.menu));
        let items = self
            .menu_items()
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        frame.render_stateful_widget(
            List::new(items)
                .style(Style::default().fg(TEXT))
                .block(panel().title("插件 · p 搜索").border_style(style))
                .highlight_style(
                    Style::default()
                        .bg(SELECTED_BG)
                        .fg(FOCUS)
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
