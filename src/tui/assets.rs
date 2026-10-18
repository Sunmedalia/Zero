//! The resource library page: source tabs, both asset panes, the inline detail
//! panel and the bottom action toolbar.
use super::*;

impl App {
    pub(super) fn draw_asset_buttons(
        &self,
        frame: &mut Frame,
        area: Rect,
        section: AssetSection,
        actions: &[(&'static str, KeyCode)],
    ) {
        let more = " 更多 ? ";
        let more_width = Span::raw(more).width() as u16;
        let mut x = area.x;
        let mut y = area.y;
        let mut shown = 0usize;
        for (label, key) in actions.iter().copied() {
            let text = format!(" {label} ");
            let width = Span::raw(&text).width() as u16;
            if width > area.width {
                continue;
            }
            // Reserve the escape hatch on whichever row is being filled.
            if x + width + more_width > area.right() {
                x = area.x;
                y += 1;
            }
            if y >= area.bottom() {
                break;
            }
            let rect = Rect::new(x, y, width, 1);
            let disabled = Command::from_key(Page::Assets, key)
                .and_then(|command| self.command_disabled(command));
            frame.render_widget(
                Paragraph::new(text).style(if disabled.is_some() {
                    Style::default().fg(MUTED).bg(RAISED)
                } else if key == KeyCode::Char('x') {
                    Style::default()
                        .fg(FOCUS)
                        .bg(SELECTED_BG)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT).bg(RAISED)
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
            shown += 1;
        }
        if shown < actions.len() {
            // The reservation during placement guarantees room on the row that
            // was being filled, unless that row ended exactly at the edge.
            // Clamp to the last drawable row: `y` may have advanced past the
            // area when the previous row filled exactly.
            let my = y.min(area.bottom().saturating_sub(1));
            let mx = if area.right().saturating_sub(x) >= more_width {
                x
            } else {
                area.x
            };
            if my >= area.y && area.right().saturating_sub(mx) >= more_width {
                let rect = Rect::new(mx, my, more_width, 1);
                frame.render_widget(
                    Paragraph::new(more).style(Style::default().fg(ACCENT).bg(RAISED)),
                    rect,
                );
                self.hits
                    .borrow_mut()
                    .asset_buttons
                    .push((rect, section, KeyCode::Char('?')));
            }
        }
    }
    pub(super) fn draw_asset_toolbar(&self, frame: &mut Frame, area: Rect) {
        let toolbar = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(BORDER))
            .title(Line::from(vec![
                Span::styled(" 操作 ", Style::default().fg(MUTED)),
                Span::styled(
                    format!("· {} · Tab 切换区域 ", self.section.title()),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
            ]));
        let buttons = toolbar.inner(area);
        frame.render_widget(toolbar, area);
        self.draw_asset_buttons(
            frame,
            buttons,
            self.section,
            &toolbar_actions(self.section, self.job.is_some()),
        );
    }
    /// Whether this pane's search field should be drawn.
    ///
    /// The field is a low-frequency control, so it only takes a row when it is
    /// being edited or already holds a query. The rest of the time the list
    /// keeps the space, which is what the user is actually reading.
    fn search_visible(&self, section: AssetSection) -> bool {
        let editing = matches!(
            &self.dialog,
            Some(Dialog::Input {
                kind: InputKind::AssetsSearch,
                ..
            })
        ) && self.section == section;
        editing || !self.asset_queries[section.slot()].is_empty()
    }
    pub(super) fn draw_asset_pane(&self, frame: &mut Frame, area: Rect, section: AssetSection) {
        if area.height == 0 || area.width < 3 {
            return;
        }
        let search = self.search_visible(section);
        let parts = if search {
            Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).split(area)
        } else {
            Layout::vertical([Constraint::Length(0), Constraint::Min(3)]).split(area)
        };
        let query = &self.asset_queries[section.slot()];
        if search {
            self.draw_search(
                frame,
                parts[0],
                query,
                InputKind::AssetsSearch,
                "搜索 / · Enter 确认 · Esc 取消",
            );
            self.hits
                .borrow_mut()
                .asset_searches
                .push((parts[0], section));
        }
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
            parts[1],
            state,
        );
        self.hits
            .borrow_mut()
            .asset_lists
            .push((parts[1], section, state.offset()));
        if self.section == section {
            self.hits.borrow_mut().assets = parts[1];
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
                parts[1].inner(ratatui::layout::Margin::new(1, 1)),
            );
        }
    }
    pub(super) fn draw_assets(&self, frame: &mut Frame, area: Rect) {
        let regions = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Min(2),
        ])
        .split(area);
        // The resource header is drawn here rather than by `draw`, so it
        // registers its own hit regions. Without this, header clicks had no
        // target and the page had no focusable header at all.
        self.hits.borrow_mut().header = regions[0];
        self.hits.borrow_mut().header_image =
            Rect::new(regions[0].x, regions[0].y, regions[0].width, 1);
        self.hits.borrow_mut().header_symbol =
            Rect::new(regions[0].x, regions[0].y + 1, regions[0].width, 1);
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
        let (mode, mode_color) = if self.settings.remote_symbols {
            ("在线", SUCCESS)
        } else {
            ("离线", WARN)
        };
        let value = Style::default().fg(TEXT);
        let separator = || Span::styled(" · ", Style::default().fg(BORDER));
        let identified = self.results.contains_key("banners");
        // Two lines instead of four: the kernel banner and the repository URL
        // are reference material, not state, and both are available in the
        // detail panel and the palette. What changes during work — image,
        // symbol, match state, network mode — stays on screen.
        //
        // Each line is filled by priority and stops at a field boundary, so a
        // narrow window drops the kernel rather than cutting the image path.
        let banner = summarise_banner(&banner);
        let banner_style = if identified {
            value
        } else {
            Style::default().fg(MUTED)
        };
        let image_line = fit(
            &[("镜像: ", image, value), ("内核: ", banner, banner_style)],
            regions[0].width,
        );
        // Status first: the match state and network mode are short, always
        // actionable, and the thing the user is waiting on. The symbol path is
        // long and predictable, so it takes what remains and is shortened.
        let mut symbol_line = vec![
            Span::styled(state, Style::default().fg(state_color)),
            separator(),
            Span::styled(mode, Style::default().fg(mode_color)),
        ];
        let used = Span::raw(state).width() + Span::raw(mode).width() + 6;
        if (used as u16) < regions[0].width {
            let fitted = fit(&[("符号: ", symbol, value)], regions[0].width - used as u16);
            if !fitted.is_empty() {
                symbol_line.push(separator());
                symbol_line.extend(fitted);
            }
        }
        frame.render_widget(
            Paragraph::new(vec![Line::from(image_line), Line::from(symbol_line)]),
            regions[0],
        );
        let mut x = regions[1].x;
        for (label, section) in [
            (" 镜像 ", AssetSection::Images),
            (" 本地库 ", AssetSection::Symbols),
            (" 远程索引 ", AssetSection::Remote),
        ] {
            let width = Span::raw(label).width() as u16;
            if x + width > regions[1].right() {
                break;
            }
            let rect = Rect::new(x, regions[1].y, width, regions[1].height);
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
        let mut body = regions[2];
        // The detail panel is reference material for the highlighted row, so it
        // only claims space when there is a row to describe and the window is
        // tall enough that it does not squeeze the lists.
        if area.width >= 100 && frame.area().height >= 24 {
            let rows = Layout::vertical([Constraint::Min(9), Constraint::Length(6)]).split(body);
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
}
