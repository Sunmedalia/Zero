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
                    Style::default().fg(color_muted()).bg(color_raised())
                } else if key == KeyCode::Char('x') {
                    Style::default()
                        .fg(color_focus())
                        .bg(color_selected_bg())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(color_text()).bg(color_raised())
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
                    Paragraph::new(more)
                        .style(Style::default().fg(color_accent()).bg(color_raised())),
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
            .border_style(Style::default().fg(color_border()))
            .title(Line::from(vec![
                Span::styled(" 操作 ", Style::default().fg(color_muted())),
                Span::styled(
                    format!("· {} · Tab 切换区域 ", self.section.title()),
                    Style::default()
                        .fg(color_accent())
                        .add_modifier(Modifier::BOLD),
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
    /// Keep remote catalog search visible even before the first query.
    fn search_visible(&self, section: AssetSection) -> bool {
        let editing = matches!(
            &self.dialog,
            Some(Dialog::Input {
                kind: InputKind::AssetsSearch,
                ..
            })
        ) && self.section == section;
        section == AssetSection::Remote || editing || !self.asset_queries[section.slot()].is_empty()
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
                if section == AssetSection::Remote {
                    "搜索远程索引 / · 点击输入 · Enter 确认 · Esc 取消"
                } else {
                    "搜索 / · Enter 确认 · Esc 取消"
                },
            );
            self.hits
                .borrow_mut()
                .asset_searches
                .push((parts[0], section));
        }
        if section == AssetSection::Images {
            self.draw_image_list(frame, parts[1]);
            return;
        }
        let rows = if section == AssetSection::Remote {
            self.remote_list()
                .iter()
                .map(|m| {
                    let (tag, color) = if self.downloads.get(&m.url).is_some_and(|p| p.is_file()) {
                        ("[已保存]", color_success())
                    } else if self.remote_cached(m) {
                        ("[缓存]", color_accent())
                    } else {
                        ("[待下载]", color_muted())
                    };
                    // The repository path ends in a 64-character content hash,
                    // which is identical for every candidate of the same
                    // kernel; the distinguishing part is the version in the
                    // middle. Show the head and the file name, and drop the
                    // hash, rather than letting the tail crowd out the rest.
                    let shown = compact_remote_path(&m.path, area.width);
                    ListItem::new(Line::from(vec![
                        Span::styled(tag, Style::default().fg(color)),
                        Span::styled(
                            format!(" {}", escaped(&shown)),
                            Style::default().fg(color_text()),
                        ),
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
                        ("●已选用", color_success())
                    } else if self.local_matches.contains_key(&a.path) {
                        ("✓匹配", color_accent())
                    } else {
                        (" ", color_muted())
                    };
                    // The path is the only field that can be arbitrarily long,
                    // so it yields to the fixed-width metadata after it. A row
                    // that shows a long path but hides the format and digest
                    // answers the wrong question.
                    // In a narrow pane the digest is the first thing to go: a
                    // truncated digest identifies nothing, while the format
                    // still does. The path then gets whatever is left.
                    let narrow = !Space::new(area.width, area.height).full_digest();
                    let metadata = if narrow {
                        format!(" · {}", a.format())
                    } else {
                        format!(" · #{} · {}", a.id(), a.format())
                    };
                    let suffix = if a.available { "" } else { " · 缺失" };
                    // Measure what is not the path instead of estimating it:
                    // borders, the highlight marker, the space before the path
                    // and the fixed fields after it.
                    let fixed = Line::from(vec![
                        Span::styled(marker, Style::default()),
                        Span::raw(" "),
                        Span::raw(metadata.clone()),
                        Span::raw(suffix),
                    ])
                    .width();
                    // `List` reserves the highlight symbol's two cells on every
                    // row, not only the selected one, and the border takes two
                    // more.
                    let room = (area.width as usize).saturating_sub(fixed + 4).max(8);
                    let path = self.display_path(&a.path);
                    let shown = path;
                    let mut spans = vec![
                        Span::styled(
                            marker,
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(" {}", escaped(&shown)),
                            Style::default().fg(if a.available {
                                color_text()
                            } else {
                                color_muted()
                            }),
                        ),
                        Span::styled(metadata, Style::default().fg(color_muted())),
                    ];
                    if !a.available {
                        spans.push(Span::styled(suffix, Style::default().fg(color_danger())));
                    }
                    let first = Line::from(spans);
                    let line = first
                        .spans
                        .iter()
                        .map(|span| span.content.as_ref())
                        .collect::<String>();
                    let mut wrapped = detail_lines(&line, area.width.saturating_sub(4));
                    if let Some(identity) = self.asset_identities.get(&a.path) {
                        let identity = format!(
                            "  已识别 {} · {}",
                            identity.system,
                            identity.kernels.first().map(String::as_str).unwrap_or("")
                        );
                        wrapped.push(truncate_with_ellipsis(
                            &escaped(&identity),
                            area.width.saturating_sub(4) as usize,
                        ));
                    }
                    let _ = room;
                    ListItem::new(
                        wrapped
                            .into_iter()
                            .enumerate()
                            .map(|(index, line)| {
                                Line::styled(
                                    line,
                                    if index == 0 {
                                        Style::default().fg(color)
                                    } else {
                                        Style::default().fg(color_text())
                                    },
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let row_heights = rows
            .iter()
            .map(|row| row.height() as u16)
            .collect::<Vec<_>>();
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
                                color_accent()
                            } else {
                                color_border()
                            },
                        )),
                )
                .highlight_symbol("› ")
                .highlight_style(
                    Style::default()
                        .bg(color_selected_bg())
                        .add_modifier(Modifier::BOLD),
                ),
            parts[1],
            state,
        );
        let mut y = parts[1].y + 1;
        for (index, height) in row_heights.iter().enumerate().skip(state.offset()) {
            if y >= parts[1].bottom().saturating_sub(1) {
                break;
            }
            if y + *height > parts[1].bottom().saturating_sub(1) {
                break;
            }
            let height = *height;
            self.hits.borrow_mut().asset_rows.push((
                Rect::new(parts[1].x + 1, y, parts[1].width.saturating_sub(2), height),
                section,
                index,
            ));
            y += height;
        }
        let viewport = self
            .hits
            .borrow()
            .asset_rows
            .iter()
            .filter(|(_, s, _)| *s == section)
            .count()
            .max(1);
        self.draw_scrollbar(
            frame,
            parts[1],
            count,
            viewport,
            state.offset(),
            ScrollTarget::Assets(section),
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
                    .style(Style::default().fg(color_muted())),
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
                .as_ref()
                .map(|label| self.display_path(std::path::Path::new(label)))
                .unwrap_or_else(|| self.display_path(&self.symbols));
            if self.preparation == Preparation::Ready {
                path
            } else {
                format!("待匹配 {path}")
            }
        };
        let (state, state_color) = match self.preparation {
            Preparation::ChooseImage => ("选用镜像后自动识别与匹配", color_muted()),
            Preparation::Matching => ("正在识别系统并匹配本地符号", color_accent()),
            Preparation::ChooseSystem => ("系统不明确；S 手动选择", color_warn()),
            Preparation::MissingSymbols => ("缺少精确符号；M 获取，y 导入", color_warn()),
            Preparation::ChooseSymbols => {
                ("多个精确候选；Space 选用，Enter 进入控制台", color_warn())
            }
            Preparation::Ready => ("符号已选用；x 进入分析，点击插件运行", color_success()),
            Preparation::Cancelled => ("匹配已取消；m 重试", color_danger()),
        };
        let (mode, mode_color) = if self.settings.remote_symbols {
            ("在线", color_success())
        } else {
            ("离线", color_warn())
        };
        let value = Style::default().fg(color_text());
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
            Style::default().fg(color_muted())
        };
        let image_line = fit(
            &[("镜像: ", image, value), ("内核: ", banner, banner_style)],
            regions[0].width,
        );
        // Symbol first, then the short status words. The symbol names the
        // selected input; the status is repeated by the footer and the detail
        // panel, so it is the field that gets dropped when space runs out.
        // Everything is measured against one width so the line cannot overflow.
        let mut symbol_line = fit(
            &[
                ("符号: ", symbol, value),
                ("", mode.to_string(), Style::default().fg(mode_color)),
                ("", state.to_string(), Style::default().fg(state_color)),
            ],
            regions[0].width,
        );
        if symbol_line.is_empty() {
            // Nothing fits whole: show the state clipped rather than nothing.
            symbol_line = vec![Span::styled(
                truncate_with_ellipsis(state, regions[0].width as usize),
                Style::default().fg(state_color),
            )];
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
                    Style::default().fg(color_focus()).bg(color_selected_bg())
                } else {
                    Style::default().fg(color_accent())
                }),
                rect,
            );
            self.hits.borrow_mut().sources.push((rect, section));
            x += width + 1;
        }
        let mut body = regions[2];
        if self.section == AssetSection::Remote {
            let mut x = body.x;
            let y = body.y;
            for (label, catalog) in [
                (format!(" 全部索引 {} ", self.remote_total), true),
                (
                    format!(
                        " 镜像匹配 {} ",
                        self.remote_matches.as_ref().map_or(0, Vec::len)
                    ),
                    false,
                ),
            ] {
                let width = (Span::raw(&label).width() as u16).min(body.right().saturating_sub(x));
                let rect = Rect::new(x, y, width, 1);
                frame.render_widget(
                    Paragraph::new(label).style(
                        Style::default()
                            .fg(if self.remote_catalog == catalog {
                                color_focus()
                            } else {
                                color_accent()
                            })
                            .bg(if self.remote_catalog == catalog {
                                color_selected_bg()
                            } else {
                                color_surface()
                            }),
                    ),
                    rect,
                );
                self.hits.borrow_mut().remote_views.push((rect, catalog));
                x += width + 1;
            }
            body.y += 1;
            body.height = body.height.saturating_sub(1);
        }
        self.draw_asset_pane(frame, body, self.section);
    }
}

impl App {
    pub(super) fn image_lines(&self, asset: &Asset, width: u16) -> Vec<Line<'static>> {
        let mut lines = detail_lines(&escaped(&asset.name()), width)
            .into_iter()
            .map(|s| {
                Line::styled(
                    s,
                    Style::default()
                        .fg(color_text())
                        .add_modifier(Modifier::BOLD),
                )
            })
            .collect::<Vec<_>>();
        lines.push(Line::styled(
            format!(
                "{} · {:.1} MiB{}",
                asset.format(),
                asset.bytes as f64 / 1048576.0,
                if asset.available { "" } else { " · 缺失" }
            ),
            Style::default().fg(color_muted()),
        ));
        if let Some(identity) = self.asset_identities.get(&asset.path) {
            lines.push(Line::styled(
                format!("已识别 {}", identity_label(identity)),
                Style::default().fg(color_accent()),
            ));
        }
        let directory = asset
            .path
            .parent()
            .map(|p| self.display_path(p))
            .unwrap_or_default();
        lines.extend(
            detail_lines(&format!("目录 {}", escaped(&directory)), width)
                .into_iter()
                .map(|s| Line::styled(s, Style::default().fg(color_muted()))),
        );
        lines.push(Line::raw(""));
        lines
    }
    fn draw_image_list(&self, frame: &mut Frame, area: Rect) {
        let assets = self.asset_list_for(AssetSection::Images);
        let rows = assets
            .iter()
            .map(|asset| self.image_lines(asset, area.width.saturating_sub(4)))
            .collect::<Vec<_>>();
        frame.render_widget(
            panel()
                .title(format!("镜像 · {} 项", rows.len()))
                .border_style(self.focus_style(Focus::Navigation)),
            area,
        );
        let viewport = area.height.saturating_sub(2) as usize;
        let selected = self.asset_rows[0].min(rows.len().saturating_sub(1));
        let mut states = self.asset_states.borrow_mut();
        let state = &mut states[0];
        let mut offset = state.offset().min(selected);
        while offset < selected
            && rows[offset..=selected].iter().map(Vec::len).sum::<usize>() > viewport
        {
            offset += 1;
        }
        state.select((!rows.is_empty()).then_some(selected));
        *state.offset_mut() = offset;
        let mut y = area.y + 1;
        let mut shown = 0;
        for (index, lines) in rows.iter().enumerate().skip(offset) {
            let height =
                (lines.len() as u16).min(area.bottom().saturating_sub(1).saturating_sub(y));
            if height == 0 {
                break;
            }
            let rect = Rect::new(area.x + 1, y, area.width.saturating_sub(2), height);
            let style = Style::default().bg(if index == selected {
                color_selected_bg()
            } else {
                color_surface()
            });
            frame.render_widget(
                Paragraph::new(" ".repeat(rect.width as usize)).style(style),
                rect,
            );
            frame.render_widget(
                Paragraph::new(lines[..height as usize].to_vec()).style(style),
                Rect::new(rect.x + 2, y, rect.width.saturating_sub(2), height),
            );
            if index == selected {
                frame.render_widget(
                    Paragraph::new("› ").style(style.fg(color_focus())),
                    Rect::new(rect.x, y, 2, 1),
                );
            }
            self.hits
                .borrow_mut()
                .asset_rows
                .push((rect, AssetSection::Images, index));
            y += height;
            shown += 1;
        }
        let mut hits = self.hits.borrow_mut();
        hits.assets = area;
        hits.asset_offset = offset;
        hits.asset_lists.push((area, AssetSection::Images, offset));
        drop(hits);
        self.draw_scrollbar(
            frame,
            area,
            rows.len(),
            shown.max(1),
            offset,
            ScrollTarget::Assets(AssetSection::Images),
        );
        if rows.is_empty() {
            frame.render_widget(
                Paragraph::new("没有镜像 · a 导入镜像").style(Style::default().fg(color_muted())),
                area.inner(ratatui::layout::Margin::new(1, 1)),
            );
        }
    }
}
