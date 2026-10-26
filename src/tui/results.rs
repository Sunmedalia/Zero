//! The analysis page workbench: plugin menu, inspector, content search and the
//! result table, including horizontal scrolling over a virtual canvas.
use super::*;

impl App {
    /// Draw the plugin menu, inspector and result table into `body`.
    pub(super) fn draw_workbench(&self, frame: &mut Frame, area: Rect, body: Rect) {
        // Two columns as soon as both can carry their content: a 20-cell menu
        // plus a table. Below that the pane switch is honest, because neither
        // would be usable. Keeping both visible at 80 columns means the menu no
        // longer hides the results on ordinary terminals.
        let layout = Space::new(area.width, frame.area().height);
        let menu_width = layout.menu_width();
        let mut main = if self.plugins_collapsed {
            body
        } else if layout.two_panes() {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(menu_width), Constraint::Min(20)])
                .split(body);
            self.draw_menu(frame, columns[0], self.focus_style(Focus::Navigation));
            columns[1]
        } else if self.focus == Focus::Navigation {
            self.draw_menu(frame, body, self.focus_style(Focus::Navigation));
            Rect::default()
        } else {
            body
        };
        if layout.inspector() && self.inspector {
            let columns =
                Layout::horizontal([Constraint::Min(50), Constraint::Length(38)]).split(main);
            main = columns[0];
            self.hits.borrow_mut().inspector = columns[1];
            let text = self.detail_text();
            let lines = detail_lines(&text, columns[1].width.saturating_sub(2));
            let total_lines = lines.len();
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
                        .border_style(self.focus_style(Focus::Detail)),
                ),
                columns[1],
            );
            self.draw_scrollbar(
                frame,
                columns[1],
                total_lines,
                columns[1].height.saturating_sub(2) as usize,
                self.detail_scroll,
                ScrollTarget::Detail,
            );
        }
        self.hits.borrow_mut().workbench = main;
        // Same rule as the asset panes: the search field only claims a row
        // while it is being edited or holds a query. The result table keeps the
        // rest, and the query is still visible in its title when set.
        let searching = matches!(
            &self.dialog,
            Some(Dialog::Input {
                kind: InputKind::Search,
                ..
            })
        ) || !self.query.is_empty();
        if main.width > 0 && searching {
            let regions = Layout::vertical([Constraint::Length(3), Constraint::Min(2)]).split(main);
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
            let block = panel()
                .title(title)
                .border_style(self.focus_style(Focus::Content));
            if let Some(result) = result {
                let columns = result
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        if self.sort == Some(i) {
                            format!("{} {}", escaped(c), if self.descending { "↓" } else { "↑" })
                        } else {
                            escaped(c)
                        }
                    })
                    .collect::<Vec<_>>();
                // Size and draw from borrowed cells: a 1200-row table is
                // re-laid out every frame, so cloning rows here dominated the
                // render.
                let natural = table_widths(&columns, rows.sample(0, 200));
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
                let row_count = rows.len().saturating_sub(page_start).min(page_size);
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
                    rows.sample(page_start, page_size)
                        .enumerate()
                        .map(|(i, row)| {
                            Row::new(cells_to_line(row)).style(
                                Style::default().fg(color_text()).bg(
                                    if (page_start + i) % 2 == 1 {
                                        color_stripe()
                                    } else {
                                        color_surface()
                                    },
                                ),
                            )
                        }),
                    widths,
                )
                .header(
                    Row::new(columns).style(
                        Style::default()
                            .fg(color_accent())
                            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                    ),
                )
                .block(block)
                .row_highlight_style(
                    Style::default()
                        .bg(color_selected_bg())
                        .fg(color_focus())
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
                if result.rows.is_empty() && main.height > 4 {
                    frame.render_widget(
                        Paragraph::new("未发现记录")
                            .alignment(ratatui::layout::Alignment::Center)
                            .style(Style::default().fg(color_muted())),
                        Rect::new(main.x + 1, main.y + 2, main.width.saturating_sub(2), 1),
                    );
                }
                let offset = page_start + state.offset();
                self.hits.borrow_mut().row_offset = offset;
                self.draw_scrollbar(
                    frame,
                    main,
                    rows.len(),
                    page_size,
                    page_start,
                    ScrollTarget::Results,
                );
                let mut saved = self.table_state.borrow_mut();
                saved.select((row_count > 0).then_some(selected_row));
                *saved.offset_mut() = offset;
            } else {
                frame.render_widget(
                    Paragraph::new(vec![
                        Line::raw(""),
                        Line::styled(
                            if self.image.is_none() {
                                "选择镜像，开始内存分析"
                            } else if self.symbols.as_os_str().is_empty() {
                                "尚未选择符号；y 选择本地符号，M 精确匹配"
                            } else {
                                "尚无结果"
                            },
                            Style::default()
                                .fg(color_text())
                                .add_modifier(Modifier::BOLD),
                        ),
                        Line::styled(
                            "浏览左侧插件或按 p 搜索",
                            Style::default().fg(color_muted()),
                        ),
                        Line::styled(
                            "点击或 Enter 选择插件即运行",
                            Style::default().fg(color_muted()),
                        ),
                        Line::styled("1 资源库 · ? 命令面板", Style::default().fg(color_muted())),
                    ])
                    .alignment(ratatui::layout::Alignment::Center)
                    .block(block),
                    main,
                );
            }
        }
        if main.width > 20 && main.height > 7 && self.image.is_none() && self.result().is_none() {
            let rect = Rect::new(
                main.x + 2,
                main.y + 6,
                main.width.saturating_sub(4).min(24),
                1,
            );
            frame.render_widget(
                Paragraph::new("[选择镜像 i]").style(Style::default().fg(color_accent())),
                rect,
            );
            self.hits
                .borrow_mut()
                .buttons
                .push((rect, KeyCode::Char('i')));
        }
        if main.width > 2 {
            self.draw_result_tabs(frame, Rect::new(main.x + 1, main.y, main.width - 2, 1));
            if let Some(origin) = self.current_origin() {
                frame.render_widget(
                    Paragraph::new(origin).style(Style::default().fg(color_muted())),
                    Rect::new(
                        main.x + 2,
                        main.bottom().saturating_sub(1),
                        main.width.saturating_sub(4),
                        1,
                    ),
                );
            }
        }
        if main.width > 2 && main.height > 2 && self.inspector && !layout.inspector() {
            let rect = main;
            frame.render_widget(Clear, rect);
            let lines = detail_lines(&self.detail_text(), rect.width.saturating_sub(2));
            let total = lines.len();
            frame.render_widget(
                Paragraph::new(
                    lines
                        .into_iter()
                        .skip(self.detail_scroll)
                        .map(Line::raw)
                        .collect::<Vec<_>>(),
                )
                .style(Style::default().fg(color_text()).bg(color_surface()))
                .block(panel().title("详情 · d / Esc 关闭")),
                rect,
            );
            self.hits.borrow_mut().inspector = rect;
            let mut hits = self.hits.borrow_mut();
            hits.columns.clear();
            hits.result_tabs.clear();
            hits.result_tab_steps.clear();
            hits.scrollbars
                .retain(|bar| bar.target != ScrollTarget::Results);
            drop(hits);
            self.draw_scrollbar(
                frame,
                rect,
                total,
                rect.height.saturating_sub(2) as usize,
                self.detail_scroll,
                ScrollTarget::Detail,
            );
        }
        if main.width > 10 && main.height > 4 && self.job.is_some() {
            let pulses = ["●··", "·●·", "··●", "·●·"];
            let elapsed = self.started.map_or(0.0, |t| t.elapsed().as_secs_f64());
            let label = format!(
                "运行中 {} · {} · Esc 取消",
                pulses[((elapsed * 1000.0 / 180.0) as usize) % 4],
                status::format_duration(elapsed)
            );
            let width = (Span::raw(&label).width() as u16 + 4).min(main.width.saturating_sub(2));
            let rect = Rect::new(
                main.x + (main.width - width) / 2,
                main.y + main.height / 2 - 1,
                width,
                3,
            );
            frame.render_widget(Clear, rect);
            frame.render_widget(
                Paragraph::new(label)
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(Style::default().fg(color_accent()).bg(color_raised()))
                    .block(panel()),
                rect,
            );
        }
    }
    pub(super) fn draw_menu(&self, frame: &mut Frame, area: Rect, style: Style) {
        // Carry the scroll offset across frames. A fresh `ListState` restarts at
        // the top every frame, so moving past the visible window left the
        // highlight off screen and the list appeared frozen.
        // `List` only scrolls far enough to reveal the selection, and it does so
        // inside the render, which cannot be observed from here. The offset is
        // therefore computed: keep the selection inside a window that starts at
        // the remembered row.
        let visible = area.height.saturating_sub(2) as usize;
        let mut offset = self.menu_scroll.get();
        if self.menu < offset {
            offset = self.menu;
        } else if visible > 0 && self.menu >= offset + visible {
            offset = self.menu + 1 - visible;
        }
        let mut state = ListState::default()
            .with_selected(Some(self.menu))
            .with_offset(offset);
        let plugins = self.navigation_plugins();
        // Rows are bare plugin names: one row per selectable item, so the
        // clicked row, the scroll offset and `self.menu` all use the same
        // index. Category boundaries are not marked here. A marker on the
        // first row of each group says "something changed" without saying
        // what, and `·` already means "label · value" everywhere else in this
        // interface, so it read as a stray separator. The category is named
        // in the title instead.
        let items = self
            .menu_items()
            .iter()
            .map(|label| ListItem::new(*label))
            .collect::<Vec<_>>();
        // The menu column is 22 cells wide, so the title names the category
        // only; `p` is already in the footer action strip.
        let title = plugins
            .get(self.menu)
            .map(|p| format!("插件 · {}", p.category()))
            .unwrap_or_else(|| "插件".into());
        frame.render_stateful_widget(
            List::new(items)
                .style(Style::default().fg(color_text()))
                .block(panel().title(title).border_style(style))
                .highlight_style(
                    Style::default()
                        .bg(color_selected_bg())
                        .fg(color_focus())
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("› "),
            area,
            &mut state,
        );
        // Remember where the list ended up: `List` scrolls the selection into
        // view internally, and the next frame has to start from there.
        self.menu_scroll.set(state.offset());
        let mut hits = self.hits.borrow_mut();
        hits.menu = area;
        hits.menu_offset = state.offset();
        drop(hits);
        self.draw_scrollbar(
            frame,
            area,
            self.menu_items().len(),
            area.height.saturating_sub(2) as usize,
            self.menu_scroll.get(),
            ScrollTarget::Menu,
        );
    }
}
