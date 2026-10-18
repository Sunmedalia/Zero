//! The analysis page workbench: plugin menu, inspector, content search and the
//! result table, including horizontal scrolling over a virtual canvas.
use super::*;

impl App {
    /// Draw the plugin menu, inspector and result table into `body`.
    pub(super) fn draw_workbench(&self, frame: &mut Frame, area: Rect, body: Rect) {
        let mut main = if area.width >= 100 && frame.area().height >= 20 {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(22), Constraint::Min(20)])
                .split(body);
            self.draw_menu(frame, columns[0], self.focus_style(Focus::Navigation));
            columns[1]
        } else if self.focus == Focus::Navigation {
            self.draw_menu(frame, body, self.focus_style(Focus::Navigation));
            Rect::default()
        } else {
            body
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
                        .border_style(self.focus_style(Focus::Detail)),
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
