//! The analysis page workbench: plugin menu, inspector, content search and the
//! result table, including horizontal scrolling over a virtual canvas.
use super::*;
use crate::bytes::{Cells, float_to_i128};

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
            self.draw_menu(frame, columns.rect(0), self.focus_style(Focus::Navigation));
            columns.rect(1)
        } else if self.focus == Focus::Navigation {
            self.draw_menu(frame, body, self.focus_style(Focus::Navigation));
            Rect::default()
        } else {
            body
        };
        if let Some((lines, scroll)) = self.detail_tab_lines(main.width.saturating_sub(2)) {
            self.hits.borrow_mut().workbench = main;
            self.hits.borrow_mut().result = main;
            let total = lines.len();
            let height = main.height.saturating_sub(2) as usize;
            let scroll = scroll.min(total.saturating_sub(height));
            frame.render_widget(
                Paragraph::new(
                    lines
                        .iter()
                        .skip(scroll)
                        .take(height)
                        .map(|line| Line::raw(line.as_str()))
                        .collect::<Vec<_>>(),
                )
                .block(panel().border_style(self.focus_style(Focus::Content))),
                main,
            );
            self.draw_scrollbar(
                frame,
                main,
                total,
                main.height.saturating_sub(2) as usize,
                scroll,
                ScrollTarget::DetailTab,
            );
            if main.width > 2 {
                self.draw_result_tabs(frame, Rect::new(main.x + 1, main.y, main.width - 2, 1));
            }
            if self.hits.borrow().menu.width == 0 {
                self.draw_plugin_toggle(frame, main, " >> ");
            }
            return;
        }
        if layout.inspector() && self.inspector {
            let columns =
                Layout::horizontal([Constraint::Min(50), Constraint::Length(38)]).split(main);
            main = columns.rect(0);
            self.hits.borrow_mut().inspector = columns.rect(1);
            let lines = self.inspector_lines(columns.rect(1).width.saturating_sub(2));
            let total_lines = lines.len();
            frame.render_widget(
                Paragraph::new(
                    lines
                        .iter()
                        .skip(self.detail_scroll)
                        .take(columns.rect(1).height.saturating_sub(2) as usize)
                        .map(|line| Line::raw(line.as_str()))
                        .collect::<Vec<_>>(),
                )
                .block(
                    panel()
                        .title("详情 · Tab 聚焦 · d 关闭")
                        .border_style(self.focus_style(Focus::Detail)),
                ),
                columns.rect(1),
            );
            self.draw_scrollbar(
                frame,
                columns.rect(1),
                total_lines,
                columns.rect(1).height.saturating_sub(2) as usize,
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
                regions.rect(0),
                &self.query,
                InputKind::Search,
                "内容搜索 · / 编辑 · Enter 确认 · Esc 撤销",
            );
            main = regions.rect(1);
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
            let pending = if self.view_pending() {
                "筛选中… · "
            } else {
                ""
            };
            let title = match result {
                Some(r) => format!(
                    " {} · {pending}{} / {} 条 · {} · 显示 {}–{} 行 ",
                    r.plugin
                        .strip_prefix("windows.")
                        .or_else(|| r.plugin.strip_prefix("linux."))
                        .unwrap_or(&r.plugin),
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
                let columns = self.result_headers(result);
                let natural = self.resolved_column_widths_with_headers(result, &rows, &columns);
                let row_count = rows.len().saturating_sub(page_start).min(page_size);
                let highlight_width: usize = if row_count > 0 { 2 } else { 0 };
                let total = table_total_width(&natural);
                let viewport_width = usize::from(main.width);
                let max_offset = total.saturating_sub(viewport_width);
                let scroll = self.horizontal.min(max_offset);
                let inner_width = usize::from(main.width.saturating_sub(2));
                let view_end = scroll.saturating_add(inner_width);
                let first_x = main.x.saturating_add(1);
                let last_x = main.right().saturating_sub(2);
                let header_y = main.y.saturating_add(1);
                let viewport_block = block.clone();

                // Compute screen column hit rects, resize handles, and the
                // contiguous visible column slice in usize so arbitrarily wide
                // tables (> u16::MAX cells) never truncate.
                let mut hit_columns = Vec::with_capacity(natural.len());
                let mut grips = Vec::new();
                let mut visible_range: Option<(usize, usize, usize)> = None;
                let mut col_start = highlight_width;
                for (index, &width) in natural.iter().enumerate() {
                    let width_usize = usize::from(width);
                    let col_end = col_start.saturating_add(width_usize);
                    let vis_start = col_start.max(scroll);
                    let vis_end = col_end.min(view_end);
                    if vis_end > vis_start {
                        let x = first_x.saturating_add(
                            u16::try_from(vis_start.saturating_sub(scroll)).unwrap_or(u16::MAX),
                        );
                        let w =
                            u16::try_from(vis_end.saturating_sub(vis_start)).unwrap_or(u16::MAX);
                        hit_columns.push(Rect::new(x, header_y, w, 1));
                    } else {
                        hit_columns.push(Rect::new(first_x, header_y, 0, 1));
                    }
                    if width > 0 && col_end >= scroll && col_end < view_end {
                        let x = first_x.saturating_add(
                            u16::try_from(col_end.saturating_sub(scroll)).unwrap_or(u16::MAX),
                        );
                        if x >= first_x && x <= last_x {
                            let left = x.saturating_sub(1).max(first_x);
                            let right = x.saturating_add(1).min(last_x);
                            grips.push(ColumnGrip {
                                cell: Rect::new(x, header_y, 1, 1),
                                hit: Rect::new(
                                    left,
                                    header_y,
                                    right.saturating_sub(left).saturating_add(1),
                                    1,
                                ),
                                index,
                                width,
                            });
                        }
                    }
                    if col_end.saturating_add(1) > scroll && col_start < view_end {
                        visible_range = match visible_range {
                            Some((first, _, first_start)) => Some((first, index, first_start)),
                            None => Some((index, index, col_start)),
                        };
                    }
                    col_start = col_end.saturating_add(1);
                }

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
                if scroll == 0 && total <= viewport_width {
                    let widths: Vec<_> = natural.iter().copied().map(Constraint::Length).collect();
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
                    frame.render_stateful_widget(table, main, &mut state);
                } else if let Some((first_col, last_col, first_start)) = visible_range {
                    let range = first_col..last_col.saturating_add(1);
                    let visible_slice = natural.get(range.clone()).unwrap_or(&[]);
                    let widths: Vec<_> = visible_slice
                        .iter()
                        .copied()
                        .map(Constraint::Length)
                        .collect();
                    let visible_headers: Vec<_> =
                        columns.get(range.clone()).unwrap_or(&[]).to_vec();
                    let window_origin = first_start.saturating_sub(highlight_width);
                    let local_scroll = scroll.saturating_sub(window_origin);
                    let local_scroll_u16 = u16::try_from(local_scroll).unwrap_or(u16::MAX);
                    let slice_width = visible_slice
                        .iter()
                        .map(|&w| usize::from(w))
                        .sum::<usize>()
                        .saturating_add(last_col.saturating_sub(first_col))
                        .saturating_add(highlight_width)
                        .saturating_add(2);
                    let mini_width =
                        u16::try_from(slice_width.max(local_scroll.saturating_add(viewport_width)))
                            .unwrap_or(u16::MAX)
                            .max(main.width);
                    let render_area = Rect::new(0, 0, mini_width, main.height);
                    let table = Table::new(
                        rows.sample(page_start, page_size)
                            .enumerate()
                            .map(|(i, row)| {
                                Row::new(cells_to_line_range(row, range.clone())).style(
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
                        Row::new(visible_headers).style(
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
                    let mut buffer = ratatui::buffer::Buffer::empty(render_area);
                    StatefulWidget::render(table, render_area, &mut buffer, &mut state);
                    for dy in 0..main.height {
                        for dx in 0..main.width {
                            let src_x = local_scroll_u16.saturating_add(dx);
                            if src_x < mini_width {
                                frame.buffer_mut()
                                    [(main.x.saturating_add(dx), main.y.saturating_add(dy))] =
                                    buffer[(src_x, dy)].clone();
                            }
                        }
                    }
                    // Preserve viewport borders when the data scrolls horizontally.
                    frame.render_widget(viewport_block, main);
                } else {
                    frame.render_widget(viewport_block, main);
                }
                let view = self.view_key();
                let dragging = self
                    .column_drag
                    .as_ref()
                    .filter(|drag| drag.view == view)
                    .and_then(|drag| drag.column.find_in(&result.columns));
                for grip in &grips {
                    let active = dragging == Some(grip.index);
                    frame.buffer_mut()[(grip.cell.x, grip.cell.y)]
                        .set_symbol(if active { "┃" } else { "│" })
                        .set_style(Style::default().fg(if active {
                            color_accent()
                        } else {
                            color_border()
                        }));
                }
                {
                    let mut hits = self.hits.borrow_mut();
                    hits.columns = hit_columns;
                    hits.column_grips = grips;
                    hits.drawn_widths = natural;
                    hits.result_header_visible = true;
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
                main.x + main.width.saturating_sub(28) / 2,
                main.y + 6,
                28.min(main.width.saturating_sub(2)),
                3,
            );
            frame.render_widget(
                Paragraph::new("打开资源库 · 镜像 →")
                    .alignment(ratatui::layout::Alignment::Center)
                    .style(
                        Style::default()
                            .fg(color_focus())
                            .bg(color_selected_bg())
                            .add_modifier(Modifier::BOLD),
                    )
                    .block(
                        panel()
                            .style(Style::default().fg(color_focus()).bg(color_selected_bg()))
                            .border_style(Style::default().fg(color_accent())),
                    ),
                rect,
            );
            self.hits
                .borrow_mut()
                .buttons
                .push((rect, KeyCode::Char('1')));
        }
        if main.width > 2 {
            self.draw_result_tabs(frame, Rect::new(main.x + 1, main.y, main.width - 2, 1));
            if let Some(origin) = self.current_origin() {
                frame.render_widget(
                    Paragraph::new(origin).style(Style::default().fg(color_muted())),
                    Rect::new(
                        main.x
                            + if self.hits.borrow().menu.width == 0 {
                                5
                            } else {
                                1
                            },
                        main.bottom().saturating_sub(1),
                        main.width.saturating_sub(6),
                        1,
                    ),
                );
            }
        }
        if main.width > 2 && main.height > 2 && self.inspector && !layout.inspector() {
            let rect = main;
            frame.render_widget(Clear, rect);
            let lines = self.inspector_lines(rect.width.saturating_sub(2));
            let total = lines.len();
            frame.render_widget(
                Paragraph::new(
                    lines
                        .iter()
                        .skip(self.detail_scroll)
                        .take(rect.height.saturating_sub(2) as usize)
                        .map(|line| Line::raw(line.as_str()))
                        .collect::<Vec<_>>(),
                )
                .style(Style::default().fg(color_text()).bg(color_surface()))
                .block(panel().title("详情 · d / Esc 关闭")),
                rect,
            );
            self.hits.borrow_mut().inspector = rect;
            let mut hits = self.hits.borrow_mut();
            hits.columns.clear();
            hits.column_grips.clear();
            hits.result_header_visible = false;
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
                pulses
                    .get(usize::try_from(float_to_i128(elapsed * 1000.0 / 180.0)).unwrap_or(0) % 4)
                    .copied()
                    .unwrap_or("●··"),
                status::format_duration(elapsed)
            );
            let width = Span::raw(&label)
                .width()
                .cells()
                .saturating_add(4)
                .min(main.width.saturating_sub(2));
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
        if self.hits.borrow().menu.width == 0 {
            self.draw_plugin_toggle(frame, main, " >> ");
        }
    }
    fn draw_plugin_toggle(&self, frame: &mut Frame, area: Rect, label: &str) {
        if area.width < 6 || area.height == 0 {
            return;
        }
        let rect = Rect::new(
            if label.contains(">>") {
                area.x
            } else {
                area.right() - 5
            },
            area.bottom() - 1,
            4,
            1,
        );
        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(color_accent()).bg(color_surface())),
            rect,
        );
        self.hits.borrow_mut().plugin_toggle = rect;
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
        self.draw_plugin_toggle(frame, area, " << ");
    }
    pub(super) fn result_headers(&self, result: &Results) -> Vec<String> {
        result
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
            .collect()
    }
    /// Natural column widths overridden by any user-adjusted widths for this
    /// view, keyed by `(column_name, duplicate_occurrence)` and clamped to the
    /// supported column width range.
    pub(super) fn resolved_column_widths_with_headers(
        &self,
        result: &Results,
        rows: &IndexedRows<'_>,
        headers: &[String],
    ) -> Vec<u16> {
        // Widths depend only on the header and the first sampled rows of this
        // index, so they are reused until either changes.
        let natural = {
            let mut cache = self.width_cache.borrow_mut();
            match cache.as_ref() {
                Some((index, cached_headers, widths))
                    if std::rc::Rc::ptr_eq(index, &rows.index)
                        && cached_headers.as_slice() == headers =>
                {
                    widths.clone()
                }
                _ => {
                    let widths = table_widths(headers, rows.sample(0, 200));
                    *cache = Some((rows.index.clone(), headers.to_vec(), widths.clone()));
                    widths
                }
            }
        };
        let keys = ColumnKey::all(&result.columns);
        natural
            .iter()
            .zip(&keys)
            .map(|(width, key)| {
                self.column_widths
                    .get(key)
                    .copied()
                    .map(|w| mouse::clamp_column_width(i32::from(w)))
                    .unwrap_or(*width)
            })
            .collect()
    }
    pub(super) fn resolved_column_widths_for(
        &self,
        result: &Results,
        rows: &IndexedRows<'_>,
    ) -> Vec<u16> {
        let headers = self.result_headers(result);
        self.resolved_column_widths_with_headers(result, rows, &headers)
    }
    /// Computes the result table viewport `Rect` from the current layout
    /// toggles (`plugins_collapsed`, `inspector`, `focus`, search bar).
    pub(super) fn workbench_result_rect(&self, area: Rect, body: Rect, frame_height: u16) -> Rect {
        let layout = Space::new(area.width, frame_height);
        let menu_width = layout.menu_width();
        let mut main = if self.plugins_collapsed {
            body
        } else if layout.two_panes() {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(menu_width), Constraint::Min(20)])
                .split(body)
                .rect(1)
        } else if self.focus == Focus::Navigation {
            Rect::default()
        } else {
            body
        };
        if self.active_detail().is_some() {
            return main;
        }
        if layout.inspector() && self.inspector {
            main = Layout::horizontal([Constraint::Min(50), Constraint::Length(38)])
                .split(main)
                .rect(0);
        }
        let searching = matches!(
            &self.dialog,
            Some(Dialog::Input {
                kind: InputKind::Search,
                ..
            })
        ) || !self.query.is_empty();
        if main.width > 0 && searching {
            main = Layout::vertical([Constraint::Length(3), Constraint::Min(2)])
                .split(main)
                .rect(1);
        }
        main
    }
    /// Current result table viewport computed from the known terminal size and
    /// live layout flags, so keyboard commands stay in sync with rendering even
    /// within the same event batch before a redraw.
    pub(super) fn current_result_area(&self) -> Rect {
        let Some((width, height)) = self.terminal_size.get() else {
            return self.hits.borrow().result;
        };
        if width < 60 || height < 16 || self.page != Page::Analysis {
            return Rect::default();
        }
        let frame_area = Rect::new(0, 0, width, height);
        let [_, _, area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(frame_area);
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(0),
                Constraint::Min(3),
                Constraint::Length(self.footer_height(width, height)),
            ])
            .split(area);
        self.workbench_result_rect(area, parts.rect(1), height)
    }
    /// Maximum horizontal scroll offset for the current result table and
    /// live viewport width.
    pub(super) fn max_horizontal_offset(&self) -> usize {
        let Some(result) = self.result() else {
            return 0;
        };
        let rows = self.visible();
        let widths = self.resolved_column_widths_for(result, &rows);
        let area = self.current_result_area();
        if area.width > 0 {
            max_horizontal_offset_for(&widths, area)
        } else {
            table_total_width(&widths)
        }
    }
    pub(super) fn clamped_horizontal_for(&self, widths: &[u16]) -> usize {
        let area = self.current_result_area();
        if area.width > 0 {
            self.horizontal.min(max_horizontal_offset_for(widths, area))
        } else {
            self.horizontal.min(table_total_width(widths))
        }
    }
}

fn cells_to_line_range(
    (cells, decoration): BorrowedRow<'_>,
    range: std::ops::Range<usize>,
) -> Vec<Line<'static>> {
    let start = range.start;
    cells
        .get(range)
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .map(|(offset, cell)| {
            let col = start.saturating_add(offset);
            let text = match decoration.as_ref() {
                Some((column, decorated)) if *column == col => decorated,
                _ => cell,
            };
            Line::from(escaped(text))
        })
        .collect()
}

pub(super) fn table_total_width(widths: &[u16]) -> usize {
    widths
        .iter()
        .map(|&width| usize::from(width))
        .sum::<usize>()
        .saturating_add(widths.len().saturating_sub(1))
        .saturating_add(4)
}

pub(super) fn max_horizontal_offset_for(widths: &[u16], area: Rect) -> usize {
    if widths.is_empty() || area.width == 0 {
        return 0;
    }
    table_total_width(widths).saturating_sub(usize::from(area.width))
}

pub(super) fn leftmost_visible_column(
    widths: &[u16],
    scroll: usize,
    has_rows: bool,
) -> Option<usize> {
    if widths.is_empty() {
        return None;
    }
    let mut offset = if has_rows { 2usize } else { 0usize };
    for (index, &width) in widths.iter().enumerate() {
        let end = offset.saturating_add(usize::from(width));
        if end > scroll {
            return Some(index);
        }
        offset = end.saturating_add(1);
    }
    widths.len().checked_sub(1)
}
