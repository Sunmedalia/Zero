//! Frame chrome shared by both pages: navigation tabs, the system picker, the
//! search field and the popup frame.
use super::*;

impl App {
    pub(super) fn draw_system_buttons(&self, frame: &mut Frame, area: Rect) {
        let mut x = area.x;
        if area.width >= 29 {
            frame.render_widget(
                Paragraph::new(" 系统: ").style(Style::default().fg(color_muted())),
                Rect::new(x, area.y, 7, area.height),
            );
            x += 7;
        }
        for (label, os) in [
            (" Linux ", crate::analysis::Os::Linux),
            (" Windows ", crate::analysis::Os::Windows),
        ] {
            let width = Span::raw(label).width() as u16;
            if width > area.right().saturating_sub(x) {
                continue;
            }
            let rect = Rect::new(x, area.y, width, area.height);
            let active = self.shown_os() == os;
            frame.render_widget(
                Paragraph::new(label).style(if active {
                    Style::default()
                        .bg(color_selected_bg())
                        .fg(color_focus())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().bg(color_raised()).fg(color_accent())
                }),
                rect,
            );
            self.hits.borrow_mut().systems.push((rect, os));
            x += width;
        }
    }
    /// Narrow analysis layouts replace the system picker with region tabs, so
    /// the only visible control stays reachable.
    pub(super) fn draw_system_row(&self, frame: &mut Frame, systems: Rect) {
        let layout = Space::new(frame.area().width, frame.area().height);
        if self.page == Page::Analysis && !layout.system_row() {
            self.draw_system_buttons(
                frame,
                Rect::new(systems.x, systems.y, 17.min(systems.width), systems.height),
            );
            let mut x = systems.x + 18.min(systems.width);
            for (label, focus) in [(" 插件 ", Focus::Navigation), (" 内容 ", Focus::Content)] {
                let width =
                    (Span::raw(label).width() as u16).min(systems.right().saturating_sub(x));
                let rect = Rect::new(x, systems.y, width, systems.height);
                frame.render_widget(
                    Paragraph::new(label).style(Style::default().fg(if self.focus == focus {
                        color_focus()
                    } else {
                        color_accent()
                    })),
                    rect,
                );
                self.hits.borrow_mut().regions.push((rect, focus));
                x += width;
            }
        } else {
            self.draw_system_buttons(frame, systems);
        }
    }
    pub(super) fn draw_tabs(&self, frame: &mut Frame, area: Rect) {
        let mut x = area.x;
        for (i, page) in Page::ALL.iter().enumerate() {
            let label = format!(" {} {} ", i + 1, page.title());
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
                        .bg(color_selected_bg())
                        .fg(color_focus())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(color_text())
                }),
                rect,
            );
            self.hits.borrow_mut().tabs.push((rect, *page));
            x = x.saturating_add(width + 1);
        }
        if self.page == Page::Analysis {
            self.draw_system_buttons(
                frame,
                Rect::new(x, area.y, 17.min(area.right().saturating_sub(x)), 1),
            );
        } else if area.width.saturating_sub(x.saturating_sub(area.x)) > 24 {
            let brand = Line::from(vec![
                Span::styled(
                    "ZERO",
                    Style::default()
                        .fg(color_accent())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" 内存取证 ", Style::default().fg(color_muted())),
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
                .block(panel().title(title).border_style(Style::default().fg(
                    if editing.is_some() {
                        color_focus()
                    } else {
                        color_border()
                    },
                ))),
            rect,
        );
        if controls > 0 && rect.height > 1 {
            let confirm = Rect::new(rect.right() - 15, rect.y + 1, 6, 1);
            let cancel = Rect::new(rect.right() - 8, rect.y + 1, 6, 1);
            frame.render_widget(
                Paragraph::new("[确认]").style(Style::default().fg(color_focus())),
                confirm,
            );
            frame.render_widget(
                Paragraph::new("[撤销]").style(Style::default().fg(color_accent())),
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

    /// Border style for a region: accent when focused, plain otherwise.
    pub(super) fn focus_style(&self, focus: Focus) -> Style {
        if self.focus == focus {
            Style::default().fg(color_accent())
        } else {
            Style::default().fg(color_border())
        }
    }
    /// Accent the popup frame and cast a one-cell shadow so modals read above
    /// the content behind them.
    pub(super) fn frame_popup(frame: &mut Frame, popup: Rect) {
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
                    cell.set_fg(color_accent());
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
    /// The one-line analysis header: platform, verification state, symbol and
    /// image, in that order of importance.
    pub(super) fn draw_header(&self, frame: &mut Frame, area: Rect) {
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
                Style::default().fg(color_success()),
            ),
            None if self.preparation == Preparation::Ready => {
                ("运行时验证页表".into(), Style::default().fg(color_text()))
            }
            None => ("尚未验证页表".into(), Style::default().fg(color_warn())),
        };
        let symbol = self
            .result()
            .filter(|r| !r.historical && !r.symbol.is_empty())
            .map(|r| self.display_path(std::path::Path::new(&r.symbol)));
        let (symbol, symbol_style) = match symbol {
            Some(symbol) => (symbol, Style::default().fg(color_text())),
            None if self.symbols.as_os_str().is_empty() => (
                "未选择 · 1 资源库".into(),
                Style::default().fg(color_warn()),
            ),
            None => (
                self.display_path(&self.symbols),
                Style::default().fg(color_text()),
            ),
        };
        let value = Style::default().fg(color_text());
        let separator = || Span::styled(" · ", Style::default().fg(color_border()));
        // One line, filled by priority: what changes, then what identifies the
        // input. Narrow windows drop the tail instead of truncating it
        // mid-word, so a field is either fully readable or not shown.
        let mut line = Vec::new();
        let mut used = 0;
        for (label, text, style) in [
            (
                "镜像: ",
                truncate_with_ellipsis(&image, (area.width as usize / 3).clamp(12, 40)),
                value,
            ),
            (
                "符号: ",
                truncate_with_ellipsis(&symbol, (area.width as usize / 3).clamp(12, 48)),
                symbol_style,
            ),
            ("验证: ", kernel, kernel_style),
        ] {
            let gap = if line.is_empty() { 0 } else { 3 };
            let width = gap + Span::raw(label).width() + Span::raw(&text).width();
            if used + width > area.width as usize {
                break;
            }
            let rect = Rect::new(
                area.x + used as u16 + gap as u16,
                area.y,
                width.saturating_sub(gap) as u16,
                area.height,
            );
            if label == "符号: " {
                self.hits.borrow_mut().header_symbol = rect;
            }
            if label == "镜像: " {
                self.hits.borrow_mut().header_image = rect;
            }
            used += width;
            if gap > 0 {
                line.push(separator());
            }
            line.extend(field(label, escaped(&text), style));
        }
        frame.render_widget(Paragraph::new(Line::from(line)), area);
    }
}
