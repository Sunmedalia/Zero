//! Frame chrome shared by both pages: navigation tabs, the system picker, the
//! search field and the popup frame.
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

    /// Border style for a region: accent when focused, plain otherwise.
    pub(super) fn focus_style(&self, focus: Focus) -> Style {
        if self.focus == focus {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(BORDER)
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
}
