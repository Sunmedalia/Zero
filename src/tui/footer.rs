//! Status line and the contextual action strip shared by both pages.
use super::*;

impl App {
    /// Draw the status line, the resource toolbar (assets page) and the action
    /// strip for the focused region.
    pub(super) fn draw_footer(&self, frame: &mut Frame, footer: Rect) {
        // The region name is part of the status line rather than its own row:
        // both describe where you are, and a bordered title row cost a line
        // that the result table needs more.
        let region = match self.focus {
            Focus::Context => "镜像信息",
            Focus::Navigation if self.page == Page::Analysis => "插件",
            Focus::Detail => "详情",
            _ if self.page == Page::Assets => self.section.title(),
            _ => "内容",
        };
        let status = Rect::new(
            footer.x,
            footer.y,
            footer.width,
            u16::from(footer.height > 0),
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
            let mut line = vec![Span::styled(
                format!(" {region} "),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )];
            line.push(Span::styled(message, Style::default().fg(color)));
            frame.render_widget(Paragraph::new(Line::from(line)), status);
        }
        if self.page == Page::Assets {
            self.draw_asset_toolbar(
                frame,
                Rect::new(
                    footer.x,
                    footer.y + 1,
                    footer.width,
                    footer.height.saturating_sub(1),
                ),
            );
        }
        // The action strip sits under the status line. On the assets page the
        // toolbar occupies that row, so the strip moves one row down.
        let strip = footer.y + if self.page == Page::Assets { 2 } else { 1 };
        // Actions that do not fit are not dropped silently: the strip ends with
        // `更多 ?`, which opens the palette listing every remaining command.
        let buttons = self.footer_actions();
        let more_label = " 更多 ? ";
        let more_width = Span::raw(more_label).width() as u16;
        let mut x = footer.x;
        let mut truncated = false;
        if footer.height >= 2 {
            for (index, (label, key)) in buttons.iter().copied().enumerate() {
                let command = Command::from_key(self.page, key);
                let text = format!(" {label} ");
                let width = Span::raw(&text).width() as u16;
                let last = index + 1 == buttons.len();
                if x + width + if last { 0 } else { 1 + more_width } > footer.right() {
                    truncated = true;
                    break;
                }
                let rect = Rect::new(x, strip, width, 1);
                let disabled = command.and_then(|command| self.command_disabled(command));
                frame.render_widget(
                    Paragraph::new(text).style(if disabled.is_some() {
                        Style::default().fg(MUTED).bg(RAISED)
                    } else {
                        Style::default().fg(FOCUS).bg(RAISED)
                    }),
                    rect,
                );
                if disabled.is_none() {
                    self.hits.borrow_mut().buttons.push((rect, key));
                }
                x += width + 1;
            }
            if truncated {
                let width = more_width.min(footer.right().saturating_sub(x));
                if width > 0 {
                    let rect = Rect::new(x, strip, width, 1);
                    frame.render_widget(
                        Paragraph::new(more_label).style(Style::default().fg(ACCENT).bg(RAISED)),
                        rect,
                    );
                    self.hits
                        .borrow_mut()
                        .buttons
                        .push((rect, KeyCode::Char('?')));
                }
            }
        }
    }
}
