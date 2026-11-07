//! Status line and the contextual action strip shared by both pages.
use super::*;
use crate::bytes::Cells;

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
                    .gauge_style(Style::default().fg(color_accent()).bg(color_raised())),
                status,
            );
        } else {
            let mut message = self
                .started
                .map(|started| {
                    format!(
                        "{} · {}s · Esc 取消",
                        escaped(&self.status),
                        started.elapsed().as_secs()
                    )
                })
                .unwrap_or_else(|| escaped(&self.status));
            if let Some(origin) = self.current_origin() {
                message = format!(
                    " {}  {}",
                    if origin.starts_with("读取缓存") {
                        "缓存读取"
                    } else {
                        "重新分析"
                    },
                    message
                );
            }
            let color = if self.last_error.as_deref() == Some(self.status.as_str()) {
                color_danger()
            } else if self.started.is_some() {
                color_accent()
            } else {
                color_text()
            };
            // The region name is a label, not part of the message: a dim
            // separator keeps them from reading as one sentence.
            let line = vec![
                Span::styled(
                    format!(" {region} "),
                    Style::default()
                        .fg(color_accent())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("│ ", Style::default().fg(color_border())),
                Span::styled(message, Style::default().fg(color)),
            ];
            frame.render_widget(Paragraph::new(Line::from(line)), status);
        }
        if self.page == Page::Assets && self.asset_console {
            self.draw_console_actions(
                frame,
                Rect::new(
                    footer.x,
                    footer.y + 1,
                    footer.width,
                    footer.height.saturating_sub(1),
                ),
            );
        } else if self.page == Page::Assets {
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
        // resource toolbar already occupies that row.
        if self.page == Page::Assets {
            return;
        }
        let strip = footer.y + 1;
        // Actions that do not fit are not dropped silently: the strip ends with
        // `更多 ?`, which opens the palette listing every remaining command.
        let buttons = self.footer_actions();
        let more_label = " 更多 ? ";
        let more_width = Span::raw(more_label).width().cells();
        if footer.height < 2 {
            return;
        }
        let count = fitting_actions(&buttons, footer.width);
        let overflowed = count < buttons.len();
        let mut placed = Vec::new();
        let mut x = footer.x;
        let y = strip;
        for (label, key) in buttons.iter().copied().take(count) {
            placed.push((x, y, label, key));
            x = x
                .saturating_add(Span::raw(format!(" {label} ")).width().cells())
                .saturating_add(1);
        }
        for (px, py, label, key) in &placed {
            let command = Command::from_key(self.page, *key);
            let width = Span::raw(format!(" {label} ")).width().cells();
            let disabled = command.and_then(|command| self.command_disabled(command));
            frame.render_widget(
                Paragraph::new(format!(" {label} ")).style(if disabled.is_some() {
                    Style::default().fg(color_muted()).bg(color_raised())
                } else {
                    Style::default().fg(color_focus()).bg(color_raised())
                }),
                Rect::new(*px, *py, width, 1),
            );
            if disabled.is_none() {
                self.hits
                    .borrow_mut()
                    .buttons
                    .push((Rect::new(*px, *py, width, 1), *key));
            }
        }
        if overflowed {
            // The reservation above guarantees the space is already free.
            let (mx, my) = (x, y);
            let width = more_width.min(footer.right().saturating_sub(mx));
            if width == more_width {
                let rect = Rect::new(mx, my, width, 1);
                frame.render_widget(
                    Paragraph::new(more_label)
                        .style(Style::default().fg(color_accent()).bg(color_raised())),
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
