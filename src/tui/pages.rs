//! Page composition. `draw` owns the frame skeleton — tabs, system row, header,
//! body and footer — and delegates each region to its module:
//! [`chrome`](super::chrome) for shared widgets, [`assets`](super::assets) for
//! the resource library, [`results`](super::results) for the analysis
//! workbench, [`footer`](super::footer) for status and actions, and
//! [`dialogs`](super::dialogs) for modals.
use super::*;

impl App {
    /// One status row and exactly one action row on every page.
    fn footer_height(&self, _width: u16, _height: u16) -> u16 {
        2
    }
    /// The analysis renderer registers individual fields; other headers use
    /// separate image and symbol rows.
    fn register_header_hits(&self, header: Rect) {
        let mut hits = self.hits.borrow_mut();
        hits.header = header;
        if self.page == Page::Analysis {
            hits.header_image = Rect::default();
            hits.header_symbol = Rect::default();
            return;
        }
        hits.header_image = Rect::new(header.x, header.y, header.width, header.height.min(1));
        hits.header_symbol = if header.height > 1 {
            Rect::new(header.x, header.y + 1, header.width, 1)
        } else {
            Rect::default()
        };
    }
    pub fn draw(&self, frame: &mut Frame) {
        self.terminal_size
            .set(Some((frame.area().width, frame.area().height)));
        theme::apply(&self.settings.theme);
        *self.hits.borrow_mut() = HitMap::default();
        frame.render_widget(
            Block::default().style(Style::default().bg(color_surface())),
            frame.area(),
        );
        if frame.area().width < 60 || frame.area().height < 16 {
            frame.render_widget(
                Paragraph::new(if matches!(self.dialog, Some(Dialog::Quit { .. })) {
                    "确定退出？Enter 确认 · Esc 取消"
                } else {
                    "终端过小，请调整至至少 60×16 · q 退出"
                })
                .style(Style::default().fg(color_text())),
                frame.area(),
            );
            return;
        }
        let [tabs, systems, area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(frame.area());
        self.draw_tabs(frame, tabs);
        if self.page == Page::Analysis {
            self.register_header_hits(systems);
            self.draw_header(frame, systems);
        } else {
            self.draw_system_row(frame, systems);
        }
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(0),
                Constraint::Min(3),
                Constraint::Length(self.footer_height(frame.area().width, frame.area().height)),
            ])
            .split(area);

        if self.page == Page::Assets {
            self.draw_assets(frame, parts.rect(1));
        } else if self.page == Page::Cache {
            self.draw_cache_page(frame, parts.rect(1));
        } else {
            self.draw_workbench(frame, area, parts.rect(1));
        }
        self.draw_footer(frame, parts.rect(2));
        self.draw_dialog(frame, area);
    }
}
