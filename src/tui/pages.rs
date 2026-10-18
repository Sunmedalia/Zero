//! Page composition. `draw` owns the frame skeleton — tabs, system row, header,
//! body and footer — and delegates each region to its module:
//! [`chrome`](super::chrome) for shared widgets, [`assets`](super::assets) for
//! the resource library, [`results`](super::results) for the analysis
//! workbench, [`footer`](super::footer) for status and actions, and
//! [`dialogs`](super::dialogs) for modals.
use super::*;

impl App {
    /// Height the footer needs: a status line, then either the resource
    /// toolbar or the wrapped action strip.
    ///
    /// The resource toolbar carries the page's actions, so it gets the toolbar
    /// budget; it never takes more than a third of the screen, so a short
    /// terminal keeps its list and `更多 ?` covers whatever does not fit.
    fn footer_height(&self, width: u16, height: u16) -> u16 {
        if self.page == Page::Assets {
            let wanted = 2 + action_rows(&toolbar_actions(self.section, self.job.is_some()), width);
            wanted.min((height / 3).max(3))
        } else {
            2
        }
    }
    /// Record where the header's two clickable fields are.
    ///
    /// The analysis header names the image and the symbol on one line; the
    /// resource header uses one line each. A single-line header cannot split
    /// them, so the whole line opens the image picker and `y` remains the way
    /// to symbols.
    fn register_header_hits(&self, header: Rect) {
        let mut hits = self.hits.borrow_mut();
        hits.header = header;
        hits.header_image = Rect::new(header.x, header.y, header.width, header.height.min(1));
        hits.header_symbol = if header.height > 1 {
            Rect::new(header.x, header.y + 1, header.width, 1)
        } else {
            Rect::default()
        };
    }
    pub fn draw(&self, frame: &mut Frame) {
        *self.hits.borrow_mut() = HitMap::default();
        frame.render_widget(
            Block::default().style(Style::default().bg(SURFACE)),
            frame.area(),
        );
        let [tabs, systems, area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(frame.area());
        self.draw_tabs(frame, tabs);
        self.draw_system_row(frame, systems);
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if self.page == Page::Analysis { 1 } else { 0 }),
                Constraint::Min(3),
                Constraint::Length(self.footer_height(frame.area().width, frame.area().height)),
            ])
            .split(area);
        self.register_header_hits(parts[0]);
        self.draw_header(frame, parts[0]);
        if self.page == Page::Assets {
            self.draw_assets(frame, parts[1]);
        } else {
            self.draw_workbench(frame, area, parts[1]);
        }
        self.draw_footer(frame, parts[2]);
        self.draw_dialog(frame, area);
    }
}
