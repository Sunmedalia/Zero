//! The same track/thumbnail geometry drives painting, clicking and dragging.
use super::*;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ScrollTarget {
    Results,
    Menu,
    Assets(AssetSection),
    CacheScopes,
    CacheItems,
    Detail,
    Popup,
}
#[derive(Clone)]
pub(super) struct Scrollbar {
    pub(super) target: ScrollTarget,
    track: Rect,
    thumb: Rect,
    total: usize,
    viewport: usize,
}
#[derive(Clone)]
pub(super) struct Drag {
    bar: Scrollbar,
    grab: u16,
}
impl App {
    pub(super) fn draw_scrollbar(
        &self,
        frame: &mut Frame,
        area: Rect,
        total: usize,
        viewport: usize,
        offset: usize,
        target: ScrollTarget,
    ) {
        if total <= viewport || area.height < 4 || area.width < 2 {
            return;
        }
        let track = Rect::new(area.right() - 1, area.y + 1, 1, area.height - 2);
        let height = ((track.height as usize * viewport) / total)
            .max(1)
            .min(track.height as usize) as u16;
        let travel = track.height - height;
        let y = track.y
            + ((offset.min(total - viewport) * travel as usize) / (total - viewport)) as u16;
        let thumb = Rect::new(track.x, y, 1, height);
        for y in track.y..track.bottom() {
            frame.buffer_mut()[(track.x, y)]
                .set_symbol(if thumb.contains(Position::new(track.x, y)) {
                    "┃"
                } else {
                    "│"
                })
                .set_fg(if thumb.contains(Position::new(track.x, y)) {
                    color_accent()
                } else {
                    color_border()
                });
        }
        self.hits.borrow_mut().scrollbars.push(Scrollbar {
            target,
            track,
            thumb,
            total,
            viewport,
        });
    }
    fn set_scroll(&mut self, target: ScrollTarget, index: usize) {
        match target {
            ScrollTarget::Results => {
                self.row = index;
                self.focus = Focus::Content;
            }
            ScrollTarget::Menu => {
                self.menu = index;
                self.focus = Focus::Navigation;
            }
            ScrollTarget::Assets(section) => {
                self.section = section;
                self.asset_rows[section.slot()] = index;
            }
            ScrollTarget::CacheScopes => {
                self.cache_page.scope = index;
                self.cache_page.row = 0;
            }
            ScrollTarget::CacheItems => self.cache_page.row = index,
            ScrollTarget::Detail => self.detail_scroll = index,
            ScrollTarget::Popup => {
                if let Some(
                    Dialog::Detail { scroll, .. }
                    | Dialog::AssetDetail { scroll, .. }
                    | Dialog::RemoteDetail { scroll, .. },
                ) = self.dialog.as_mut()
                {
                    *scroll = index;
                }
            }
        }
    }
    pub(super) fn scrollbar_mouse(&mut self, mouse: MouseEvent) -> bool {
        if mouse.kind == MouseEventKind::Up(MouseButton::Left) {
            self.drag = None;
            return true;
        }
        if mouse.kind == MouseEventKind::Drag(MouseButton::Left)
            && let Some(drag) = self.drag.clone()
        {
            let travel = drag.bar.track.height - drag.bar.thumb.height;
            let y = mouse
                .row
                .saturating_sub(drag.bar.track.y + drag.grab)
                .min(travel);
            let offset = if travel == 0 {
                0
            } else {
                (y as usize * (drag.bar.total - drag.bar.viewport) + travel as usize / 2)
                    / travel as usize
            };
            let index = if matches!(drag.bar.target, ScrollTarget::Detail | ScrollTarget::Popup) {
                offset
            } else if offset == 0 {
                0
            } else {
                offset + drag.bar.viewport - 1
            };
            self.set_scroll(drag.bar.target, index);
            return true;
        }
        if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
            return false;
        }
        let point = Position::new(mouse.column, mouse.row);
        let bar = self
            .hits
            .borrow()
            .scrollbars
            .iter()
            .find(|bar| bar.track.contains(point))
            .cloned();
        if let Some(bar) = bar {
            if bar.thumb.contains(point) {
                self.drag = Some(Drag {
                    grab: mouse.row - bar.thumb.y,
                    bar,
                });
            } else {
                let index = (mouse.row - bar.track.y) as usize * (bar.total - 1)
                    / bar.track.height.saturating_sub(1).max(1) as usize;
                self.set_scroll(bar.target, index);
            }
            return true;
        }
        false
    }
}
