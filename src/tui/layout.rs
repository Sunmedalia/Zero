//! One place that decides what the current terminal can show.
//!
//! Layout thresholds used to be scattered across the renderers and the focus
//! logic, with several different numbers for the same question: the analysis
//! page asked `width >= 64` to split into columns, `width < 100` to show the
//! region tabs, and `width < 140` to allow the inspector, so a 100-column
//! terminal was simultaneously "wide enough" and "too narrow" depending on
//! which line of code asked. This module answers every such question from one
//! description of the space, so the renderers, the focus cycle and the resize
//! handler cannot disagree.

/// What the current frame has room for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Space {
    pub(super) width: u16,
    pub(super) height: u16,
}

impl Space {
    pub(super) fn new(width: u16, height: u16) -> Self {
        Self { width, height }
    }
    /// Narrowest terminal the two-pane layouts are drawn in. Below this a
    /// 20-cell menu would leave too little for the table beside it, so the
    /// panes become a switch instead.
    pub(super) const MIN_TWO_PANE: u16 = 100;
    /// Below this height the panes are stacked rather than side by side: a
    /// table needs a header row and a few rows to be worth splitting.
    pub(super) const MIN_TWO_PANE_HEIGHT: u16 = 24;
    /// Menu column widths. The longest plugin label is 18 cells and the
    /// highlight marker takes two more, so anything narrower clips names.
    pub(super) const WIDE_MENU: u16 = 24;
    pub(super) const NARROW_MENU: u16 = 22;
    /// Width at which the analysis page can afford the system picker row and
    /// the inspector column beside the workbench.
    pub(super) const MIN_INSPECTOR: u16 = 160;
    /// Width and height at which the resource page can afford its inline
    /// detail panel below the lists.
    pub(super) const MIN_ASSET_DETAIL_WIDTH: u16 = 100;
    pub(super) const MIN_ASSET_DETAIL_HEIGHT: u16 = 28;
    /// Two panes side by side, rather than one pane at a time.
    pub(super) fn two_panes(&self) -> bool {
        self.width >= Self::MIN_TWO_PANE && self.height >= Self::MIN_TWO_PANE_HEIGHT
    }
    pub(super) fn menu_width(&self) -> u16 {
        if self.width >= 100 {
            Self::WIDE_MENU
        } else {
            Self::NARROW_MENU
        }
    }
    /// The analysis inspector column beside the workbench.
    pub(super) fn inspector(&self) -> bool {
        self.width >= Self::MIN_INSPECTOR && self.height >= 28
    }
    /// The resource page's inline detail panel.
    pub(super) fn asset_detail(&self) -> bool {
        self.width >= Self::MIN_ASSET_DETAIL_WIDTH && self.height >= Self::MIN_ASSET_DETAIL_HEIGHT
    }
    /// Width below which a list pane cannot also show a full digest: the
    /// metadata after the path has to shrink to just the format.
    pub(super) const MIN_FULL_DIGEST_PANE: u16 = 60;
    /// Whether a pane this wide can keep the digest beside the path.
    pub(super) fn full_digest(&self) -> bool {
        self.width >= Self::MIN_FULL_DIGEST_PANE
    }
    /// The analysis page's system picker row, which the narrow layout replaces
    /// with region tabs.
    pub(super) fn system_row(&self) -> bool {
        self.width >= Self::MIN_ASSET_DETAIL_WIDTH && self.height >= 20
    }
}
