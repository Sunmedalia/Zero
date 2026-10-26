//! Palettes are local to the UI thread, so independent test renderers cannot race.
use ratatui::style::Color;
use std::cell::Cell;
pub(super) const THEMES: &[(&str, &str)] = &[
    ("auto", "跟随终端"),
    ("slate", "石板（深色）"),
    ("light", "纸白（浅色）"),
    ("solarized", "Solarized（深色）"),
    ("phosphor", "荧光绿（终端）"),
    ("contrast", "高对比"),
];
thread_local! { static CURRENT: Cell<usize> = const { Cell::new(0) }; static LIGHT: Cell<bool> = const { Cell::new(false) }; }
pub(super) fn apply(id: &str) {
    let id = if id == "auto" {
        if LIGHT.get() { "light" } else { "slate" }
    } else {
        id
    };
    CURRENT.set(
        THEMES[1..]
            .iter()
            .position(|(key, _)| *key == id)
            .unwrap_or(0),
    );
}
pub(super) fn set_background(light: bool) {
    LIGHT.set(light);
}
pub(super) fn color_accent() -> Color {
    let colors = [
        Color::Rgb(130, 180, 232),
        Color::Rgb(31, 95, 158),
        Color::Rgb(38, 139, 210),
        Color::Rgb(95, 215, 135),
        Color::Rgb(92, 200, 255),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_focus() -> Color {
    let colors = [
        Color::Rgb(184, 216, 250),
        Color::Rgb(11, 61, 110),
        Color::Rgb(147, 212, 255),
        Color::Rgb(175, 255, 207),
        Color::Rgb(255, 255, 255),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_selected_bg() -> Color {
    let colors = [
        Color::Rgb(38, 59, 82),
        Color::Rgb(207, 224, 243),
        Color::Rgb(13, 61, 77),
        Color::Rgb(22, 64, 42),
        Color::Rgb(0, 58, 117),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_surface() -> Color {
    let colors = [
        Color::Rgb(21, 27, 36),
        Color::Rgb(247, 248, 250),
        Color::Rgb(0, 43, 54),
        Color::Rgb(11, 18, 13),
        Color::Rgb(0, 0, 0),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_raised() -> Color {
    let colors = [
        Color::Rgb(32, 42, 55),
        Color::Rgb(230, 233, 238),
        Color::Rgb(7, 54, 66),
        Color::Rgb(19, 32, 25),
        Color::Rgb(26, 26, 26),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_stripe() -> Color {
    let colors = [
        Color::Rgb(25, 34, 46),
        Color::Rgb(238, 240, 243),
        Color::Rgb(4, 49, 60),
        Color::Rgb(15, 25, 18),
        Color::Rgb(13, 13, 13),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_border() -> Color {
    let colors = [
        Color::Rgb(54, 67, 84),
        Color::Rgb(180, 188, 200),
        Color::Rgb(42, 82, 92),
        Color::Rgb(43, 74, 53),
        Color::Rgb(140, 140, 140),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_text() -> Color {
    let colors = [
        Color::Rgb(220, 227, 237),
        Color::Rgb(28, 36, 48),
        Color::Rgb(213, 220, 215),
        Color::Rgb(201, 242, 213),
        Color::Rgb(255, 255, 255),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_muted() -> Color {
    let colors = [
        Color::Rgb(151, 166, 184),
        Color::Rgb(91, 102, 118),
        Color::Rgb(147, 161, 161),
        Color::Rgb(127, 169, 140),
        Color::Rgb(200, 200, 200),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_success() -> Color {
    let colors = [
        Color::Rgb(139, 199, 163),
        Color::Rgb(29, 122, 70),
        Color::Rgb(159, 191, 59),
        Color::Rgb(135, 231, 168),
        Color::Rgb(93, 245, 138),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_warn() -> Color {
    let colors = [
        Color::Rgb(223, 185, 116),
        Color::Rgb(138, 90, 0),
        Color::Rgb(217, 166, 46),
        Color::Rgb(229, 199, 107),
        Color::Rgb(255, 215, 95),
    ];
    colors[CURRENT.get()]
}
pub(super) fn color_danger() -> Color {
    let colors = [
        Color::Rgb(237, 147, 140),
        Color::Rgb(179, 38, 30),
        Color::Rgb(239, 107, 98),
        Color::Rgb(255, 140, 122),
        Color::Rgb(255, 107, 107),
    ];
    colors[CURRENT.get()]
}
