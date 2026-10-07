mod application;
mod generation;
mod interaction;
mod pages;
mod tasks;
mod workflow;
include!("tui/state.rs");
include!("tui/actions.rs");
include!("tui/components.rs");
use crate::{
    Job, cache,
    dump::{DumpOptions, parse_address},
    linux::{self, Outcome, PLUGINS, Plugin},
    store::{self, Results, Settings},
    symbols::{self, RemoteMatch},
    workspace::{self, Asset, Kind, Registry},
};
use anyhow::{Context, Result};
use crossterm::{
    cursor::Show,
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
        MouseEventKind,
    },
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Flex, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Row,
        StatefulWidget, Table, TableState, Wrap,
    },
};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, atomic::Ordering, mpsc},
    thread,
    time::{Duration, Instant},
};
use workflow::*;

const ACCENT: Color = Color::Rgb(72, 201, 184);
const FOCUS: Color = Color::Rgb(243, 178, 92);
const SELECTED_BG: Color = Color::Rgb(31, 54, 61);
const SURFACE: Color = Color::Rgb(17, 25, 31);
/// Raised surface for chips, buttons and alternating table rows.
const RAISED: Color = Color::Rgb(27, 42, 48);
const STRIPE: Color = Color::Rgb(21, 31, 38);
const BORDER: Color = Color::Rgb(52, 70, 78);
const TEXT: Color = Color::Rgb(214, 222, 224);
const MUTED: Color = Color::Rgb(112, 130, 137);
const SUCCESS: Color = Color::Rgb(126, 211, 135);
const WARN: Color = Color::Rgb(240, 196, 102);
const DANGER: Color = Color::Rgb(236, 112, 99);

/// Rounded, dim-bordered panel shared by every framed region and popup.
fn panel<'a>() -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .title_style(Style::default().fg(TEXT))
}
/// Muted label followed by a value, for key/value header lines.
fn field<'a>(label: &'a str, value: String, style: Style) -> [Span<'a>; 2] {
    [
        Span::styled(label, Style::default().fg(MUTED)),
        Span::styled(value, style),
    ]
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}
fn restore() {
    let _ = terminal::disable_raw_mode();
    let _ = execute!(
        std::io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        Show
    );
}
pub fn run(
    image: Option<PathBuf>,
    symbols: PathBuf,
    cache: PathBuf,
    settings: Settings,
) -> Result<()> {
    run_with_options(
        image,
        symbols,
        cache,
        settings,
        crate::analysis::Options::default(),
    )
}
pub fn run_with_options(
    image: Option<PathBuf>,
    symbols: PathBuf,
    cache: PathBuf,
    settings: Settings,
    options: crate::analysis::Options,
) -> Result<()> {
    terminal::enable_raw_mode().context("TUI 需要真实终端；批处理请使用 analyze")?;
    let _guard = TerminalGuard;
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let previous = std::panic::take_hook();
    let ui_thread = thread::current().id();
    std::panic::set_hook(Box::new(move |info| {
        if thread::current().id() == ui_thread {
            restore();
            previous(info);
        }
        // Worker panics are caught and reported through the event channel.
    }));
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut app = App::new(image, symbols, cache, settings);
    app.initialize(options);
    let outcome = (|| -> Result<()> {
        let mut dirty = true;
        let mut last_tick = Instant::now();
        loop {
            if app.job.is_some() && last_tick.elapsed() >= Duration::from_millis(280) {
                dirty = true;
                last_tick = Instant::now();
            }
            dirty |= app.drain();
            if dirty {
                terminal.draw(|f| app.draw(f))?;
                dirty = false;
            }
            if event::poll(Duration::from_millis(80))? {
                let next = event::read()?;
                dirty = !matches!(
                    next,
                    Event::Mouse(MouseEvent {
                        kind: MouseEventKind::Moved,
                        ..
                    })
                );
                let quit = match next {
                    Event::Key(key) => app.key(key),
                    Event::Mouse(mouse) => app.mouse(mouse),
                    Event::Resize(width, height) => {
                        app.resize(width, height);
                        false
                    }
                    Event::Paste(text) => {
                        app.paste(&text);
                        false
                    }
                    _ => false,
                };
                if quit {
                    break;
                }
            }
        }
        Ok(())
    })();
    app.cancel();
    app.finish_worker();
    outcome
}

#[cfg(test)]
#[path = "tui/tests.rs"]
mod tests;
