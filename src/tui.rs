mod application;
mod cache_page;
mod scrollbars;
mod status;
mod tabs;
use scrollbars::ScrollTarget;
use tabs::OpenTab;
mod assets;
mod chrome;
mod commands;
mod dialog_keys;
mod dialogs;
mod footer;
mod generation;
mod layout;
use layout::Space;
mod interaction;
mod pages;
mod results;
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

mod screenshots;
mod terminal_theme;
mod theme;
pub use screenshots::run as screenshots;
use theme::*;
/// Rounded, dim-bordered panel shared by every framed region and popup.
fn panel<'a>() -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color_border()))
        .title_style(Style::default().fg(color_text()))
}
/// Muted label followed by a value, for key/value header lines.
fn field<'a>(label: &'a str, value: String, style: Style) -> [Span<'a>; 2] {
    [
        Span::styled(label, Style::default().fg(color_muted())),
        Span::styled(value, style),
    ]
}

type PanicHook = Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync>;
struct TerminalGuard {
    previous: Option<PanicHook>,
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
        if !thread::panicking()
            && let Some(previous) = self.previous.take()
        {
            std::panic::set_hook(Box::new(move |info| previous(info)));
        }
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
    let mut guard = TerminalGuard { previous: None };
    execute!(
        std::io::stdout(),
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let previous: PanicHook = std::panic::take_hook().into();
    guard.previous = Some(previous.clone());
    let ui_thread = thread::current().id();
    std::panic::set_hook(Box::new(move |info| {
        if thread::current().id() == ui_thread {
            restore();
            previous(info);
        }
        // Worker panics are caught and reported through the event channel.
    }));
    theme::set_background(terminal_theme::detect());
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
                let quit = match next {
                    Event::Key(key) => {
                        dirty = true;
                        app.key(key)
                    }
                    Event::Mouse(mouse) => {
                        // Moves are not consumed, so they must not force a
                        // repaint; only actions that can change the screen do.
                        if !matches!(mouse.kind, MouseEventKind::Moved) {
                            dirty = true;
                        }
                        app.mouse(mouse)
                    }
                    Event::Resize(width, height) => {
                        app.resize(width, height);
                        dirty = true;
                        false
                    }
                    Event::Paste(text) => {
                        app.paste(&text);
                        dirty = true;
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

#[cfg(test)]
#[test]
#[ignore = "requires a local Linux memory image and exact symbols"]
fn native_acceptance() {
    let image = std::env::var_os("ZERO_TEST_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("images/linux-sample-1.bin"));
    let symbols = std::env::var_os("ZERO_TEST_SYMBOLS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("symbols/linux.zip"));
    let project = tempfile::tempdir().unwrap();
    let cache = project.path().join(".zero/rust");
    let settings = Settings {
        remote_symbols: false,
        ..Default::default()
    };
    store::save_settings(&cache, &settings).unwrap();
    let mut app = App::new(
        Some(image.canonicalize().expect("local image")),
        symbols.canonicalize().expect("local symbols"),
        cache,
        settings,
    );
    app.initialize(Default::default());
    let settle = |app: &mut App| {
        let started = Instant::now();
        while app.job.is_some() {
            app.drain();
            assert!(
                started.elapsed() < Duration::from_secs(600),
                "task timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!app.status.starts_with("失败"), "{}", app.status);
    };
    settle(&mut app);
    assert!(app.verified.as_ref().is_some_and(|v| v.digest.len() == 64));
    app.activate_plugin(Plugin::Pslist);
    settle(&mut app);
    let result = app.result().expect("analysis result");
    assert!(result.complete && !result.rows.is_empty() && result.page_table != 0);
    let result = result.clone();
    let export = project.path().join("exports/pslist.json");
    app.start_work(Work::Export(
        export.clone(),
        result.metadata(),
        result.rows.clone(),
    ));
    settle(&mut app);
    assert_eq!(store::exported(&export).unwrap().rows, result.rows);
    app.switch_page(Page::Cache);
    settle(&mut app);
    assert!(!app.cache_page.records.is_empty());
    app.start_work(Work::Record(app.cache_page.records[0].key.clone()));
    settle(&mut app);
    assert!(app.result().unwrap().historical);
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(120, 35)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
}
