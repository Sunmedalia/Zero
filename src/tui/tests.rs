use super::*;
use ratatui::backend::TestBackend;
mod assets;
mod mouse;
mod parameters;
mod rendering;
mod symbol_workflows;
mod system;
mod workflow;

thread_local! { static TEST_DIRECTORIES: RefCell<Vec<tempfile::TempDir>> = const { RefCell::new(Vec::new()) }; }

fn app() -> App {
    let dir = tempfile::tempdir().unwrap();
    let mut app = App::new(
        None,
        "symbols".into(),
        dir.path().join("cache"),
        Settings {
            image_dir: dir.path().join("images").display().to_string(),
            symbols: dir.path().join("symbols").display().to_string(),
            ..Settings::default()
        },
    );
    app.results.insert(
        "pslist".into(),
        Results {
            plugin: "pslist".into(),
            columns: vec!["PID", "TGID", "PPID", "Name", "Address"]
                .into_iter()
                .map(String::from)
                .collect(),
            rows: vec![
                vec!["10", "10", "0", "zsh", "0x1000"],
                vec!["2", "2", "0", "init", "0x2000"],
            ]
            .into_iter()
            .map(|r| r.into_iter().map(String::from).collect())
            .collect(),
            complete: true,
            diagnostics: vec![],
            banner: String::new(),
            symbol: String::new(),
            page_table: 0,
            historical: false,
            system: "linux".into(),
            kernel_identity: serde_json::Value::Null,
        },
    );
    app.page = Page::Analysis;
    TEST_DIRECTORIES.with(|directories| directories.borrow_mut().push(dir));
    app
}
/// Render the buffer as text, one line per terminal row.
///
/// Every buffer cell is one column, even when its symbol is a wide glyph: the
/// wide glyph occupies the cell and its neighbour is left empty by ratatui. The
/// previous version advanced by the symbol's *display* width, so it skipped a
/// cell after every CJK character and reported roughly half of each row.
fn screen(terminal: &Terminal<TestBackend>, width: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    // Split on the buffer's own width: a caller that passes a stale size would
    // otherwise produce rows offset against the real frame, and every string
    // assertion downstream would be reading the wrong cells.
    let actual = terminal.backend().buffer().area.width as usize;
    debug_assert_eq!(actual, width, "screen() called with a stale width");
    let mut text = String::new();
    for row in terminal.backend().buffer().content.chunks(actual) {
        let mut skip = 0usize;
        for cell in row {
            if skip > 0 {
                // The cell after a wide glyph is its second half and carries
                // no text of its own.
                skip -= 1;
                continue;
            }
            let symbol = cell.symbol();
            text.push_str(symbol);
            skip = symbol.width().saturating_sub(1);
        }
        text.push('\n');
    }
    text
}
fn mouse_event(kind: MouseEventKind, x: u16, y: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column: x,
        row: y,
        modifiers: KeyModifiers::NONE,
    }
}
fn click(app: &mut App, x: u16, y: u16) -> bool {
    app.mouse(mouse_event(MouseEventKind::Down(MouseButton::Left), x, y))
}
fn fixture_isf(banner: &str, variant: u8) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    serde_json::to_vec(&serde_json::json!({
        "base_types": { "pointer": { "size": 8 } },
        "symbols": { "linux_banner": { "address": 256,
            "constant_data": STANDARD.encode(format!("{banner}\n\0")) } },
        "metadata": { "variant": variant }
    }))
    .unwrap()
}
fn finish_test_job(app: &mut App) {
    for _ in 0..20 {
        if let Some(worker) = app.worker.take() {
            worker.join().unwrap();
        }
        app.drain();
        if app.job.is_none() {
            return;
        }
    }
    panic!("task chain did not settle");
}
fn cache_fixture(app: &App, candidate: &RemoteMatch, bytes: &[u8]) -> PathBuf {
    use std::io::Write;
    let path = app
        .cache
        .join("symbols/isf")
        .join(symbols::cache_filename(&candidate.path).unwrap());
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(bytes).unwrap();
    store::atomic_write(&path, &encoder.finish().unwrap()).unwrap();
    path
}
const PREPARATION_BANNER: &str =
    "Linux version 3.2.0-test (test@test) (gcc version 4.6.3) #1 SMP test";
fn preparation_fixture() -> (tempfile::TempDir, App) {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("images/test.raw");
    std::fs::create_dir_all(image.parent().unwrap()).unwrap();
    let mut bytes = vec![0; 8192];
    let banner = format!("{PREPARATION_BANNER}\n\0");
    bytes[256..256 + banner.len()].copy_from_slice(banner.as_bytes());
    std::fs::write(&image, bytes).unwrap();
    let mut app = App::new(
        Some(image),
        PathBuf::new(),
        dir.path().join("cache"),
        Settings {
            image_dir: dir.path().join("images").display().to_string(),
            symbols: dir.path().join("symbols").display().to_string(),
            remote_symbols: false,
            ..Settings::default()
        },
    );
    app.root = dir.path().into();
    (dir, app)
}
#[test]
#[ignore = "requires local Linux and Windows samples and exact symbols; offline TUI acceptance"]
fn offline_tui_resources_to_analysis_acceptance() {
    let root = std::env::current_dir().unwrap();
    for (image, symbols, windows) in [
        (
            std::env::var_os("ZERO_TEST_IMAGE")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("images/linux-sample-1.bin.gz")),
            std::env::var_os("ZERO_TEST_SYMBOLS")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("symbols/linux.zip")),
            false,
        ),
        (
            std::env::var_os("ZERO_TUI_WINDOWS_IMAGE")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("images/feat-windows-plugins/server2019/MEMORY.DMP")),
            std::env::var_os("ZERO_TUI_WINDOWS_SYMBOLS")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join(".zero/rust/symbols/isf/windows")),
            true,
        ),
    ] {
        assert!(image.is_file(), "sample missing: {}", image.display());
        assert!(symbols.exists(), "symbols missing: {}", symbols.display());
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            Some(image),
            symbols.clone(),
            dir.path().join("cache"),
            Settings {
                image_dir: dir.path().join("images").display().to_string(),
                symbols: symbols.display().to_string(),
                remote_symbols: false,
                enable_cache: false,
                ..Settings::default()
            },
        );
        app.root = dir.path().into();
        app.initialize(Default::default());
        app.page = Page::Assets;
        finish_test_job(&mut app);
        if matches!(app.dialog, Some(Dialog::Symbols { .. })) {
            app.dialog_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        }
        assert_eq!(app.preparation, Preparation::Ready, "{}", app.status);
        assert_eq!(app.windows, windows);
        assert!(app.job.is_none());
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.page, Page::Analysis);
        assert!(app.job.is_none());
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        let y = hits.menu.y + 1 + (app.menu - hits.menu_offset) as u16;
        click(&mut app, hits.menu.x + 2, y);
        finish_test_job(&mut app);
        let result = app.result().unwrap_or_else(|| panic!("{}", app.status));
        assert!(!result.rows.is_empty(), "{}", app.status);
        assert!(result.page_table > 0, "页表未验证");
        assert_eq!(result.system, if windows { "windows" } else { "linux" });
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 140).contains("页表已验证"));
        eprintln!(
            "TUI offline acceptance: {} · {} rows · page table {:#x}",
            result.system,
            result.rows.len(),
            result.page_table
        );
    }
}

/// Assert a frame is safe to show: no control characters and no cell outside
/// the buffer that the terminal would have to clip.
fn check_frame(terminal: &Terminal<TestBackend>, w: u16, h: u16, what: &str) {
    let buffer = terminal.backend().buffer();
    assert_eq!(buffer.area.width, w, "{what}: buffer width");
    assert_eq!(buffer.area.height, h, "{what}: buffer height");
    for (i, cell) in buffer.content.iter().enumerate() {
        let symbol = cell.symbol();
        assert!(
            !symbol.chars().any(char::is_control),
            "{what}: control character at {i}: {symbol:?}"
        );
        let x = (i as u16) % w;
        let y = (i as u16) / w;
        assert!(x < w && y < h, "{what}: cell {i} outside {w}x{h}");
    }
    // A row that fills the width exactly may be complete or cut, so this cannot
    // be decided from the frame alone. What can be checked is that no row
    // *starts* a wide glyph in the last column, which the terminal would have
    // to wrap or clip.
    use unicode_width::UnicodeWidthStr;
    let rows = screen(terminal, w as usize);
    for (row, line) in rows.lines().enumerate() {
        let trimmed = line.trim_end();
        assert!(
            trimmed.width() <= w as usize,
            "{what}: row {row} is wider than the terminal"
        );
    }
}

#[path = "migration_tests.rs"]
mod migration;

#[path = "parity_tests.rs"]
mod parity;

#[path = "review_tests.rs"]
mod review;

#[path = "diagnostic_tests.rs"]
mod diagnostic;
