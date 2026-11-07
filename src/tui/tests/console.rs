use super::*;
use crate::tui::console::{ConsoleResult, Method, Readiness};

fn console_app() -> (tempfile::TempDir, App) {
    let (dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    (dir, app)
}

/// Screen text with spaces removed: wide CJK cells are followed by padding cells.
fn screen(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect::<String>()
        .replace(' ', "")
}

fn method_index(app: &App, method: Method) -> usize {
    app.console_methods()
        .iter()
        .position(|s| s.method == method)
        .unwrap()
}

#[test]
fn console_tab_is_reachable_by_click_tab_and_k_and_leaves_with_tab() {
    let (_dir, mut app) = console_app();
    let mut terminal = Terminal::new(TestBackend::new(120, 34)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let tab = app.hits.borrow().console_tab;
    assert!(tab.width > 0, "the console tab is drawn beside the sources");
    click(&mut app, tab.x + 1, tab.y);
    assert!(app.asset_console);
    // Tab leaves for the image list; Shift+Tab from images comes back.
    app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(!app.asset_console);
    assert_eq!(app.section, AssetSection::Images);
    app.key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
    assert!(app.asset_console);
    // Remote -> Tab -> console; any source tab click leaves it again.
    app.switch_section(AssetSection::Remote);
    assert!(!app.asset_console);
    app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(app.asset_console);
    app.switch_section(AssetSection::Symbols);
    app.page = Page::Analysis;
    app.key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE));
    assert_eq!(app.page, Page::Assets);
    assert!(app.asset_console && app.dialog.is_none());
}

#[test]
fn console_renders_steps_methods_and_buttons_inside_every_size() {
    let (_dir, mut app) = console_app();
    app.open_generation_console();
    for (width, height) in [(140, 40), (100, 30), (80, 24), (60, 18), (20, 8), (1, 1)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow();
        for rect in hits
            .buttons
            .iter()
            .map(|(r, _)| *r)
            .chain(hits.console_methods.iter().map(|(r, _)| *r))
        {
            assert!(
                rect.right() <= width && rect.bottom() <= height,
                "{width}x{height}"
            );
        }
    }
    let mut terminal = Terminal::new(TestBackend::new(120, 34)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let text = screen(&terminal);
    for expected in [
        "符号表生成控制台",
        "① 镜像",
        "② 内核",
        "③ 符号",
        "从镜像生成",
        "官方调试包",
        "本地调试文件",
        "推荐",
        "开始生成 Enter",
    ] {
        assert!(
            text.contains(&expected.replace(' ', "")),
            "missing {expected}"
        );
    }
    assert_eq!(app.hits.borrow().console_methods.len(), 3);
}

#[test]
fn recommendation_follows_what_can_run_and_blocked_methods_never_start() {
    let (_dir, mut app) = console_app();
    app.open_generation_console();
    let states = app.console_methods();
    // A banner without a known distribution cannot use official packages.
    let official = &states[method_index(&app, Method::Official)];
    assert_eq!(official.readiness, Readiness::Blocked);
    assert_eq!(app.console.selected, method_index(&app, Method::FromImage));
    app.console.selected = method_index(&app, Method::Official);
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.job.is_none(), "a blocked method does not start");
    assert!(app.status.contains("发行版"));
    // Without an image nothing is runnable and the first step says why.
    app.image = None;
    assert!(
        app.console_methods()
            .iter()
            .all(|s| s.readiness == Readiness::Blocked)
    );
    // Hidden list actions are refused instead of acting on an invisible row.
    app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert!(app.status.contains("列表"));
    assert!(app.dialog.is_none());
}

#[test]
fn one_key_generation_from_image_reports_failure_and_keeps_the_selection() {
    let (_dir, mut app) = console_app();
    let selected = app.symbols.clone();
    app.open_generation_console();
    assert_eq!(app.console.selected, method_index(&app, Method::FromImage));
    let mut terminal = Terminal::new(TestBackend::new(120, 34)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let start = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Enter)
        .unwrap()
        .0;
    click(&mut app, start.x + 1, start.y);
    assert!(app.job.is_some());
    assert_eq!(app.console.running, Some(Method::FromImage));
    finish_test_job(&mut app);
    // The fixture has a banner but no kernel tables: the log and result explain it.
    assert!(!app.console.log.is_empty());
    assert!(matches!(
        &app.console.result,
        Some(ConsoleResult::Failed(Method::FromImage, error)) if error.contains("kallsyms")
    ));
    assert!(app.asset_console && app.page == Page::Assets);
    assert_eq!(app.symbols, selected);
    // A fresh backend: TestBackend keeps stale halves of redrawn wide characters.
    let mut terminal = Terminal::new(TestBackend::new(120, 34)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let text = screen(&terminal);
    assert!(text.contains("未完成") && text.contains("运行日志") && text.contains("建议"));
}

#[test]
fn official_failure_moves_to_image_generation_and_success_stays_on_the_card() {
    let (_dir, mut app) = console_app();
    app.open_generation_console();
    app.console.selected = method_index(&app, Method::Official);
    app.console.running = Some(Method::Official);
    app.console_failed("候选的官方来源均不可用");
    assert_eq!(app.console.selected, method_index(&app, Method::FromImage));
    // Repeated step messages collapse into one log line.
    app.console.running = Some(Method::FromImage);
    app.console_progress("扫描候选: 0x1000");
    app.console_progress("扫描候选: 0x2000");
    app.console_progress("读取并转换内核 BTF");
    assert_eq!(app.console.log, ["扫描候选: 0x2000", "读取并转换内核 BTF"]);
    let path = PathBuf::from("/tmp/generated.json.xz");
    assert!(app.console_saved(&path));
    assert!(
        matches!(&app.console.result, Some(ConsoleResult::Saved(Method::FromImage, p)) if *p == path)
    );
    assert!(!app.console_saved(&path), "a result is recorded once");
    // Unrelated work started afterwards is never attributed to the console.
    app.console.running = Some(Method::FromImage);
    app.start_work(Work::Identify);
    assert!(app.console.running.is_none());
    finish_test_job(&mut app);
}

#[test]
fn local_files_method_opens_the_manual_form() {
    let (_dir, mut app) = console_app();
    app.open_generation_console();
    app.console.selected = method_index(&app, Method::LocalFiles);
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::GenerateSymbols {
            automatic: false,
            field: 0,
            ..
        })
    ));
    assert_eq!(app.console.running, Some(Method::LocalFiles));
}

/// ZERO_BTF_IMAGE: x86_64 BTF + KALLSYMS_ALL capture. Drives the console from
/// image selection to saved, selected symbols through the real engine, offline.
#[test]
#[ignore = "requires a local BTF-enabled x86_64 capture"]
fn console_generates_and_selects_symbols_from_a_real_image() {
    let image = PathBuf::from(std::env::var("ZERO_BTF_IMAGE").expect("set ZERO_BTF_IMAGE"));
    let dir = tempfile::tempdir().unwrap();
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
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    app.key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE));
    // Offline, the image path is the recommendation.
    assert_eq!(app.console.selected, method_index(&app, Method::FromImage));
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert!(
        matches!(
            app.console.result,
            Some(ConsoleResult::Saved(Method::FromImage, _))
        ),
        "{:?} · {}",
        app.console.result,
        app.status
    );
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(
        app.symbols
            .starts_with(dir.path().join("symbols").canonicalize().unwrap())
    );
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let rows: Vec<String> = terminal
        .backend()
        .buffer()
        .content()
        .chunks(120)
        .map(|row| row.iter().map(|c| c.symbol()).collect())
        .collect();
    println!("{}", rows.join("\n"));
    assert!(screen(&terminal).contains("已通过“从镜像生成”生成并选用符号表"));
}

#[test]
fn console_generates_then_reuses_validated_image_symbols_offline() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("memory.raw");
    std::fs::write(&image, crate::prepare::from_image::tests::fixture()).unwrap();
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
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    let mut saved = None;
    for attempt in 0..2 {
        app.key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE));
        app.console.selected = method_index(&app, Method::FromImage);
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert!(
            matches!(
                app.console.result,
                Some(ConsoleResult::Saved(Method::FromImage, _))
            ),
            "{:?}: {}",
            app.console.result,
            app.status
        );
        assert_eq!(app.preparation, Preparation::Ready);
        assert!(
            app.symbols
                .starts_with(dir.path().join("symbols").canonicalize().unwrap())
        );
        if attempt == 0 {
            saved = Some(app.symbols.clone());
        } else {
            assert_eq!(Some(&app.symbols), saved.as_ref());
            assert!(
                app.console.log.iter().any(|s| s.contains("复用已验证")),
                "{:?}",
                app.console.log
            );
        }
    }
}

#[test]
fn reused_local_symbols_are_not_presented_as_new_btf_output() {
    let (_dir, mut app) = console_app();
    app.open_generation_console();
    app.console.result = Some(ConsoleResult::Saved(Method::FromImage, app.symbols.clone()));
    app.console.log.push(
        "复用本地精确符号：完整 banner 和页表已验证；保留原始来源，此次未从镜像生成新类型".into(),
    );
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let text = screen(&terminal);
    assert!(text.contains("已验证并复用本地精确符号表"));
    assert!(!text.contains("已通过“从镜像生成”生成"));
    assert!(!text.contains("BTF不记录多数全局变量类型"));
}

#[test]
fn arm64_can_request_verified_local_reuse_without_build_tools() {
    let (_dir, mut app) = console_app();
    for row in &mut app.results.get_mut("banners").unwrap().rows {
        row[1] = "Linux version 6.8.11-arm64 (aarch64-linux-gnu-gcc)".into();
    }
    app.console.missing_tools = Some(vec!["git", "go"]);
    app.settings.remote_symbols = false;
    app.open_generation_console();
    let states = app.console_methods();
    let state = &states[method_index(&app, Method::FromImage)];
    assert_eq!(state.readiness, Readiness::Limited);
    assert!(state.notes.iter().any(|s| s.contains("精确本地 ISF")));
}
