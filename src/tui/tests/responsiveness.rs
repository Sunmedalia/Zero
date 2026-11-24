//! Regression tests for work kept off, or out of the way of, the UI thread.
use super::*;
use std::rc::Rc;

fn big_pslist(app: &mut App, rows: usize) {
    let template = app.result().unwrap().rows[0].clone();
    app.results.get_mut("linux.pslist.basic").unwrap().rows = (0..rows)
        .map(|i| {
            let mut row = template.clone();
            row[0] = i.to_string();
            row[3] = if i % 2 == 0 { "bash" } else { "sshd" }.into();
            row
        })
        .collect();
}
fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    terminal
}
fn settle_view(app: &mut App) {
    let started = Instant::now();
    // Request the current view, as drawing a frame does.
    app.view_index();
    while app.view_pending() {
        app.drain();
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "view build hung"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn large_results_are_indexed_in_the_background_and_keep_the_last_view() {
    let mut app = app();
    let rows = SYNC_VIEW_CELLS / 5 + 1000;
    big_pslist(&mut app, rows);
    // First view of a large result: nothing shown yet, build pending.
    assert_eq!(app.visible().len(), 0);
    assert!(app.view_pending());
    settle_view(&mut app);
    assert_eq!(app.visible().len(), rows);
    // A narrower query keeps the previous rows on screen until it is ready.
    app.query = "BASH".into();
    assert_eq!(app.visible().len(), rows);
    assert!(app.view_pending());
    let frame = render(&app, 120, 35);
    assert!(screen(&frame, 120).contains("筛选中"));
    settle_view(&mut app);
    assert_eq!(app.visible().len(), rows.div_ceil(2));
    // Narrowed and sorted results equal a full synchronous build.
    app.query = "bash".into();
    app.sort = Some(0);
    app.descending = true;
    settle_view(&mut app);
    let full = crate::result_view::Index::build(
        app.result().unwrap(),
        "bash",
        Some(0),
        true,
        None,
        &HashSet::new(),
    );
    assert_eq!(app.view_index().filtered, full.filtered);
}

#[test]
fn storing_a_finished_result_shares_one_allocation_for_both_keys() {
    let mut app = app();
    let result = app.results["linux.pslist.basic"].as_ref().clone();
    app.results.clear();
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    app.job = Some(Job::default());
    app.active_request = Some(Execution {
        key: "pslist|pid=1".into(),
        plugin: Plugin::Pslist,
        parameters: String::new(),
        snapshot: ExecutionSnapshot {
            plugin: Plugin::Pslist,
            force: false,
            options: Default::default(),
            dump: None,
        },
    });
    tx.send(WorkerEvent::Done(Outcome::Ready(result))).unwrap();
    app.drain();
    let by_request = app.results.shared("pslist|pid=1").unwrap();
    let by_plugin = app.results.shared("linux.pslist.basic").unwrap();
    assert!(Arc::ptr_eq(by_request, by_plugin));
}

#[test]
fn export_uses_the_confirmed_filter_and_sort_while_the_view_is_pending() {
    let mut app = app();
    let rows = SYNC_VIEW_CELLS / 5 + 1000;
    big_pslist(&mut app, rows);
    settle_view(&mut app);

    app.query = "bash".into();
    app.sort = Some(0);
    app.descending = true;
    assert_eq!(app.view_index().filtered.len(), rows);
    assert!(app.view_pending());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("filtered.json");
    app.open_input(InputKind::Export);
    app.paste(path.to_str().unwrap());
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    app.query = "sshd".into();
    finish_test_job(&mut app);

    let exported = store::exported(&path).unwrap();
    assert_eq!(exported.rows.len(), rows.div_ceil(2));
    for (row, pid) in exported.rows.iter().zip((0..rows).step_by(2).rev()) {
        assert_eq!(row[0], pid.to_string());
        assert_eq!(row[3], "bash");
    }
}

#[test]
fn inspector_wraps_once_per_row_and_width() {
    let mut app = app();
    app.inspector = true;
    let first = app.inspector_lines(30);
    assert!(Rc::ptr_eq(&first, &app.inspector_lines(30)));
    assert!(!Rc::ptr_eq(&first, &app.inspector_lines(31)));
    app.row = 1;
    let second = app.inspector_lines(31);
    assert!(second.iter().any(|line| line.contains("init")));
    // Wrapping agrees with per-character display width.
    let lines = detail_lines("名称: 一二三四五六 abc", 8);
    assert!(
        lines
            .iter()
            .all(|line| Span::raw(line.as_str()).width() <= 8)
    );
    assert_eq!(lines.concat(), "名称: 一二三四五六 abc");
}

#[test]
fn tiny_terminal_still_cancels_and_shows_the_running_task() {
    let mut app = app();
    app.job = Some(Job::default());
    app.started = Some(Instant::now());
    app.status = "正在分析 pslist".into();
    let tiny = render(&app, 50, 12);
    let text = screen(&tiny, 50);
    assert!(text.contains("终端过小"));
    assert!(text.contains("Esc 取消"));
    assert!(text.contains("正在分析"));
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.job.as_ref().unwrap().cancel.load(Ordering::Relaxed));
}

#[test]
fn scrollbar_drag_follows_the_current_frame_and_ends_on_resize() {
    let mut app = app();
    big_pslist(&mut app, 60);
    app.focus = Focus::Content;
    let _frame = render(&app, 100, 30);
    let bar = app
        .hits
        .borrow()
        .scrollbars
        .iter()
        .find(|bar| bar.target == ScrollTarget::Results)
        .cloned()
        .unwrap();
    let thumb = bar.thumb();
    let mouse = |kind, row| MouseEvent {
        kind,
        column: thumb.x,
        row,
        modifiers: KeyModifiers::NONE,
    };
    app.mouse(mouse(MouseEventKind::Down(MouseButton::Left), thumb.y));
    assert!(app.drag.is_some());
    // The result grows while dragging: the drag uses the new total.
    big_pslist(&mut app, 600);
    let _frame = render(&app, 100, 30);
    let bottom = bar.track().bottom() - 1;
    app.mouse(mouse(MouseEventKind::Drag(MouseButton::Left), bottom));
    assert!(
        app.row > 60,
        "row {} still bounded by the old total",
        app.row
    );
    app.resize(80, 24);
    assert!(app.drag.is_none());
}

#[test]
fn startup_input_dispatches_paste_and_key_shortcuts_separately() {
    let mut app = app();
    let mut input = terminal_theme::StartupInput::from_bytes(b"\x1b[200~q\r\x1b[201~q\r");
    let mut dispatch = |app: &mut App| {
        let event = input.next_event(Duration::ZERO).unwrap().unwrap();
        super::super::handle_event(app, event).1
    };
    assert!(!dispatch(&mut app));
    assert!(app.dialog.is_none());
    assert!(!dispatch(&mut app));
    assert!(matches!(app.dialog, Some(Dialog::Quit { .. })));
    assert!(dispatch(&mut app));
}
