//! Behavior introduced after the historical Rust UI, ported from the TS tests.
use super::*;

fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    terminal
}
fn seed_tab(app: &mut App, plugin: Plugin) {
    let mut result = app.results["linux.pslist.basic"].as_ref().clone();
    result.plugin = plugin.name().into();
    app.results.insert(plugin.name().into(), result);
    app.activate_plugin(plugin);
}
#[test]
fn native_startup_with_image_verifies_before_matching_and_stays_on_analysis() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    assert_eq!(app.page, Page::Analysis);
    assert!(matches!(app.pending_work, Some(Work::MatchLocal(..))));
    finish_test_job(&mut app);
    assert!(
        app.verified
            .as_ref()
            .is_some_and(|v| v.computed && v.digest.len() == 64)
    );
    assert!(app.results.contains_key("linux.banners"));
    assert!(!app.results.contains_key("linux.pslist.basic"));
    assert!(app.open_tabs.is_empty());
}
#[test]
fn result_tabs_deduplicate_switch_and_close_without_reanalysis() {
    let mut app = app();
    seed_tab(&mut app, Plugin::Pslist);
    app.query = "init".into();
    seed_tab(&mut app, Plugin::Lsmod);
    seed_tab(&mut app, Plugin::Pslist);
    assert_eq!(app.open_tabs.len(), 2);
    assert_eq!(app.query, "init");
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    assert_eq!(app.plugin, Plugin::Lsmod);
    assert!(app.job.is_none());
    app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
    assert_eq!(app.plugin, Plugin::Pslist);
    assert!(!app.results.contains_key("linux.lsmod"));
    assert_eq!(app.query, "init");
}
#[test]
fn history_tabs_retain_independent_filters_and_survive_source_changes() {
    let mut app = app();
    seed_tab(&mut app, Plugin::Pslist);
    let mut result = app.result().unwrap().clone();
    result.historical = true;
    app.open_history_tab(PathBuf::from("record-a"), result.clone());
    app.query = "init".into();
    let first = app.active_tab.unwrap();
    app.open_history_tab(PathBuf::from("record-b"), result);
    app.query = "zsh".into();
    let second = app.active_tab.unwrap();
    app.switch_result_tab(first);
    assert_eq!(app.query, "init");
    app.switch_result_tab(second);
    assert_eq!(app.query, "zsh");
    app.invalidate_source();
    assert_eq!(app.open_tabs.len(), 2);
    app.switch_result_tab(0);
    assert!(app.result().unwrap().historical);
}
#[test]
fn history_tab_starts_with_automatic_column_widths() {
    let mut app = app();
    seed_tab(&mut app, Plugin::Pslist);
    let name = ColumnKey::new("Name", 0);
    app.column_widths.insert(name.clone(), 30);
    app.horizontal = 5;
    let mut result = app.result().unwrap().clone();
    result.historical = true;
    app.open_history_tab(PathBuf::from("record-a"), result);
    // The live result's widths share column names but do not leak in.
    assert!(app.column_widths.is_empty());
    assert_eq!(app.horizontal, 0);
    app.switch_result_tab(0);
    assert_eq!(app.column_widths.get(&name), Some(&30));
    assert_eq!(app.horizontal, 5);
}
#[test]
fn ctrl_r_from_history_tab_preserves_history_widths_and_restores_live_view() {
    let mut app = app();
    app.image = Some(app.root.join("missing.raw"));
    seed_tab(&mut app, Plugin::Pslist);
    let name = ColumnKey::new("Name", 0);
    let pid = ColumnKey::new("PID", 0);
    app.column_widths.insert(name.clone(), 30);
    app.horizontal = 5;

    let mut history = app.result().unwrap().clone();
    history.historical = true;
    app.open_history_tab(PathBuf::from("record-ctrl-r"), history);
    app.column_widths.insert(pid.clone(), 45);
    app.column_widths.insert(name.clone(), 18);

    // Pressing Ctrl+R from the history tab saves the history view, clears
    // history, and restores the live plugin's saved view instead of leaking
    // history column widths.
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(app.history.is_none());
    assert_eq!(app.column_widths.get(&name), Some(&30));
    assert_eq!(app.column_widths.get(&pid), None);
    assert_eq!(app.horizontal, 5);

    // Cancel and release the background worker spawned for missing.raw.
    app.cancel();
    app.release_worker(Duration::from_secs(2));

    // Switching back to the history tab restores its adjusted widths.
    app.switch_result_tab(1);
    assert!(app.history.is_some());
    assert_eq!(app.column_widths.get(&pid), Some(&45));
    assert_eq!(app.column_widths.get(&name), Some(&18));
}
#[test]
fn queued_ctrl_r_from_history_preserves_current_view_across_tab_and_plugin_switches() {
    let mut app = app();
    app.image = Some(app.root.join("missing.raw"));
    let name = ColumnKey::new("Name", 0);
    let pid = ColumnKey::new("PID", 0);

    // Prepare live Pslist view and another plugin Psaux view.
    seed_tab(&mut app, Plugin::Pslist);
    app.column_widths.insert(name.clone(), 30);
    app.query = "init".into();
    let mut psaux = app.result().unwrap().clone();
    psaux.plugin = Plugin::Psaux.name().into();
    app.results.insert(Plugin::Psaux.name().into(), psaux);

    // Open a history tab and give it distinct widths and filter.
    let mut history = app.result().unwrap().clone();
    history.historical = true;
    app.open_history_tab(PathBuf::from("record-busy"), history);
    app.column_widths.insert(pid.clone(), 45);
    app.column_widths.insert(name.clone(), 18);
    app.query = "hist".into();
    let history_tab = app.active_tab;

    // Queue Ctrl+R while busy; staying on the history tab must keep history
    // displayed and untouched when the queued snapshot starts.
    app.job = Some(Job::default());
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    let queued = app.pending_execution.take().expect("queued snapshot");
    app.pending_work = None;
    app.job = None;
    app.start_snapshot(queued.clone());
    assert_eq!(app.active_tab, history_tab);
    assert!(app.history.is_some());
    assert_eq!(app.query, "hist");
    assert_eq!(app.column_widths.get(&pid), Some(&45));
    assert_eq!(app.column_widths.get(&name), Some(&18));
    app.cancel();
    app.release_worker(Duration::from_secs(2));
    app.job = None;

    // Browsing to another plugin while the snapshot starts must not leak the
    // queued plugin's widths/query into the browsed plugin or corrupt history.
    app.select_plugin(Plugin::Psaux);
    app.column_widths.insert(pid.clone(), 22);
    app.query = "bash".into();
    app.start_snapshot(queued);
    assert_eq!(app.plugin, Plugin::Psaux);
    assert!(app.history.is_none());
    assert_eq!(app.query, "bash");
    assert_eq!(app.column_widths.get(&pid), Some(&22));
    assert_eq!(app.column_widths.get(&name), None);
    app.cancel();
    app.release_worker(Duration::from_secs(2));

    // Switching back to the history tab still restores its original widths/query.
    app.switch_result_tab(history_tab.unwrap());
    assert!(app.history.is_some());
    assert_eq!(app.query, "hist");
    assert_eq!(app.column_widths.get(&pid), Some(&45));
    assert_eq!(app.column_widths.get(&name), Some(&18));
}
#[test]
fn symbol_retry_registers_and_activates_plugin_tab_after_clearing_tabs() {
    let mut app = app();
    app.image = Some(app.root.join("missing.raw"));
    seed_tab(&mut app, Plugin::Pslist);
    app.symbol_retry = Some(SymbolRetry::Analysis(Box::new(ExecutionSnapshot {
        force: false,
        plugin: Plugin::Pslist,
        options: app.analysis_options.clone(),
        dump: None,
    })));
    app.dialog = Some(Dialog::Symbols {
        labels: vec!["candidate-a".into()],
        selected: 0,
    });
    app.dialog_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(
        app.open_tabs
            .iter()
            .any(|t| matches!(t, OpenTab::Plugin(Plugin::Pslist)))
    );
    assert!(matches!(
        app.active_tab.and_then(|i| app.open_tabs.get(i)),
        Some(OpenTab::Plugin(Plugin::Pslist))
    ));
    app.cancel();
    app.release_worker(Duration::from_secs(2));
}
#[test]
fn queued_run_from_history_only_tabs_registers_plugin_tab_without_changing_view() {
    let mut app = app();
    app.image = Some(app.root.join("missing.raw"));
    let pid = ColumnKey::new("PID", 0);
    let mut history = app.result().unwrap().clone();
    history.historical = true;
    app.open_tabs.clear();
    app.active_tab = None;
    app.open_history_tab(PathBuf::from("record-only"), history);
    app.column_widths.insert(pid.clone(), 42);
    app.query = "only-hist".into();
    let history_tab = app.active_tab;

    app.job = Some(Job::default());
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    let queued = app.pending_execution.take().expect("queued snapshot");
    app.pending_work = None;
    app.job = None;

    app.start_snapshot(queued);
    assert!(
        app.open_tabs
            .iter()
            .any(|t| matches!(t, OpenTab::Plugin(Plugin::Pslist)))
    );
    assert_eq!(app.active_tab, history_tab);
    assert!(app.history.is_some());
    assert_eq!(app.query, "only-hist");
    assert_eq!(app.column_widths.get(&pid), Some(&42));
    app.cancel();
    app.release_worker(Duration::from_secs(2));
}
#[test]
fn empty_result_tab_is_reused_and_running_tab_cannot_close() {
    let mut app = app();
    app.ensure_plugin_tab(Plugin::Psaux);
    app.ensure_plugin_tab(Plugin::Maps);
    assert_eq!(app.open_tabs.len(), 1);
    app.job = Some(Job::default());
    app.active_request = Some(Execution {
        plugin: Plugin::Maps,
        key: "maps".into(),
        parameters: String::new(),
        snapshot: ExecutionSnapshot {
            plugin: Plugin::Maps,
            force: false,
            options: Default::default(),
            dump: None,
        },
    });
    app.close_result_tab(0);
    assert_eq!(app.open_tabs.len(), 1);
    assert!(app.status.contains("取消"));
    app.job = None;
}
#[test]
fn tab_close_hit_and_middle_click_use_the_rendered_geometry() {
    let mut app = app();
    seed_tab(&mut app, Plugin::Pslist);
    seed_tab(&mut app, Plugin::Lsmod);
    let _terminal = render(&app, 120, 35);
    let (_, close, index) = app.hits.borrow().result_tabs[0];
    assert_eq!(index, 0);
    click(&mut app, close.x, close.y);
    assert_eq!(app.open_tabs.len(), 1);
    let _terminal = render(&app, 120, 35);
    let (rect, _, _) = app.hits.borrow().result_tabs[0];
    app.mouse(mouse_event(
        MouseEventKind::Down(MouseButton::Middle),
        rect.x,
        rect.y,
    ));
    assert!(app.open_tabs.is_empty());
}
#[test]
fn result_scrollbar_drags_outside_track_and_release_stops_motion() {
    let mut app = app();
    app.focus = Focus::Content;
    app.results.get_mut("linux.pslist.basic").unwrap().rows = (0..300)
        .map(|i| {
            vec![
                i.to_string(),
                "1".into(),
                "0".into(),
                "proc".into(),
                "0x1000".into(),
            ]
        })
        .collect();
    let terminal = render(&app, 120, 35);
    let result = app.hits.borrow().result;
    let x = result.right() - 1;
    let y = result.y + 1;
    assert_eq!(terminal.backend().buffer()[(x, y)].symbol(), "┃");
    app.mouse(mouse_event(MouseEventKind::Down(MouseButton::Left), x, y));
    assert!(app.drag.is_some());
    app.mouse(mouse_event(
        MouseEventKind::Drag(MouseButton::Left),
        x + 5,
        result.bottom() + 3,
    ));
    assert_eq!(app.row, 299);
    app.mouse(mouse_event(MouseEventKind::Up(MouseButton::Left), x, y));
    assert!(app.drag.is_none());
    app.mouse(mouse_event(MouseEventKind::Drag(MouseButton::Left), x, y));
    assert_eq!(app.row, 299);
}
#[test]
fn all_themes_fill_the_background_and_persist_the_setting() {
    let mut app = app();
    for (id, _) in THEMES {
        app.settings.theme = (*id).into();
        app.persist_settings();
        assert_eq!(store::read_settings(&app.cache).theme, *id);
        let terminal = render(&app, 120, 35);
        assert_eq!(terminal.backend().buffer()[(119, 34)].bg, color_surface());
    }
    theme::apply("missing");
    assert_eq!(color_surface(), Color::Rgb(21, 27, 36));
}
#[test]
fn cache_inventory_groups_results_and_scope_confirmation_never_deletes_evidence() {
    let (_dir, mut app) = preparation_fixture();
    let image = app.image.clone().unwrap();
    let result = app
        .results
        .get("linux.pslist.basic")
        .cloned()
        .unwrap_or_else(|| super::app().results["linux.pslist.basic"].as_ref().clone());
    let key = "a".repeat(64);
    let owner = store::Owner::new(&"b".repeat(64), &image);
    store::save(&app.cache, &key, &owner, &result, &Job::default()).unwrap();
    app.switch_page(Page::Cache);
    finish_test_job(&mut app);
    let before = render(&app, 120, 35);
    assert!(screen(&before, 120).contains("个结果"));
    app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let after = render(&app, 120, 35);
    assert!(screen(&after, 120).contains("▸"));
    app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert!(app.cache_page.confirm);
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.cache.join(format!("{key}.result.json")).exists());
    app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert!(image.exists());
    assert!(!app.cache.join(format!("{key}.result.json")).exists());
}
#[test]
fn export_and_record_reopen_are_worker_tasks_and_keep_partial_status() {
    let mut app = app();
    app.results.get_mut("linux.pslist.basic").unwrap().complete = false;
    let path = app.root.join("exports/test.json");
    app.export_result(path.clone());
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    let records = store::export_records(&app.cache);
    assert_eq!(records.len(), 1);
    assert!(!records[0].complete);
    std::fs::remove_file(path).unwrap();
    app.start_work(Work::Record(records[0].key.clone()));
    finish_test_job(&mut app);
    assert!(app.result().unwrap().historical);
    assert!(!app.result().unwrap().complete);
    assert_eq!(app.open_tabs.len(), 1);
}
#[test]
fn tiny_terminal_has_only_size_notice_and_restores_layout_on_resize() {
    let mut app = app();
    let tiny = render(&app, 59, 15);
    assert!(screen(&tiny, 59).contains("终端过小"));
    assert!(app.hits.borrow().tabs.is_empty());
    app.resize(120, 35);
    let _wide = render(&app, 120, 35);
    assert_eq!(app.hits.borrow().tabs.len(), 3);
}
#[test]
fn scanner_parameters_and_all_dump_modes_are_available() {
    let mut app = app();
    app.select_plugin(Plugin::Vmayarascan);
    app.windows_parameters();
    app.paste("hex:4d5a??00");
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(
        app.analysis_options.pattern.as_deref(),
        Some("hex:4d5a??00")
    );
    app.select_os(crate::analysis::Os::Windows);
    app.open_dump(Plugin::WinProcdump, false);
    for (i, plugin) in dump_modes(true).iter().enumerate() {
        app.dialog_key(KeyEvent::new(
            KeyCode::Char((b'1' + i as u8) as char),
            KeyModifiers::ALT,
        ));
        assert!(matches!(app.dialog,Some(Dialog::Dump{mode,..}) if mode==*plugin));
    }
}
#[test]
fn text_editing_removes_one_grapheme_at_a_time() {
    let mut text = "中e\u{301}".to_owned();
    let mut cursor = text.len();
    let mut selected = false;
    edit_input(
        &mut text,
        &mut cursor,
        &mut selected,
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
    );
    assert_eq!(text, "中");
    edit_input(
        &mut text,
        &mut cursor,
        &mut selected,
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
    );
    assert!(text.is_empty());
}

#[test]
fn result_tabs_replace_the_entire_table_title() {
    let mut app = app();
    seed_tab(&mut app, Plugin::Pslist);
    seed_tab(&mut app, Plugin::Lsmod);
    let terminal = render(&app, 120, 35);
    let row = app.hits.borrow().result.y as usize;
    let text = screen(&terminal, 120);
    let line = text.lines().nth(row).unwrap();
    assert!(line.contains("pslist") && line.contains("lsmod"));
    assert!(!line.contains("显示") && !line.contains("条"), "{line}");
}
