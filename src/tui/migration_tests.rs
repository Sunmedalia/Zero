//! Behavior introduced after the historical Rust UI, ported from the TS tests.
use super::*;

fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    terminal
}
fn seed_tab(app: &mut App, plugin: Plugin) {
    let mut result = app.results["pslist"].clone();
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
    assert!(app.results.contains_key("banners"));
    assert!(!app.results.contains_key("pslist"));
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
    assert!(!app.results.contains_key("lsmod"));
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
    app.results.get_mut("pslist").unwrap().rows = (0..300)
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
        .get("pslist")
        .cloned()
        .unwrap_or_else(|| super::app().results["pslist"].clone());
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
    app.results.get_mut("pslist").unwrap().complete = false;
    let result = app.result().unwrap().clone();
    let path = app.root.join("exports/test.json");
    app.start_work(Work::Export(
        path.clone(),
        result.metadata(),
        result.rows.clone(),
    ));
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
