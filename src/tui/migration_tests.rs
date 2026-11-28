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
    app.clear_plugin_tabs();
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

fn deliver_outcome(app: &mut App, outcome: Outcome) {
    deliver_event(app, WorkerEvent::Done(outcome));
}

fn deliver_event(app: &mut App, event: WorkerEvent) {
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    let (sender, receiver) = mpsc::channel();
    app.receiver = Some(receiver);
    let events = EventSender {
        sender,
        id: app.task_id,
        version: app.object_version,
    };
    assert!(events.send(event));
    app.drain();
}

fn request_result(app: &App, plugin: Plugin, name: &str) -> Results {
    let mut result = app.results.get(Plugin::Pslist.name()).unwrap().clone();
    result.plugin = plugin.name().into();
    result.rows[0][3] = name.into();
    result
}

fn assert_result_tab(app: &App, plugin: Plugin, key: &str, name: &str) {
    assert!(matches!(
        app.active_tab.and_then(|index| app.open_tabs.get(index)),
        Some(OpenTab::Plugin(active)) if *active == plugin
    ));
    assert_eq!(app.plugin, plugin);
    assert_eq!(app.displayed_request_key(), key);
    assert_eq!(app.view_key(), key);
    let stored = app.results.shared(key).unwrap();
    assert_eq!(stored.plugin, plugin.name());
    assert_eq!(stored.rows[0][3], name);
    assert!(Arc::ptr_eq(
        stored,
        app.results.shared(plugin.name()).unwrap()
    ));
    assert!(Arc::ptr_eq(stored, app.result_shared().unwrap()));
    assert!(screen(&render(app, 120, 35), 120).contains(name));
}

#[test]
fn same_plugin_symbol_retry_restores_the_originating_request_view() {
    let mut app = app();
    let plugin = Plugin::Pslist;
    seed_tab(&mut app, plugin);
    app.image = Some(app.root.join("missing.raw"));
    app.analysis_options.pid = Some(42);
    app.query = "target".into();
    let width = ColumnKey::new("Name", 0);
    app.column_widths.insert(width.clone(), 24);
    let key = app.request_key();
    app.request_analysis(true);

    // Save the originating view and edit the draft before the choice arrives.
    app.save_view();
    app.analysis_options.pid = Some(7);
    app.query = "other".into();
    app.column_widths.insert(width.clone(), 12);
    let draft_key = app.request_key();
    deliver_outcome(&mut app, Outcome::Choose(vec!["exact-symbol".into()]));
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.choice.as_deref(), Some("exact-symbol"));
    assert_eq!(app.active_request.as_ref().unwrap().key, key);
    assert_eq!(app.analysis_options.pid, Some(7));

    let result = request_result(&app, plugin, "target-retry");
    deliver_outcome(&mut app, Outcome::Ready(result));
    assert_result_tab(&app, plugin, &key, "target-retry");
    assert_eq!(app.query, "target");
    assert_eq!(app.column_widths.get(&width), Some(&24));
    assert_eq!(app.views[&draft_key].query, "other");
    assert!(app.status.contains(plugin.name()));
}

#[test]
fn cross_plugin_symbol_retry_preserves_the_browsed_result_tab() {
    let mut app = app();
    app.windows = true;
    let origin = Plugin::WinPslist;
    let browser = Plugin::WinCmdline;
    for plugin in [origin, browser] {
        seed_tab(&mut app, plugin);
    }
    app.analysis_options.pid = Some(10);
    app.query = "zsh".into();
    let width = ColumnKey::new("Name", 0);
    app.column_widths.insert(width.clone(), 23);
    let browser_key = app.request_key();
    let browsed = app.result_shared().unwrap().clone();
    app.results.insert(browser_key.clone(), browsed.clone());

    app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL));
    app.analysis_options.pid = Some(42);
    app.query = "target".into();
    let retry_key = app.request_key();
    app.image = Some(app.root.join("missing.raw"));
    app.request_analysis(true);
    deliver_outcome(&mut app, Outcome::Choose(vec!["exact-symbol".into()]));
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    assert_eq!(app.plugin, browser);
    assert!(app.choosing_analysis_symbols());
    app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL));
    assert_eq!(app.plugin, origin);

    let _terminal = render(&app, 120, 35);
    let (rect, _, _) = app.hits.borrow().result_tabs[1];
    click(&mut app, rect.x + 1, rect.y);
    assert!(app.choosing_analysis_symbols());
    let browser_tab = app.active_tab;
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.active_request.as_ref().unwrap().key, retry_key);
    assert_eq!(app.active_tab, browser_tab);
    assert_eq!(app.query, "zsh");
    assert_eq!(app.column_widths.get(&width), Some(&23));
    assert!(Arc::ptr_eq(&browsed, app.result_shared().unwrap()));

    let result = request_result(&app, origin, "target-cross");
    deliver_outcome(&mut app, Outcome::Ready(result));
    assert_eq!(app.active_tab, browser_tab);
    assert_result_tab(&app, browser, &browser_key, "zsh");
    app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL));
    assert_eq!(app.query, "target");
    assert_result_tab(&app, origin, &retry_key, "target-cross");
}

#[test]
fn background_symbol_retry_restores_execution_view_and_keeps_edited_draft() {
    let mut app = app();
    let origin = Plugin::Pslist;
    let other = Plugin::Psaux;
    for plugin in [other, origin] {
        seed_tab(&mut app, plugin);
    }
    app.image = Some(app.root.join("missing.raw"));
    app.analysis_options.pid = Some(42);
    app.query = "original".into();
    let column = ColumnKey::new("Name", 0);
    app.column_widths.insert(column.clone(), 23);
    let original_key = app.request_key();
    app.request_analysis(true);

    app.windows_parameters();
    let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog else {
        panic!("expected parameter editor");
    };
    fields[2] = "7".into();
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(app.analysis_options.pid, Some(7));
    let draft_key = app.request_key();
    let old_draft = request_result(&app, origin, "old-draft");
    app.results.insert(draft_key.clone(), old_draft);
    app.query = "old-draft".into();

    deliver_outcome(&mut app, Outcome::Choose(vec!["exact-symbol".into()]));
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    assert_eq!(app.plugin, other);
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    let result = request_result(&app, origin, "original-retry");
    deliver_outcome(&mut app, Outcome::Ready(result));
    assert_eq!(app.plugin, other);

    app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL));
    assert_eq!(app.query, "original");
    assert_eq!(app.column_widths.get(&column), Some(&23));
    assert_result_tab(&app, origin, &original_key, "original-retry");
    assert_eq!(app.request_key(), draft_key);
    assert_eq!(app.analysis_options.pid, Some(7));
    assert_eq!(app.views[&draft_key].query, "old-draft");
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert_eq!(app.active_request.as_ref().unwrap().key, draft_key);
    assert_eq!(app.query, "original");
    let draft_result = request_result(&app, origin, "old-draft-updated");
    deliver_outcome(&mut app, Outcome::Ready(draft_result));
    assert_result_tab(&app, origin, &draft_key, "old-draft-updated");
    assert_eq!(app.query, "old-draft");
    assert!(app.status.contains(origin.name()));
}

fn rerun_from_bound_result() -> (App, String, String) {
    let mut app = app();
    for plugin in [Plugin::Psaux, Plugin::Pslist] {
        seed_tab(&mut app, plugin);
    }
    app.image = Some(app.root.join("missing.raw"));
    app.analysis_options.pid = Some(42);
    app.query = "original".into();
    let original_key = app.request_key();
    app.request_analysis(true);
    deliver_outcome(&mut app, Outcome::Choose(vec!["exact-symbol".into()]));
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    let original = request_result(&app, Plugin::Pslist, "original-result");
    deliver_outcome(&mut app, Outcome::Ready(original));

    app.windows_parameters();
    let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog else {
        panic!("expected parameter editor");
    };
    fields[2] = "7".into();
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(app.analysis_options.pid, Some(7));
    let draft_key = app.request_key();
    let previous_draft = request_result(&app, Plugin::Pslist, "old-draft-result");
    app.results.insert(draft_key.clone(), previous_draft);
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert_eq!(app.active_request.as_ref().unwrap().key, draft_key);
    (app, original_key, draft_key)
}

fn assert_previous_result_after_rerun(app: &mut App, original_key: &str, draft_key: &str) {
    app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL));
    assert_eq!(app.plugin, Plugin::Psaux);
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    assert_result_tab(app, Plugin::Pslist, original_key, "original-result");
    assert_eq!(app.query, "original");
    assert_eq!(app.request_key(), draft_key);
    assert_eq!(
        app.results.get(draft_key).unwrap().rows[0][3],
        "old-draft-result"
    );
}

#[test]
fn failed_rerun_keeps_the_previous_result_tab_binding() {
    let (mut app, original_key, draft_key) = rerun_from_bound_result();
    app.views.insert(
        draft_key.clone(),
        View {
            query: "old-draft".into(),
            ..Default::default()
        },
    );
    deliver_event(&mut app, WorkerEvent::Failed("分析失败".into()));
    assert_eq!(app.last_error.as_deref(), Some("分析失败"));
    assert!(app.status.contains("分析失败"));
    // Without switching tabs, the active tab still displays the last completed result and view.
    assert_result_tab(&app, Plugin::Pslist, &original_key, "original-result");
    assert_eq!(app.query, "original");
    assert!(!screen(&render(&app, 120, 35), 120).contains("old-draft-result"));
    assert_previous_result_after_rerun(&mut app, &original_key, &draft_key);
}

#[test]
fn cancelled_rerun_keeps_the_previous_result_tab_binding() {
    let (mut app, original_key, draft_key) = rerun_from_bound_result();
    app.views.insert(
        draft_key.clone(),
        View {
            query: "old-draft".into(),
            ..Default::default()
        },
    );
    app.cancel();
    // Even if the worker has already produced rows, cancellation drops them.
    let cancelled_result = request_result(&app, Plugin::Pslist, "cancelled-result");
    deliver_outcome(&mut app, Outcome::Ready(cancelled_result));
    assert!(app.status.contains("已取消"));
    // Without switching tabs, the active tab still displays the last completed result and view.
    assert_result_tab(&app, Plugin::Pslist, &original_key, "original-result");
    assert_eq!(app.query, "original");
    let rendered = screen(&render(&app, 120, 35), 120);
    assert!(!rendered.contains("old-draft-result"));
    assert!(!rendered.contains("cancelled-result"));
    assert_previous_result_after_rerun(&mut app, &original_key, &draft_key);
}

#[test]
fn successful_rerun_replaces_the_previous_result_tab_binding() {
    let (mut app, original_key, draft_key) = rerun_from_bound_result();
    app.views.insert(
        draft_key.clone(),
        View {
            query: "new-draft".into(),
            ..Default::default()
        },
    );
    // While running, the active tab stays on the previous completed result and view.
    assert_result_tab(&app, Plugin::Pslist, &original_key, "original-result");
    assert_eq!(app.query, "original");
    let result = request_result(&app, Plugin::Pslist, "new-draft-result");
    deliver_outcome(&mut app, Outcome::Ready(result));
    assert_result_tab(&app, Plugin::Pslist, &draft_key, "new-draft-result");
    assert_eq!(app.query, "new-draft");
    assert!(app.status.contains(Plugin::Pslist.name()));
    assert_eq!(app.views[&original_key].query, "original");
    app.analysis_options.pid = Some(9);
    app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL));
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    assert_result_tab(&app, Plugin::Pslist, &draft_key, "new-draft-result");
    assert_eq!(app.query, "new-draft");
    assert_eq!(app.analysis_options.pid, Some(9));
}

#[test]
fn successful_rerun_after_switching_tabs_updates_active_view_and_table() {
    let (mut app, original_key, draft_key) = rerun_from_bound_result();
    app.views.insert(
        draft_key.clone(),
        View {
            query: "new-draft".into(),
            ..Default::default()
        },
    );
    // Switch away and back while the rerun is still in progress.
    app.key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::CONTROL));
    assert_eq!(app.plugin, Plugin::Psaux);
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    assert_result_tab(&app, Plugin::Pslist, &original_key, "original-result");
    assert_eq!(app.query, "original");

    // When the rerun succeeds on the active tab, table, view, and status bar all update together.
    let result = request_result(&app, Plugin::Pslist, "new-draft-result");
    deliver_outcome(&mut app, Outcome::Ready(result));
    assert_result_tab(&app, Plugin::Pslist, &draft_key, "new-draft-result");
    assert_eq!(app.query, "new-draft");
    assert_eq!(app.views[&original_key].query, "original");
    let rendered = screen(&render(&app, 140, 35), 140);
    assert!(rendered.contains("new-draft-result"));
    assert!(!rendered.contains("original-result"));
    assert!(app.status.contains(Plugin::Pslist.name()));
    assert!(rendered.contains(Plugin::Pslist.name()));
}

#[test]
fn queued_rerun_while_staying_on_origin_tab_updates_binding_when_ready() {
    let (mut app, original_key, _draft_key) = rerun_from_bound_result();
    app.analysis_options.pid = Some(9);
    let queued_key = app.request_key();
    app.views.insert(
        queued_key.clone(),
        View {
            query: "queued-nine".into(),
            ..Default::default()
        },
    );
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(app.pending_execution.is_some());

    // Finish the cancelled job so the queued snapshot starts while staying on Pslist.
    let cancelled = request_result(&app, Plugin::Pslist, "cancelled-seven");
    deliver_outcome(&mut app, Outcome::Ready(cancelled));
    assert_eq!(app.active_request.as_ref().unwrap().key, queued_key);
    assert_result_tab(&app, Plugin::Pslist, &original_key, "original-result");
    assert_eq!(app.query, "original");

    let queued = request_result(&app, Plugin::Pslist, "queued-nine-result");
    deliver_outcome(&mut app, Outcome::Ready(queued));
    assert_result_tab(&app, Plugin::Pslist, &queued_key, "queued-nine-result");
    assert_eq!(app.query, "queued-nine");
    assert_eq!(app.views[&original_key].query, "original");
    let rendered = screen(&render(&app, 140, 35), 140);
    assert!(rendered.contains("queued-nine-result"));
    assert!(!rendered.contains("original-result"));
    assert!(app.status.contains(Plugin::Pslist.name()));
}

#[test]
fn failed_symbol_retry_while_staying_on_origin_tab_keeps_previous_binding() {
    let (mut app, original_key, draft_key) = rerun_from_bound_result();
    deliver_outcome(&mut app, Outcome::Choose(vec!["exact-symbol".into()]));
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.active_request.as_ref().unwrap().key, draft_key);
    assert_result_tab(&app, Plugin::Pslist, &original_key, "original-result");
    assert_eq!(app.query, "original");

    deliver_event(&mut app, WorkerEvent::Failed("符号重试失败".into()));
    assert_eq!(app.last_error.as_deref(), Some("符号重试失败"));
    assert!(app.status.contains("符号重试失败"));
    assert_result_tab(&app, Plugin::Pslist, &original_key, "original-result");
    assert_eq!(app.query, "original");
    assert!(!screen(&render(&app, 120, 35), 120).contains("old-draft-result"));
}

#[test]
fn symbol_choice_marks_other_candidates_stale_and_skips_their_session_cache() {
    let mut app = app();
    let symbols = app.cache.parent().unwrap().join("candidates.zip");
    std::fs::write(&symbols, []).unwrap();
    app.symbols = symbols.canonicalize().unwrap();
    app.registry
        .import(&app.symbols, Kind::Symbols, &app.cache)
        .unwrap();
    app.refresh_assets();
    app.local_matches.insert(
        app.symbols.clone(),
        vec!["candidate-x".into(), "candidate-y".into()],
    );
    app.choice = Some("candidate-x".into());
    let browser = Plugin::Psaux;
    seed_tab(&mut app, browser);
    let mut old = request_result(&app, browser, "old-symbol-row");
    old.symbol = "candidate-x".into();
    let browser_key = app.request_key();
    let old = Arc::new(old);
    app.results.insert(browser.name().into(), old.clone());
    app.results.insert(browser_key.clone(), old);
    let origin = Plugin::Pslist;
    seed_tab(&mut app, origin);
    let mut stale = request_result(&app, origin, "old-symbol-row");
    stale.symbol = "candidate-x".into();
    app.results.insert(app.request_key(), stale);

    app.switch_page(Page::Assets);
    app.switch_section(AssetSection::Symbols);
    app.focus_asset(Kind::Symbols, &app.symbols.clone());
    assert!(app.use_selected_asset());
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.choice.is_none());
    app.switch_page(Page::Analysis);
    app.image = Some(app.root.join("missing.raw"));
    app.activate_plugin(browser);
    assert_eq!(app.active_request.as_ref().unwrap().key, browser_key);
    deliver_outcome(
        &mut app,
        Outcome::Choose(vec!["candidate-x".into(), "candidate-y".into()]),
    );
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    let mut fresh = request_result(&app, browser, "new-symbol-row");
    fresh.symbol = "candidate-y".into();
    deliver_outcome(&mut app, Outcome::Ready(fresh));

    // An untouched plugin's old rows still render, but its request cannot hit
    // the session cache under the newly selected candidate.
    let shown = screen(&render(&app, 140, 35), 140);
    assert!(shown.contains("candidate-y"));
    assert!(shown.contains("旧符号结果"));
    assert!(shown.contains("old-symbol-row"));
    assert!(!shown.contains("candidate-x"));
    app.activate_plugin(origin);
    assert_eq!(app.active_request.as_ref().unwrap().plugin, origin);
    app.job.as_ref().unwrap().mark_cached();
    let mut cached_alias = request_result(&app, origin, "reopened-row");
    cached_alias.symbol = "candidate-x".into();
    deliver_outcome(&mut app, Outcome::Ready(cached_alias));
    assert_eq!(app.result().unwrap().symbol, "candidate-y");
    app.activate_plugin(origin);
    assert!(app.job.is_none());
}

#[test]
fn result_tab_overflow_arrows_keep_symbol_selection_open() {
    let mut app = app();
    for plugin in [Plugin::Pslist, Plugin::Psaux, Plugin::Lsmod, Plugin::Maps] {
        seed_tab(&mut app, plugin);
    }
    app.image = Some(app.root.join("missing.raw"));
    app.switch_result_tab(0);
    app.request_analysis(true);
    deliver_outcome(&mut app, Outcome::Choose(vec!["exact-symbol".into()]));
    let active = app.active_tab;
    for offset in [1, 0] {
        let _terminal = render(&app, 80, 28);
        let (rect, _) = app
            .hits
            .borrow()
            .result_tab_steps
            .iter()
            .find(|(_, index)| *index == Some(offset))
            .copied()
            .unwrap();
        click(&mut app, rect.x, rect.y);
        assert_eq!(app.tab_offset.get(), offset);
        assert_eq!(app.active_tab, active);
        assert!(app.choosing_analysis_symbols());
    }
}

#[test]
fn disabled_result_tab_arrows_keep_symbol_selection_open() {
    let mut app = app();
    for plugin in [Plugin::Pslist, Plugin::Psaux, Plugin::Lsmod, Plugin::Maps] {
        seed_tab(&mut app, plugin);
    }
    app.image = Some(app.root.join("missing.raw"));
    app.switch_result_tab(0);
    app.request_analysis(true);
    deliver_outcome(
        &mut app,
        Outcome::Choose(vec!["candidate-a".into(), "candidate-b".into()]),
    );
    app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    let active = app.active_tab;
    let _terminal = render(&app, 80, 28);

    for (offset, arrow) in [(0, "<"), (1, ">")] {
        app.tab_offset.set(offset);
        let terminal = render(&app, 80, 28);
        let hits = app.hits.borrow();
        let y = hits.result_tabs[0].0.y;
        let x = if offset == 0 {
            hits.result_tabs[0].0.x - 2
        } else {
            hits.result_tabs.last().unwrap().0.right() + 1
        };
        drop(hits);
        assert_eq!(terminal.backend().buffer()[(x, y)].symbol(), arrow);
        click(&mut app, x, y);
        assert_eq!(app.tab_offset.get(), offset);
        assert_eq!(app.active_tab, active);
        assert!(app.choosing_analysis_symbols());
        assert!(matches!(
            app.dialog,
            Some(Dialog::Symbols { selected: 1, .. })
        ));
    }
}

#[test]
fn busy_queued_run_stores_its_result_without_activating_the_tab() {
    let mut app = app();
    let origin = Plugin::Pslist;
    let browser = Plugin::Psaux;
    seed_tab(&mut app, browser);
    let browser_key = app.request_key();
    let browsed = app.result_shared().unwrap().clone();
    app.results.insert(browser_key.clone(), browsed);
    app.image = Some(app.root.join("missing.raw"));

    // Request a plugin with no tab while another job is active.
    app.select_plugin(origin);
    app.analysis_options.pid = Some(42);
    let queued_key = app.request_key();
    let job = Job::default();
    app.job = Some(job.clone());
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(job.cancel.load(Ordering::Relaxed));
    assert!(app.pending_execution.is_some());
    app.switch_result_tab(0);
    app.query = "zsh".into();
    let browser_tab = app.active_tab;

    let result = request_result(&app, origin, "cancelled");
    deliver_outcome(&mut app, Outcome::Ready(result));
    assert_eq!(app.active_request.as_ref().unwrap().key, queued_key);
    assert_eq!(app.active_tab, browser_tab);
    assert!(!app.results.contains_key(&queued_key));
    assert_result_tab(&app, browser, &browser_key, "zsh");

    let result = request_result(&app, origin, "queued-result");
    deliver_outcome(&mut app, Outcome::Ready(result));
    assert_eq!(app.active_tab, browser_tab);
    assert_result_tab(&app, browser, &browser_key, "zsh");
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::CONTROL));
    assert_result_tab(&app, origin, &queued_key, "queued-result");
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
