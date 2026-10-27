use super::*;
fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    terminal
}
fn diagnosed_app() -> (tempfile::TempDir, App) {
    let (dir, mut app) = preparation_fixture();
    std::fs::create_dir_all(dir.path().join("symbols")).unwrap();
    std::fs::write(
        dir.path().join("symbols/exact.json"),
        fixture_isf(PREPARATION_BANNER, 1),
    )
    .unwrap();
    app.key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    finish_test_job(&mut app);
    (dir, app)
}
#[test]
fn diagnosis_collects_failure_in_a_report_without_running_a_plugin_or_changing_existing_results() {
    let (dir, mut app) = preparation_fixture();
    std::fs::create_dir_all(dir.path().join("symbols")).unwrap();
    std::fs::write(
        dir.path().join("symbols/exact.json"),
        fixture_isf(PREPARATION_BANNER, 1),
    )
    .unwrap();
    let old = super::app().results.remove("pslist").unwrap();
    app.results.insert("pslist".into(), old.clone());
    app.ensure_plugin_tab(Plugin::Pslist);
    app.row = 1;
    app.query = "init".into();
    app.last_error = Some("previous page-table failure".into());
    app.key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    assert!(app.diagnosis_running);
    assert!(matches!(app.dialog, Some(Dialog::KernelDiagnostics { .. })));
    let _frame = render(&app, 120, 35);
    finish_test_job(&mut app);
    assert!(!app.diagnosis_running);
    let report = app.kernel_report.as_ref().unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert!(!report.candidates[0].passed);
    assert_eq!(
        report.previous_analysis_error.as_deref(),
        Some("previous page-table failure")
    );
    assert_eq!(app.results["pslist"], old);
    assert_eq!(app.open_tabs.len(), 1);
    assert_eq!(app.row, 1);
    assert_eq!(app.query, "init");
    assert!(app.job.is_none());
    let frame = render(&app, 80, 24);
    assert!(screen(&frame, 80).contains("内核诊断"));
    let popup = app.hits.borrow().popup;
    let cell = &frame.backend().buffer()[(popup.x + 1, popup.y + 1)];
    assert_eq!(cell.fg, color_text());
    assert_eq!(cell.bg, color_surface());
    app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    assert!(matches!(app.dialog,Some(Dialog::KernelDiagnostics { scroll }) if scroll>0));
}
#[test]
fn reports_export_from_the_popup_and_survive_reopening_but_not_source_changes() {
    let (dir, mut app) = diagnosed_app();
    let _frame = render(&app, 120, 35);
    let button = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, k)| *k == KeyCode::Char('e'))
        .unwrap()
        .0;
    click(&mut app, button.x, button.y);
    assert!(matches!(
        app.dialog,
        Some(Dialog::Input {
            kind: InputKind::DiagnosticExport,
            ..
        })
    ));
    let output = dir.path().join("diagnostics/report.txt");
    app.paste(&output.display().to_string());
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert!(
        std::fs::read_to_string(&output)
            .unwrap()
            .contains("内核诊断报告")
    );
    assert!(matches!(app.dialog, Some(Dialog::KernelDiagnostics { .. })));
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let report = app.kernel_report.as_ref().unwrap().clone();
    app.key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    assert!(app.job.is_none());
    assert!(Arc::ptr_eq(app.kernel_report.as_ref().unwrap(), &report));
    app.invalidate_symbols();
    assert!(app.kernel_report.is_none());
}
#[test]
fn report_viewing_does_not_cancel_an_analysis_and_rerun_and_export_wait_for_idle() {
    let (_dir, mut app) = diagnosed_app();
    app.dialog = None;
    let job = Job::default();
    app.job = Some(job.clone());
    app.key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::KernelDiagnostics { .. })));
    for key in [KeyCode::Char('r'), KeyCode::Char('e'), KeyCode::Esc] {
        app.key(KeyEvent::new(key, KeyModifiers::NONE));
    }
    assert!(!job.cancel.load(Ordering::Relaxed));
    assert!(app.pending_work.is_none());
    assert!(app.job.is_some());
    app.job = None;
}
#[test]
fn kernel_diagnostic_command_needs_an_image_and_esc_cancels_only_diagnostic_work() {
    let mut app = app();
    assert!(app.image.is_none());
    app.key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    assert!(app.dialog.is_none());
    let (_dir, mut app) = preparation_fixture();
    app.key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    let job = app.job.clone().unwrap();
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.dialog.is_none());
    assert!(job.cancel.load(Ordering::Relaxed));
    finish_test_job(&mut app);
    assert!(app.kernel_report.is_none());
}

#[test]
fn a_report_is_regenerated_after_automatic_symbol_selection_changes_its_source() {
    let (dir, mut app) = diagnosed_app();
    let old = app.kernel_report.clone().unwrap();
    app.dialog = None;
    let next = dir.path().join("next.json");
    std::fs::write(&next, fixture_isf(PREPARATION_BANNER, 2)).unwrap();
    app.symbols = next.clone();
    app.key(KeyEvent::new(KeyCode::Char('J'), KeyModifiers::NONE));
    assert!(app.diagnosis_running);
    finish_test_job(&mut app);
    assert_eq!(app.kernel_report.as_ref().unwrap().symbol_source, next);
    assert!(!Arc::ptr_eq(app.kernel_report.as_ref().unwrap(), &old));
}

#[test]
fn report_paths_use_project_relative_names_with_canonical_root_aliases() {
    let (_dir, mut app) = diagnosed_app();
    let mut report = app.kernel_report.as_ref().unwrap().as_ref().clone();
    report.symbol_source = app.root.canonicalize().unwrap().join("symbols");
    app.kernel_report = Some(Arc::new(report));
    assert!(app.kernel_diagnostic_text().contains("符号来源: symbols\n"));
}
