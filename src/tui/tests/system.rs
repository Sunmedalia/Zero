use super::*;

#[test]
fn windows_menu_and_parameters_follow_identification() {
    let mut app = app();
    let mut result = app.results["pslist"].clone();
    result.rows = vec![vec![
        "0x1000".into(),
        "Windows PDB ntkrnlmp.pdb/GUID1".into(),
    ]];
    app.apply_identification(&result);
    assert_eq!(app.plugin, Plugin::WinPslist);
    assert!(app.navigation_plugins().iter().all(|p| p.is_windows()));
    assert!(!app.navigation_plugins().iter().any(|p| p.is_dump()));
    app.analysis_options.hive = Some(0xffff800000001000);
    app.analysis_options.key = "Software".into();
    app.plugin = Plugin::WinPrintkey;
    app.windows_parameters();
    let Some(Dialog::WindowsParameters { fields, field, .. }) = &app.dialog else {
        panic!("missing Windows parameters");
    };
    assert_eq!(fields[0], "0xffff800000001000");
    assert_eq!(fields[1], "Software");
    assert_eq!(*field, 0);
}

#[test]
fn windows_plugin_labels_omit_prefix_in_navigation_and_search() {
    let mut app = app();
    app.select_os(crate::analysis::Os::Windows);
    assert!(app.menu_items().contains(&"pslist"));
    assert!(
        app.menu_items()
            .iter()
            .all(|label| !label.starts_with("windows."))
    );
    assert_eq!(app.plugin_matches("pslist"), vec![Plugin::WinPslist]);
    assert_eq!(
        app.plugin_matches("windows.pslist"),
        vec![Plugin::WinPslist]
    );
    let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(!screen(&terminal, 100).contains("windows."));
    app.dialog = Some(Dialog::Plugins {
        query: "pslist".into(),
        selected: 0,
    });
    terminal.draw(|f| app.draw(f)).unwrap();
    let rendered = screen(&terminal, 100);
    assert!(rendered.contains("pslist"));
    assert!(!rendered.contains("windows.pslist"));
    assert_eq!(Plugin::WinPslist.name(), "windows.pslist");
}

#[test]
fn auto_identification_switches_windows_and_preserves_unknown_system() {
    let mut app = app();
    let mut banner = app.results["pslist"].clone();
    banner.plugin = "banners".into();
    banner.system = "windows".into();
    banner.rows = vec![vec![
        "[container]".into(),
        "Windows container minidump".into(),
    ]];
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Identified(banner.clone())).unwrap();
    app.drain();
    assert!(app.windows);
    assert_eq!(app.plugin, Plugin::WinPslist);
    assert!(app.status.contains("自动识别 Windows"));
    banner.system = "linux".into();
    banner.rows.clear();
    app.apply_identification(&banner);
    assert!(app.windows);
    assert!(app.identification_status(&banner).contains("未识别系统"));
    app.analysis_options.os = crate::analysis::Os::Linux;
    banner.system = "windows".into();
    app.apply_identification(&banner);
    assert!(!app.windows);
    assert_eq!(app.identification_status(&banner), "保留手动系统选择");
}

#[test]
fn system_picker_opens_windows_without_identification_and_survives_image_change() {
    let mut app = app();
    let mut linux_banner = app.results["pslist"].clone();
    app.page = Page::Assets;
    app.key(KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::System { selected: 0 })));
    for _ in 0..2 {
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    }
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.dialog.is_none());
    assert!(app.job.is_none());
    assert_eq!(app.page, Page::Assets);
    assert_eq!(app.analysis_options.os, crate::analysis::Os::Windows);
    assert_eq!(app.navigation_plugins()[app.menu], Plugin::WinPslist);
    assert!(app.navigation_plugins().contains(&Plugin::WinThreads));
    assert!(app.results.is_empty());
    app.invalidate_source();
    assert_eq!(app.analysis_options.os, crate::analysis::Os::Windows);
    linux_banner.plugin = "banners".into();
    app.apply_identification(&linux_banner);
    assert!(app.windows);
    app.results.insert("banners".into(), linux_banner);
    app.analysis_options.hive = Some(0x1000);
    app.analysis_options.pid = Some(123);
    app.analysis_options.key = "Software".into();
    app.analysis_options.swapfile = Some("swapfile.sys".into());
    app.select_os(crate::analysis::Os::Auto);
    assert!(!app.windows);
    assert_eq!(app.plugin, Plugin::Pslist);
    assert!(app.analysis_options.pid.is_none());
    assert!(app.analysis_options.hive.is_none());
    assert!(app.analysis_options.key.is_empty());
    assert!(app.analysis_options.swapfile.is_none());
}

#[test]
fn system_picker_footer_and_mouse_work_on_both_pages() {
    for page in [Page::Analysis, Page::Assets] {
        let mut app = app();
        app.page = page;
        let mut terminal = Terminal::new(TestBackend::new(60, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        if page == Page::Assets {
            assert!(
                !app.hits
                    .borrow()
                    .buttons
                    .iter()
                    .any(|(_, key)| *key == KeyCode::F(6))
            );
            app.key(KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE));
        } else {
            // F6 is the last footer entry and may be truncated at 45 columns;
            // it stays reachable through `更多 ?`.
            let hit = app
                .hits
                .borrow()
                .buttons
                .iter()
                .find(|(_, key)| matches!(key, KeyCode::F(6) | KeyCode::Char('?')))
                .copied()
                .unwrap();
            app.mouse(mouse_event(
                MouseEventKind::Down(MouseButton::Left),
                hit.0.x,
                hit.0.y,
            ));
            if hit.1 == KeyCode::Char('?') {
                for key in [KeyCode::Char('系'), KeyCode::Char('统')] {
                    app.dialog_key(KeyEvent::new(key, KeyModifiers::NONE));
                }
                app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            }
        }
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 60).contains("Windows"));
        let popup = app.hits.borrow().popup;
        app.mouse(mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            popup.x + 2,
            popup.y + 2,
        ));
        assert!(app.windows);
        assert!(app.dialog.is_none());
    }
}

#[test]
fn direct_system_buttons_switch_plugins_and_preserve_current_view() {
    for page in [Page::Assets, Page::Analysis] {
        for width in [60, 80, 120] {
            let mut app = app();
            app.page = page;
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            let hits = app.hits.borrow().clone();
            assert!(screen(&terminal, width.into()).contains("Windows"));
            let windows = hits
                .systems
                .iter()
                .find(|(_, os)| *os == crate::analysis::Os::Windows)
                .unwrap()
                .0;
            click(&mut app, windows.x + 1, windows.y);
            assert!(app.windows);
            assert_eq!(app.plugin, Plugin::WinPslist);
            assert!(app.dialog.is_none());
            app.query = "preserve".into();
            click(&mut app, windows.x + 1, windows.y);
            assert_eq!(app.query, "preserve");
            terminal.draw(|f| app.draw(f)).unwrap();
            let linux = app
                .hits
                .borrow()
                .systems
                .iter()
                .find(|(_, os)| *os == crate::analysis::Os::Linux)
                .unwrap()
                .0;
            click(&mut app, linux.x + 1, linux.y);
            assert!(!app.windows);
            assert_eq!(app.plugin, Plugin::Pslist);
            assert_eq!(app.analysis_options.os, crate::analysis::Os::Linux);
            assert_eq!(app.page, page);
            assert!(
                app.hits
                    .borrow()
                    .systems
                    .iter()
                    .all(|(_, os)| *os != crate::analysis::Os::Auto)
            );
        }
    }
}

#[test]
fn system_switch_waits_for_worker_and_discards_old_results() {
    let mut app = app();
    let old = Job::default();
    app.job = Some(old.clone());
    app.pending_work = Some(Work::Analyze(false));
    app.select_os(crate::analysis::Os::Windows);
    assert!(old.cancel.load(Ordering::Relaxed));
    assert!(!app.windows);
    assert!(app.pending_work.is_none());
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Failed("cancelled".into())).unwrap();
    assert!(app.drain());
    assert!(app.windows);
    assert!(app.job.is_none());
    assert!(app.results.is_empty());
    assert!(app.last_error.is_none());
    assert!(app.pending_os.is_none());
    app.job = Some(Job::default());
    app.select_os(crate::analysis::Os::Linux);
    app.cancel();
    assert!(app.pending_os.is_none());
}
