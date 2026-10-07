use super::*;
use ratatui::backend::TestBackend;
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
    assert!(app.menu_items().contains(&"pslist".into()));
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
fn clicking_auto_reidentifies_loaded_image_and_switches_plugins() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = app();
    app.cache = dir.path().join("cache");
    let image = dir.path().join("linux.raw");
    let mut bytes = vec![0; 4096];
    let banner = b"Linux version 3.2.0-test (test@test) (gcc version 4.6.3) #1 SMP test\n\0";
    bytes[256..256 + banner.len()].copy_from_slice(banner);
    std::fs::write(&image, bytes).unwrap();
    app.select_os(crate::analysis::Os::Windows);
    app.image = Some(image);
    app.analysis_options.swapfile = Some("swapfile.sys".into());
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let auto = app
        .hits
        .borrow()
        .systems
        .iter()
        .find(|(_, os)| *os == crate::analysis::Os::Auto)
        .unwrap()
        .0;
    click(&mut app, auto.x + 1, auto.y);
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    assert_eq!(app.analysis_options.os, crate::analysis::Os::Auto);
    assert!(!app.windows);
    assert_eq!(app.plugin, Plugin::Pslist);
    assert!(app.status.contains("精确匹配"));
    assert!(app.analysis_options.swapfile.is_none());
    terminal.draw(|f| app.draw(f)).unwrap();
    click(&mut app, auto.x + 1, auto.y);
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    assert!(app.status.contains("精确匹配"));
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
        let mut terminal = Terminal::new(TestBackend::new(45, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let rect = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(_, key)| *key == KeyCode::F(6))
            .unwrap()
            .0;
        app.mouse(mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            rect.x,
            rect.y,
        ));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(screen(&terminal, 45).contains("Windows"));
        let popup = app.hits.borrow().popup;
        app.mouse(mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            popup.x + 2,
            popup.y + 3,
        ));
        assert!(app.windows);
        assert!(app.dialog.is_none());
    }
}
#[test]
fn direct_system_buttons_switch_plugins_and_preserve_current_view() {
    for page in [Page::Assets] {
        for width in [20, 45, 80, 120] {
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
            if width >= 45 {
                terminal.draw(|f| app.draw(f)).unwrap();
                let auto = app
                    .hits
                    .borrow()
                    .systems
                    .iter()
                    .find(|(_, os)| *os == crate::analysis::Os::Auto)
                    .unwrap()
                    .0;
                click(&mut app, auto.x + 1, auto.y);
                assert_eq!(app.analysis_options.os, crate::analysis::Os::Auto);
            }
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
#[test]
fn asset_tabs_import_filter_selection_and_non_destructive_removal() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("sample.raw");
    let symbols = dir.path().join("exact.json.xz");
    std::fs::write(&image, b"image").unwrap();
    std::fs::write(&symbols, b"symbols").unwrap();
    let image = image.canonicalize().unwrap();
    let symbols = symbols.canonicalize().unwrap();
    let cache = dir.path().join("cache");
    let mut app = App::new(None, "missing".into(), cache.clone(), Settings::default());
    app.root = dir.path().into();
    app.settings.symbols = symbols.display().to_string();
    app.settings.image_dir = dir.path().join("images").display().to_string();
    app.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    app.paste(&image.display().to_string());
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.image.as_ref(), Some(&image));
    assert_eq!(
        Registry::load(&cache).unwrap().selected(Kind::Image),
        Some(image.as_path())
    );
    assert_eq!(app.asset_count(), 1);
    assert!(app.job.is_some()); // importing an image starts banner identification
    app.finish_worker();
    app.switch_page(Page::Assets);

    app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.paste("absent");
    assert_eq!(app.asset_count(), 0);
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.asset_count(), 1);
    app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.paste("sample");
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.asset_queries[0].is_empty());
    app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert!(image.exists());
    assert!(app.image.is_none());
    assert_eq!(app.asset_count(), 0);
    assert!(
        Registry::load(&cache)
            .unwrap()
            .selected(Kind::Image)
            .is_none()
    );
    app.switch_section(AssetSection::Symbols);
    assert_eq!(app.section, AssetSection::Symbols);
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.symbols, symbols);
    assert_eq!(
        Registry::load(&cache).unwrap().selected(Kind::Symbols),
        Some(symbols.as_path())
    );
    assert!(app.results.is_empty());
    app.key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    assert!(symbols.exists());
    assert!(app.symbols.as_os_str().is_empty());
    assert!(Registry::load(&cache).unwrap().excluded(&symbols));

    app.switch_section(AssetSection::Images);
    app.key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
    assert!(app.job.is_none());
    assert!(app.dialog.is_none()); // no selected image must not silently use the old one
}
#[test]
fn remote_tabs_mouse_scrolling_full_links_events_and_cancellation() {
    let mut app = app();
    app.switch_section(AssetSection::Remote);
    app.remote = (0..50)
        .map(|i| RemoteMatch {
            banner: format!("Linux version exact-{i}\tcomplete"),
            path: format!("Linux/sample-{i}.json.xz"),
            url: format!(
                "https://example.test/{}-{i}.json.xz",
                "long-path/".repeat(100)
            ),
        })
        .collect();
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    assert!(hits.asset_offset > 0);
    click(&mut app, hits.assets.x + 2, hits.assets.y + 1);
    assert_eq!(app.asset_rows[2], hits.asset_offset);
    assert!(app.job.is_none()); // row selection never triggers download
    let Some(Dialog::RemoteDetail { candidate, .. }) = &app.dialog else {
        panic!("detail missing")
    };
    let text = app.remote_detail_text(candidate);
    assert!(text.contains(&app.remote[hits.asset_offset].url));
    assert!(text.contains("\\t"));
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.focus = Focus::Content;
    app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    assert!(app.asset_scroll[2] > 0);
    let job = Job::default();
    app.job = Some(job.clone());
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(job.cancel.load(Ordering::Relaxed));
    app.job = None;
    let (tx, rx) = mpsc::channel();
    tx.send(WorkerEvent::Links(app.remote.clone())).unwrap();
    app.receiver = Some(rx);
    app.drain();
    assert!(app.dialog.is_none());
    assert_eq!(app.remote.len(), 50);
    terminal.draw(|f| app.draw(f)).unwrap();
    let rect = app.hits.borrow().tabs[1].0;
    click(&mut app, rect.x, rect.y);
    assert_eq!(app.section, AssetSection::Remote); // Switching a top-level tab preserves the region.
    app.key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
    assert_eq!(app.page, Page::Analysis);
}
#[test]
fn downloaded_symbols_are_registered_without_starting_analysis_in_manager() {
    let dir = tempfile::tempdir().unwrap();
    let symbols = dir.path().join("download.json.xz");
    std::fs::write(&symbols, b"validated worker output").unwrap();
    let symbols = symbols.canonicalize().unwrap();
    let cache = dir.path().join("cache");
    let settings = Settings {
        image_dir: dir.path().join("images").display().to_string(),
        symbols: dir.path().join("symbols").display().to_string(),
        ..Settings::default()
    };
    let mut app = App::new(None, "absent".into(), cache.clone(), settings);
    app.root = dir.path().into();
    app.switch_section(AssetSection::Remote);
    app.download_url = Some("https://example.test/exact.json.xz".into());
    let (tx, rx) = mpsc::channel();
    tx.send(WorkerEvent::Downloaded(symbols.clone())).unwrap();
    app.receiver = Some(rx);
    app.drain();
    assert_eq!(app.section, AssetSection::Remote);
    assert!(app.job.is_none());
    assert_eq!(app.symbols, symbols);
    assert_eq!(app.downloads.len(), 1);
    app.switch_section(AssetSection::Symbols);
    assert!(app.asset_list().iter().any(|a| a.path == symbols));
    assert_eq!(
        Registry::load(&cache).unwrap().selected(Kind::Symbols),
        Some(symbols.as_path())
    );
}
#[test]
fn all_asset_pages_render_on_wide_narrow_and_tiny_terminals() {
    let mut app = app();
    for (w, h) in [(170, 32), (80, 24), (45, 16), (20, 8), (1, 1)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        for page in Page::ALL {
            app.switch_page(page);
            terminal.draw(|f| app.draw(f)).unwrap();
        }
    }
}
#[test]
fn compact_columns_mixed_numeric_sort_and_paginated_mouse_rows() {
    let columns = vec!["PID".into(), "Name".into(), "Path".into()];
    let rows = vec![vec!["2".into(), "sh".into(), "/very/long/path".into()]];
    assert_eq!(table_widths(&columns, &rows), vec![3, 4, 15]);
    let mut mixed = vec!["2", "10", "1a", "0x3", ""];
    mixed.sort_by(|a, b| compare_values(a, b));
    assert_eq!(mixed, vec!["2", "0x3", "10", "", "1a"]);
    let mut app = app();
    let result = app.results.get_mut("pslist").unwrap();
    result.rows = (0..20)
        .map(|i| {
            vec![
                i.to_string(),
                i.to_string(),
                "0".into(),
                "sh".into(),
                "0x1000".into(),
            ]
        })
        .collect();
    app.settings.page_size = 2;
    app.focus = Focus::Content;
    app.key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE));
    assert_eq!(app.row, 2);
    let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let hit = app.hits.borrow().clone();
    assert_eq!(hit.row_offset, 2);
    click(&mut app, hit.result.x + 2, hit.result.y + 2);
    assert_eq!(app.row, 2);
    assert_eq!(app.rows().len(), 20); // page does not limit export
    app.key(KeyEvent::new(KeyCode::Char('['), KeyModifiers::NONE));
    assert_eq!(app.row, 0);
    assert_eq!(menu_items().len(), navigation_plugins().len() + 1);
    assert!(!menu_items().iter().any(|i| i.contains("CSV")));
}
#[test]
fn directory_configuration_picker_navigation_and_export_history() {
    let dir = tempfile::tempdir().unwrap();
    let images = dir.path().join("images");
    let nested = images.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("one.raw"), b"image").unwrap();
    let mut app = App::new(
        None,
        "missing".into(),
        dir.path().join("cache"),
        Settings::default(),
    );
    app.accept_path(InputKind::ImageDirectory, images.clone());
    assert_eq!(
        store::settings(&app.cache).unwrap().image_dir,
        images.canonicalize().unwrap().display().to_string()
    );
    app.open_files(InputKind::Image);
    assert!(matches!(app.dialog, Some(Dialog::Files { .. })));
    if let Some(Dialog::Files {
        entries,
        selected,
        root,
        ..
    }) = &mut app.dialog
    {
        assert!(same_path(root, &images));
        assert!(entries.iter().any(|e| e.path.ends_with("nested")));
        *selected = entries
            .iter()
            .position(|e| e.directory && same_path(&e.path, &nested))
            .unwrap();
    }
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(&app.dialog, Some(Dialog::Files { root, .. }) if root.ends_with("nested")));
    app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    assert!(matches!(&app.dialog, Some(Dialog::Files { root, .. }) if root.ends_with("images")));
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::History,
            ..
        })
    ));
    let result = super::tests::app().results.remove("pslist").unwrap();
    let json = dir.path().join("history.json");
    store::export(&json, &result, result.rows.clone()).unwrap();
    app.accept_path(InputKind::History, json);
    assert!(app.result().unwrap().historical);
    assert_eq!(app.rows().len(), 2);
}
#[test]
fn refresh_without_image_does_not_prompt_and_offline_error_is_actionable() {
    let mut app = app();
    app.settings.remote_symbols = false;
    app.switch_section(AssetSection::Remote);
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert!(app.dialog.is_none());
    for _ in 0..100 {
        app.drain();
        if app.job.is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(app.job.is_none());
    assert!(app.status.contains("按 o"));
    assert!(app.logs.iter().any(|s| s.contains("离线")));
}
#[test]
fn imported_image_automatically_identifies_banner_and_renders_progress() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("one.raw");
    let mut bytes = vec![0; 8192];
    let banner = b"Linux version 3.2.0-test (test@test) (gcc version 4.6.3) #1 SMP test\n\0";
    bytes[256..256 + banner.len()].copy_from_slice(banner);
    std::fs::write(&path, bytes).unwrap();
    let mut app = App::new(
        None,
        "missing".into(),
        dir.path().join("cache"),
        Settings {
            image_dir: dir.path().join("images").display().to_string(),
            symbols: dir.path().join("symbols").display().to_string(),
            ..Settings::default()
        },
    );
    app.accept_path(InputKind::Image, path);
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    assert_eq!(app.results["banners"].rows.len(), 1);
    let candidate = app.results.get_mut("banners").unwrap();
    candidate.rows.insert(
        0,
        vec![
            "0x1".into(),
            format!(
                "Linux version 4.4.0 #1 SMP {}",
                "embedded application data".repeat(40)
            ),
        ],
    );
    assert!(banner_candidates(candidate)[0][1].contains("3.2.0-test"));
    assert_eq!(candidate.rows.len(), 2); // full banner output is retained
    let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(rendered.contains("Linux version 3.2.0-test"));
    app.started = Some(Instant::now());
    app.progress = Some(42);
    terminal.draw(|f| app.draw(f)).unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(rendered.contains("42%"));
}
#[test]
fn layouts_and_popup() {
    for (w, h) in [(80, 24), (120, 32), (45, 16), (20, 8)] {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        app.focus = Focus::Content;
        terminal.draw(|f| app.draw(f)).unwrap();
        app.open_input(InputKind::Export);
        terminal.draw(|f| app.draw(f)).unwrap();
        use unicode_width::UnicodeWidthStr;
        let mut text = String::new();
        for row in terminal.backend().buffer().content.chunks(w as usize) {
            let mut x = 0;
            while x < row.len() {
                let symbol = row[x].symbol();
                text.push_str(symbol);
                x += symbol.width().max(1);
            }
        }
        assert!(text.contains("导出当前筛选") || w < 45, "{w}x{h}: {text:?}");
    }
}
fn screen(terminal: &Terminal<TestBackend>, width: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    let mut text = String::new();
    for row in terminal.backend().buffer().content.chunks(width) {
        let mut x = 0;
        while x < row.len() {
            let symbol = row[x].symbol();
            text.push_str(symbol);
            x += symbol.width().max(1);
        }
        text.push('\n');
    }
    text
}
#[test]
fn closing_popup_restores_results() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let before = screen(&terminal, 80);
    app.open_input(InputKind::Export);
    terminal.draw(|f| app.draw(f)).unwrap();
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(screen(&terminal, 80), before);
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
#[test]
fn mouse_menu_header_and_modal() {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let header = app.hits.borrow().header;
    assert!(!click(&mut app, 5, header.y + 1));
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Symbols,
            ..
        })
    ));
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    // Modal clicks must not activate the underlying menu.
    click(&mut app, 0, 0);
    assert!(app.dialog.is_some());
    let cancel = hits
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Esc)
        .unwrap()
        .0;
    click(&mut app, cancel.x, cancel.y);
    assert!(app.dialog.is_none());
    terminal.draw(|f| app.draw(f)).unwrap();
    let menu = app.hits.borrow().menu;
    click(&mut app, 5, menu.y + 2);
    assert_eq!(app.plugin, app.navigation_plugins()[1]);
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Image,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.job.is_none());
    terminal.draw(|f| app.draw(f)).unwrap();
    let menu = app.hits.borrow().menu;
    click(&mut app, 5, menu.y + 1);
    assert_eq!(app.plugin, Plugin::Pslist);
    assert_eq!(app.focus, Focus::Content);
}
#[test]
fn mouse_scrolled_rows_sort_and_wheel() {
    let mut app = app();
    let template = app.result().unwrap().rows[0].clone();
    app.results.get_mut("pslist").unwrap().rows = (0..40)
        .map(|i| {
            let mut r = template.clone();
            r[0] = i.to_string();
            r
        })
        .collect();
    app.row = 25;
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    assert!(hits.row_offset > 0);
    click(&mut app, hits.result.x + 3, hits.result.y + 2);
    assert_eq!(app.row, hits.row_offset);
    app.mouse(mouse_event(
        MouseEventKind::ScrollDown,
        hits.result.x + 3,
        hits.result.y + 2,
    ));
    assert_eq!(app.row, hits.row_offset + 3);
    let col = hits.columns[0];
    click(&mut app, col.x, hits.result.y + 1);
    assert_eq!(app.sort, Some(0));
    assert!(!app.descending);
    click(&mut app, col.x, hits.result.y + 1);
    assert!(app.descending);
    let focus = app.focus;
    app.mouse(mouse_event(MouseEventKind::Moved, 5, 8));
    assert_eq!(app.focus, focus);
}
#[test]
fn mouse_tree_and_sort_popup() {
    let mut app = app();
    let mut result = app.result().unwrap().clone();
    result.plugin = "pstree".into();
    result.rows[1][2] = "10".into();
    app.results.insert("pstree".into(), result);
    app.plugin = Plugin::Pstree;
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    click(&mut app, hits.columns[3].x, hits.result.y + 2);
    assert_eq!(app.visible().len(), 1);
    terminal.draw(|f| app.draw(f)).unwrap();
    click(&mut app, hits.columns[3].x, hits.result.y + 2);
    assert_eq!(app.visible().len(), 2);
    app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    let popup = app.hits.borrow().popup;
    click(&mut app, popup.x + 2, popup.y + 2);
    assert_eq!(app.sort, Some(1));
    assert!(app.dialog.is_none());
}
#[test]
fn mouse_narrow_pages_and_footer_actions() {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(45, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    assert_eq!(hits.result.width, 0);
    let tab = hits
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Tab)
        .unwrap()
        .0;
    click(&mut app, tab.x, tab.y);
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(app.hits.borrow().result.width > 0);
    let search = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Char('/'))
        .unwrap()
        .0;
    click(&mut app, search.x, search.y);
    assert!(matches!(
        app.dialog,
        Some(Dialog::Input {
            kind: InputKind::Search,
            ..
        })
    ));
}
#[test]
fn mouse_input_confirm_and_symbol_candidates() {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    app.open_input(InputKind::Search);
    app.dialog_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    let confirm = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Enter)
        .unwrap()
        .0;
    click(&mut app, confirm.x, confirm.y);
    assert!(app.dialog.is_none());
    assert_eq!(app.rows().len(), 1);
    app.dialog = Some(Dialog::Symbols {
        labels: (0..20).map(|i| format!("symbol-{i}")).collect(),
        selected: 15,
    });
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    assert!(hits.popup_offset > 0);
    click(&mut app, hits.popup.x + 2, hits.popup.y + 1);
    assert_eq!(app.choice, Some(format!("symbol-{}", hits.popup_offset)));
    // No image is loaded, so selecting a candidate asks for the image.
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Image,
            ..
        })
    ));
}
#[test]
fn search_sort_cancel() {
    let mut app = app();
    app.sort = Some(0);
    assert_eq!(app.rows()[0][0], "2");
    app.descending = true;
    assert_eq!(app.rows()[0][0], "10");
    app.open_input(InputKind::Search);
    app.dialog_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.rows().len(), 1);
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.rows().len(), 2);
}
#[test]
fn tree_expansion_and_cycle() {
    let rows = vec![
        vec!["1", "1", "0", "init", "0"],
        vec!["2", "2", "1", "child", "0"],
        vec!["3", "3", "2", "leaf", "0"],
    ]
    .into_iter()
    .map(|r| r.into_iter().map(String::from).collect())
    .collect::<Vec<_>>();
    assert_eq!(tree_rows(rows.clone(), &HashSet::new()).len(), 3);
    assert_eq!(tree_rows(rows, &HashSet::from(["1".into()])).len(), 1);
}
#[test]
fn new_plugin_menu_mouse_details_and_raw_export() {
    let mut app = app();
    for d in PLUGINS {
        let mut r = app.results["pslist"].clone();
        r.plugin = d.plugin.name().into();
        r.columns = d.columns.iter().map(|s| (*s).into()).collect();
        r.rows = (0..40)
            .map(|n| {
                d.columns
                    .iter()
                    .enumerate()
                    .map(|(index, c)| {
                        if index == 0 {
                            format!("item-{n:03}")
                        } else {
                            format!("{c}\n\x1b{}", "长".repeat(500))
                        }
                    })
                    .collect()
            })
            .collect();
        app.results.insert(d.plugin.name().into(), r);
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    for d in PLUGINS
        .iter()
        .filter(|d| !d.plugin.is_windows())
        .skip(3)
        .filter(|d| !d.plugin.is_dump())
    {
        app.focus = Focus::Navigation;
        app.menu = navigation_plugins()
            .iter()
            .position(|p| *p == d.plugin)
            .unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let h = app.hits.borrow().clone();
        let y = h.menu.y + 1 + (app.menu - h.menu_offset) as u16;
        click(&mut app, h.menu.x + 2, y);
        assert_eq!(app.plugin, d.plugin);
        assert_eq!(app.focus, Focus::Content);
        app.focus = Focus::Content;
        app.row = 25;
        terminal.draw(|f| app.draw(f)).unwrap();
        let h = app.hits.borrow().clone();
        click(&mut app, h.result.x + 3, h.result.y + 2);
        assert_eq!(app.row, h.row_offset);
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(matches!(app.dialog, Some(Dialog::Detail { .. })));
        assert!(screen(&terminal, 80).contains("\\n\\u{1b}"));
        app.dialog_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(matches!(app.dialog,Some(Dialog::Detail {scroll,..}) if scroll>0));
        app.mouse(mouse_event(MouseEventKind::Down(MouseButton::Right), 0, 0));
        assert!(app.dialog.is_none());
        terminal.draw(|f| app.draw(f)).unwrap();
        let h = app.hits.borrow().clone();
        let button = h
            .buttons
            .iter()
            .find(|(_, k)| *k == KeyCode::Char('d'))
            .unwrap()
            .0;
        click(&mut app, button.x, button.y);
        assert!(app.dialog.is_some());
        app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.query = "item-025".into();
        assert_eq!(app.rows().len(), 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.json");
        store::export(&path, app.result().unwrap(), app.rows()).unwrap();
        let exported: Results = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(exported.rows[0][1].contains('\x1b'));
        app.query.clear();
    }
    assert!(detail_lines(&"x".repeat(1024 * 1024), 10).len() > u16::MAX as usize);
}
#[test]
fn searchable_picker_context_navigation_and_help() {
    let mut app = app();
    app.focus = Focus::Navigation;
    app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    assert_eq!(app.menu, menu_items().len() - 1);
    app.key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    assert_eq!(app.menu, 0);
    app.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    app.paste("pscred");
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 80).contains("pscred"));
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.plugin, Plugin::Pscred);
    assert!(app.job.is_none());
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Image,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Image,
            ..
        })
    ));
    assert!(matches!(app.pending_work, Some(Work::Analyze(false))));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.pending_work.is_none());
    app.key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));
    assert!(!app.settings.remote_symbols);
    app.key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 80).contains("取证工作台"));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.last_error = Some("download failed\nurl detail".into());
    app.key(KeyEvent::new(KeyCode::F(8), KeyModifiers::NONE));
    assert!(matches!(&app.dialog,Some(Dialog::Detail {text,..}) if text.contains("url detail")));
}
#[test]
fn editable_inputs_paste_and_link_detail_back_navigation() {
    let mut app = app();
    app.open_input(InputKind::Export);
    app.paste("/tmp/路径.json");
    assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="/tmp/路径.json"));
    app.dialog_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
    assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="X/tmp/路径.json"));
    app.dialog_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="Xtmp/路径.jso"));
    app.dialog_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
    app.paste("替换");
    assert!(
        matches!(&app.dialog,Some(Dialog::Input {text,cursor,..}) if text=="替换" && *cursor==6)
    );
    app.dialog_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
    assert!(matches!(&app.dialog,Some(Dialog::Input {text,..}) if text=="换"));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let candidate = RemoteMatch {
        banner: "Linux version fixture".into(),
        path: "Debian/amd64/a.json.xz".into(),
        url: symbols::repository_url("Debian/amd64/a.json.xz").unwrap(),
    };
    app.dialog = Some(Dialog::Links {
        matches: vec![candidate.clone()],
        selected: 0,
    });
    app.dialog_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(
        matches!(&app.dialog,Some(Dialog::RemoteDetail {candidate: shown,..}) if shown.url == candidate.url)
    );
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::Links { .. })));
    app.dialog_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(matches!(app.pending_work, Some(Work::Download(_))));
}
#[test]
fn browsing_busy_plugin_preserves_worker_and_explicit_run_replaces_it() {
    let mut app = app();
    let old = Job::default();
    app.job = Some(old.clone());
    app.select_plugin(Plugin::Pstree);
    assert!(!old.cancel.load(Ordering::Relaxed));
    assert!(app.pending_work.is_none());
    app.start();
    assert!(old.cancel.load(Ordering::Relaxed));
    assert!(matches!(app.pending_work, Some(Work::Analyze(false))));
    assert_eq!(
        app.pending_execution.as_ref().unwrap().plugin,
        Plugin::Pstree
    );
    app.select_plugin(Plugin::Pscred);
    app.start();
    assert_eq!(
        app.pending_execution.as_ref().unwrap().plugin,
        Plugin::Pscred
    );
    app.cancel();
    assert!(app.pending_work.is_none());
    assert!(app.pending_execution.is_none());
}

#[test]
fn workstation_palette_views_and_responsive_inspector() {
    let mut app = app();
    let mut result = app.results["pslist"].clone();
    result.plugin = "psaux".into();
    result.columns = vec![
        "PID".into(),
        "Name".into(),
        "CommandLine".into(),
        "Status".into(),
    ];
    result.rows = vec![vec![
        "1".into(),
        "bash".into(),
        "长命令行".repeat(200),
        "OK".into(),
    ]];
    app.results.insert("psaux".into(), result);
    app.query = "10".into();
    app.sort = Some(0);
    app.descending = true;
    app.horizontal = 24;
    app.select_plugin(Plugin::Psaux);
    assert!(app.query.is_empty());
    assert_eq!(app.horizontal, 0);
    app.select_plugin(Plugin::Pslist);
    assert_eq!(app.query, "10");
    assert_eq!(app.sort, Some(0));
    assert!(app.descending);
    assert_eq!(app.horizontal, 24);
    app.select_plugin(Plugin::Psaux);
    let mut terminal = Terminal::new(TestBackend::new(170, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(app.hits.borrow().inspector.width > 0);
    assert!(app.dialog.is_none());
    let inspector = app.hits.borrow().inspector;
    click(&mut app, inspector.x + 2, inspector.y + 2);
    assert_eq!(app.focus, Focus::Detail);
    app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    assert!(app.detail_scroll > 0);
    app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::ALT));
    assert_eq!(app.horizontal, 12);
    terminal.draw(|f| app.draw(f)).unwrap();
    terminal.backend_mut().resize(80, 24);
    app.resize(80, 24);
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.focus, Focus::Content);
    assert_eq!(app.hits.borrow().inspector.width, 0);
    app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::Detail { .. })));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
    app.paste("cache");
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 80).contains("缓存"));
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::Cache { confirm: false, .. })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::Cache { confirm: true, .. })
    ));
    // Cancelling the concrete preview must never start deletion.
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.pending_work.is_none());
    assert!(app.dialog.is_none());
}
#[test]
fn automatic_rows_fill_viewport_and_custom_rows_persist() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = app();
    app.cache = dir.path().join("cache");
    app.results.get_mut("pslist").unwrap().rows = (1..=200)
        .map(|i| {
            vec![
                i.to_string(),
                i.to_string(),
                "0".into(),
                format!("row{i}"),
                "0x1000".into(),
            ]
        })
        .collect();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let result = app.hits.borrow().result;
    assert_eq!(app.page_rows(), usize::from(result.height - 3));
    let bottom = result.bottom() - 2;
    let bottom_text: String = (result.x + 1..result.right() - 1)
        .map(|x| terminal.backend().buffer()[(x, bottom)].symbol())
        .collect();
    assert!(bottom_text.contains(&format!("row{}", app.page_rows())));
    let initial_rows = app.page_rows();
    terminal.backend_mut().resize(100, 50);
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.page_rows(), initial_rows + 10);
    app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    app.paste("17");
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.page_rows(), 17);
    assert_eq!(crate::store::settings(&app.cache).unwrap().page_size, 17);
    app.key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE));
    assert_eq!(app.row, 17);
    terminal.backend_mut().resize(80, 24);
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(
        app.page_rows(),
        usize::from(app.hits.borrow().result.height - 3)
    );
    assert!(app.page_rows() < 17);
    assert_eq!(app.settings.page_size, 17); // Desired size is preserved for a larger screen.
    app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    app.paste("auto");
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.settings.page_size, 0);
    assert_eq!(app.row, 0);
}
#[test]
fn unified_symbol_manager_has_inline_search_and_analysis_only_header() {
    let mut app = app();
    let dir = tempfile::tempdir().unwrap();
    app.root = dir.path().into();
    std::fs::create_dir_all(dir.path().join("images")).unwrap();
    let image = dir.path().join("images/capture.raw");
    std::fs::write(&image, b"image").unwrap();
    app.image = Some(image.clone());
    assert_eq!(app.display_path(&image), "images/capture.raw");
    assert!(std::path::Path::new(&app.display_path(std::path::Path::new("/tmp"))).is_absolute());
    let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 100).contains("镜像: images/capture.raw"));
    app.switch_section(AssetSection::Symbols);
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    assert_eq!(hits.tabs.len(), 2);
    assert_eq!(hits.header.height, 0);
    assert_eq!(hits.search.height, 3);
    assert!(screen(&terminal, 100).contains("镜像: images/capture.raw"));
    click(&mut app, hits.search.x + 2, hits.search.y + 1);
    app.paste("test symbol");
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().popup.height, 0);
    assert!(screen(&terminal, 100).contains("test symbol"));
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.asset_queries[1].is_empty());
    app.key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.section, AssetSection::Remote);
    app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL));
    assert_eq!(app.page, Page::Analysis);
}
#[test]
fn manual_catalog_download_preserves_analysis_context() {
    let mut app = app();
    let dir = tempfile::tempdir().unwrap();
    app.cache = dir.path().join("cache");
    let downloaded = app.cache.join("symbols/isf/example.json");
    std::fs::create_dir_all(downloaded.parent().unwrap()).unwrap();
    std::fs::write(&downloaded, b"{}").unwrap();
    let selected = app.symbols.clone();
    app.switch_section(AssetSection::Remote);
    app.remote_catalog = true;
    app.download_url = Some("https://example.test/example.json".into());
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::CatalogDownloaded(downloaded.clone()))
        .unwrap();
    app.drain();
    assert_eq!(app.symbols, selected);
    assert!(app.image.is_none());
    assert_eq!(app.results["pslist"].rows.len(), 2);
    assert!(
        app.assets
            .iter()
            .any(|asset| same_path(&asset.path, &downloaded))
    );
    assert_eq!(app.section, AssetSection::Remote);
    assert!(app.status.contains("已保存到"));
    assert!(app.job.is_none());
}
#[test]
fn horizontally_scrolled_headers_keep_mouse_column_identity() {
    let mut app = app();
    let d = Plugin::Sockstat.descriptor();
    let mut result = app.results["pslist"].clone();
    result.plugin = "sockstat".into();
    result.columns = d.columns.iter().map(|s| (*s).into()).collect();
    result.rows = vec![d.columns.iter().map(|s| (*s).into()).collect()];
    app.results.insert("sockstat".into(), result);
    app.select_plugin(Plugin::Sockstat);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let before = app.hits.borrow().columns.clone();
    for _ in 0..3 {
        app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::ALT));
    }
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    assert_ne!(hits.columns, before);
    let (index, rect) = hits
        .columns
        .iter()
        .enumerate()
        .find(|(_, r)| r.width >= 3)
        .unwrap();
    click(&mut app, rect.x + 1, hits.result.y + 1);
    assert_eq!(app.sort, Some(index));
    assert_eq!(
        terminal.backend().buffer()[(hits.result.x, hits.result.y)].symbol(),
        "╭"
    );
    assert_eq!(
        terminal.backend().buffer()[(hits.result.right() - 1, hits.result.y)].symbol(),
        "╮"
    );
}
#[test]
fn contextual_footer_and_symbol_sources_follow_focus() {
    let mut app = app();
    let has = |app: &App, code| app.footer_actions().iter().any(|(_, key)| *key == code);
    app.focus = Focus::Navigation;
    assert!(has(&app, KeyCode::F(5)));
    assert!(!has(&app, KeyCode::Char('n')));
    app.focus = Focus::Content;
    assert!(has(&app, KeyCode::Char('n')));
    assert!(has(&app, KeyCode::Char(']')));
    assert!(!has(&app, KeyCode::Enter));
    app.switch_section(AssetSection::Symbols);
    assert!(has(&app, KeyCode::Char('a')));
    assert!(!has(&app, KeyCode::Char('g')));
    let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let source = app.hits.borrow().sources[2].0;
    click(&mut app, source.x, source.y);
    assert_eq!(app.section, AssetSection::Remote);
    assert!(has(&app, KeyCode::Char('g')));
    assert!(!has(&app, KeyCode::Char('a')));
    app.focus = Focus::Content;
    assert!(!has(&app, KeyCode::Enter));
    assert!(has(&app, KeyCode::PageDown));
    assert!(command_matches("导出结果", Page::Assets, Focus::Navigation).is_empty());
    assert!(command_matches("导出结果", Page::Analysis, Focus::Navigation).is_empty());
    assert!(!command_matches("导出结果", Page::Analysis, Focus::Content).is_empty());
    assert!(menu_items().iter().all(|item| !item.contains(' ')));
    for width in [30, 80, 160] {
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(
            app.hits
                .borrow()
                .buttons
                .iter()
                .any(|(_, key)| *key == KeyCode::Char('?'))
        );
    }
}
#[test]
fn inline_content_search_has_mouse_confirmation_and_reversible_filter() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let search = app.hits.borrow().search;
    let result = app.hits.borrow().result;
    assert_eq!(search.bottom(), result.y);
    click(&mut app, search.x + 2, search.y + 1);
    app.paste("init");
    assert_eq!(app.rows().len(), 1);
    terminal.draw(|f| app.draw(f)).unwrap();
    let confirm = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(r, key)| *key == KeyCode::Enter && r.y == search.y + 1)
        .unwrap()
        .0;
    click(&mut app, confirm.x, confirm.y);
    assert!(app.dialog.is_none());
    app.open_input(InputKind::Search);
    app.paste(&"x".repeat(200));
    terminal.draw(|f| app.draw(f)).unwrap();
    let position = terminal.get_cursor_position().unwrap();
    assert!(position.x < search.right() - 1);
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.query, "init");
}
#[test]
fn dump_form_requires_target_range_and_explicit_run() {
    let mut app = app();
    app.select_plugin(Plugin::Memdump);
    assert!(app.job.is_none());
    assert!(matches!(app.dialog, Some(Dialog::Dump { .. })));
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(matches!(&app.dialog,Some(Dialog::Dump{error,..}) if error.contains("PID")));
    app.paste("12");
    app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    app.paste("0x4000");
    app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    app.paste("0x5000");
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let directory = app
        .hits
        .borrow()
        .dump_fields
        .iter()
        .find(|(_, i)| *i == 3)
        .unwrap()
        .0;
    click(&mut app, directory.x, directory.y);
    app.paste("exports/targeted");
    assert!(app.job.is_none());
    for size in [(40, 10), (80, 24), (160, 40)] {
        let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(!app.hits.borrow().dump_fields.is_empty());
    }
    terminal.draw(|f| app.draw(f)).unwrap();
    let run = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Enter)
        .unwrap()
        .0;
    click(&mut app, run.x, run.y);
    let (_, options) = app.dump_options.as_ref().unwrap();
    assert_eq!(options.pid, 12);
    assert_eq!(options.start, Some(0x4000));
    assert_eq!(options.end, Some(0x5000));
    assert_eq!(options.directory, PathBuf::from("exports/targeted"));
    assert!(app.job.is_none()); // No image: ask for it only after validating the parameters.
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Image,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.start();
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.dialog.is_none());
    assert!(app.job.is_none());
}
#[test]
fn managed_symbol_library_hides_cache_duplicates_and_survives_cache_removal() {
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("library/exact.json.xz");
    let cached = dir.path().join("cache/symbols/isf/exact.json.xz");
    for path in [&local, &cached] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"validated-symbol").unwrap();
        store::atomic_write(
            &path.with_extension("source.json"),
            &serde_json::to_vec(&RemoteMatch {
                banner: "Linux version exact".into(),
                path: "Debian/exact.json.xz".into(),
                url: "https://example.test/exact".into(),
            })
            .unwrap(),
        )
        .unwrap();
    }
    let settings = || Settings {
        symbols: local.parent().unwrap().display().to_string(),
        ..Settings::default()
    };
    let mut app = App::new(
        None,
        local.parent().unwrap().into(),
        dir.path().join("cache"),
        settings(),
    );
    app.root = dir.path().into();
    app.switch_section(AssetSection::Symbols);
    assert!(app.asset_list().iter().any(|a| same_path(&a.path, &local)));
    assert!(!app.asset_list().iter().any(|a| same_path(&a.path, &cached)));
    app.focus_asset(Kind::Symbols, &local);
    assert!(same_path(&app.selected_asset().unwrap().path, &local));
    assert!(cached.is_file()); // The duplicate is hidden, not deleted.
    std::fs::remove_file(&cached).unwrap();
    let mut restored = App::new(
        None,
        local.parent().unwrap().into(),
        dir.path().join("cache"),
        settings(),
    );
    restored.root = dir.path().into();
    restored.switch_section(AssetSection::Symbols);
    assert!(
        restored
            .asset_list()
            .iter()
            .any(|a| same_path(&a.path, &local))
    );
    restored.focus_asset(Kind::Symbols, &local);
    assert!(restored.use_selected_asset());
    assert!(local.is_file());
    assert_eq!(
        restored.downloads.get("https://example.test/exact"),
        Some(&local.canonicalize().unwrap())
    );
}
#[test]
fn startup_does_not_load_saved_choices_and_pickers_show_cross_directory_samples() {
    let dir = tempfile::tempdir().unwrap();
    let images = dir.path().join("images");
    let symbols = dir.path().join("symbols");
    std::fs::create_dir_all(&images).unwrap();
    std::fs::create_dir_all(&symbols).unwrap();
    let kali = images.join("kali.raw");
    let kali_isf = symbols.join("kali.json.xz");
    let sample = symbols.join("linux-sample-1.bin.gz");
    let zip = images.join("linux.zip");
    for file in [&kali, &kali_isf, &sample, &zip] {
        std::fs::write(file, b"read-only-fixture").unwrap();
    }
    let cache = dir.path().join("cache");
    let mut registry = Registry::default();
    registry.import(&kali, Kind::Image, &cache).unwrap();
    registry.import(&kali_isf, Kind::Symbols, &cache).unwrap();
    let downloaded = cache.join("symbols/isf");
    std::fs::create_dir_all(&downloaded).unwrap();
    for n in 0..20 {
        std::fs::write(downloaded.join(format!("cached-{n}.json.xz")), b"cached").unwrap();
    }
    let before = std::fs::read(cache.join("workspace.json")).unwrap();
    let settings = Settings {
        image_dir: images.display().to_string(),
        symbols: symbols.display().to_string(),
        ..Settings::default()
    };
    let mut app = App::new(None, PathBuf::new(), cache.clone(), settings);
    app.root = dir.path().into();
    assert!(app.image.is_none());
    assert!(app.symbols.as_os_str().is_empty());
    assert!(app.job.is_none());
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 120).contains("尚未选择"));
    assert!(screen(&terminal, 120).contains("尚未选择"));
    let archive = images.join("another-capture.zip");
    let notes = images.join("notes.txt");
    std::fs::write(&archive, b"archive").unwrap();
    std::fs::write(&notes, b"notes").unwrap();
    std::fs::write(dir.path().join("unrelated.raw"), b"outside").unwrap();
    app.open_files(InputKind::Image);
    let Some(Dialog::Files { root, entries, .. }) = &app.dialog else {
        panic!("missing image picker")
    };
    assert!(same_path(root, &images));
    for file in [&kali, &zip, &archive, &notes] {
        assert!(entries.iter().any(|e| same_path(&e.path, file)));
    }
    assert!(!entries.iter().any(|e| same_path(&e.path, &sample)));
    assert!(!entries.iter().any(|e| e.path.ends_with("unrelated.raw")));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 120).contains("linux.zip"));
    app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    let Some(Dialog::Files {
        root,
        entries,
        kind,
        ..
    }) = &app.dialog
    else {
        panic!("missing symbol picker")
    };
    assert!(*kind == InputKind::Symbols);
    assert!(same_path(root, &symbols));
    for file in [&kali_isf, &sample] {
        assert!(entries.iter().any(|e| same_path(&e.path, file)));
    }
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 120).contains("linux-sample-1.bin.gz"));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.image.is_none());
    assert!(app.symbols.as_os_str().is_empty());
    assert_eq!(std::fs::read(cache.join("workspace.json")).unwrap(), before);
    for file in [kali, kali_isf, sample, zip] {
        assert_eq!(std::fs::read(file).unwrap(), b"read-only-fixture");
    }
}
#[test]
fn unified_dump_modes_cancel_and_mouse_selection() {
    let mut app = app();
    let previous = app.plugin;
    app.row = 1;
    app.key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));
    assert_eq!(app.plugin, previous);
    assert!(matches!(
        &app.dialog,
        Some(Dialog::Dump {
            mode: Plugin::Procdump,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
    assert!(matches!(
        &app.dialog,
        Some(Dialog::Dump {
            mode: Plugin::Memdump,
            ..
        })
    ));
    if let Some(Dialog::Dump { fields, .. }) = &mut app.dialog {
        fields[1] = "0x4000".into();
        fields[2] = "0x5000".into();
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let elf = app
        .hits
        .borrow()
        .dump_modes
        .iter()
        .find(|(_, mode)| *mode == Plugin::Elfdump)
        .unwrap()
        .0;
    click(&mut app, elf.x, elf.y);
    assert!(
        matches!(&app.dialog, Some(Dialog::Dump { mode: Plugin::Elfdump, fields, .. })
            if fields[1].is_empty() && fields[2].is_empty())
    );
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.plugin, previous);
    assert_eq!(app.results["pslist"].rows.len(), 2);
    assert!(app.job.is_none());
    assert_eq!(menu_items().iter().filter(|s| **s == "dump").count(), 1);
    assert_eq!(plugin_matches("dump"), vec![Plugin::Procdump]);
    app.dialog = Some(Dialog::Plugins {
        query: "dump".into(),
        selected: 0,
    });
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(&app.dialog, Some(Dialog::Dump { .. })));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.plugin, previous);
}
#[test]
fn local_matches_stay_in_manager_and_reuse_image_context() {
    let dir = tempfile::tempdir().unwrap();
    let images = dir.path().join("images");
    let symbols = dir.path().join("symbols");
    std::fs::create_dir_all(&images).unwrap();
    std::fs::create_dir_all(&symbols).unwrap();
    let image = images.join("test.raw");
    let exact = symbols.join("exact.json");
    let wrong = symbols.join("wrong.json");
    for file in [&image, &exact, &wrong] {
        std::fs::write(file, b"fixture").unwrap();
    }
    let settings = Settings {
        image_dir: images.display().to_string(),
        symbols: symbols.display().to_string(),
        ..Settings::default()
    };
    let mut app = App::new(
        Some(image.clone()),
        PathBuf::new(),
        dir.path().join("cache"),
        settings,
    );
    app.root = dir.path().into();
    app.switch_section(AssetSection::Symbols);
    let exact = exact.canonicalize().unwrap();
    let mut banner = super::tests::app().results.remove("pslist").unwrap();
    banner.plugin = "banners".into();
    let mut report = symbols::LocalMatches::default();
    report
        .matched
        .insert(exact.clone(), vec!["exact-candidate".into()]);
    let stamp = app.local_stamp();
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::LocalMatched(report, stamp, banner.clone()))
        .unwrap();
    app.drain();
    assert_eq!(app.asset_list().len(), 1);
    assert!(same_path(&app.selected_asset().unwrap().path, &exact));
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.page, Page::Assets);
    assert!(same_path(&app.symbols, &exact));
    assert_eq!(app.choice.as_deref(), Some("exact-candidate"));
    assert_eq!(app.results["banners"], banner);
    assert!(app.job.is_none());
    app.key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
    assert_eq!(app.section, AssetSection::Symbols);
    assert!(app.job.is_none());
    assert!(app.status.contains("复用"));
    app.key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
    assert_eq!(app.asset_list().len(), 2);
    app.invalidate_source();
    assert!(app.local_match_stamp.is_none());
    assert!(app.local_matches.is_empty());
}
#[test]
fn fetch_during_matching_keeps_remote_source_mode() {
    let mut app = app();
    app.switch_section(AssetSection::Remote);
    app.remote_catalog = false;
    app.job = Some(Job::default());
    app.key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
    assert!(!app.remote_catalog);
    assert!(app.status.contains("任务执行中"));
    assert!(app.dialog.is_none());
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
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    app.drain();
    assert!(app.job.is_none());
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
#[test]
fn remote_detail_download_button_saves_offline_without_selecting_or_navigating() {
    for catalog in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app();
        app.cache = dir.path().join("cache");
        app.root = dir.path().into();
        app.settings.symbols = dir.path().join("library").display().to_string();
        app.settings.image_dir = dir.path().join("images").display().to_string();
        app.settings.remote_symbols = false;
        app.history = app.results.get("pslist").cloned();
        app.query = "init".into();
        let previous_symbols = app.symbols.clone();
        let history = app.history.clone();
        app.switch_section(AssetSection::Remote);
        let candidate = RemoteMatch {
            banner: "Linux version fixture".into(),
            path: "Debian/amd64/fixture.json.xz".into(),
            url: symbols::repository_url("Debian/amd64/fixture.json.xz").unwrap(),
        };
        let cached = cache_fixture(&app, &candidate, &fixture_isf(&candidate.banner, 0));
        app.remote = vec![candidate.clone()];
        app.remote_catalog = catalog;
        app.asset_queries[2] = "fixture".into();
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let list = app.hits.borrow().assets;
        click(&mut app, list.x + 1, list.y + 1);
        assert!(
            matches!(&app.dialog, Some(Dialog::RemoteDetail { candidate: detail, .. }) if detail.url == candidate.url)
        );
        assert!(app.job.is_none());
        terminal.draw(|f| app.draw(f)).unwrap();
        let button = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(_, k)| *k == KeyCode::Char('w'))
            .unwrap()
            .0;
        if catalog {
            click(&mut app, button.x, button.y);
        } else {
            app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        }
        finish_test_job(&mut app);
        let saved = app.downloads[&candidate.url].clone();
        assert!(saved.starts_with(dir.path().join("library").canonicalize().unwrap()));
        assert!(saved.is_file());
        assert!(saved.with_extension("source.json").is_file());
        assert_eq!(app.page, Page::Assets);
        assert_eq!(app.section, AssetSection::Remote);
        assert_eq!(app.remote_catalog, catalog);
        assert_eq!(app.asset_queries[2], "fixture");
        assert_eq!(app.symbols, previous_symbols);
        assert_eq!(app.history, history);
        assert_eq!(app.query, "init");
        assert!(
            Registry::load(&app.cache)
                .unwrap()
                .selected(Kind::Symbols)
                .is_none()
        );
        assert!(matches!(app.dialog, Some(Dialog::RemoteDetail { .. })));
        assert!(
            app.remote_detail_text(&candidate)
                .contains(&saved.display().to_string())
        );
        // Durable copies work without the regenerable cache and do not create duplicates.
        std::fs::remove_file(cached).unwrap();
        app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert_eq!(app.downloads[&candidate.url], saved);
        assert!(app.last_error.is_none());
        assert_eq!(
            app.asset_list_for(AssetSection::Symbols)
                .iter()
                .filter(|a| a.path == saved)
                .count(),
            1
        );
        app.key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
        assert_eq!(app.section, AssetSection::Symbols);
        assert!(same_path(&app.selected_asset().unwrap().path, &saved));
        assert_eq!(app.symbols, previous_symbols);
        assert!(app.dialog.is_none());
    }
}
#[test]
fn remote_detail_failed_download_retains_candidate_and_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = app();
    app.cache = dir.path().join("cache");
    app.settings.symbols = dir.path().join("library").display().to_string();
    app.settings.image_dir = dir.path().join("images").display().to_string();
    app.settings.remote_symbols = false;
    app.switch_section(AssetSection::Remote);
    let path = "Debian/amd64/fixture.json.xz";
    let candidate = RemoteMatch {
        banner: "Linux version fixture".into(),
        path: path.into(),
        url: symbols::repository_url(path).unwrap(),
    };
    app.remote = vec![candidate.clone()];
    app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    // No cache: failure is actionable and does not register a local file.
    app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert!(app.last_error.as_deref().unwrap().contains("离线"));
    assert!(app.downloads.is_empty());
    assert!(matches!(app.dialog, Some(Dialog::RemoteDetail { .. })));
    // Wrong banner must not be copied into the durable library.
    cache_fixture(&app, &candidate, &fixture_isf("Linux version wrong", 0));
    app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert!(app.last_error.as_deref().unwrap().contains("banner"));
    assert!(app.downloads.is_empty());
    // A corrected cache can be retried directly from the same detail.
    cache_fixture(&app, &candidate, &fixture_isf(&candidate.banner, 0));
    app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert!(app.last_error.is_none());
    let saved = app.downloads[&candidate.url].clone();
    std::fs::remove_file(&saved).unwrap();
    app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert!(saved.is_file());
}
#[test]
fn manager_automatically_matches_images_and_requires_explicit_symbol_selection() {
    let dir = tempfile::tempdir().unwrap();
    let images = dir.path().join("images");
    let library = dir.path().join("symbols");
    std::fs::create_dir_all(&images).unwrap();
    std::fs::create_dir_all(&library).unwrap();
    let first = images.join("first.raw");
    let second = images.join("second.raw");
    for (path, banner) in [
        (&first, "Linux version fixture"),
        (&second, "Linux version other"),
    ] {
        let mut bytes = vec![0; 4096];
        let banner = format!("{banner}\n\0");
        bytes[256..256 + banner.len()].copy_from_slice(banner.as_bytes());
        std::fs::write(path, bytes).unwrap();
    }
    for (name, banner, variant) in [
        ("one.json", "Linux version fixture", 0),
        ("two.json", "Linux version fixture", 1),
        ("other.json", "Linux version other", 0),
    ] {
        std::fs::write(library.join(name), fixture_isf(banner, variant)).unwrap();
    }
    let settings = Settings {
        image_dir: images.display().to_string(),
        symbols: library.display().to_string(),
        remote_symbols: false,
        ..Settings::default()
    };
    let mut app = App::new(
        None,
        library.join("other.json"),
        dir.path().join("cache"),
        settings,
    );
    app.switch_section(AssetSection::Images);
    app.focus_asset(Kind::Image, &first);
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert_eq!(app.page, Page::Assets);
    assert!(app.symbols.as_os_str().is_empty());
    assert_eq!(app.local_matches.len(), 2);
    assert_eq!(app.asset_list_for(AssetSection::Symbols).len(), 2);
    assert_eq!(app.results["banners"].rows.len(), 1);
    assert!(
        Registry::load(&app.cache)
            .unwrap()
            .selected(Kind::Symbols)
            .is_none()
    );
    // A highlighted image must not replace the selected target when matching.
    app.focus_asset(Kind::Image, &second);
    app.key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
    assert!(same_path(app.image.as_ref().unwrap(), &first));
    assert!(app.job.is_none());
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(!app.symbols.as_os_str().is_empty());
    assert_eq!(app.page, Page::Assets);
    app.switch_section(AssetSection::Images);
    app.focus_asset(Kind::Image, &second);
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(app.symbols.as_os_str().is_empty());
    finish_test_job(&mut app);
    assert_eq!(app.local_matches.len(), 1);
    assert!(app.local_matches.keys().all(|p| p.ends_with("other.json")));
}
#[test]
fn manager_cancel_stops_preparation_and_detail_download_without_followup_actions() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = app();
    app.cache = dir.path().join("cache");
    app.settings.image_dir = dir.path().join("images").display().to_string();
    app.settings.symbols = dir.path().join("symbols").display().to_string();
    app.settings.remote_symbols = false;
    let path = "Debian/amd64/fixture.json.xz";
    let candidate = RemoteMatch {
        banner: "Linux version fixture".into(),
        path: path.into(),
        url: symbols::repository_url(path).unwrap(),
    };
    cache_fixture(&app, &candidate, &fixture_isf(&candidate.banner, 0));
    app.switch_section(AssetSection::Remote);
    app.remote = vec![candidate];
    app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    let session = app.session.clone();
    let guard = session.lock().unwrap();
    app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
    drop(guard);
    finish_test_job(&mut app);
    assert!(app.downloads.is_empty());
    assert!(matches!(app.dialog, Some(Dialog::RemoteDetail { .. })));
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let image = dir.path().join("fixture.raw");
    std::fs::write(&image, vec![0; 4096]).unwrap();
    app.image = Some(image);
    let guard = session.lock().unwrap();
    app.prepare_selected_image();
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    drop(guard);
    finish_test_job(&mut app);
    assert!(app.local_match_stamp.is_none());
    assert!(app.local_matches.is_empty());
    assert!(app.dialog.is_none());
    assert_eq!(app.page, Page::Assets);
}
#[test]
fn combined_manager_layout_focus_and_actions_work_at_supported_sizes() {
    let mut app = app();
    app.switch_section(AssetSection::Images);
    for (w, h) in [(160, 40), (100, 32), (80, 24), (60, 18)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert_eq!(hits.tabs.len(), 2);
        assert_eq!(hits.asset_lists.len(), if h < 20 { 1 } else { 2 });
        if h >= 20 {
            assert!(hits.asset_lists.iter().all(|(r, _, _)| r.height >= 3));
        }
        assert_eq!(hits.asset_detail.height > 0, w >= 100 && h >= 28);
        assert!(
            hits.asset_buttons
                .iter()
                .all(|(rect, _, _)| rect.right() <= w && rect.bottom() <= h)
        );
        app.section = AssetSection::Images;
        app.focus = Focus::Navigation;
        app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.section, AssetSection::Symbols);
        app.key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
        assert_eq!(app.section, AssetSection::Images);
        assert!(
            app.asset_disabled(AssetSection::Images, KeyCode::Char('x'))
                .is_some()
        );
        assert!(
            app.available_commands("进入分析")
                .iter()
                .any(|(_, k)| *k == KeyCode::Char('x'))
        );
    }
    app.key(KeyEvent::new(KeyCode::F(9), KeyModifiers::NONE));
    assert_eq!(app.page, Page::Assets); // Old page shortcuts have been removed.
    app.key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
    assert_eq!(app.page, Page::Analysis);
    app.key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
    assert_eq!(app.page, Page::Assets);
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
fn preparation_startup_unique_missing_and_object_change() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.initialize(Default::default());
    assert_eq!(app.page, Page::Assets);
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(same_path(&app.symbols, &exact));
    assert!(app.results.contains_key("banners"));
    assert!(!app.results.contains_key("pslist"));
    app.enter_workbench();
    assert_eq!(app.page, Page::Analysis);
    assert_eq!(app.plugin, Plugin::Pslist);
    assert!(app.job.is_none());
    // Changing the source invalidates preparation before any plugin can execute.
    let mut bytes = std::fs::read(app.image.as_ref().unwrap()).unwrap();
    bytes[256] = b'X';
    std::fs::write(app.image.as_ref().unwrap(), bytes).unwrap();
    app.request_analysis(false);
    assert_eq!(app.page, Page::Assets);
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::ChooseSystem);
    app.select_os(crate::analysis::Os::Linux);
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::MissingSymbols);
    std::fs::remove_file(app.image.as_ref().unwrap()).unwrap();
    app.prepare_selected_image();
    finish_test_job(&mut app);
    assert!(app.last_error.is_some());
    assert!(!app.status.contains("可开始分析"));
}
#[test]
fn preparation_zip_candidates_are_individual_and_selection_never_runs() {
    use std::io::Write;
    let (dir, mut app) = preparation_fixture();
    let path = dir.path().join("symbols/multiple.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    for (name, variant) in [("one.json", 1), ("two.json", 2)] {
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&fixture_isf(PREPARATION_BANNER, variant))
            .unwrap();
    }
    zip.finish().unwrap();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::ChooseSymbols);
    let Some(Dialog::Symbols { labels, .. }) = &app.dialog else {
        panic!("候选列表缺失")
    };
    assert_eq!(labels.len(), 2);
    assert!(labels.iter().any(|label| label.contains("one.json")));
    assert!(labels.iter().any(|label| label.contains("two.json")));
    app.dialog_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(same_path(&app.symbols, &path));
    assert!(app.job.is_none());
    assert!(!app.results.contains_key("pslist"));
}
#[test]
fn stale_events_cannot_update_new_object_or_release_new_task() {
    let mut app = app();
    let result = app.results["pslist"].clone();
    app.results.clear();
    app.object_version = 2;
    app.task_id = 7;
    app.job = Some(Job::default());
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Tagged(
        6,
        1,
        Box::new(WorkerEvent::Done(Outcome::Ready(result.clone()))),
    ))
    .unwrap();
    app.drain();
    assert!(app.results.is_empty());
    assert!(app.job.is_some());
    tx.send(WorkerEvent::Tagged(
        7,
        1,
        Box::new(WorkerEvent::Done(Outcome::Ready(result))),
    ))
    .unwrap();
    app.drain();
    assert!(app.results.is_empty());
    assert!(app.job.is_none());
}
#[test]
fn execution_parameters_and_results_survive_browsing_and_keep_separate_views() {
    let mut app = app();
    let mut result = app.results.remove("pslist").unwrap();
    app.analysis_options.pid = Some(10);
    let key = app.request_key();
    let parameters = app.parameter_summary();
    app.active_request = Some(Execution {
        plugin: Plugin::Pslist,
        key: key.clone(),
        parameters,
        snapshot: ExecutionSnapshot {
            force: false,
            plugin: Plugin::Pslist,
            options: app.analysis_options.clone(),
            dump: None,
        },
    });
    app.job = Some(Job::default());
    app.select_plugin(Plugin::Psaux);
    app.query = "browse".into();
    app.row = 3;
    result.rows.truncate(1);
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Done(Outcome::Ready(result))).unwrap();
    app.drain();
    assert_eq!(app.plugin, Plugin::Psaux);
    assert_eq!(app.query, "browse");
    assert_eq!(app.row, 3);
    assert_eq!(app.results[&key].rows.len(), 1);
    app.select_plugin(Plugin::Pslist);
    assert_eq!(app.analysis_options.pid, Some(10));
    app.query = "zsh".into();
    app.horizontal = 12;
    app.save_view();
    app.analysis_options.pid = Some(2);
    app.restore_view();
    assert!(app.query.is_empty());
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 140).contains("旧结果参数"));
    app.analysis_options.pid = Some(10);
    app.restore_view();
    assert_eq!(app.query, "zsh");
    assert_eq!(app.horizontal, 12);
}
#[test]
fn cancellation_waits_then_runs_last_snapshot_and_never_continues_preparation() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.select_plugin(Plugin::Banners);
    app.start();
    app.select_plugin(Plugin::Psaux);
    app.select_plugin(Plugin::Banners);
    app.analysis_options.pid = None;
    app.start();
    let old = app.job.as_ref().unwrap().clone();
    assert!(old.cancel.load(Ordering::Relaxed));
    // Browsing afterwards must not change the queued execution.
    app.select_plugin(Plugin::Pslist);
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    app.drain();
    assert!(app.job.is_some());
    assert_eq!(app.active_request.as_ref().unwrap().plugin, Plugin::Banners);
    assert_eq!(app.plugin, Plugin::Pslist);
    finish_test_job(&mut app);
    assert!(app.results.contains_key("banners"));
    assert!(!app.results.contains_key("pslist"));
    app.page = Page::Assets;
    app.job = Some(Job::default());
    app.preparation_lookup = true;
    app.cancel();
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Links(vec![RemoteMatch {
        banner: PREPARATION_BANNER.into(),
        path: "one.json.xz".into(),
        url: "https://example.test/one".into(),
    }]))
    .unwrap();
    app.drain();
    assert!(app.job.is_none());
    assert!(app.dialog.is_none());
    assert!(!app.preparation_lookup);
    assert!(app.symbols.as_os_str().is_empty());
}
#[test]
fn parameter_form_only_shows_supported_fields_and_saves_without_running() {
    let mut app = app();
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![2, 6]);
    app.paste("42");
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(app.analysis_options.pid, Some(42));
    assert!(app.job.is_none());
    app.select_plugin(Plugin::Lsmod);
    assert_eq!(app.parameter_fields(false), vec![6]);
    app.select_os(crate::analysis::Os::Windows);
    app.select_plugin(Plugin::WinPrintkey);
    assert_eq!(app.parameter_fields(false), vec![0, 1, 6]);
    assert_eq!(app.parameter_fields(true), vec![0, 1, 3, 4, 5, 6]);
    app.windows_parameters();
    app.paste("0xffff800000001000");
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.analysis_options.hive.is_some());
    assert!(app.job.is_none());
}
#[test]
fn preparation_and_analysis_layouts_have_valid_actions_at_target_sizes() {
    for (width, height) in [(140, 40), (100, 30), (80, 24), (60, 18), (8, 3), (1, 1)] {
        let mut app = app();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        for page in Page::ALL {
            app.switch_page(page);
            terminal.draw(|f| app.draw(f)).unwrap();
            let hits = app.hits.borrow().clone();
            assert!(
                hits.buttons
                    .iter()
                    .all(|(rect, _)| rect.right() <= width && rect.bottom() <= height)
            );
            if page == Page::Analysis && height >= 20 {
                assert_eq!(hits.menu.width > 0 && hits.result.width > 0, width >= 100);
            }
            if page == Page::Analysis && width < 100 && height >= 18 {
                let region = hits
                    .regions
                    .iter()
                    .find(|(_, focus)| *focus == Focus::Content)
                    .unwrap()
                    .0;
                click(&mut app, region.x, region.y);
                terminal.draw(|f| app.draw(f)).unwrap();
                assert!(app.hits.borrow().result.width > 0);
            }
        }
    }
}

#[test]
fn windows_preparation_matches_exact_pdb_identity_offline() {
    let (dir, mut app) = preparation_fixture();
    let identity = crate::windows_symbols::PdbIdentity {
        name: "ntkrnlmp.pdb".into(),
        guid: "00112233445566778899AABBCCDDEEFF".into(),
        age: 1,
    };
    let mut image = vec![0; 8192];
    image[256..260].copy_from_slice(b"RSDS");
    image[260..276].copy_from_slice(&[
        0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    image[276..280].copy_from_slice(&1u32.to_le_bytes());
    image[280..293].copy_from_slice(b"ntkrnlmp.pdb\0");
    std::fs::write(app.image.as_ref().unwrap(), image).unwrap();
    let isf = |age| {
        serde_json::to_vec(&serde_json::json!({
        "metadata":{"windows":{"pdb":{"database":identity.name,"GUID":identity.guid,"age":age,"machine_type":34404}}},
        "base_types":{"pointer":{"size":8}}, "symbols":{}, "user_types":{}
    })).unwrap()
    };
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, isf(1)).unwrap();
    std::fs::write(dir.path().join("symbols/wrong-age.json"), isf(2)).unwrap();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    assert!(app.windows);
    assert_eq!(app.plugin, Plugin::WinPslist);
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(same_path(&app.symbols, &exact));
    assert_eq!(app.preparation_candidates.len(), 1);
    assert!(app.job.is_none());
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

#[test]
fn preparation_fetch_queries_downloads_selects_and_allows_retry_without_analysis() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::MissingSymbols);
    let path = "Debian/amd64/exact.json.xz";
    let candidate = RemoteMatch {
        banner: PREPARATION_BANNER.into(),
        path: path.into(),
        url: symbols::repository_url(path).unwrap(),
    };
    let index = serde_json::json!({ PREPARATION_BANNER: [path] });
    store::atomic_write(
        &app.cache.join("symbols/banners_plain.json"),
        &serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();
    // First download fails because offline cache has no bytes. Retry uses the same exact match.
    app.asset_key(KeyEvent::new(KeyCode::Char('M'), KeyModifiers::NONE));
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    app.drain();
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    assert!(app.last_error.is_some());
    assert!(app.symbols.as_os_str().is_empty());
    cache_fixture(&app, &candidate, &fixture_isf(PREPARATION_BANNER, 1));
    app.asset_key(KeyEvent::new(KeyCode::Char('M'), KeyModifiers::NONE));
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    app.drain();
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(app.symbols.is_file());
    assert!(
        app.symbols.starts_with(
            store::expand_home(&app.settings.symbols)
                .canonicalize()
                .unwrap()
        )
    );
    assert!(app.symbols.with_extension("source.json").is_file());
    assert!(app.last_error.is_none());
    assert!(!app.results.contains_key("pslist"));
    assert_eq!(app.page, Page::Assets);
}
#[test]
fn symbol_retry_keeps_execution_snapshot_after_plugin_browsing() {
    let (_dir, mut app) = preparation_fixture();
    let options = crate::analysis::Options {
        pid: Some(42),
        ..Default::default()
    };
    app.active_request = Some(Execution {
        plugin: Plugin::Pslist,
        key: "original".into(),
        parameters: "PID=42".into(),
        snapshot: ExecutionSnapshot {
            force: true,
            plugin: Plugin::Pslist,
            options,
            dump: None,
        },
    });
    app.job = Some(Job::default());
    app.select_plugin(Plugin::Psaux);
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Done(Outcome::Choose(vec![
        "original-symbol".into(),
    ])))
    .unwrap();
    app.drain();
    app.dialog_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(app.plugin, Plugin::Psaux);
    let request = app.active_request.as_ref().unwrap();
    assert_eq!(request.plugin, Plugin::Pslist);
    assert_eq!(request.snapshot.options.pid, Some(42));
    assert!(request.snapshot.force);
    app.cancel();
    finish_test_job(&mut app);
}

#[test]
fn remote_search_and_history_browsing_preserve_running_task_and_position() {
    let mut app = app();
    let job = Job::default();
    app.job = Some(job.clone());
    app.switch_section(AssetSection::Remote);
    app.open_input(InputKind::AssetsSearch);
    app.paste("Debian");
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(!job.cancel.load(Ordering::Relaxed));
    assert!(app.pending_work.is_none());
    let result = app.results["pslist"].clone();
    app.history = Some(Results {
        historical: true,
        ..result.clone()
    });
    app.row = 1;
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Done(Outcome::Ready(result))).unwrap();
    app.drain();
    assert_eq!(app.row, 1);
    assert!(app.result().unwrap().historical);
    app.history.as_mut().unwrap().symbol = "historical-symbol.json".into();
    app.page = Page::Analysis;
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(!screen(&terminal, 140).contains("historical-symbol.json"));
}

#[test]
fn clicking_cached_plugin_shows_content_immediately_at_all_widths() {
    for (width, height) in [(140, 40), (100, 30), (80, 24), (60, 18)] {
        let mut app = app();
        app.focus = Focus::Navigation;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        let index = app
            .navigation_plugins()
            .iter()
            .position(|p| *p == Plugin::Pslist)
            .unwrap();
        click(
            &mut app,
            hits.menu.x + 2,
            hits.menu.y + 1 + (index - hits.menu_offset) as u16,
        );
        assert_eq!(app.focus, Focus::Content);
        assert!(app.dialog.is_none());
        assert!(app.job.is_none());
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(app.hits.borrow().result.width > 0);
        assert!(app.result().is_some());
    }
}

#[test]
fn plugin_activation_runs_and_changed_parameters_queue_the_last_request() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    // No previous execution snapshot exists for the identification result; psaux is uncached.
    app.activate_plugin(Plugin::Psaux);
    assert!(app.job.is_some());
    assert_eq!(app.active_request.as_ref().unwrap().plugin, Plugin::Psaux);
    let first = app.job.as_ref().unwrap().clone();
    app.analysis_options.pid = Some(42);
    app.activate_plugin(Plugin::Psaux);
    assert!(first.check().is_err());
    let next = app.pending_execution.as_ref().unwrap();
    assert_eq!(next.plugin, Plugin::Psaux);
    assert_eq!(next.options.pid, Some(42));
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    app.drain();
    assert_eq!(
        app.active_request.as_ref().unwrap().snapshot.options.pid,
        Some(42)
    );
    finish_test_job(&mut app);
}

#[test]
fn resource_home_remote_multiple_candidates_require_selection_and_zero_preserves_local() {
    let (dir, mut app) = preparation_fixture();
    assert_eq!(app.page, Page::Assets);
    assert_eq!(Page::ALL, [Page::Assets, Page::Analysis]);
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    let selected = app.symbols.clone();
    for paths in [
        vec!["Debian/amd64/one.json.xz", "Debian/amd64/two.json.xz"],
        vec![],
    ] {
        store::atomic_write(
            &app.cache.join("symbols/banners_plain.json"),
            &serde_json::to_vec(&serde_json::json!({PREPARATION_BANNER: paths})).unwrap(),
        )
        .unwrap();
        app.key(KeyEvent::new(KeyCode::Char('M'), KeyModifiers::NONE));
        finish_test_job(&mut app);
        assert_eq!(app.symbols, selected);
        assert_eq!(app.preparation, Preparation::Ready);
        if paths.len() == 2 {
            assert!(
                matches!(&app.dialog, Some(Dialog::Links { matches, .. }) if matches.len() == 2)
            );
            app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        } else {
            assert!(app.dialog.is_none());
            assert!(app.status.contains("完整 banner"));
            assert!(app.status.contains(symbols::REPOSITORY));
        }
    }
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let rendered = screen(&terminal, 140);
    assert!(rendered.contains(symbols::REPOSITORY));
    assert!(!rendered.contains("准备引导"));
    assert!(rendered.contains("离线"));
}

#[test]
fn space_selects_assets_and_detail_inspects_symbols_without_changing_the_object() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    app.symbols = PathBuf::new();
    app.choice = None;
    app.preparation = Preparation::MissingSymbols;
    app.switch_section(AssetSection::Symbols);
    app.focus_asset(Kind::Symbols, &exact);
    let version = app.object_version;
    app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::AssetDetail { .. })));
    assert!(app.symbols.as_os_str().is_empty());
    finish_test_job(&mut app);
    assert_eq!(app.object_version, version);
    assert!(app.symbols.as_os_str().is_empty());
    assert!(
        app.asset_details
            .values()
            .any(|text| text.contains("SHA256") && text.contains(PREPARATION_BANNER))
    );
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(same_path(&app.symbols, &exact));
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(app.job.is_none());
    assert!(!app.results.contains_key("pslist"));
}

#[test]
fn candidate_detail_inspects_and_returns_to_the_same_zip_selection() {
    use std::io::Write;
    let (dir, mut app) = preparation_fixture();
    let path = dir.path().join("symbols/multiple.zip");
    let mut archive = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    for (variant, name) in [(1, "one.json"), (2, "two.json")] {
        archive
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        archive
            .write_all(&fixture_isf(PREPARATION_BANNER, variant))
            .unwrap();
    }
    archive.finish().unwrap();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    app.dialog_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::AssetDetail { .. })));
    assert!(app.choice.is_none());
    finish_test_job(&mut app);
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::Symbols { selected: 1, .. })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert!(app.choice.as_ref().unwrap().contains("two.json"));
    assert!(app.job.is_none());
}

#[test]
fn current_image_symbol_generation_validates_inputs_and_persists_exact_output() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    let original_image = std::fs::read(app.image.as_ref().unwrap()).unwrap();
    app.key(KeyEvent::new(KeyCode::Char('K'), KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::GenerateSymbols {
            automatic: false,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(
        matches!(&app.dialog, Some(Dialog::GenerateSymbols { error, .. }) if error.contains("ELF"))
    );
    assert!(app.job.is_none());
    // Minimal ELF with a symbol table, and a deterministic dwarf2json fixture executable.
    let mut elf_bytes = vec![0; 512];
    elf_bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf_bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf_bytes[40..48].copy_from_slice(&64u64.to_le_bytes());
    elf_bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    elf_bytes[60..62].copy_from_slice(&3u16.to_le_bytes());
    elf_bytes[152..160].copy_from_slice(&256u64.to_le_bytes());
    elf_bytes[160..168].copy_from_slice(&16u64.to_le_bytes());
    elf_bytes[196..200].copy_from_slice(&2u32.to_le_bytes());
    elf_bytes[216..224].copy_from_slice(&280u64.to_le_bytes());
    elf_bytes[224..232].copy_from_slice(&24u64.to_le_bytes());
    elf_bytes[232..236].copy_from_slice(&1u32.to_le_bytes());
    elf_bytes[248..256].copy_from_slice(&24u64.to_le_bytes());
    elf_bytes[256..272].copy_from_slice(b"\0sys_call_table\0");
    elf_bytes[280..284].copy_from_slice(&1u32.to_le_bytes());
    elf_bytes[296..304].copy_from_slice(&3696u64.to_le_bytes());
    let elf = dir.path().join("debug ELF");
    let config = dir.path().join("kernel config");
    let tool = dir.path().join("fixture-tool");
    std::fs::write(&elf, elf_bytes).unwrap();
    std::fs::write(&config, "CONFIG_X86_64=y\n").unwrap();
    std::fs::write(&tool, "#!/bin/sh\ncat \"$0.json\"\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        tool.with_extension("json"),
        fixture_isf(PREPARATION_BANNER, 1),
    )
    .unwrap();
    if let Some(Dialog::GenerateSymbols {
        fields,
        field,
        error,
        ..
    }) = &mut app.dialog
    {
        *fields = [
            elf.display().to_string(),
            config.display().to_string(),
            tool.display().to_string(),
        ];
        *field = 3;
        error.clear();
    }
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 100).contains("生成当前镜像符号表"));
    let button = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Enter)
        .unwrap()
        .0;
    click(&mut app, button.x + 1, button.y);
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::Ready, "{}", app.status);
    assert!(
        app.symbols
            .starts_with(dir.path().join("symbols").canonicalize().unwrap())
    );
    assert!(app.symbols.with_extension("source.json").is_file());
    let selected = app.symbols.clone();
    assert!(
        symbols::matching(
            &selected,
            &crate::image::Image::open(app.image.as_ref().unwrap(), &app.cache, &Job::default())
                .unwrap(),
            &Job::default()
        )
        .is_ok()
    );
    assert!(!app.results.contains_key("pslist"));
    assert_eq!(
        std::fs::read(app.image.as_ref().unwrap()).unwrap(),
        original_image
    );
    // Generating from another kernel must not replace the selected exact symbol.
    std::fs::write(
        tool.with_extension("json"),
        fixture_isf("Linux version different", 1),
    )
    .unwrap();
    app.start_work(Work::GenerateSymbols([elf, config, tool]));
    finish_test_job(&mut app);
    assert!(app.last_error.as_ref().unwrap().contains("banner"));
    assert_eq!(app.symbols, selected);
}

#[test]
fn generation_form_supports_current_kali_and_safe_layouts() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    app.results.get_mut("banners").unwrap().rows = vec![vec![
        "0x1".into(),
        "Linux version 6.8.11-arm64 #1 Kali 6.8.11-1kali2".into(),
    ]];
    app.open_symbol_generation();
    assert!(matches!(
        app.dialog,
        Some(Dialog::GenerateSymbols {
            automatic: true,
            ..
        })
    ));
    for (width, height) in [(140, 40), (100, 30), (80, 24), (60, 18), (8, 3), (1, 1)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(
            app.hits
                .borrow()
                .buttons
                .iter()
                .all(|(rect, _)| rect.right() <= width && rect.bottom() <= height)
        );
    }
    app.dialog_key(KeyEvent::new(KeyCode::F(7), KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::GenerateSymbols {
            automatic: false,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.job.is_none());
    app.windows = true;
    app.open_symbol_generation();
    assert!(app.dialog.is_none());
    assert!(app.status.contains("PDB"));
}

#[test]
fn file_picker_detail_inspects_then_space_button_imports_the_selected_symbol() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.open_files(InputKind::Symbols);
    app.dialog_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::AssetDetail { .. })));
    assert!(app.symbols.as_os_str().is_empty());
    finish_test_job(&mut app);
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::Files { .. })));
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let button = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Char(' '))
        .unwrap()
        .0;
    click(&mut app, button.x + 1, button.y);
    finish_test_job(&mut app);
    assert!(same_path(&app.symbols, &exact));
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(!app.results.contains_key("pslist"));
}

#[test]
fn space_then_enter_enters_the_analysis_console_with_the_selected_object() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    let image = app.image.take().unwrap();
    app.refresh_assets();
    app.switch_section(AssetSection::Images);
    app.focus_asset(Kind::Image, &image);
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    finish_test_job(&mut app);
    app.switch_section(AssetSection::Symbols);
    app.focus_asset(Kind::Symbols, &exact);
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    let choice = app.choice.clone();
    let version = app.object_version;
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.page, Page::Analysis);
    assert_eq!(app.plugin, Plugin::Pslist);
    assert_eq!(app.focus, Focus::Navigation);
    assert!(app.dialog.is_none());
    assert!(app.job.is_none());
    assert!(same_path(app.image.as_ref().unwrap(), &image));
    assert!(same_path(&app.symbols, &exact));
    assert_eq!(app.choice, choice);
    assert_eq!(app.object_version, version);
}

#[test]
fn console_enter_works_from_empty_filtered_lists_and_keeps_the_running_task() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    let image = app.image.clone();
    for section in [
        AssetSection::Images,
        AssetSection::Symbols,
        AssetSection::Remote,
    ] {
        app.switch_section(section);
        app.asset_queries[section.slot()] = "no_matching_asset".into();
        app.remote.clear();
        assert_eq!(app.asset_count(), 0);
        let running = Job::default();
        app.job = Some(running.clone());
        assert!(app.asset_disabled(section, KeyCode::Enter).is_none());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let button = app
            .hits
            .borrow()
            .asset_buttons
            .iter()
            .find(|(_, _, key)| *key == KeyCode::Enter)
            .unwrap()
            .0;
        click(&mut app, button.x + 1, button.y);
        assert_eq!(app.page, Page::Analysis);
        assert!(app.dialog.is_none());
        assert_eq!(app.image, image);
        assert!(running.check().is_ok());
        assert!(app.job.is_some());
        app.job = None;
    }
}

#[test]
fn file_and_symbol_dialog_enter_open_the_console_without_selecting_the_highlight() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    let other = dir.path().join("symbols/other.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    std::fs::write(&other, fixture_isf("Linux version another kernel", 1)).unwrap();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    let selected = app.symbols.clone();
    app.open_files(InputKind::Symbols);
    if let Some(Dialog::Files {
        entries, selected, ..
    }) = &mut app.dialog
    {
        *selected = entries
            .iter()
            .position(|entry| same_path(&entry.path, &other))
            .unwrap();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.page, Page::Analysis);
    assert!(app.dialog.is_none());
    assert_eq!(app.symbols, selected);
    assert!(app.job.is_none());
    app.switch_section(AssetSection::Symbols);
    app.dialog = Some(Dialog::Symbols {
        labels: vec!["unselected-candidate".into()],
        selected: 0,
    });
    let choice = app.choice.clone();
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.page, Page::Analysis);
    assert!(app.dialog.is_none());
    assert_eq!(app.symbols, selected);
    assert_eq!(app.choice, choice);
    assert!(app.job.is_none());
}

#[test]
fn enter_selects_highlighted_image_and_opens_analysis_once_matched() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    let image = app.image.take().unwrap();
    app.refresh_assets();
    app.switch_section(AssetSection::Images);
    app.focus_asset(Kind::Image, &image);
    assert!(
        app.asset_disabled(AssetSection::Images, KeyCode::Enter)
            .is_none()
    );
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    // The highlighted image is selected and matching starts; the page waits for it.
    assert!(same_path(app.image.as_ref().unwrap(), &image));
    assert!(app.job.is_some());
    assert_eq!(app.page, Page::Assets);
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::Ready);
    assert_eq!(app.page, Page::Analysis);
    assert!(same_path(&app.symbols, &exact));
    // Enter again on the active image goes straight in.
    app.switch_page(Page::Assets);
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.page, Page::Analysis);
}
#[test]
fn enter_intent_is_dropped_on_cancel_and_when_symbols_are_missing() {
    let (_dir, mut app) = preparation_fixture();
    let image = app.image.take().unwrap();
    app.refresh_assets();
    app.switch_section(AssetSection::Images);
    app.focus_asset(Kind::Image, &image);
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(app.enter_when_ready);
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.enter_when_ready);
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    app.drain();
    assert_eq!(app.page, Page::Assets);
    // No exact symbols: Enter selects, matching settles on MissingSymbols, page stays.
    app.image = None;
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert_eq!(app.page, Page::Assets);
    assert!(!app.enter_when_ready);
}
#[test]
fn quit_needs_confirmation_only_while_a_task_runs() {
    let mut app = app();
    assert!(app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    assert!(app.job.is_some());
    assert!(!app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(app.status.contains("再按 q"));
    app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert!(!app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    finish_test_job(&mut app);
}
#[test]
fn escape_clears_content_filter_before_cancelling() {
    let mut app = app();
    app.switch_page(Page::Analysis);
    app.query = "zsh".into();
    app.row = 1;
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.query.is_empty());
    assert_eq!(app.row, 0);
}
#[test]
fn page_switch_replaces_stale_hints_but_keeps_errors() {
    let mut app = app();
    app.page = Page::Assets;
    app.last_error = None;
    app.switch_page(Page::Analysis);
    assert!(app.status.starts_with("分析"), "{}", app.status);
    app.switch_page(Page::Assets);
    assert!(app.status.starts_with("资源库"));
    app.status = "读取失败".into();
    app.last_error = Some("读取失败".into());
    app.switch_page(Page::Analysis);
    assert_eq!(app.status, "读取失败");
}
#[test]
fn palette_and_plugin_search_are_case_insensitive_and_multi_term() {
    let mut app = app();
    app.switch_page(Page::Analysis);
    app.focus = Focus::Content;
    assert!(!app.available_commands("dump").is_empty());
    assert!(!app.available_commands("导出 结果").is_empty());
    assert!(app.available_commands("导出 不存在").is_empty());
    assert!(COMMANDS.iter().all(|(_, key)| *key != KeyCode::Char('f')));
    assert!(plugin_matches("网络").contains(&Plugin::Sockstat));
    assert!(plugin_matches("PSTREE").contains(&Plugin::Pstree));
    app.select_os(crate::analysis::Os::Windows);
    assert!(app.plugin_matches("网络").contains(&Plugin::WinNetscan));
}
#[test]
fn clicking_the_highlighted_asset_again_selects_it() {
    let (_dir, mut app) = preparation_fixture();
    let image = app.image.take().unwrap();
    app.refresh_assets();
    app.switch_section(AssetSection::Images);
    app.focus_asset(Kind::Image, &image);
    let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let (rect, _, offset) = app
        .hits
        .borrow()
        .asset_lists
        .iter()
        .find(|(_, s, _)| *s == AssetSection::Images)
        .copied()
        .unwrap();
    let y = rect.y + 1 + (app.asset_rows[0] - offset) as u16;
    click(&mut app, rect.x + 3, y);
    assert!(app.image.is_some());
    finish_test_job(&mut app);
}
