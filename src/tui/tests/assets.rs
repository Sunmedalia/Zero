use super::*;

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
    finish_test_job(&mut app);
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
fn resource_actions_are_unique_and_import_stays_accessible_on_small_screens() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(app.menu_items().contains(&"bash"));
    assert!(!app.menu_items().contains(&"history"));
    for section in [
        AssetSection::Images,
        AssetSection::Symbols,
        AssetSection::Remote,
    ] {
        app.switch_section(section);
        for (width, height) in [(160, 40), (100, 32), (80, 24), (60, 18)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            let hits = app.hits.borrow().clone();
            let rendered = screen(&terminal, width as usize);
            assert!(!rendered.contains("资源库 ·"));
            let mut seen = HashSet::new();
            for (_, target, key) in &hits.asset_buttons {
                assert!(
                    seen.insert((target.slot(), *key)),
                    "duplicate button: {target:?} {key:?}\n{rendered}"
                );
            }
            for key in [KeyCode::Char('x'), KeyCode::Char('M'), KeyCode::Char('m')] {
                let visible = hits
                    .asset_buttons
                    .iter()
                    .any(|(_, _, action)| *action == key);
                assert!(
                    visible
                        || (hits
                            .asset_buttons
                            .iter()
                            .any(|(_, _, action)| *action == KeyCode::Char('?'))
                            && app
                                .available_commands("")
                                .iter()
                                .any(|(_, action)| *action == key)),
                    "{width}x{height}\n{rendered}"
                );
                assert!(!hits.buttons.iter().any(|(_, action)| *action == key));
            }
            assert!(
                hits.asset_buttons
                    .iter()
                    .all(|(rect, _, _)| rect.y == height - 1)
            );
            assert!(!hits.asset_buttons.iter().any(|(_, _, key)| matches!(
                key,
                KeyCode::Enter | KeyCode::Char('i' | 'y' | 'K' | 'b')
            )));
            assert!(
                hits.buttons.is_empty(),
                "resource actions must stay in the toolbar"
            );
            assert!(
                hits.asset_buttons
                    .iter()
                    .any(|(_, _, key)| *key == KeyCode::Char('?'))
            );
            assert_eq!(
                hits.asset_buttons
                    .iter()
                    .map(|(rect, _, _)| rect.bottom())
                    .max(),
                Some(height)
            );
            let sources_y = hits.sources.first().unwrap().0.y;
            assert!(hits.asset_buttons.iter().all(|(rect, target, _)| {
                *target == section
                    && hits
                        .asset_lists
                        .iter()
                        .all(|(list, _, _)| rect.y >= list.bottom())
                    && (hits.asset_detail.height == 0 || rect.y >= hits.asset_detail.bottom())
            }));
            assert!(
                hits.asset_lists
                    .iter()
                    .all(|(rect, _, _)| rect.y > sources_y)
            );
            if section == AssetSection::Remote {
                assert!(
                    hits.asset_buttons
                        .iter()
                        .any(|(_, target, key)| *target == section
                            && matches!(key, KeyCode::Char('g' | '?')))
                );
            } else {
                let import = hits
                    .asset_buttons
                    .iter()
                    .find(|(_, target, key)| *target == section && *key == KeyCode::Char('a'))
                    .unwrap()
                    .0;
                click(&mut app, import.x + 1, import.y);
                let kind = if section == AssetSection::Images {
                    InputKind::Image
                } else {
                    InputKind::Symbols
                };
                assert!(
                    matches!(app.dialog, Some(Dialog::Files { kind: active, .. }) if active == kind)
                );
                app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
            }
            for key in [
                KeyCode::Char('K'),
                KeyCode::Char('b'),
                KeyCode::Char('r'),
                KeyCode::Delete,
            ] {
                if section != AssetSection::Remote || key != KeyCode::Delete {
                    assert!(
                        app.available_commands("")
                            .iter()
                            .any(|(_, action)| *action == key)
                    );
                }
            }
        }
    }
}

#[test]
fn resource_toolbar_dispatches_settings_commands_and_cancellation() {
    let mut app = app();
    app.switch_section(AssetSection::Images);
    let mut terminal = Terminal::new(TestBackend::new(60, 18)).unwrap();
    for key in [KeyCode::Char(','), KeyCode::Char('?')] {
        terminal = Terminal::new(TestBackend::new(
            if key == KeyCode::Char(',') { 500 } else { 60 },
            18,
        ))
        .unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let rect = app
            .hits
            .borrow()
            .asset_buttons
            .iter()
            .find(|(_, _, action)| *action == key)
            .unwrap()
            .0;
        click(&mut app, rect.x + 1, rect.y);
        if key == KeyCode::Char(',') {
            assert!(matches!(app.dialog, Some(Dialog::Settings { .. })));
        } else {
            assert!(matches!(app.dialog, Some(Dialog::Commands { .. })));
        }
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    }
    let job = Job::default();
    app.job = Some(job.clone());
    terminal.draw(|f| app.draw(f)).unwrap();
    let rect = app
        .hits
        .borrow()
        .asset_buttons
        .iter()
        .find(|(_, _, action)| *action == KeyCode::Esc)
        .unwrap()
        .0;
    click(&mut app, rect.x + 1, rect.y);
    assert!(job.check().is_err());
}

#[test]
fn asset_filters_refresh_when_inputs_change() {
    // The list index is cached per frame, so every input that can change the
    // visible rows must invalidate it. A stale cache would show the wrong
    // assets, which is worse than the cost it removes.
    let mut app = app();
    app.section = AssetSection::Symbols;
    app.symbol_source = AssetSection::Symbols;
    app.local_only_matches = false;
    for name in ["alpha.json", "beta.json", "gamma.json"] {
        app.assets.push(crate::workspace::Asset {
            path: std::path::PathBuf::from(format!("/tmp/symbols/{name}")),
            kind: crate::workspace::Kind::Symbols,
            bytes: 1024,
            available: true,
            directory: false,
            stamp: None,
            origin: "已导入",
        });
    }
    let names = |app: &App| {
        app.asset_list()
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>()
    };
    // The fixture already registers the symbols directory itself, so compare
    // only the entries this test adds.
    let added = |app: &App| {
        names(app)
            .into_iter()
            .filter(|n| n.ends_with(".json"))
            .collect::<Vec<_>>()
    };
    assert_eq!(added(&app), ["alpha.json", "beta.json", "gamma.json"]);
    // Query change is reflected immediately.
    app.asset_queries[1] = "beta".into();
    assert_eq!(added(&app), ["beta.json"]);
    app.asset_queries[1].clear();
    assert_eq!(added(&app).len(), 3);
    // Hidden cache copies drop out.
    app.hidden_cache_copies
        .insert(std::path::PathBuf::from("/tmp/symbols/beta.json"));
    assert_eq!(added(&app), ["alpha.json", "gamma.json"]);
    app.hidden_cache_copies.clear();
    assert_eq!(added(&app).len(), 3);
    // The matched-only toggle drops rows with no match.
    app.local_only_matches = true;
    assert!(added(&app).is_empty());
    app.local_matches
        .insert(std::path::PathBuf::from("/tmp/symbols/gamma.json"), vec![]);
    assert_eq!(added(&app), ["gamma.json"]);
    app.local_only_matches = false;
    assert_eq!(added(&app).len(), 3);
    // Replacing the asset list with the same length still invalidates.
    app.assets[0].path = std::path::PathBuf::from("/tmp/symbols/renamed.json");
    app.refresh_assets();
    assert!(!added(&app).iter().any(|n| n == "alpha.json"));
}

#[test]
fn resource_header_click_opens_the_named_picker() {
    // The resource header has one line for the image and one for the symbol.
    // Clicking each must open the matching picker, and neither may leave focus
    // on a header region that does not exist on this page.
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    for (row, kind) in [(0u16, InputKind::Image), (1, InputKind::Symbols)] {
        app.dialog = None;
        app.focus = Focus::Navigation;
        terminal.draw(|f| app.draw(f)).unwrap();
        let header = app.hits.borrow().header;
        assert_eq!(header.height, 2, "resource header is two lines: {header:?}");
        click(&mut app, header.x + 3, header.y + row);
        assert!(
            matches!(&app.dialog, Some(Dialog::Files { kind: active, .. }) if *active == kind),
            "row {row} did not open the expected picker"
        );
        assert_ne!(app.focus, Focus::Context, "no header focus region here");
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    }
}
