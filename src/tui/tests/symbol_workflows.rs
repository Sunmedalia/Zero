use super::*;

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
    assert_eq!(app.asset_rows[2], app.remote.len() - 1);
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
    assert_eq!(hits.tabs.len(), 3);
    // The resource header is drawn by the page, not by `draw`, but it still
    // registers its two rows so header clicks have targets.
    assert_eq!(hits.header.height, 2);
    // The search field only takes a row while it is in use, so an idle pane
    // gives that row to the list.
    assert_eq!(hits.search.height, 0);
    assert!(hits.asset_searches.is_empty());
    assert!(screen(&terminal, 100).contains("镜像: images/capture.raw"));
    // Opening the search gives it a row again.
    app.open_input(InputKind::AssetsSearch);
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().search.height, 3);
    app.paste("test symbol");
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().popup.height, 0);
    assert!(screen(&terminal, 100).contains("test symbol"));
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.asset_queries[1].is_empty());
    app.key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
    assert_eq!(app.section, AssetSection::Remote);
    app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL));
    assert_eq!(app.page, Page::Cache);
    finish_test_job(&mut app);
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
fn contextual_footer_and_symbol_sources_follow_focus() {
    let mut app = app();
    let has = |app: &App, code| app.footer_actions().iter().any(|(_, key)| *key == code);
    app.focus = Focus::Navigation;
    assert!(has(&app, KeyCode::Char('R')));
    assert!(!has(&app, KeyCode::Char('n')));
    app.focus = Focus::Content;
    assert!(has(&app, KeyCode::Char('n')));
    assert!(has(&app, KeyCode::Char(']')));
    assert!(!has(&app, KeyCode::Enter));
    app.switch_section(AssetSection::Symbols);
    assert!(!has(&app, KeyCode::Char('a')));
    assert!(!has(&app, KeyCode::Char('g')));
    let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(
        app.hits
            .borrow()
            .asset_buttons
            .iter()
            .any(|(_, section, key)| {
                *section == AssetSection::Symbols && *key == KeyCode::Char('a')
            })
    );
    let source = app.hits.borrow().sources[2].0;
    click(&mut app, source.x, source.y);
    assert_eq!(app.section, AssetSection::Remote);
    assert!(!has(&app, KeyCode::Char('g')));
    assert!(!has(&app, KeyCode::Char('a')));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(
        app.hits
            .borrow()
            .asset_buttons
            .iter()
            .any(|(_, section, key)| {
                *section == AssetSection::Remote && *key == KeyCode::Char('g')
            })
    );
    app.focus = Focus::Content;
    assert!(!has(&app, KeyCode::Enter));
    assert!(app.footer_actions().is_empty());
    assert!(command_matches("导出结果", Page::Assets, Focus::Navigation, None).is_empty());
    assert!(command_matches("导出结果", Page::Analysis, Focus::Navigation, None).is_empty());
    assert!(!command_matches("导出结果", Page::Analysis, Focus::Content, None).is_empty());
    assert!(menu_items().iter().all(|item| !item.contains(' ')));
    for width in [60, 80, 160] {
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(
            app.hits
                .borrow()
                .asset_buttons
                .iter()
                .any(|(_, _, key)| *key == KeyCode::Char('?'))
        );
    }
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
    assert_eq!(app.page, Page::Analysis);
    app.switch_page(Page::Assets);
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
        app.history = app.results.get("pslist").cloned().map(Arc::new);
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
fn preparation_reuses_persisted_banners_after_restart() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    assert_eq!(app.preparation, Preparation::Ready);
    let banners = app.results["banners"].rows.clone();
    let image = app.image.clone();
    let cache = app.cache.clone();
    let settings = std::mem::take(&mut app.settings);
    drop(app);
    let mut restarted = App::new(image, PathBuf::new(), cache, settings);
    restarted.root = dir.path().into();
    restarted.initialize(Default::default());
    finish_test_job(&mut restarted);
    assert_eq!(restarted.preparation, Preparation::Ready);
    assert!(same_path(&restarted.symbols, &exact));
    assert_eq!(restarted.results["banners"].rows, banners);
    // The restarted UI matched symbols without computing the full image digest.
    assert!(
        restarted
            .session
            .lock()
            .unwrap()
            .identify_image(
                restarted.image.as_ref().unwrap(),
                &restarted.cache,
                &Job::default()
            )
            .unwrap()
            .digest
            .is_empty()
    );
}

#[test]
fn preparation_startup_unique_missing_and_object_change() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.initialize(Default::default());
    app.page = Page::Assets;
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
    app.page = Page::Assets;
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
fn cancellation_waits_then_runs_last_snapshot_and_never_continues_preparation() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
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
    app.page = Page::Assets;
    finish_test_job(&mut app);
    assert!(app.windows);
    assert_eq!(app.plugin, Plugin::WinPslist);
    assert_eq!(app.preparation, Preparation::Ready);
    assert!(same_path(&app.symbols, &exact));
    assert_eq!(app.preparation_candidates.len(), 1);
    assert!(app.job.is_none());
}

#[test]
fn preparation_fetch_queries_downloads_selects_and_allows_retry_without_analysis() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
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
    assert_eq!(app.page, Page::Analysis);
    assert!(app.open_tabs.is_empty());
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
    app.history = Some(Arc::new(Results {
        historical: true,
        ..result.clone()
    }));
    app.row = 1;
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Done(Outcome::Ready(result))).unwrap();
    app.drain();
    assert_eq!(app.row, 1);
    assert!(app.result().unwrap().historical);
    Arc::make_mut(app.history.as_mut().unwrap()).symbol = "historical-symbol.json".into();
    app.page = Page::Analysis;
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(!screen(&terminal, 140).contains("historical-symbol.json"));
}

#[test]
fn resource_home_remote_multiple_candidates_require_selection_and_zero_preserves_local() {
    let (dir, mut app) = preparation_fixture();
    assert_eq!(app.page, Page::Assets);
    assert_eq!(Page::ALL, [Page::Assets, Page::Analysis, Page::Cache]);
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    app.initialize(Default::default());
    app.page = Page::Assets;
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
    app.page = Page::Assets;
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
    app.page = Page::Assets;
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
    app.page = Page::Assets;
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
    let mut generated: serde_json::Value =
        serde_json::from_slice(&fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    generated["user_types"] =
        serde_json::json!({"task_struct":{"kind":"struct","size":8,"fields":{}}});
    std::fs::write(
        tool.with_extension("json"),
        serde_json::to_vec(&generated).unwrap(),
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
    let different: serde_json::Value =
        serde_json::from_slice(&fixture_isf("Linux version different", 1)).unwrap();
    generated["symbols"] = different["symbols"].clone();
    std::fs::write(
        tool.with_extension("json"),
        serde_json::to_vec(&generated).unwrap(),
    )
    .unwrap();
    app.start_work(Work::GenerateSymbols([elf, config, tool]));
    finish_test_job(&mut app);
    assert!(app.last_error.as_ref().unwrap().contains("banner"));
    assert_eq!(app.symbols, selected);
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
fn file_and_symbol_dialog_enter_open_the_console_without_selecting_the_highlight() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    let other = dir.path().join("symbols/other.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    std::fs::write(&other, fixture_isf("Linux version another kernel", 1)).unwrap();
    app.initialize(Default::default());
    app.page = Page::Assets;
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
fn official_package_candidates_require_selection_before_downloading() {
    let mut app = app();
    let candidate = crate::prepare::KernelPackage {
        banners: Vec::new(),
        sources: Vec::new(),
        banner: "Linux version 6.12.105+deb13-amd64 #1 Debian 6.12.105-1".into(),
        distribution: "Debian".into(),
        release: "6.12.105+deb13-amd64".into(),
        architecture: "amd64".into(),
        version: "6.12.105-1".into(),
        debug_url: "https://deb.debian.org/debian/pool/main/l/linux/linux-image-test-dbg.deb"
            .into(),
        kernel_url: "https://deb.debian.org/debian/pool/main/l/linux/linux-image-test-unsigned.deb"
            .into(),
        download_size: Some("1.2G".into()),
    };
    let (tx, rx) = mpsc::channel();
    tx.send(WorkerEvent::KernelPackages(vec![
        candidate.clone(),
        candidate,
    ]))
    .unwrap();
    app.receiver = Some(rx);
    app.drain();
    assert!(app.job.is_none());
    assert!(matches!(
        app.dialog,
        Some(Dialog::KernelPackages { selected: 0, .. })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert!(matches!(
        app.dialog,
        Some(Dialog::KernelPackages { selected: 1, .. })
    ));
    for (width, height) in [(140, 40), (80, 24), (60, 18), (8, 3), (1, 1)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
    }
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let rendered = screen(&terminal, 140);
    assert!(rendered.contains("deb.debian.org"));
    assert!(rendered.contains("1.2G"));
    app.settings.remote_symbols = false;
    app.dialog_key(KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::KernelPackages { .. })));
    assert!(app.job.is_none());
    assert!(app.status.contains("离线"));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.dialog.is_none());
    assert!(app.job.is_none());
}
