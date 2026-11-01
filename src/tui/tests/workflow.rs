use super::*;

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
fn inline_content_search_has_mouse_confirmation_and_reversible_filter() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    // Idle: the field is not drawn and the table owns the rows.
    assert_eq!(app.hits.borrow().search.height, 0);
    app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    let search = app.hits.borrow().search;
    let result = app.hits.borrow().result;
    assert_eq!(search.height, 3);
    assert_eq!(search.bottom(), result.y);
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
fn selecting_an_image_enters_the_detected_analysis_console_after_matching() {
    let (dir, mut app) = preparation_fixture();
    let exact = dir.path().join("symbols/exact.json");
    std::fs::write(&exact, fixture_isf(PREPARATION_BANNER, 1)).unwrap();
    let image = app.image.take().unwrap();
    app.refresh_assets();
    app.switch_section(AssetSection::Images);
    app.focus_asset(Kind::Image, &image);
    app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    finish_test_job(&mut app);
    assert_eq!(app.page, Page::Analysis);
    assert_eq!(app.plugin, Plugin::Pslist);
    assert_eq!(app.focus, Focus::Navigation);
    assert!(app.dialog.is_none());
    assert!(app.job.is_none());
    assert!(same_path(app.image.as_ref().unwrap(), &image));
    assert!(same_path(&app.symbols, &exact));
    assert!(app.choice.is_some());
    assert!(app.open_tabs.is_empty());
    assert!(!app.results.contains_key("pslist"));
}

#[test]
fn console_enter_works_from_empty_filtered_lists_and_keeps_the_running_task() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
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
        assert!(app.command_disabled(Command::SelectAndEnter).is_none());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let button = app
            .hits
            .borrow()
            .asset_buttons
            .iter()
            .find(|(_, _, key)| *key == KeyCode::Char('x'))
            .unwrap()
            .0;
        click(&mut app, button.x + 1, button.y);
        assert_eq!(app.page, Page::Analysis);
        assert!(app.dialog.is_none());
        assert_eq!(app.image, image);
        assert!(running.check().is_ok());
        assert!(app.job.is_some());
        app.page = Page::Assets;
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.page, Page::Analysis);
        assert!(running.check().is_ok());
        app.job = None;
    }
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
    assert!(app.command_disabled(Command::SelectAndEnter).is_none());
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
fn quit_always_requires_confirmation_and_cancel_preserves_the_task() {
    let mut idle = app();
    assert!(!idle.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(matches!(idle.dialog, Some(Dialog::Quit { .. })));
    assert!(!idle.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    assert!(idle.dialog.is_none());
    assert!(!idle.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(idle.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    assert!(app.job.is_some());
    let job = app.job.as_ref().unwrap().clone();
    assert!(!app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(!app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(!app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
    assert!(!app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
    assert!(app.dialog.is_none());
    assert!(job.check().is_ok());
    assert!(!app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    assert!(app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
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
    // The hint no longer repeats the page name: the footer shows the region
    // separately, so the message starts with the action.
    app.switch_page(Page::Analysis);
    // Without an image the hint points at the library instead of the plugins.
    assert!(app.status.starts_with("尚未选用镜像"), "{}", app.status);
    app.switch_page(Page::Assets);
    assert!(app.status.starts_with("Space 选用"), "{}", app.status);
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
    assert!(
        ACTIONS
            .iter()
            .all(|action| action.key != KeyCode::Char('f'))
    );
    assert!(plugin_matches("网络").contains(&Plugin::Sockstat));
    assert!(plugin_matches("网络").contains(&Plugin::Netscan));
    assert!(plugin_matches("PSTREE").contains(&Plugin::Pstree));
    app.select_os(crate::analysis::Os::Windows);
    assert!(app.plugin_matches("网络").contains(&Plugin::WinNetscan));
}

#[test]
fn indexed_view_reuses_rows_and_invalidates_after_result_replacement() {
    let mut app = app();
    let first = app.view_index();
    assert!(std::rc::Rc::ptr_eq(&first, &app.view_index()));
    app.row = 1;
    assert!(std::rc::Rc::ptr_eq(&first, &app.view_index()));
    app.query = "needle".into();
    let query = app.view_index();
    assert!(!std::rc::Rc::ptr_eq(&first, &query));
    app.results.clear();
    assert!(!std::rc::Rc::ptr_eq(&query, &app.view_index()));
}

#[test]
fn indexed_tree_matches_legacy_cycles_and_raw_export_order() {
    let mut result = app().result().unwrap().clone();
    result.rows = vec![
        vec!["1".into(), "1".into(), "2".into(), "one".into()],
        vec!["2".into(), "2".into(), "1".into(), "two".into()],
        vec!["3".into(), "3".into(), "0".into(), "three".into()],
    ];
    for collapsed in [HashSet::new(), HashSet::from(["1".into()])] {
        let index =
            crate::result_view::Index::build(&result, "", None, false, Some((2, 3)), &collapsed);
        let rows: Vec<_> = (0..index.visible.len())
            .map(|i| index.row(&result, i).unwrap())
            .collect();
        assert_eq!(rows, tree_rows(result.rows.clone(), &collapsed));
        assert_eq!(index.filtered, vec![0, 1, 2]);
    }
}

#[test]
fn every_action_has_one_binding_and_surfaces_agree() {
    // A command must appear once in the table, and every table entry must
    // resolve from its own key on its own page.
    let mut seen = HashSet::new();
    for action in ACTIONS {
        assert!(
            seen.insert(action.command),
            "duplicate command in ACTIONS: {:?}",
            action.command
        );
        if action.placement == 0 {
            continue;
        }
        let page = match action.scope {
            Scope::Analysis => Page::Analysis,
            Scope::Assets => Page::Assets,
            Scope::Anywhere => Page::Assets,
            Scope::Cache => Page::Cache,
        };
        assert_eq!(
            Command::from_key(page, action.key),
            Some(action.command),
            "{:?} does not resolve from {:?} on {page:?}",
            action.command,
            action.key
        );
    }
    // Keys reused across pages must resolve to the page-specific command.
    assert_eq!(
        Command::from_key(Page::Assets, KeyCode::Char('d')),
        Some(Command::AssetDetail)
    );
    assert_eq!(
        Command::from_key(Page::Analysis, KeyCode::Char('d')),
        Some(Command::Detail)
    );
    assert_eq!(
        Command::from_key(Page::Assets, KeyCode::Char('r')),
        Some(Command::RefreshAssets)
    );
    assert_eq!(
        Command::from_key(Page::Analysis, KeyCode::Char('r')),
        Some(Command::Rerun)
    );
}

#[test]
fn palette_offers_every_toolbar_entry_in_every_section() {
    // The palette is the documented fallback when a strip is truncated, so it
    // must never be missing an action the toolbar offers.
    for section in [
        AssetSection::Images,
        AssetSection::Symbols,
        AssetSection::Remote,
    ] {
        let palette = command_matches("", Page::Assets, Focus::Navigation, Some(section));
        let offered = palette
            .iter()
            .map(|i| ACTIONS[*i].command)
            .collect::<HashSet<_>>();
        for command in toolbar_commands(section, false) {
            assert!(
                offered.contains(&command),
                "{command:?} is on the {section:?} toolbar but not in the palette"
            );
        }
    }
}

#[test]
fn online_toggle_has_one_message_on_both_pages() {
    let mut app = app();
    app.switch_page(Page::Assets);
    app.key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));
    let assets = app.status.clone();
    assert!(!app.settings.remote_symbols);
    app.switch_page(Page::Analysis);
    app.key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));
    assert!(app.settings.remote_symbols);
    app.key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE));
    assert_eq!(app.status, assets, "both pages must report the same state");
}

#[test]
fn section_specific_keys_fall_back_to_the_page_action() {
    // `g` means "fetch the index" only in the remote section. Elsewhere it is
    // the analysis page's symbol generation, not a silent no-op.
    let mut app = app();
    app.switch_section(AssetSection::Images);
    app.remote_catalog = false;
    app.key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
    // No image is loaded, so the analysis-page meaning refuses with a reason
    // instead of silently starting a remote catalog fetch.
    assert!(
        app.status.contains("镜像"),
        "g on the image section must explain itself: {}",
        app.status
    );
    assert!(!app.remote_catalog);
    assert!(app.job.is_none());
}
