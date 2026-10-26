use super::*;
fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    terminal
}
#[test]
fn outside_click_closes_image_and_symbol_details_without_activating_underlying_tabs() {
    let mut app = app();
    let image = app.root.join("case.raw");
    std::fs::write(&image, b"image").unwrap();
    app.image = Some(image);
    app.symbols = app.root.join("kernel.json");
    for symbols in [false, true] {
        let _frame = render(&app, 120, 35);
        let hits = app.hits.borrow().clone();
        let rect = if symbols {
            hits.header_symbol
        } else {
            hits.header_image
        };
        click(&mut app, rect.x, rect.y);
        assert!(matches!(
            app.dialog,
            Some(Dialog::AssetDetail {
                read_only: true,
                ..
            })
        ));
        let _frame = render(&app, 120, 35);
        let before = app.object_version;
        click(&mut app, 1, 0);
        assert!(app.dialog.is_none());
        assert_eq!(app.page, Page::Analysis);
        assert_eq!(app.object_version, before);
        assert!(app.results.contains_key("pslist"));
        finish_test_job(&mut app);
    }
}
#[test]
fn crowded_tabs_pan_without_switching_or_squeezing_results() {
    let mut app = app();
    app.open_tabs = app
        .navigation_plugins()
        .iter()
        .take(14)
        .copied()
        .map(OpenTab::Plugin)
        .collect();
    app.active_tab = Some(13);
    app.focus = Focus::Content;
    for width in [80, 120] {
        let _frame = render(&app, width, 35);
        let hits = app.hits.borrow().clone();
        assert!(hits.result_tabs.iter().all(|(r, _, _)| r.width == 24));
        assert!(hits.result_tabs.iter().any(|(_, _, i)| *i == 13));
        let before = app.tab_offset.get();
        let (rect, _) = hits
            .result_tab_steps
            .iter()
            .find(|(_, offset)| *offset < before)
            .copied()
            .unwrap();
        click(&mut app, rect.x + 1, rect.y);
        let _frame = render(&app, width, 35);
        assert_eq!(app.tab_offset.get(), before - 1);
        assert_eq!(app.active_tab, Some(13));
        let (rect, _) = app
            .hits
            .borrow()
            .result_tab_steps
            .iter()
            .find(|(_, offset)| *offset > app.tab_offset.get())
            .copied()
            .unwrap();
        click(&mut app, rect.x + 1, rect.y);
        let _frame = render(&app, width, 35);
        assert_eq!(app.tab_offset.get(), before);
        assert_eq!(app.active_tab, Some(13));
        assert!(
            app.hits
                .borrow()
                .result_tab_steps
                .iter()
                .all(|(r, _)| r.right() <= width)
        );
    }
}
#[test]
fn plugin_sidebar_can_collapse_and_expand_without_losing_result_state() {
    let mut app = app();
    app.row = 1;
    app.sort = Some(0);
    for width in [60, 80, 120, 160] {
        app.focus = Focus::Navigation;
        let _frame = render(&app, width, 35);
        let rect = app.hits.borrow().plugin_toggle;
        assert!(rect.width > 0 && rect.right() <= width);
        assert_eq!(rect.y, app.hits.borrow().menu.bottom() - 1);
        click(&mut app, rect.x + 1, rect.y);
        let _frame = render(&app, width, 35);
        assert!(app.plugins_collapsed);
        let expand = app.hits.borrow().plugin_toggle;
        assert_eq!(expand.y, app.hits.borrow().result.bottom() - 1);
        assert_eq!(expand.right() + 1, app.hits.borrow().result.right());
        assert_eq!(app.hits.borrow().menu.width, 0);
        assert_eq!(app.hits.borrow().result.width, width);
        for _ in 0..8 {
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
            assert_ne!(app.focus, Focus::Navigation);
        }
        app.resize(width, 24);
        assert!(app.plugins_collapsed);
        click(&mut app, expand.x + 1, expand.y);
        let _frame = render(&app, width, 35);
        assert!(!app.plugins_collapsed);
        assert!(app.hits.borrow().menu.width > 0);
        assert_eq!(app.row, 1);
        assert_eq!(app.sort, Some(0));
    }
}
#[test]
fn analysis_object_header_moves_up_and_omits_the_platform_prefix() {
    let mut app = app();
    app.windows = true;
    app.image = Some(app.root.join("case.mem"));
    app.symbols = app.root.join("kernel.json");
    let frame = render(&app, 120, 35);
    let text = screen(&frame, 120);
    let row = text.lines().nth(1).unwrap();
    assert!(row.starts_with("镜像: "));
    assert!(row.contains("符号: "));
    assert!(!row.contains("Windows"));
    let hits = app.hits.borrow();
    assert_eq!(hits.header.y, 1);
    assert_eq!(hits.header_image.y, 1);
    assert_eq!(hits.header_symbol.y, 1);
    assert_eq!(hits.result.y, 2);
    assert!(hits.systems.iter().all(|(r, _)| r.y == 0));
}

#[test]
fn slash_search_follows_the_focused_pane_without_changing_the_other_query() {
    for width in [80, 120] {
        let mut app = app();
        app.focus = Focus::Navigation;
        app.query = "content filter".into();
        let _frame = render(&app, width, 30);
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(matches!(app.dialog, Some(Dialog::Plugins { .. })));
        let frame = render(&app, width, 30);
        let hits = app.hits.borrow().clone();
        assert_eq!(hits.popup, hits.menu);
        assert_eq!(hits.popup_list.y, hits.menu.y + 3);
        assert!(screen(&frame, width as usize).contains("搜索插件"));
        app.paste("pslist");
        assert!(matches!(&app.dialog, Some(Dialog::Plugins { query, .. }) if query == "pslist"));
        assert_eq!(app.query, "content filter");
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.dialog.is_none());
        assert!(app.job.is_none());
        app.focus = Focus::Content;
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(matches!(
            app.dialog,
            Some(Dialog::Input {
                kind: InputKind::Search,
                ..
            })
        ));
        let frame = render(&app, width, 30);
        let hits = app.hits.borrow().clone();
        assert_eq!(hits.search.x, hits.workbench.x);
        assert_eq!(hits.search.y, hits.workbench.y);
        assert_eq!(hits.search.width, hits.workbench.width);
        assert!(screen(&frame, width as usize).contains("内容搜索"));
        app.paste("changed");
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.query, "content filter");
        assert!(app.dialog.is_none());
    }
}
#[test]
fn plugin_search_field_click_does_not_activate_a_plugin_and_list_click_selects_the_correct_row() {
    let mut app = app();
    app.focus = Focus::Navigation;
    app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
    app.paste("pslist");
    let _frame = render(&app, 120, 30);
    let popup = app.hits.borrow().popup;
    click(&mut app, popup.x + 1, popup.y + 1);
    assert!(matches!(app.dialog, Some(Dialog::Plugins { .. })));
    assert!(app.job.is_none());
    let list = app.hits.borrow().popup_list;
    click(&mut app, list.x + 2, list.y + 1);
    assert!(app.dialog.is_none());
    assert_eq!(app.plugin, Plugin::Pslist);
    assert_eq!(app.focus, Focus::Content);
    assert!(app.job.is_none());
}
#[test]
fn hidden_plugin_pane_has_a_bottom_right_expand_button_and_no_top_toggle() {
    let mut app = app();
    app.focus = Focus::Content;
    let frame = render(&app, 80, 24);
    let top = screen(&frame, 80).lines().next().unwrap().to_owned();
    assert!(!top.contains("收起插件") && !top.contains("展开插件"));
    assert_eq!(app.hits.borrow().menu.width, 0);
    let rect = app.hits.borrow().plugin_toggle;
    assert_eq!(rect.y, app.hits.borrow().result.bottom() - 1);
    click(&mut app, rect.x + 1, rect.y);
    let frame = render(&app, 80, 24);
    assert!(!app.plugins_collapsed);
    assert_eq!(app.focus, Focus::Navigation);
    assert!(app.hits.borrow().menu.width > 0);
    assert!(screen(&frame, 80).contains(" << "));
    let rect = app.hits.borrow().plugin_toggle;
    click(&mut app, rect.x + 1, rect.y);
    let frame = render(&app, 80, 24);
    assert!(app.plugins_collapsed);
    assert_eq!(app.focus, Focus::Content);
    assert!(screen(&frame, 80).contains(" >> "));
}

#[test]
fn github_download_route_can_be_selected_with_settings_keyboard_and_mouse_and_is_saved() {
    let mut app = app();
    app.dialog = Some(Dialog::Settings { selected: 9 });
    assert_eq!(app.settings.github_access, symbols::GithubAccess::Auto);
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.settings.github_access, symbols::GithubAccess::Direct);
    assert_eq!(
        store::read_settings(&app.cache).github_access,
        symbols::GithubAccess::Direct
    );
    let _frame = render(&app, 120, 35);
    let hits = app.hits.borrow().clone();
    let y = hits.popup.y + 1 + (9 - hits.popup_offset) as u16;
    click(&mut app, hits.popup.x + 2, y);
    assert_eq!(app.settings.github_access, symbols::GithubAccess::GhProxy);
    assert_eq!(
        store::read_settings(&app.cache).github_access,
        symbols::GithubAccess::GhProxy
    );
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.settings.github_access, symbols::GithubAccess::Auto);
    let legacy: store::Settings = serde_json::from_str("{}").unwrap();
    assert_eq!(legacy.github_access, symbols::GithubAccess::Auto);
    assert_eq!(
        serde_json::to_value(symbols::GithubAccess::GhProxy).unwrap(),
        "gh-proxy"
    );
}
