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
        assert_eq!(expand.x, app.hits.borrow().result.x);
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
fn hidden_plugin_pane_has_a_bottom_left_expand_button_and_no_top_toggle() {
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

#[test]
fn empty_analysis_opens_the_image_library_without_a_file_dialog() {
    let mut app = app();
    app.results.clear();
    app.plugins_collapsed = true;
    app.section = AssetSection::Remote;
    let terminal = render(&app, 80, 24);
    assert!(screen(&terminal, 80).contains("打开资源库"));
    let rect = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Char('1'))
        .unwrap()
        .0;
    click(&mut app, rect.x + 2, rect.y + 1);
    assert_eq!(app.page, Page::Assets);
    assert_eq!(app.section, AssetSection::Images);
    assert!(app.dialog.is_none());
}

#[test]
fn detail_popup_expands_focuses_and_preserves_plugin_view_and_its_own_scroll() {
    let mut app = app();
    app.ensure_plugin_tab(Plugin::Pslist);
    app.query = "init".into();
    app.sort = Some(0);
    app.focus = Focus::Content;
    app.key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    assert!(matches!(app.dialog, Some(Dialog::Detail { .. })));
    let text = (0..100)
        .map(|i| format!("诊断 {i}: 内容与证据"))
        .collect::<Vec<_>>()
        .join("\n");
    app.dialog = Some(Dialog::Detail {
        title: "详情",
        text: text.clone(),
        scroll: 2,
    });
    let terminal = render(&app, 100, 32);
    let expand = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Char('t'))
        .unwrap()
        .0;
    assert!(screen(&terminal, 100).contains("⤢"));
    assert!(
        app.hits
            .borrow()
            .buttons
            .iter()
            .any(|(_, key)| *key == KeyCode::Char('c'))
    );
    click(&mut app, expand.x + 1, expand.y);
    assert!(app.dialog.is_none());
    assert_eq!(app.page, Page::Analysis);
    assert_eq!(app.focus, Focus::Content);
    assert_eq!(app.open_tabs.len(), 2);
    assert_eq!(app.active_detail(), Some((text.as_str(), 2)));
    assert!(app.job.is_none());
    let terminal = render(&app, 100, 32);
    assert!(screen(&terminal, 100).contains("诊断 2:"));
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
    let scroll = app.active_detail().unwrap().1;
    assert!(scroll > 2);
    app.switch_result_tab(0);
    assert_eq!(app.query, "init");
    assert_eq!(app.sort, Some(0));
    assert!(app.result().is_some());
    app.switch_result_tab(1);
    assert_eq!(app.active_detail().unwrap().1, scroll);
    app.query.clear();
    app.activate_plugin(Plugin::Pslist);
    assert_eq!(app.query, "init");
    app.switch_result_tab(1);
    app.close_result_tab(1);
    assert_eq!(app.query, "init");
    assert_eq!(app.sort, Some(0));
    assert!(app.results.contains_key("pslist"));
    assert_eq!(app.active_tab, Some(0));
}

#[test]
fn action_bars_stay_on_one_row_and_show_all_actions_when_they_fit() {
    let mut app = app();
    app.focus = Focus::Content;
    for page in [Page::Assets, Page::Analysis, Page::Cache] {
        app.switch_page(page);
        for width in [60, 80, 100, 160, 500] {
            let _terminal = render(&app, width, 32);
            let hits = app.hits.borrow();
            let buttons = if page == Page::Assets {
                hits.asset_buttons
                    .iter()
                    .map(|(r, _, k)| (*r, *k))
                    .collect::<Vec<_>>()
            } else {
                hits.buttons.clone()
            };
            assert!(
                buttons
                    .iter()
                    .all(|(r, _)| r.y == 31 && r.height == 1 && r.right() <= width)
            );
            if width == 500 {
                let actions = if page == Page::Assets {
                    toolbar_actions(app.section, false)
                } else {
                    app.footer_actions()
                };
                for (_, key) in actions {
                    let command = Command::from_key(page, key);
                    if command.and_then(|c| app.command_disabled(c)).is_none() {
                        assert!(buttons.iter().any(|(_, k)| *k == key), "{page:?}: {key:?}");
                    }
                }
            } else if width == 60 {
                assert!(
                    buttons.iter().any(|(_, k)| *k == KeyCode::Char('?')),
                    "{page:?}: {width}"
                );
            }
        }
    }
}

#[test]
fn modal_text_and_cleared_cells_use_each_theme_palette() {
    let mut app = app();
    for (theme, _) in THEMES {
        app.settings.theme = (*theme).into();
        for dialog in [
            Dialog::Detail {
                title: "详情",
                text: "可复制的详情\n第二行".into(),
                scroll: 0,
            },
            Dialog::Settings { selected: 0 },
            Dialog::System { selected: 0 },
            Dialog::Commands {
                query: String::new(),
                selected: 0,
            },
        ] {
            app.dialog = Some(dialog);
            let terminal = render(&app, 100, 32);
            let popup = app.hits.borrow().popup;
            for y in popup.y..popup.bottom() {
                let mut x = popup.x;
                while x < popup.right() {
                    let cell = &terminal.backend().buffer()[(x, y)];
                    assert_ne!(cell.bg, Color::Reset, "{theme} at {x},{y}");
                    assert_ne!(cell.fg, Color::Reset, "{theme} at {x},{y}");
                    x += unicode_width::UnicodeWidthStr::width(cell.symbol()).max(1) as u16;
                }
            }
        }
    }
}

#[test]
fn quit_confirmation_mouse_buttons_and_small_terminal_confirmation_work() {
    let mut app = app();
    for theme in ["light", "dusk"] {
        app.settings.theme = theme.into();
        app.request_quit();
        let terminal = render(&app, 60, 18);
        assert!(screen(&terminal, 60).contains("退出 ZERO"));
        let cancel = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(_, k)| *k == KeyCode::Esc)
            .unwrap()
            .0;
        assert!(!click(&mut app, cancel.x + 1, cancel.y));
        assert!(app.dialog.is_none());
        app.request_quit();
        let _terminal = render(&app, 60, 18);
        let confirm = app
            .hits
            .borrow()
            .buttons
            .iter()
            .find(|(_, k)| *k == KeyCode::Char('y'))
            .unwrap()
            .0;
        assert!(click(&mut app, confirm.x + 1, confirm.y));
    }
    let _terminal = render(&app, 40, 12);
    assert!(!app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    let terminal = render(&app, 40, 12);
    assert!(screen(&terminal, 40).contains("确定退出"));
    assert!(app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
}

#[test]
fn diagnostics_header_keeps_its_title_and_actions_separate_at_all_widths() {
    let mut app = app();
    app.focus = Focus::Content;
    for width in [60, 80, 120, 160] {
        app.diagnostics();
        let terminal = render(&app, width, 32);
        let hits = app.hits.borrow();
        let copy = hits
            .buttons
            .iter()
            .find(|(_, k)| *k == KeyCode::Char('c'))
            .unwrap()
            .0;
        let expand = hits
            .buttons
            .iter()
            .find(|(_, k)| *k == KeyCode::Char('t'))
            .unwrap()
            .0;
        let text = screen(&terminal, width as usize);
        let header = text.lines().nth(hits.popup.y as usize).unwrap();
        assert!(header.contains("分析诊断"), "{header}");
        assert!(
            header.contains("复制 c") && header.contains("⤢ t"),
            "{header}"
        );
        assert!(copy.right() < expand.x && expand.right() < hits.popup.right());
        drop(hits);
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    }
}
