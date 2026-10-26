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
        app.focus = Focus::Content;
        let _frame = render(&app, width, 35);
        let rect = app.hits.borrow().plugin_toggle;
        assert!(rect.width > 0 && rect.right() <= width);
        click(&mut app, rect.x + 1, rect.y);
        let _frame = render(&app, width, 35);
        assert!(app.plugins_collapsed);
        assert_eq!(app.hits.borrow().menu.width, 0);
        assert_eq!(app.hits.borrow().result.width, width);
        for _ in 0..8 {
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
            assert_ne!(app.focus, Focus::Navigation);
        }
        app.resize(width, 24);
        assert!(app.plugins_collapsed);
        app.key(KeyEvent::new(KeyCode::Char('B'), KeyModifiers::NONE));
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
