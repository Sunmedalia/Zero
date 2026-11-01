use super::*;

#[test]
fn mouse_menu_header_and_modal() {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    // The analysis header is one line: its image field opens the image picker,
    // and symbols stay on `y` because a single line cannot host two targets.
    let header = app.hits.borrow().header;
    assert!(!click(&mut app, 5, header.y));
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Image,
            ..
        })
    ));
    terminal.draw(|f| app.draw(f)).unwrap();
    // Outside clicks dismiss without activating the page tab underneath.
    click(&mut app, 0, 0);
    assert!(app.dialog.is_none());
    assert_eq!(app.page, Page::Analysis);
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
    assert_eq!(app.row, hits.row_offset + 1);
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
    let mut terminal = Terminal::new(TestBackend::new(60, 24)).unwrap();
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
    // At 45 columns the strip cannot fit every action, so it ends with
    // `更多 ?` instead of silently dropping the ones that do not fit.
    let more = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Char('?'))
        .expect("the truncated strip must keep a 更多 entry")
        .0;
    click(&mut app, more.x, more.y);
    assert!(matches!(app.dialog, Some(Dialog::Commands { .. })));
    app.dialog_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 60).contains("搜索当前区域"));
    // "搜索当前区域" is the second entry after filtering; move down and run it.
    app.dialog_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
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

#[test]
fn wheel_scrolls_one_row_across_page_boundaries_and_clamps_at_ends() {
    let mut app = app();
    let template = app.result().unwrap().rows[0].clone();
    app.results.get_mut("pslist").unwrap().rows = (0..30)
        .map(|i| {
            let mut row = template.clone();
            row[0] = i.to_string();
            row
        })
        .collect();
    app.settings.page_size = 5;
    app.focus = Focus::Content;
    app.row = 4;
    let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().row_offset, 0);
    for expected in 1..=7 {
        let h = app.hits.borrow().clone();
        app.mouse(mouse_event(
            MouseEventKind::ScrollDown,
            h.result.x + 3,
            h.result.y + 2,
        ));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(app.hits.borrow().row_offset, expected);
        assert_eq!(app.row, expected + 4);
    }
    let h = app.hits.borrow().clone();
    click(&mut app, h.result.x + 3, h.result.y + 2);
    assert_eq!(app.row, 7); // Hit testing uses the continuous window offset.
    click(&mut app, h.result.x + 3, h.result.y + 7);
    assert_eq!(app.row, 7); // Blank space below a custom-sized window is not a row.
    for expected in (0..7).rev() {
        let h = app.hits.borrow().clone();
        app.mouse(mouse_event(
            MouseEventKind::ScrollUp,
            h.result.x + 3,
            h.result.y + 2,
        ));
        terminal.draw(|f| app.draw(f)).unwrap();
        assert_eq!(app.hits.borrow().row_offset, expected);
    }
    let h = app.hits.borrow().clone();
    app.mouse(mouse_event(
        MouseEventKind::ScrollUp,
        h.result.x + 3,
        h.result.y + 2,
    ));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().row_offset, 0);
    assert_eq!(app.row, 0);
    for _ in 0..40 {
        let h = app.hits.borrow().clone();
        app.mouse(mouse_event(
            MouseEventKind::ScrollDown,
            h.result.x + 3,
            h.result.y + 2,
        ));
        terminal.draw(|f| app.draw(f)).unwrap();
    }
    assert_eq!(app.hits.borrow().row_offset, 25);
    assert_eq!(app.row, 29);
    // Keyboard paging still advances a page; arrow keys remain continuous.
    app.key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.row, 5);
    assert_eq!(app.hits.borrow().row_offset, 5);
    app.row = 9;
    terminal.draw(|f| app.draw(f)).unwrap();
    app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().row_offset, 6);
}

#[test]
fn mouse_moves_are_ignored_without_touching_state() {
    // Terminal mouse-move events arrive continuously and nothing consumes them.
    // They must not alter focus, selection or dialogs, and must not be treated
    // as clicks by the hit map.
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let before = app.hits.borrow().clone();
    let focus = app.focus;
    let page = app.page;
    let row = app.row;
    let menu = app.menu;
    for (x, y) in [(0, 0), (5, 3), (60, 20), (119, 31)] {
        assert!(!app.mouse(mouse_event(MouseEventKind::Moved, x, y)));
    }
    assert_eq!(app.focus, focus);
    assert_eq!(app.page, page);
    assert_eq!(app.row, row);
    assert_eq!(app.menu, menu);
    assert!(app.dialog.is_none());
    // The hit map is untouched, so hit testing still describes the last frame.
    let after = app.hits.borrow();
    assert_eq!(after.tabs, before.tabs);
    assert_eq!(after.buttons, before.buttons);
    assert_eq!(after.asset_buttons, before.asset_buttons);
    assert_eq!(after.columns, before.columns);
}
