use super::*;

#[test]
fn clicking_verification_status_or_header_space_does_not_open_image_picker() {
    for selected in [false, true] {
        let mut app = app();
        if selected {
            app.image = Some(app.root.join("test.raw"));
        }
        let mut terminal = Terminal::new(TestBackend::new(160, 35)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert!(screen(&terminal, 160).contains("验证:"));
        let hits = app.hits.borrow().clone();
        click(&mut app, hits.header_symbol.right() + 4, hits.header.y);
        assert!(app.dialog.is_none());
        assert!(app.job.is_none());
        click(&mut app, hits.header.right() - 1, hits.header.y);
        assert!(app.dialog.is_none());
        assert!(app.pending_work.is_none());
    }
}

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
    assert!(app.dialog.is_none());
    assert!(app.pending_work.is_none());
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
    app.results.get_mut("linux.pslist.basic").unwrap().rows = (0..40)
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
fn dragging_header_separator_resizes_column_without_sorting() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let hits = app.hits.borrow().clone();
    let ColumnGrip {
        cell: grip,
        index,
        width,
        ..
    } = hits.column_grips[0];
    assert_eq!(index, 0);
    assert_eq!(grip.x, hits.columns[0].right());
    assert_eq!(grip.y, hits.result.y + 1);
    assert_eq!(terminal.backend().buffer()[(grip.x, grip.y)].symbol(), "│");
    let key = ColumnKey::new(app.result().unwrap().columns[0].clone(), 0);

    assert!(!click(&mut app, grip.x, grip.y));
    assert_eq!(app.sort, None);
    app.mouse(mouse_event(
        MouseEventKind::Drag(MouseButton::Left),
        grip.x + 7,
        grip.y,
    ));
    assert_eq!(app.column_widths.get(&key), Some(&(width + 7)));
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().columns[0].width, width + 7);
    // Dragging far left stops at the minimum width.
    app.mouse(mouse_event(
        MouseEventKind::Drag(MouseButton::Left),
        0,
        grip.y,
    ));
    assert_eq!(app.column_widths.get(&key), Some(&3));
    app.mouse(mouse_event(
        MouseEventKind::Up(MouseButton::Left),
        0,
        grip.y,
    ));
    assert!(app.column_drag.is_none());
    // Later drags after release do nothing.
    app.mouse(mouse_event(
        MouseEventKind::Drag(MouseButton::Left),
        50,
        grip.y,
    ));
    assert_eq!(app.column_widths.get(&key), Some(&3));
    assert_eq!(app.sort, None);

    // The width is saved with the view and restored with it.
    app.save_view();
    app.column_widths.clear();
    app.restore_view();
    assert_eq!(app.column_widths.get(&key), Some(&3));
}

#[test]
fn stale_column_resize_ends_on_the_next_press_or_a_missing_column() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let ColumnGrip {
        cell: grip, width, ..
    } = app.hits.borrow().column_grips[0];
    let key = ColumnKey::new(app.result().unwrap().columns[0].clone(), 0);
    // Press on the grip, then lose the release outside the terminal.
    click(&mut app, grip.x, grip.y);
    assert!(app.column_drag.is_some());
    // A press anywhere else ends it, so its drags (e.g. a scrollbar) are
    // not taken for a resize.
    click(&mut app, 1, 1);
    assert!(app.column_drag.is_none());
    app.mouse(mouse_event(
        MouseEventKind::Drag(MouseButton::Left),
        grip.x + 9,
        grip.y,
    ));
    assert_eq!(app.column_widths.get(&key), None);

    // A drag on a column the current result no longer has ends the drag
    // without recording a width.
    app.column_drag = Some(ColumnDrag {
        view: app.view_key(),
        column: ColumnKey::new("Gone", 0),
        origin: grip.x,
        width,
        moved: false,
        double_click: false,
    });
    app.mouse(mouse_event(
        MouseEventKind::Drag(MouseButton::Left),
        grip.x + 4,
        grip.y,
    ));
    assert!(app.column_drag.is_none());
    assert!(app.column_widths.is_empty());
}

#[test]
fn separator_grabs_a_cell_either_side_and_double_click_restores_auto_width() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let grip = app.hits.borrow().column_grips[1];
    let key = ColumnKey::new(app.result().unwrap().columns[1].clone(), 0);
    let base = Instant::now();
    assert_eq!(grip.hit, Rect::new(grip.cell.x - 1, grip.cell.y, 3, 1));
    // Only the separator itself is drawn as a handle.
    let buffer = terminal.backend().buffer();
    assert_eq!(buffer[(grip.cell.x, grip.cell.y)].symbol(), "│");
    assert_ne!(buffer[(grip.cell.x + 1, grip.cell.y)].symbol(), "│");
    for x in [grip.cell.x - 1, grip.cell.x + 1] {
        app.grip_click = None;
        app.mouse_at(
            mouse_event(MouseEventKind::Down(MouseButton::Left), x, grip.cell.y),
            base,
        );
        assert_eq!(app.column_drag.as_ref().map(|d| &d.column), Some(&key));
        app.mouse_at(
            mouse_event(MouseEventKind::Up(MouseButton::Left), x, grip.cell.y),
            base,
        );
    }
    assert_eq!(app.sort, None);

    // Drag to a width, then double-click the separator to drop it again on
    // the second release.
    app.grip_click = None;
    let t0 = base + std::time::Duration::from_secs(1);
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            grip.cell.x,
            grip.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Drag(MouseButton::Left),
            grip.cell.x + 5,
            grip.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            grip.cell.x + 5,
            grip.cell.y,
        ),
        t0,
    );
    assert_eq!(app.column_widths.get(&key), Some(&(grip.width + 5)));
    terminal.draw(|f| app.draw(f)).unwrap();
    let moved = app.hits.borrow().column_grips[1];
    let t1 = t0 + std::time::Duration::from_millis(50);
    let t2 = t1 + std::time::Duration::from_millis(100);
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            moved.cell.x,
            moved.cell.y,
        ),
        t1,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            moved.cell.x,
            moved.cell.y,
        ),
        t1,
    );
    assert_eq!(app.column_widths.get(&key), Some(&(grip.width + 5)));
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            moved.cell.x,
            moved.cell.y,
        ),
        t2,
    );
    // Reset happens on the second release, not the press.
    assert!(app.column_drag.is_some());
    assert_eq!(app.column_widths.get(&key), Some(&(grip.width + 5)));
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            moved.cell.x,
            moved.cell.y,
        ),
        t2,
    );
    assert!(app.column_drag.is_none());
    assert_eq!(app.column_widths.get(&key), None);
    assert_eq!(app.sort, None);
    terminal.draw(|f| app.draw(f)).unwrap();

    // Two presses far apart in time are two single clicks.
    app.grip_click = Some(GripClick {
        view: app.view_key(),
        column: key,
        at: t2,
    });
    let t3 = t2 + std::time::Duration::from_secs(2);
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            grip.cell.x,
            grip.cell.y,
        ),
        t3,
    );
    assert!(app.column_drag.is_some());
    assert!(!app.column_drag.as_ref().unwrap().double_click);
    // A terminal resize ends the drag.
    app.resize(120, 24);
    assert!(app.column_drag.is_none());
}

#[test]
fn keyboard_steps_the_sorted_or_leftmost_column_and_resets_all() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let columns = app.result().unwrap().columns.clone();
    let widths = app.hits.borrow().drawn_widths.clone();
    // Without a sort, the leftmost visible column changes.
    app.key(KeyEvent::new(KeyCode::Char('>'), KeyModifiers::SHIFT));
    assert_eq!(
        app.column_widths
            .get(&ColumnKey::new(columns[0].clone(), 0)),
        Some(&(widths[0] + 2))
    );
    // With a sort, the sorted column changes and clamps at the minimum.
    app.sort = Some(3);
    for _ in 0..200 {
        app.key(KeyEvent::new(KeyCode::Char('<'), KeyModifiers::SHIFT));
    }
    assert_eq!(
        app.column_widths
            .get(&ColumnKey::new(columns[3].clone(), 0)),
        Some(&3)
    );
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().drawn_widths[3], 3);
    app.key(KeyEvent::new(KeyCode::Char('='), KeyModifiers::NONE));
    assert!(app.column_widths.is_empty());
}

#[test]
fn narrow_full_width_inspector_clears_column_grips_and_cancels_drag() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let grip = app.hits.borrow().column_grips[0];
    let key = ColumnKey::new(app.result().unwrap().columns[0].clone(), 0);
    click(&mut app, grip.cell.x, grip.cell.y);
    assert!(app.column_drag.is_some());

    // Opening the narrow full-width inspector cancels the drag and clears grips.
    app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(app.inspector);
    assert!(app.column_drag.is_none());
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(app.hits.borrow().column_grips.is_empty());
    assert_eq!(app.hits.borrow().inspector, app.hits.borrow().result);

    // Even if a drag state existed before redrawing under the overlay, dragging
    // over the inspector cancels it without resizing any hidden column.
    app.column_drag = Some(ColumnDrag {
        view: app.view_key(),
        column: key.clone(),
        origin: grip.cell.x,
        width: grip.width,
        moved: false,
        double_click: false,
    });
    app.mouse(mouse_event(
        MouseEventKind::Drag(MouseButton::Left),
        grip.cell.x + 8,
        grip.cell.y,
    ));
    assert!(app.column_drag.is_none());
    assert_eq!(app.column_widths.get(&key), None);
}

#[test]
fn single_click_then_immediate_drag_resizes_instead_of_resetting() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let grip = app.hits.borrow().column_grips[1];
    let key = ColumnKey::new(app.result().unwrap().columns[1].clone(), 0);
    app.column_widths.insert(key.clone(), grip.width + 6);
    terminal.draw(|f| app.draw(f)).unwrap();
    let moved = app.hits.borrow().column_grips[1];

    let t0 = Instant::now();
    let t1 = t0 + std::time::Duration::from_millis(80);
    // First non-dragged click arms a double-click candidate.
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            moved.cell.x,
            moved.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            moved.cell.x,
            moved.cell.y,
        ),
        t0,
    );
    assert!(app.grip_click.is_some());
    // Pressing again within the double-click interval and dragging must resize,
    // not be swallowed as a double-click reset.
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            moved.cell.x,
            moved.cell.y,
        ),
        t1,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Drag(MouseButton::Left),
            moved.cell.x + 4,
            moved.cell.y,
        ),
        t1,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            moved.cell.x + 4,
            moved.cell.y,
        ),
        t1,
    );
    assert_eq!(app.column_widths.get(&key), Some(&(moved.width + 4)));
    assert!(app.column_drag.is_none());
    assert!(app.grip_click.is_none());
}

#[test]
fn view_transitions_clear_column_drag_and_prevent_cross_view_double_click() {
    let mut app = app();
    app.focus = Focus::Content;
    let mut psaux = app.result().unwrap().clone();
    psaux.plugin = Plugin::Psaux.name().into();
    app.results.insert(Plugin::Psaux.name().into(), psaux);
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let grip = app.hits.borrow().column_grips[1];
    let key = ColumnKey::new(app.result().unwrap().columns[1].clone(), 0);
    let t0 = Instant::now();
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            grip.cell.x,
            grip.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            grip.cell.x,
            grip.cell.y,
        ),
        t0,
    );
    assert!(app.grip_click.is_some());

    // Switching plugins saves/restores views and clears pending drag/click state.
    app.select_plugin(Plugin::Psaux);
    assert!(app.column_drag.is_none());
    assert!(app.grip_click.is_none());
    app.column_widths.insert(key.clone(), grip.width + 10);
    terminal.draw(|f| app.draw(f)).unwrap();
    let other_grip = app.hits.borrow().column_grips[1];
    // Even if a stale candidate from another view were injected, clicking the
    // same column in the new view within the interval does not reset it.
    app.grip_click = Some(GripClick {
        view: "other-view".into(),
        column: key.clone(),
        at: t0,
    });
    let t1 = t0 + std::time::Duration::from_millis(50);
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            other_grip.cell.x,
            other_grip.cell.y,
        ),
        t1,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            other_grip.cell.x,
            other_grip.cell.y,
        ),
        t1,
    );
    assert_eq!(app.column_widths.get(&key), Some(&(grip.width + 10)));

    // reset_view also clears active drag and click candidate.
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            other_grip.cell.x,
            other_grip.cell.y,
        ),
        t1,
    );
    assert!(app.column_drag.is_some());
    app.reset_view();
    assert!(app.column_drag.is_none());
    assert!(app.grip_click.is_none());
}

#[test]
fn widened_columns_extend_horizontal_scroll_limit_to_rightmost_column() {
    let mut app = app();
    app.focus = Focus::Content;
    let count = 20usize;
    let columns: Vec<String> = (0..count).map(|i| format!("Col{i:02}")).collect();
    let row: Vec<String> = (0..count).map(|i| format!("val-{i:02}")).collect();
    {
        let result = app.results.get_mut("linux.pslist.basic").unwrap();
        result.columns = columns.clone();
        result.rows = vec![row];
    }
    for name in columns.iter().take(count - 1) {
        app.column_widths.insert(
            ColumnKey::new(name.clone(), 0),
            crate::tui::mouse::COLUMN_MAX_WIDTH,
        );
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let expected_max = app.max_horizontal_offset();
    assert!(expected_max > 4096);
    for _ in 0..500 {
        app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::ALT));
    }
    assert_eq!(app.horizontal, expected_max);
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(app.hits.borrow().columns[count - 1].width > 0);
    assert!(screen(&terminal, 80).contains("Col19"));
    // A single Alt+Left immediately steps back from the clamped edge.
    app.key(KeyEvent::new(KeyCode::Left, KeyModifiers::ALT));
    assert_eq!(app.horizontal, expected_max - 12);
}

#[test]
fn keyboard_column_resize_uses_current_view_and_horizontal_offset_without_redraw() {
    let mut app = app();
    let d = Plugin::Sockstat.descriptor();
    let mut sock = app.results["linux.pslist.basic"].as_ref().clone();
    sock.plugin = Plugin::Sockstat.name().into();
    sock.columns = d.columns.iter().map(|s| (*s).into()).collect();
    sock.rows = vec![d.columns.iter().map(|s| (*s).into()).collect()];
    app.results.insert(Plugin::Sockstat.name().into(), sock);
    app.focus = Focus::Content;

    // Works even before any frame has ever been drawn.
    app.key(KeyEvent::new(KeyCode::Char('>'), KeyModifiers::SHIFT));
    let first_pslist = ColumnKey::new(app.result().unwrap().columns[0].clone(), 0);
    assert!(app.column_widths.contains_key(&first_pslist));

    // Draw Sockstat, then scroll horizontally WITHOUT redrawing and press `>`.
    app.select_plugin(Plugin::Sockstat);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    for _ in 0..3 {
        app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::ALT));
    }
    assert!(app.horizontal > 0);
    // No terminal.draw() here: `>` must resolve against the new horizontal offset,
    // not the previous frame's hit map (where column 0 was leftmost).
    app.key(KeyEvent::new(KeyCode::Char('>'), KeyModifiers::SHIFT));
    let sock_col0 = ColumnKey::new(d.columns[0], 0);
    assert!(!app.column_widths.contains_key(&sock_col0));
    assert_eq!(app.column_widths.len(), 1);

    // Switching back to Pslist without redrawing targets Pslist's column, not Sockstat's.
    app.select_plugin(Plugin::Pslist);
    app.column_widths.clear();
    app.key(KeyEvent::new(KeyCode::Char('>'), KeyModifiers::SHIFT));
    assert!(app.column_widths.contains_key(&first_pslist));
}

#[test]
fn duplicate_column_headers_track_widths_independently() {
    let mut app = app();
    app.focus = Focus::Content;
    {
        let result = app.results.get_mut("linux.pslist.basic").unwrap();
        result.columns = vec!["PID".into(), "Name".into(), "PID".into()];
        result.rows = vec![vec!["1".into(), "init".into(), "9999".into()]];
    }
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let grip0 = app.hits.borrow().column_grips[0];
    let grip2 = app.hits.borrow().column_grips[2];
    let first_pid = ColumnKey::new("PID", 0);
    let second_pid = ColumnKey::new("PID", 1);

    let t0 = Instant::now();
    // Drag first PID by +6.
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            grip0.cell.x,
            grip0.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Drag(MouseButton::Left),
            grip0.cell.x + 6,
            grip0.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            grip0.cell.x + 6,
            grip0.cell.y,
        ),
        t0,
    );
    terminal.draw(|f| app.draw(f)).unwrap();
    // Drag second PID by +14.
    let moved_grip2 = app.hits.borrow().column_grips[2];
    app.mouse_at(
        mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            moved_grip2.cell.x,
            moved_grip2.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Drag(MouseButton::Left),
            moved_grip2.cell.x + 14,
            moved_grip2.cell.y,
        ),
        t0,
    );
    app.mouse_at(
        mouse_event(
            MouseEventKind::Up(MouseButton::Left),
            moved_grip2.cell.x + 14,
            moved_grip2.cell.y,
        ),
        t0,
    );
    assert_eq!(app.column_widths.get(&first_pid), Some(&(grip0.width + 6)));
    assert_eq!(
        app.column_widths.get(&second_pid),
        Some(&(grip2.width + 14))
    );
    terminal.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().drawn_widths[0], grip0.width + 6);
    assert_eq!(app.hits.borrow().drawn_widths[2], grip2.width + 14);

    // Double-clicking the second PID resets only the second PID.
    let reset_grip2 = app.hits.borrow().column_grips[2];
    let t1 = t0 + std::time::Duration::from_millis(50);
    let t2 = t1 + std::time::Duration::from_millis(80);
    for t in [t1, t2] {
        app.mouse_at(
            mouse_event(
                MouseEventKind::Down(MouseButton::Left),
                reset_grip2.cell.x,
                reset_grip2.cell.y,
            ),
            t,
        );
        app.mouse_at(
            mouse_event(
                MouseEventKind::Up(MouseButton::Left),
                reset_grip2.cell.x,
                reset_grip2.cell.y,
            ),
            t,
        );
    }
    assert_eq!(app.column_widths.get(&first_pid), Some(&(grip0.width + 6)));
    assert_eq!(app.column_widths.get(&second_pid), None);
}

#[test]
fn mouse_tree_and_sort_popup() {
    let mut app = app();
    let mut result = app.result().unwrap().clone();
    result.plugin = Plugin::Pstree.name().into();
    result.rows[1][2] = "10".into();
    app.results.insert(Plugin::Pstree.name().into(), result);
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
    let mut result = app.results["linux.pslist.basic"].as_ref().clone();
    result.plugin = Plugin::Sockstat.name().into();
    result.columns = d.columns.iter().map(|s| (*s).into()).collect();
    result.rows = vec![d.columns.iter().map(|s| (*s).into()).collect()];
    app.results.insert(Plugin::Sockstat.name().into(), result);
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
fn clicking_uncached_plugin_without_image_does_not_open_a_dialog() {
    for (width, height) in [(140, 40), (80, 24)] {
        let mut app = app();
        app.results.clear();
        app.focus = Focus::Navigation;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let hits = app.hits.borrow().clone();
        let index = app
            .navigation_plugins()
            .iter()
            .position(|plugin| *plugin == Plugin::Pslist)
            .unwrap();
        click(
            &mut app,
            hits.menu.x + 2,
            hits.menu.y + 1 + (index - hits.menu_offset) as u16,
        );
        assert_eq!(app.plugin, Plugin::Pslist);
        assert_eq!(app.focus, Focus::Content);
        assert!(app.dialog.is_none());
        assert!(app.job.is_none());
        assert!(app.pending_work.is_none());
        terminal.draw(|frame| app.draw(frame)).unwrap();
        assert!(screen(&terminal, width as usize).contains("打开资源库"));
    }
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
fn clicking_image_previews_before_selecting_even_when_already_highlighted() {
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
    assert!(app.image.is_none());
    assert!(app.dialog.is_none());
    assert!(
        app.image_preview
            .as_ref()
            .is_some_and(|path| same_path(path, &image))
    );
    finish_test_job(&mut app);
    terminal.draw(|f| app.draw(f)).unwrap();
    let detail = app.hits.borrow().asset_detail;
    assert!(detail.width > 0);
    let list = app.hits.borrow().asset_lists[0].0;
    assert_eq!(list.right(), detail.x);
    assert!(app.asset_text().contains(PREPARATION_BANNER));
    assert!(screen(&terminal, 120).contains("镜像详情"));
    // Resizing hides the preview without selecting the image.
    let mut narrow = Terminal::new(TestBackend::new(80, 24)).unwrap();
    narrow.draw(|f| app.draw(f)).unwrap();
    assert_eq!(app.hits.borrow().asset_detail.width, 0);
    assert!(app.image.is_none());
    terminal.draw(|f| app.draw(f)).unwrap();
    let (row, _, _) = app.hits.borrow().asset_rows[0];
    click(&mut app, row.x + 2, row.y);
    finish_test_job(&mut app);
    assert!(
        app.image
            .as_ref()
            .is_some_and(|path| same_path(path, &image))
    );
}

#[test]
fn wheel_scrolls_one_row_across_page_boundaries_and_clamps_at_ends() {
    let mut app = app();
    let template = app.result().unwrap().rows[0].clone();
    app.results.get_mut("linux.pslist.basic").unwrap().rows = (0..30)
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
