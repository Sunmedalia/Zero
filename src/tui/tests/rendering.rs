use super::*;

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
    let rows = [vec!["2".into(), "sh".into(), "/very/long/path".into()]];
    let borrowed = rows.iter().map(|r| (r.as_slice(), None));
    assert_eq!(table_widths(&columns, borrowed), vec![3, 4, 15]);
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
    assert!(
        rendered.contains("Linux version 3.2.0-test"),
        "rendered={rendered:.600}"
    );
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
        assert!(text.contains("导出当前筛选") || w < 60, "{w}x{h}: {text:?}");
    }
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
        .filter(|d| !d.plugin.is_dump() && !d.plugin.is_tree())
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
        // `End` scrolls to the last page. When the dialog happens to fit the
        // whole detail text the maximum is zero, so assert the reachable
        // invariant instead of a fixed non-zero value.
        app.dialog_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        terminal.draw(|f| app.draw(f)).unwrap();
        let popup = app.hits.borrow().popup;
        let maximum = app.dialog.as_ref().map_or(0, |dialog| match dialog {
            Dialog::Detail { text, .. } => detail_lines(text, popup.width.saturating_sub(2))
                .len()
                .saturating_sub(popup.height.saturating_sub(2) as usize),
            _ => 0,
        });
        assert!(
            matches!(app.dialog, Some(Dialog::Detail { scroll, .. }) if scroll == maximum),
            "End must land on the last page (maximum {maximum})"
        );
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
        assert!(app.inspector);
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
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
    assert_eq!(app.focus, Focus::Detail);
    assert_eq!(app.hits.borrow().inspector.width, 80);
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.inspector);
    app.key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
    app.paste("cache");
    terminal.draw(|f| app.draw(f)).unwrap();
    assert!(screen(&terminal, 80).contains("缓存"));
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.page, Page::Cache);
    finish_test_job(&mut app);
    app.key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    assert!(app.cache_page.confirm);
    app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!app.cache_page.confirm);
    assert!(app.job.is_none());
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
    assert!(app.page_rows() <= 17);
    assert_eq!(app.settings.page_size, 17); // Desired size is preserved for a larger screen.
    app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    app.paste("auto");
    app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.settings.page_size, 0);
    assert_eq!(app.row, 0);
}

#[test]
fn combined_manager_layout_focus_and_actions_work_at_supported_sizes() {
    let mut app = app();
    app.switch_section(AssetSection::Images);
    for (w, h) in [(160, 40), (100, 32), (80, 24), (60, 18)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        assert_eq!(hits.tabs.len(), 3, "{w}x{h}");
        assert_eq!(hits.asset_lists.len(), 1, "{w}x{h}");
        if h >= 20 {
            assert!(hits.asset_lists.iter().all(|(r, _, _)| r.height >= 3));
        }
        assert_eq!(hits.asset_detail.height, 0);
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
        assert!(app.command_disabled(Command::EnterAnalysis).is_some());
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
            // Both columns are shown once a 20-cell menu and a table can share
            // the row; below that the pane switch takes over.
            if page == Page::Analysis && height >= 16 {
                assert_eq!(
                    hits.menu.width > 0 && hits.result.width > 0,
                    width >= 100 && height >= 24
                );
            }
            if page == Page::Analysis && (60..100).contains(&width) && height >= 18 {
                let toggle = hits.plugin_toggle;
                click(&mut app, toggle.x, toggle.y);
                terminal.draw(|f| app.draw(f)).unwrap();
                let toggle = app.hits.borrow().plugin_toggle;
                click(&mut app, toggle.x, toggle.y);
                terminal.draw(|f| app.draw(f)).unwrap();
                assert!(app.hits.borrow().result.width > 0);
            }
        }
    }
}

#[test]
fn generation_form_supports_current_kali_and_safe_layouts() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
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
fn truncated_footer_keeps_a_palette_entry() {
    let mut app = app();
    app.switch_page(Page::Analysis);
    app.focus = Focus::Content;
    for width in [60, 70, 80] {
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let buttons = app.hits.borrow().buttons.clone();
        let last = buttons.last().expect("the strip always offers something");
        assert!(
            matches!(
                last.1,
                KeyCode::Char('?') | KeyCode::Char('d') | KeyCode::Char('/')
            ),
            "at {width} columns the strip ends with {last:?}"
        );
        if last.1 == KeyCode::Char('?') {
            click(&mut app, last.0.x, last.0.y);
            assert!(matches!(app.dialog, Some(Dialog::Commands { .. })));
            app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        }
    }
}

#[test]
fn escaped_renders_controls_and_leaves_text_untouched() {
    // The fast path returns ordinary text unchanged; the slow path must still
    // escape every control character so a result cannot corrupt the terminal.
    assert_eq!(
        escaped("plain /usr/lib/x86_64.so"),
        "plain /usr/lib/x86_64.so"
    );
    assert_eq!(escaped("中文与 emoji 🔒"), "中文与 emoji 🔒");
    assert_eq!(escaped(""), "");
    assert_eq!(escaped("a\nb"), "a\\nb");
    assert_eq!(escaped("a\tb"), "a\\tb");
    assert_eq!(escaped("a\u{1b}[31mb"), "a\\u{1b}[31mb");
    assert_eq!(escaped("a\0b"), "a\\u{0}b");
    // Mixed content keeps the readable part and escapes only the controls.
    assert_eq!(escaped("ok\r\nnext"), "ok\\r\\nnext");
}

#[test]
fn extreme_terminal_sizes_never_panic() {
    // Terminals can be resized to anything, including zero-height panes and
    // one-column widths. Rendering must degrade, not panic.
    let mut app = app();
    for width in [1u16, 2, 3, 5, 10, 21, 22, 23, 40, 99, 100, 139, 140, 200] {
        for height in [1u16, 2, 3, 5, 12, 19, 20, 27, 28, 40] {
            for page in Page::ALL {
                app.switch_page(page);
                for focus in [
                    Focus::Context,
                    Focus::Navigation,
                    Focus::Content,
                    Focus::Detail,
                ] {
                    app.focus = focus;
                    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                    terminal.draw(|f| app.draw(f)).unwrap();
                }
            }
        }
    }
}

#[test]
fn hostile_result_content_renders_safely() {
    // Memory images are untrusted input: cell values reach the terminal
    // directly, so control characters, ANSI escapes, NUL bytes and very wide
    // or very long values must not corrupt the screen or panic the renderer.
    let mut app = app();
    let hostile = vec![
        "\u{1b}[2J\u{1b}[31mred".to_string(),
        "a\0b\0c".to_string(),
        "line\nbreak\ttab\r".to_string(),
        "\u{202e}reversed".to_string(),
        "中".repeat(300),
        "x".repeat(5000),
        String::new(),
        "\u{7f}del\u{8}bs".to_string(),
    ];
    let mut rows = Vec::new();
    for value in &hostile {
        rows.push(vec![
            "1".into(),
            value.clone(),
            value.clone(),
            value.clone(),
            value.clone(),
        ]);
    }
    app.results.get_mut("pslist").unwrap().rows = rows;
    app.query.clear();
    for (width, height) in [(80u16, 24u16), (140, 40), (30, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        // Every cell must be a single printable symbol; nothing may leak a raw
        // control character into the frame.
        for cell in terminal.backend().buffer().content.iter() {
            let symbol = cell.symbol();
            assert!(
                !symbol.chars().any(char::is_control),
                "control character leaked into the frame: {symbol:?}"
            );
        }
        // The detail view takes the same values through a different path.
        app.open_detail();
        terminal.draw(|f| app.draw(f)).unwrap();
        app.dialog = None;
    }
}

#[test]
fn paging_never_scrolls_past_the_last_row() {
    // Page down when the page is taller than the data, and when the data ends
    // mid-page: the offset must stay on a page that has rows in it.
    let mut app = app();
    let template = app.result().unwrap().rows[0].clone();
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    for total in [0usize, 1, 2, 5, 40, 41, 100] {
        app.results.get_mut("pslist").unwrap().rows = (0..total)
            .map(|i| {
                let mut r = template.clone();
                r[0] = i.to_string();
                r
            })
            .collect();
        app.query.clear();
        app.row = 0;
        *app.table_state.borrow_mut().offset_mut() = 0;
        terminal.draw(|f| app.draw(f)).unwrap();
        // Walk to the end one page at a time.
        for _ in 0..(total / 2 + 4) {
            app.key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE));
            terminal.draw(|f| app.draw(f)).unwrap();
            let offset = app.table_state.borrow().offset();
            let page = app.page_rows();
            assert!(
                offset <= total.saturating_sub(page),
                "total={total} offset={offset} page={page} scrolled past the end"
            );
            if total > 0 {
                assert!(
                    app.row < total,
                    "total={total} row={} out of range",
                    app.row
                );
                assert!(
                    app.row >= offset,
                    "total={total} row={} above offset={offset}",
                    app.row
                );
            }
        }
        // And back to the start.
        for _ in 0..(total / 2 + 4) {
            app.key(KeyEvent::new(KeyCode::Char('['), KeyModifiers::NONE));
            terminal.draw(|f| app.draw(f)).unwrap();
        }
        assert_eq!(app.row, 0);
        assert_eq!(app.table_state.borrow().offset(), 0, "total={total}");
    }
}

#[test]
fn focus_never_lands_on_a_hidden_region() {
    // Tab order must stay inside what the frame actually draws, at every size.
    // A focus on an invisible pane routes every key to something the user
    // cannot see.
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    for (w, h) in [
        (140u16, 40u16),
        (120, 40),
        (100, 30),
        (80, 24),
        (64, 18),
        (60, 18),
    ] {
        for page in Page::ALL {
            app.switch_page(page);
            app.resize(w, h);
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            for step in 0..12 {
                terminal.draw(|f| app.draw(f)).unwrap();
                let hits = app.hits.borrow().clone();
                let hidden = match app.focus {
                    Focus::Detail => hits.inspector.width == 0 && hits.asset_detail.height == 0,
                    Focus::Context => page != Page::Analysis || hits.header.height == 0,
                    _ => false,
                };
                assert!(
                    !hidden,
                    "{w}x{h} {page:?} step {step}: focus {:?} is not drawn",
                    app.focus
                );
                app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
            }
        }
    }
}

#[test]
fn layout_thresholds_live_in_one_place() {
    // Every renderer and the focus cycle ask `Space`, so the same question
    // cannot get different answers in different files. This pins the answers
    // that the layout actually depends on.
    let narrow = Space::new(60, 18);
    assert!(!narrow.two_panes(), "60 cols cannot host menu + table");
    // 18 rows leaves five per list, so the page shows one at a time.
    assert!(!narrow.asset_detail());
    assert!(!narrow.inspector());
    assert!(!narrow.system_row());

    let standard = Space::new(80, 24);
    assert!(!standard.two_panes(), "80x24 shows the focused pane");
    assert!(!standard.asset_detail(), "no room for the detail panel");
    assert!(!standard.inspector());
    // Narrow layouts replace the system picker with region tabs.
    assert!(!standard.system_row());

    let wide = Space::new(160, 40);
    assert!(wide.two_panes());
    assert!(wide.asset_detail());
    assert!(wide.inspector());
    assert_eq!(wide.menu_width(), Space::WIDE_MENU);
    assert_eq!(standard.menu_width(), Space::NARROW_MENU);

    // The menu is sized by its longest label (18 cells plus the highlight
    // marker), not by a fraction of the terminal: clipping a plugin name is
    // worse than a narrow table.
    assert!(Space::new(64, 16).menu_width() >= 20);
    assert!(
        Space::new(64, 16).menu_width() + 20 <= 64,
        "a table still fits"
    );
}

#[test]
fn dialogs_size_to_their_content() {
    // Every modal used to be 12 rows and `screen - 6` columns regardless of
    // what it held, so a three-option picker filled the terminal and a
    // 60x18 window lost two thirds of its screen to a two-line list.
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let measure = |app: &mut App, dialog: Dialog, terminal: &mut Terminal<TestBackend>| {
        app.dialog = Some(dialog);
        terminal.draw(|f| app.draw(f)).unwrap();
        let popup = app.hits.borrow().popup;
        app.dialog = None;
        popup
    };

    let system = measure(&mut app, Dialog::System { selected: 0 }, &mut terminal);
    assert!(
        system.height <= 6,
        "three options do not need {} rows",
        system.height
    );
    assert!(
        system.width < 70,
        "a short list does not need {} columns",
        system.width
    );

    // A sort list is as tall as the result's columns, not a fixed 12.
    let columns = app.result().map_or(0, |r| r.columns.len()) as u16;
    let sort = measure(&mut app, Dialog::Sort { column: 0 }, &mut terminal);
    assert_eq!(sort.height, columns + 2);

    // Text entry gets room for the path being edited.
    let input = measure(
        &mut app,
        Dialog::Input {
            kind: InputKind::Export,
            text: "exports/evidence.json".into(),
            original: String::new(),
            cursor: 0,
            selected: false,
        },
        &mut terminal,
    );
    assert!(input.width >= 40, "input needs room, got {}", input.width);

    // Nothing may exceed the screen or hide the page behind it.
    for (w, h) in [(80u16, 24u16), (60, 18), (40, 12)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        for dialog in [
            Dialog::Commands {
                query: String::new(),
                selected: 0,
            },
            Dialog::Plugins {
                query: String::new(),
                selected: 0,
            },
        ] {
            let plugin_search = matches!(dialog, Dialog::Plugins { .. });
            let popup = measure(&mut app, dialog, &mut terminal);
            assert!(
                popup.width <= w && popup.height <= h,
                "{popup:?} in {w}x{h}"
            );
            assert!(
                plugin_search || popup.height * 4 <= h * 3 || h < 12,
                "{popup:?} hides the page in {w}x{h}"
            );
        }
    }
}

#[test]
fn plugin_menu_scrolls_the_selection_into_view() {
    // The menu used to restart at the top every frame, so once the selection
    // moved past the visible rows the highlight was off screen and the list
    // looked frozen while keys did nothing visible.
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    app.switch_page(Page::Analysis);
    app.focus = Focus::Navigation;
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let last = app.menu_items().len() - 1;
    for target in [0usize, last / 2, last] {
        app.menu = target;
        terminal.draw(|f| app.draw(f)).unwrap();
        let hits = app.hits.borrow().clone();
        let rows = hits.menu.height.saturating_sub(2) as usize;
        let offset = hits.menu_offset;
        assert!(
            target >= offset && target < offset + rows,
            "selection {target} is outside rows {offset}..{} (height {})",
            offset + rows,
            hits.menu.height
        );
        // The highlighted row must be inside the drawn area.
        let row = hits.menu.y + 1 + (target - offset) as u16;
        assert!(row < hits.menu.bottom() - 1, "row {row} outside menu");
    }
}

#[test]
fn plugin_labels_are_not_clipped_by_the_menu_column() {
    // The column is sized from the longest label; a clipped plugin name reads
    // as a different plugin.
    let app = app();
    let longest = app
        .menu_items()
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0) as u16;
    for space in [Space::new(80, 24), Space::new(120, 40)] {
        let width = space.menu_width();
        // Two cells of highlight marker, and two of border.
        assert!(
            width >= longest + 4,
            "menu {width} clips a {longest}-cell label"
        );
    }
}

#[test]
fn menu_rows_are_exactly_the_plugin_names() {
    // One row per selectable item keeps the drawn row, the scroll offset and
    // `menu` on the same index. A category marker prefixed to some rows broke
    // that reading: it consumed cells, said only that something had changed,
    // and reused `·`, which means "label · value" everywhere else in the
    // interface. The category is named in the title instead.
    let mut app = app();
    app.switch_page(Page::Analysis);
    for (w, h) in [(80u16, 24u16), (120, 40)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let text = screen(&terminal, w as usize);
        for (i, label) in app.menu_items().iter().enumerate() {
            // Rows scrolled out of view cannot be checked from the frame.
            let hits = app.hits.borrow().clone();
            let rows = hits.menu.height.saturating_sub(2) as usize;
            if i < hits.menu_offset || i >= hits.menu_offset + rows {
                continue;
            }
            let row = hits.menu.y as usize + 1 + (i - hits.menu_offset);
            let line = text.lines().nth(row).unwrap_or_default();
            // Border, then the two cells `List` reserves for `› ` on every
            // row so the labels stay aligned whether selected or not.
            let cell = line
                .chars()
                .skip(hits.menu.x as usize + 3)
                .take(label.chars().count())
                .collect::<String>();
            assert_eq!(cell, *label, "{w}x{h} row {i} is not the bare label");
        }
    }
}

#[test]
fn long_asset_paths_keep_the_row_readable() {
    // The path is the only field of unbounded length, so it yields to the
    // fields after it. A long path used to fill the row and cut the format
    // off entirely; in a narrow pane the digest is dropped as well, because a
    // truncated digest identifies nothing while the format still does.
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    for i in 0..6 {
        app.assets.push(crate::workspace::Asset {
            path: std::path::PathBuf::from(format!(
                "/evidence/a-very-long-directory-name-{i}/linux-sample-capture-{i}.raw"
            )),
            kind: crate::workspace::Kind::Image,
            bytes: 2_147_483_648,
            available: true,
            directory: false,
            stamp: None,
            origin: "已导入",
        });
    }
    app.section = AssetSection::Images;
    for (w, h) in [(120u16, 40u16), (80, 24), (60, 18)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let text = screen(&terminal, w as usize);
        let hits = app.hits.borrow();
        assert!(!hits.asset_rows.is_empty(), "{w}x{h}: {text}");
        let lines: Vec<_> = text.lines().collect();
        for (rect, _, index) in &hits.asset_rows {
            let rendered = lines[rect.y as usize..rect.bottom() as usize].join("");
            assert!(
                rendered.contains("RAW/LiME") || rect.height == 1,
                "wrapped asset {index}: {rendered}"
            );
            assert!(rect.width > 0 && rect.bottom() <= h);
        }
    }
}

#[test]
fn remote_rows_stay_distinguishable_without_losing_the_download_path() {
    // Repository paths end in a 64-character content hash that is identical
    // across the candidates for one kernel, so the tail is the least
    // informative part. It is elided for display only: the full path still
    // reaches the downloader and the detail panel.
    let mut app = app();
    app.switch_page(Page::Assets);
    app.section = AssetSection::Remote;
    app.symbol_source = AssetSection::Remote;
    app.remote = (0..8)
        .map(|i| crate::symbols::RemoteMatch {
            banner: format!("Linux version 6.8.{i}-amd64 (build@host) #1 SMP"),
            path: format!(
                "linux/6.8.{i}-amd64/Debian_6.8.{i}-1_amd64-{}.json.xz",
                "abcdef0123456789".repeat(4)
            ),
            url: format!("https://example.invalid/6.8.{i}.json.xz"),
        })
        .collect();
    let full: Vec<String> = app.remote.iter().map(|m| m.path.clone()).collect();
    for (w, h) in [(120u16, 40u16), (80, 24), (60, 18)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        let text = screen(&terminal, w as usize);
        let rows: Vec<&str> = text.lines().filter(|l| l.contains("待下载")).collect();
        assert!(!rows.is_empty(), "{w}x{h}: no remote rows");
        // Each row shows its own version, so no two rows are identical.
        let mut seen = std::collections::HashSet::new();
        for row in &rows {
            assert!(
                seen.insert(row.to_string()),
                "{w}x{h}: duplicate remote row {row}"
            );
        }
        // The rendered rows must not have been truncated to the point that the
        // version is gone.
        assert!(
            rows.iter().any(|r| r.contains("6.8.")),
            "{w}x{h}: version missing from every row\n{text}"
        );
    }
    // The model still holds the untouched paths.
    assert_eq!(
        app.remote
            .iter()
            .map(|m| m.path.clone())
            .collect::<Vec<_>>(),
        full,
        "display compaction must not rewrite the candidate"
    );
}

#[test]
fn every_screen_fits_the_terminal() {
    // One sweep over every page, section, focus and dialog at every supported
    // size: nothing may draw outside the frame or overflow a line. Earlier
    // rounds each measured one surface; this checks them together so a fix in
    // one place cannot have pushed another out.
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    app.remote = (0..4)
        .map(|i| crate::symbols::RemoteMatch {
            banner: format!("Linux version 6.8.{i} (b@h) #1 SMP"),
            path: format!(
                "linux/6.8.{i}/Debian_6.8.{i}-1_amd64-{}.json.xz",
                "abc123".repeat(10)
            ),
            url: format!("https://example.invalid/{i}.json.xz"),
        })
        .collect();
    let dialogs: Vec<Dialog> = vec![
        Dialog::System { selected: 0 },
        Dialog::Sort { column: 0 },
        Dialog::Commands {
            query: String::new(),
            selected: 0,
        },
        Dialog::Plugins {
            query: String::new(),
            selected: 0,
        },
        Dialog::Settings { selected: 0 },
        Dialog::Detail {
            title: "详情",
            text: "line\n".repeat(40),
            scroll: 0,
        },
        Dialog::Symbols {
            labels: (0..8).map(|i| format!("candidate-{i}")).collect(),
            selected: 0,
        },
    ];
    for (w, h) in [
        (160u16, 48u16),
        (120, 40),
        (100, 30),
        (80, 24),
        (70, 22),
        (60, 18),
    ] {
        for page in Page::ALL {
            app.switch_page(page);
            for section in [
                AssetSection::Images,
                AssetSection::Symbols,
                AssetSection::Remote,
            ] {
                app.section = section;
                app.symbol_source = section;
                for focus in [Focus::Context, Focus::Navigation, Focus::Content] {
                    app.focus = focus;
                    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                    terminal.draw(|f| app.draw(f)).unwrap();
                    check_frame(&terminal, w, h, &format!("{page:?}/{section:?}/{focus:?}"));
                }
            }
        }
        for dialog in &dialogs {
            app.dialog = Some(dialog.clone());
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            terminal.draw(|f| app.draw(f)).unwrap();
            let popup = app.hits.borrow().popup;
            assert!(
                popup.width <= w && popup.height <= h,
                "{w}x{h}: popup {popup:?} escapes the frame"
            );
            check_frame(&terminal, w, h, "dialog");
            app.dialog = None;
        }
    }
}

#[test]
fn remote_rows_render_fully_wherever_a_large_index_is_scrolled() {
    // Only rows that can reach the viewport are fully built; every row that is
    // actually drawn must still carry its state tag and its own version.
    let mut app = app();
    app.switch_page(Page::Assets);
    app.section = AssetSection::Remote;
    app.symbol_source = AssetSection::Remote;
    app.remote = (0..3000)
        .map(|i| crate::symbols::RemoteMatch {
            banner: format!("Linux version 6.8.{i} (b@h) #1 SMP"),
            path: format!("linux/6.8.{i}/v{i}.json.xz"),
            url: format!("https://example.invalid/{i}.json.xz"),
        })
        .collect();
    let (w, h) = (120u16, 40u16);
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    for target in [2500usize, 10, 2999, 0] {
        app.asset_rows.0[2] = target;
        terminal.draw(|f| app.draw(f)).unwrap();
        let text = screen(&terminal, w as usize);
        assert!(
            text.contains(&format!("v{target}.json.xz")),
            "row {target} not drawn\n{text}"
        );
        let drawn = app
            .hits
            .borrow()
            .asset_rows
            .iter()
            .filter(|(_, s, _)| *s == AssetSection::Remote)
            .count();
        let tagged = text.lines().filter(|l| l.contains("待下载")).count();
        assert!(drawn > 10, "viewport too small: {drawn}");
        assert_eq!(tagged, drawn, "a visible remote row was left blank\n{text}");
    }
}

#[test]
fn batched_events_wait_for_a_repaint_only_when_hit_testing_needs_one() {
    use crate::tui::{HitTest, hit_test};
    let mouse = |kind| Event::Mouse(mouse_event(kind, 1, 1));
    assert!(hit_test(&mouse(MouseEventKind::Moved)) == HitTest::None);
    assert!(hit_test(&mouse(MouseEventKind::ScrollDown)) == HitTest::Scroll);
    assert!(hit_test(&mouse(MouseEventKind::Down(MouseButton::Left))) == HitTest::Click);
    assert!(hit_test(&mouse(MouseEventKind::Drag(MouseButton::Left))) == HitTest::Click);
    assert!(
        hit_test(&Event::Key(KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE
        ))) == HitTest::None
    );
}
