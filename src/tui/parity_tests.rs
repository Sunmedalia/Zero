//! Contract cases from b345694: ts/src/test/{assets,library,cache,verify,
//! workbench,origin,tabs,app,theme}.test.ts. Keep these independent of legacy UI tests.
use super::*;
fn key(app: &mut App, code: KeyCode) {
    app.key(KeyEvent::new(code, KeyModifiers::NONE));
}
fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    terminal
}
fn remote(name: &str) -> RemoteMatch {
    RemoteMatch {
        banner: format!(
            "Linux version {name} (build@host) (gcc version 9.4.0 (Ubuntu 9.4.0)) #1 SMP test"
        ),
        path: format!("Ubuntu_{name}_amd64.json.xz"),
        url: format!("https://example.test/{name}.json.xz"),
    }
}
#[test]
fn primary_bindings_match_typescript_and_keep_function_keys_as_aliases() {
    for (page, code, command) in [
        (Page::Assets, 'H', Command::Help),
        (Page::Analysis, 'S', Command::SystemSelect),
        (Page::Analysis, 'R', Command::Run),
        (Page::Assets, 'V', Command::VerifyImage),
        (Page::Cache, 'x', Command::CacheClear),
    ] {
        assert_eq!(Command::from_key(page, KeyCode::Char(code)), Some(command));
        assert_eq!(action_of(command).key, KeyCode::Char(code));
    }
    assert!(ACTIONS.iter().all(|a| !matches!(a.key, KeyCode::F(_))));
    assert_eq!(
        Command::from_key(Page::Analysis, KeyCode::F(5)),
        Some(Command::Run)
    );
}
#[test]
fn selecting_analysis_focuses_content_and_launch_does_not_open_a_result_tab() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    assert_eq!(app.focus, Focus::Content);
    assert!(app.open_tabs.is_empty());
    finish_test_job(&mut app);
    app.switch_page(Page::Assets);
    app.switch_page(Page::Analysis);
    assert_eq!(app.focus, Focus::Content);
}
#[test]
fn image_name_and_directory_wrap_without_digest_and_oversize_rows_are_clickable() {
    let mut app = app();
    app.page = Page::Assets;
    app.section = AssetSection::Images;
    let mut asset = Asset {
        path: PathBuf::from(format!(
            "/cases/{}/{}.raw",
            "long-directory/".repeat(16),
            "内存镜像".repeat(25)
        )),
        kind: Kind::Image,
        bytes: 1024,
        available: true,
        directory: false,
        stamp: None,
        origin: "已导入",
    };
    let lines = app
        .image_lines(&asset, 76)
        .iter()
        .map(|l| {
            l.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    assert!(
        !lines
            .iter()
            .any(|l| l.contains('…') || l.contains(&asset.id()))
    );
    assert!(lines.join("").contains(&asset.name()));
    asset.path = PathBuf::from(format!(
        "/cases/{}/capture.raw",
        "long-directory/".repeat(40)
    ));
    app.assets = vec![asset];
    let terminal = render(&app, 80, 24);
    assert!(screen(&terminal, 80).contains("capture.raw"));
    let (rect, _, index) = app.hits.borrow().asset_rows[0];
    assert_eq!(index, 0);
    assert!(rect.height > 1);
    app.asset_rows[0] = 1;
    click(&mut app, rect.x + 2, rect.y + rect.height - 1);
    assert_eq!(app.asset_rows[0], 0);
    assert!(app.image.is_none());
}
#[test]
fn remote_source_loads_saved_index_once_and_never_needs_network() {
    let mut app = app();
    app.settings.remote_symbols = false;
    let index = symbols::Repository::configured(&app.cache)
        .unwrap()
        .index_file(&app.cache);
    store::atomic_write(
        &index,
        &serde_json::to_vec(&serde_json::json!({PREPARATION_BANNER:["Debian/amd64/one.json.xz"]}))
            .unwrap(),
    )
    .unwrap();
    app.switch_section(AssetSection::Remote);
    assert!(app.job.is_some());
    finish_test_job(&mut app);
    assert_eq!(app.remote.len(), 1);
    assert!(app.status.contains("本地已保存索引"));
    store::atomic_write(&index, b"broken").unwrap();
    app.switch_section(AssetSection::Symbols);
    app.switch_section(AssetSection::Remote);
    assert!(app.job.is_none());
    assert_eq!(app.remote.len(), 1);
}
#[test]
fn missing_index_shows_fetch_hint_without_prompting_for_evidence() {
    let mut app = app();
    app.switch_section(AssetSection::Remote);
    assert!(app.status.contains("尚未获取远程索引；g 获取"));
    assert!(app.job.is_none() && app.dialog.is_none());
}
#[test]
fn remote_exact_matches_preserve_the_whole_catalog_and_both_views_have_mouse_hits() {
    let mut app = app();
    app.remote = vec![remote("all")];
    app.remote_total = 1;
    app.remote_loaded = true;
    app.remote_matches = Some(vec![remote("matched")]);
    app.image = Some(PathBuf::from("/cases/memory.raw"));
    app.show_remote_view(false);
    assert_eq!(app.remote_list()[0].path, "Ubuntu_matched_amd64.json.xz");
    let _frame = render(&app, 120, 35);
    let rect = app
        .hits
        .borrow()
        .remote_views
        .iter()
        .find(|(_, all)| *all)
        .unwrap()
        .0;
    click(&mut app, rect.x, rect.y);
    assert_eq!(app.remote_list()[0].path, "Ubuntu_all_amd64.json.xz");
    key(&mut app, KeyCode::Char('z'));
    assert_eq!(app.remote_list()[0].path, "Ubuntu_matched_amd64.json.xz");
    assert_eq!(app.remote.len(), 1);
}
#[test]
fn matches_without_an_image_do_not_run_a_task_or_reuse_catalog_as_matches() {
    let mut app = app();
    app.remote = vec![remote("all")];
    app.remote_loaded = true;
    app.show_remote_view(false);
    assert!(app.remote_list().is_empty());
    assert!(app.status.contains("需要先选用镜像"));
    assert!(app.job.is_none());
}
#[test]
fn remote_details_show_structured_fields_and_both_download_actions() {
    let mut app = app();
    let candidate = remote("5.4.0-1098-kvm");
    let fields = remote_fields(&candidate);
    assert!(fields.iter().any(|(k, v)| k == "发行版" && v == "Ubuntu"));
    assert!(
        fields
            .iter()
            .any(|(k, v)| k == "编译器" && v.contains("9.4.0"))
    );
    app.image = Some(PathBuf::from("/cases/memory.raw"));
    app.dialog = Some(Dialog::RemoteDetail {
        candidate,
        scroll: 0,
    });
    let frame = render(&app, 120, 35);
    let text = screen(&frame, 120);
    assert!(text.contains("下载并选用 Space") && text.contains("仅下载 w"));
    let hits = app.hits.borrow();
    assert!(hits.buttons.iter().any(|(_, k)| *k == KeyCode::Char(' ')));
    assert!(hits.buttons.iter().any(|(_, k)| *k == KeyCode::Char('w')));
}
#[test]
fn cache_click_highlights_first_and_activates_second_and_keyboard_moves_between_columns() {
    let mut app = app();
    app.switch_page(Page::Cache);
    finish_test_job(&mut app);
    let _frame = render(&app, 120, 35);
    let rect = app.hits.borrow().cache_scopes;
    click(&mut app, rect.x + 2, rect.y + 2);
    assert_eq!(app.cache_page.scope, 1);
    let _frame = render(&app, 120, 35);
    assert!(screen(&_frame, 120).contains("[ ] 导出记录"));
    click(&mut app, rect.x + 2, rect.y + 2);
    let frame = render(&app, 120, 35);
    assert!(screen(&frame, 120).contains("[x] 导出记录"));
    key(&mut app, KeyCode::Right);
    assert!(app.cache_page.content);
    key(&mut app, KeyCode::Left);
    assert!(!app.cache_page.content);
}
#[test]
fn cache_toolbar_is_clickable_without_an_image_and_empty_ticks_do_not_fall_back_to_all() {
    let mut app = app();
    app.switch_page(Page::Cache);
    finish_test_job(&mut app);
    assert!(app.image.is_none());
    assert!(app.command_disabled(Command::CacheRefresh).is_none());
    let _frame = render(&app, 120, 35);
    let rect = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, k)| *k == KeyCode::Char('x'))
        .unwrap()
        .0;
    click(&mut app, rect.x, rect.y);
    assert!(app.cache_page.confirm);
    assert!(app.status.contains("再按 x 确认清理"));
    key(&mut app, KeyCode::Esc);
    assert!(!app.cache_page.confirm);
    app.cache_page.scope = 0;
    key(&mut app, KeyCode::Char(' '));
    app.cache_page.scope = 2;
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Char('x'));
    assert!(app.status.contains("清理 0 个文件"));
    key(&mut app, KeyCode::Char('x'));
    finish_test_job(&mut app);
    assert!(app.last_error.is_none());
}
#[test]
fn entering_cache_during_analysis_preserves_the_worker_and_reads_inventory_separately() {
    let mut app = app();
    let job = Job::default();
    app.job = Some(job.clone());
    app.switch_page(Page::Cache);
    assert!(!job.cancel.load(Ordering::Relaxed));
    assert!(app.pending_work.is_none());
    for _ in 0..100 {
        if app.drain_cache_query() {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(!job.cancel.load(Ordering::Relaxed));
    assert!(app.job.is_some());
    app.cache_page.content = true;
    for code in [
        KeyCode::Enter,
        KeyCode::Char('r'),
        KeyCode::Delete,
        KeyCode::Char('x'),
    ] {
        key(&mut app, code);
        assert!(!job.cancel.load(Ordering::Relaxed));
        assert!(app.pending_work.is_none());
        assert!(!app.cache_page.confirm);
    }
    app.job = None;
}
#[test]
fn inspector_keeps_row_and_scroll_when_switching_between_overlay_and_sidebar() {
    let mut app = app();
    app.focus = Focus::Content;
    app.row = 1;
    let _frame = render(&app, 120, 35);
    key(&mut app, KeyCode::Char('d'));
    let _frame = render(&app, 120, 35);
    assert_eq!(app.hits.borrow().inspector, app.hits.borrow().result);
    assert_eq!(app.focus, Focus::Detail);
    let before = app.row;
    let rect = app.hits.borrow().inspector;
    click(&mut app, rect.x + 2, rect.y + 2);
    assert_eq!(app.row, before);
    app.resize(160, 45);
    let _frame = render(&app, 160, 45);
    assert_eq!(app.hits.borrow().inspector.width, 38);
    app.resize(80, 24);
    let _frame = render(&app, 80, 24);
    assert_eq!(app.hits.borrow().inspector.width, 80);
    assert_eq!(app.row, before);
    key(&mut app, KeyCode::Esc);
    assert!(!app.inspector);
}
#[test]
fn running_indicator_is_inside_results_even_when_a_previous_result_is_visible() {
    let mut app = app();
    app.focus = Focus::Content;
    app.job = Some(Job::default());
    app.started = Some(Instant::now());
    let frame = render(&app, 120, 35);
    let text = screen(&frame, 120);
    assert!(!text.lines().next().unwrap().contains("SCAN"));
    let row = text.lines().position(|s| s.contains("运行中")).unwrap();
    let rect = app.hits.borrow().result;
    assert!(row > rect.y as usize && row < rect.bottom() as usize);
    app.job = None;
}
#[test]
fn tiny_screen_ignores_hidden_commands_and_clicks_but_accepts_quit_with_a_dialog_open() {
    let mut app = app();
    let _frame = render(&app, 50, 12);
    key(&mut app, KeyCode::Char('i'));
    click(&mut app, 1, 1);
    assert!(app.dialog.is_none());
    app.dialog = Some(Dialog::Plugins {
        query: String::new(),
        selected: 0,
    });
    assert!(app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
}
#[test]
fn theme_arrows_settings_positions_and_scanner_fields_match_the_reference() {
    let mut app = app();
    assert!(app.settings_labels()[6].starts_with("远程符号仓库:"));
    assert!(app.settings_labels()[7].starts_with("镜像摘要:"));
    app.settings.theme = "slate".into();
    app.dialog = Some(Dialog::Settings { selected: 5 });
    key(&mut app, KeyCode::Right);
    assert_eq!(app.settings.theme, "light");
    key(&mut app, KeyCode::Left);
    assert_eq!(app.settings.theme, "slate");
    app.select_os(crate::analysis::Os::Windows);
    app.select_plugin(Plugin::WinVadyarascan);
    app.windows_parameters();
    app.dialog_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL));
    let _frame = render(&app, 100, 32);
    let hit = app
        .hits
        .borrow()
        .dump_fields
        .iter()
        .find(|(_, i)| *i == 3)
        .unwrap()
        .0;
    click(&mut app, hit.x, hit.y);
    app.paste("x64");
    assert!(
        matches!(&app.dialog,Some(Dialog::WindowsParameters{fields,field:3,..}) if fields[3]=="x64")
    );
}
#[test]
fn all_seven_dump_modes_have_visible_mouse_targets_and_switching_resets_ranges() {
    let mut app = app();
    app.windows = true;
    app.open_dump(Plugin::WinMemdump, false);
    app.page = Page::Analysis;
    app.focus = Focus::Content;
    if let Some(Dialog::Dump {
        fields,
        field,
        cursor,
        selected,
        ..
    }) = &mut app.dialog
    {
        fields[1] = "0x1000".into();
        *field = 1;
        *cursor = 6;
        *selected = false;
    }
    let _frame = render(&app, 80, 24);
    assert_eq!(app.hits.borrow().dump_modes.len(), 7);
    app.dialog_key(KeyEvent::new(KeyCode::Char('6'), KeyModifiers::ALT));
    app.dialog_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
    assert!(
        matches!(&app.dialog,Some(Dialog::Dump{fields,mode:Plugin::WinModdump,..}) if fields[1]=="1"&&fields[2].is_empty())
    );
}
#[test]
fn diagnostics_use_exclusive_families_and_origin_survives_other_status_messages() {
    let mut app = app();
    let result = app.results.get_mut("pslist").unwrap();
    result.complete = false;
    result.diagnostics = vec![
        "Windows 链表不一致".into(),
        "Windows 缺页".into(),
        "布局未验收".into(),
        "对象超限".into(),
        "unknown".into(),
    ];
    assert_eq!(
        status::diagnostic_summary(&result.diagnostics),
        "页面不在镜像中 1 · 布局未验收 1 · 达到上限 1 · 对象前后矛盾 1 · 其他 1"
    );
    let body = status::diagnostics_text(result);
    assert!(body.contains("── 对象前后矛盾 1 ──"));
    app.result_origins
        .insert("pslist".into(), "读取缓存 · 1.3 s".into());
    app.status = "其他提示".into();
    let frame = render(&app, 120, 35);
    assert!(screen(&frame, 120).contains("缓存读取"));
    assert_eq!(status::format_duration(79.04), "1m19s");
    assert_eq!(status::format_duration(1.25), "1.3 s");
}

#[test]
fn explicit_verify_reuses_the_session_and_does_not_open_or_run_plugins() {
    let (_dir, mut app) = preparation_fixture();
    std::fs::File::options()
        .write(true)
        .open(app.image.as_ref().unwrap())
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() - Duration::from_secs(10)),
        )
        .unwrap();
    app.initialize(Default::default());
    finish_test_job(&mut app);
    assert!(app.verified.as_ref().unwrap().computed);
    key(&mut app, KeyCode::Char('V'));
    finish_test_job(&mut app);
    assert!(!app.verified.as_ref().unwrap().computed);
    assert!(app.open_tabs.is_empty());
    assert!(!app.results.contains_key("pslist"));
}
#[test]
fn readonly_header_details_show_only_close_and_preserve_analysis() {
    let mut app = app();
    let image = app.root.join("Space Enter.raw");
    std::fs::write(&image, b"image").unwrap();
    app.image = Some(image.clone());
    app.row = 1;
    app.focus = Focus::Content;
    let _frame = render(&app, 120, 35);
    let header = app.hits.borrow().header_image;
    click(&mut app, header.x + 1, header.y);
    let frame = render(&app, 120, 35);
    let text = screen(&frame, 120);
    assert!(text.contains("当前分析对象"));
    let Some(Dialog::AssetDetail {
        asset, read_only, ..
    }) = &app.dialog
    else {
        panic!("expected asset details")
    };
    assert!(*read_only);
    assert!(!app.asset_detail_body(asset, true).contains("Space 选用"));
    assert!(
        app.asset_detail_body(asset, true)
            .contains("Space Enter.raw")
    );
    assert!(
        app.hits
            .borrow()
            .buttons
            .iter()
            .any(|(_, code)| *code == KeyCode::Esc)
    );
    key(&mut app, KeyCode::Enter);
    assert!(app.dialog.is_none());
    assert_eq!(app.image, Some(image));
    assert_eq!(app.row, 1);
    assert!(app.results.contains_key("pslist"));
}
#[test]
fn overlay_scrollbar_does_not_scroll_hidden_result_rows_or_activate_hidden_tabs() {
    let mut app = app();
    app.focus = Focus::Content;
    let result = app.results.get_mut("pslist").unwrap();
    result.rows = (0..200)
        .map(|i| {
            vec![
                i.to_string(),
                "value".repeat(2000),
                "0".into(),
                "process".into(),
                "0x1000".into(),
            ]
        })
        .collect();
    app.ensure_plugin_tab(Plugin::Pslist);
    let _frame = render(&app, 120, 35);
    key(&mut app, KeyCode::Char('d'));
    let _frame = render(&app, 120, 35);
    assert!(app.hits.borrow().result_tabs.is_empty());
    let rect = app.hits.borrow().inspector;
    let before = app.row;
    click(&mut app, rect.right() - 1, rect.bottom() - 2);
    assert_eq!(app.row, before);
    assert!(app.detail_scroll > 0);
}

#[test]
fn clicking_the_detected_system_preserves_auto_mode_and_loaded_results() {
    let mut app = app();
    app.analysis_options.os = crate::analysis::Os::Auto;
    let mut banner = app.results["pslist"].clone();
    banner.system = "linux".into();
    app.results.insert("banners".into(), banner);
    let _frame = render(&app, 120, 35);
    let rect = app
        .hits
        .borrow()
        .systems
        .iter()
        .find(|(_, os)| *os == crate::analysis::Os::Linux)
        .unwrap()
        .0;
    click(&mut app, rect.x, rect.y);
    assert_eq!(app.analysis_options.os, crate::analysis::Os::Auto);
    assert!(app.results.contains_key("pslist"));
    let _frame = render(&app, 120, 35);
    let rect = app
        .hits
        .borrow()
        .systems
        .iter()
        .find(|(_, os)| *os == crate::analysis::Os::Windows)
        .unwrap()
        .0;
    click(&mut app, rect.x, rect.y);
    assert_eq!(app.analysis_options.os, crate::analysis::Os::Windows);
}

#[test]
fn closing_the_final_result_tab_returns_to_plugin_navigation() {
    let mut app = app();
    app.ensure_plugin_tab(Plugin::Pslist);
    app.focus = Focus::Content;
    app.close_result_tab(0);
    assert!(app.open_tabs.is_empty());
    assert_eq!(app.focus, Focus::Navigation);
    assert!(app.status.contains("已关闭全部页面"));
}

#[test]
fn remote_search_is_always_visible_and_supports_mouse_edit_filter_and_clear() {
    let mut app = app();
    app.page = Page::Assets;
    app.section = AssetSection::Remote;
    app.remote_catalog = true;
    app.remote = vec![remote("5.10"), remote("6.1")];
    app.remote_total = 2;
    for (width, height) in [(80, 24), (120, 35)] {
        let frame = render(&app, width, height);
        assert!(screen(&frame, width as usize).contains("搜索远程索引"));
        let rect = app.hits.borrow().search;
        assert_eq!(rect.height, 3);
        click(&mut app, rect.x + 2, rect.y + 1);
        assert!(matches!(
            app.dialog,
            Some(Dialog::Input {
                kind: InputKind::AssetsSearch,
                ..
            })
        ));
        app.paste("6.1");
        assert_eq!(app.remote_list().len(), 1);
        assert!(app.remote_list()[0].banner.contains("6.1"));
        key(&mut app, KeyCode::Esc);
        assert!(app.asset_queries[2].is_empty());
        assert_eq!(app.remote_list().len(), 2);
        let _frame = render(&app, width, height);
        assert_eq!(app.hits.borrow().search.height, 3);
    }
}

#[test]
fn selecting_a_new_image_clears_the_previous_manual_platform_override() {
    let (_dir, mut app) = preparation_fixture();
    let image = app.image.take().unwrap();
    app.analysis_options.os = crate::analysis::Os::Windows;
    app.windows = true;
    app.refresh_assets();
    app.section = AssetSection::Images;
    app.focus_asset(Kind::Image, &image);
    assert!(app.use_selected_asset());
    assert_eq!(app.analysis_options.os, crate::analysis::Os::Auto);
    app.prepare_selected_image();
    finish_test_job(&mut app);
    assert!(!app.windows);
    assert_eq!(app.plugin, Plugin::Pslist);
}
