use super::*;

#[test]
fn dump_form_requires_target_range_and_explicit_run() {
    let mut app = app();
    app.select_plugin(Plugin::Memdump);
    assert!(app.job.is_none());
    assert!(matches!(app.dialog, Some(Dialog::Dump { .. })));
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(matches!(&app.dialog,Some(Dialog::Dump{error,..}) if error.contains("PID")));
    app.paste("12");
    app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    app.paste("0x4000");
    app.dialog_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    app.paste("0x5000");
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let directory = app
        .hits
        .borrow()
        .dump_fields
        .iter()
        .find(|(_, i)| *i == 3)
        .unwrap()
        .0;
    click(&mut app, directory.x, directory.y);
    app.paste("exports/targeted");
    assert!(app.job.is_none());
    for size in [(60, 16), (80, 24), (160, 40)] {
        let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        assert!(!app.hits.borrow().dump_fields.is_empty());
    }
    terminal.draw(|f| app.draw(f)).unwrap();
    let run = app
        .hits
        .borrow()
        .buttons
        .iter()
        .find(|(_, key)| *key == KeyCode::Enter)
        .unwrap()
        .0;
    click(&mut app, run.x, run.y);
    let (_, options) = app.dump_options.as_ref().unwrap();
    assert_eq!(options.pid, 12);
    assert_eq!(options.start, Some(0x4000));
    assert_eq!(options.end, Some(0x5000));
    assert_eq!(options.directory, PathBuf::from("exports/targeted"));
    assert!(app.job.is_none()); // No image: ask for it only after validating the parameters.
    assert!(matches!(
        app.dialog,
        Some(Dialog::Files {
            kind: InputKind::Image,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.start();
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.dialog.is_none());
    assert!(app.job.is_none());
}

#[test]
fn unified_dump_modes_cancel_and_mouse_selection() {
    let mut app = app();
    let previous = app.plugin;
    app.row = 1;
    app.key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));
    assert_eq!(app.plugin, previous);
    assert!(matches!(
        &app.dialog,
        Some(Dialog::Dump {
            mode: Plugin::Procdump,
            ..
        })
    ));
    app.dialog_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE));
    assert!(matches!(
        &app.dialog,
        Some(Dialog::Dump {
            mode: Plugin::Memdump,
            ..
        })
    ));
    if let Some(Dialog::Dump { fields, .. }) = &mut app.dialog {
        fields[1] = "0x4000".into();
        fields[2] = "0x5000".into();
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let elf = app
        .hits
        .borrow()
        .dump_modes
        .iter()
        .find(|(_, mode)| *mode == Plugin::Elfdump)
        .unwrap()
        .0;
    click(&mut app, elf.x, elf.y);
    assert!(
        matches!(&app.dialog, Some(Dialog::Dump { mode: Plugin::Elfdump, fields, .. })
            if fields[1].is_empty() && fields[2].is_empty())
    );
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.plugin, previous);
    assert_eq!(app.results["pslist"].rows.len(), 2);
    assert!(app.job.is_none());
    assert_eq!(menu_items().iter().filter(|s| **s == "dump").count(), 1);
    assert_eq!(plugin_matches("dump"), vec![Plugin::Procdump]);
    app.dialog = Some(Dialog::Plugins {
        query: "dump".into(),
        selected: 0,
    });
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(matches!(&app.dialog, Some(Dialog::Dump { .. })));
    app.dialog_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.plugin, previous);
}

#[test]
fn execution_parameters_and_results_survive_browsing_and_keep_separate_views() {
    let mut app = app();
    let mut result = app.results.remove("pslist").unwrap();
    app.analysis_options.pid = Some(10);
    let key = app.request_key();
    let parameters = app.parameter_summary();
    app.active_request = Some(Execution {
        plugin: Plugin::Pslist,
        key: key.clone(),
        parameters,
        snapshot: ExecutionSnapshot {
            force: false,
            plugin: Plugin::Pslist,
            options: app.analysis_options.clone(),
            dump: None,
        },
    });
    app.job = Some(Job::default());
    app.select_plugin(Plugin::Psaux);
    app.query = "browse".into();
    app.row = 3;
    result.rows.truncate(1);
    let (tx, rx) = mpsc::channel();
    app.receiver = Some(rx);
    tx.send(WorkerEvent::Done(Outcome::Ready(result))).unwrap();
    app.drain();
    assert_eq!(app.plugin, Plugin::Psaux);
    assert_eq!(app.query, "browse");
    assert_eq!(app.row, 3);
    assert_eq!(app.results[&key].rows.len(), 1);
    app.select_plugin(Plugin::Pslist);
    assert_eq!(app.analysis_options.pid, Some(10));
    app.query = "zsh".into();
    app.horizontal = 12;
    app.save_view();
    app.analysis_options.pid = Some(2);
    app.restore_view();
    assert!(app.query.is_empty());
    let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let text = screen(&terminal, 140);
    for label in [
        "适用参数：",
        "旧结果参数：",
        "草稿：",
        "[编辑参数 P]",
        "[运行 Ctrl+R]",
    ] {
        assert!(!text.contains(label), "removed plugin controls: {label}");
    }
    // With no query the search field is hidden and the table starts at the
    // workbench top; the header row is not reserved.
    assert_eq!(app.hits.borrow().search.height, 0);
    assert_eq!(app.hits.borrow().result.y, app.hits.borrow().workbench.y);
    app.analysis_options.pid = Some(10);
    app.restore_view();
    assert_eq!(app.query, "zsh");
    assert_eq!(app.horizontal, 12);
}

#[test]
fn parameter_form_only_shows_supported_fields_and_saves_without_running() {
    let mut app = app();
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![2, 6]);
    app.paste("42");
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(app.analysis_options.pid, Some(42));
    assert!(app.job.is_none());
    app.select_plugin(Plugin::Lsmod);
    assert_eq!(app.parameter_fields(false), vec![6]);
    app.select_os(crate::analysis::Os::Windows);
    app.select_plugin(Plugin::WinPrintkey);
    assert_eq!(app.parameter_fields(false), vec![0, 1, 6]);
    assert_eq!(app.parameter_fields(true), vec![0, 1, 3, 4, 5, 6]);
    app.windows_parameters();
    app.paste("0xffff800000001000");
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.analysis_options.hive.is_some());
    assert!(app.job.is_none());
}

#[test]
fn plugin_activation_runs_and_changed_parameters_queue_the_last_request() {
    let (_dir, mut app) = preparation_fixture();
    app.initialize(Default::default());
    app.page = Page::Assets;
    finish_test_job(&mut app);
    // No previous execution snapshot exists for the identification result; psaux is uncached.
    app.activate_plugin(Plugin::Psaux);
    assert!(app.job.is_some());
    assert_eq!(app.active_request.as_ref().unwrap().plugin, Plugin::Psaux);
    let first = app.job.as_ref().unwrap().clone();
    app.analysis_options.pid = Some(42);
    app.activate_plugin(Plugin::Psaux);
    assert!(first.check().is_err());
    let next = app.pending_execution.as_ref().unwrap();
    assert_eq!(next.plugin, Plugin::Psaux);
    assert_eq!(next.options.pid, Some(42));
    if let Some(worker) = app.worker.take() {
        worker.join().unwrap();
    }
    app.drain();
    assert_eq!(
        app.active_request.as_ref().unwrap().snapshot.options.pid,
        Some(42)
    );
    finish_test_job(&mut app);
}

#[test]
fn official_pslist_options_save_reject_invalid_boolean_and_separate_request_keys() {
    let mut app = app();
    app.select_plugin(Plugin::LinuxPslist);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![2, 8, 9, 6]);
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[8] = "true".into();
        fields[9] = "invalid".into();
    } else {
        panic!("parameter dialog missing");
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    assert!(!app.analysis_options.include_threads);
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[9] = "true".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert!(app.analysis_options.include_threads);
    assert!(app.analysis_options.decorate_comm);
    assert_ne!(before, app.request_key());
    assert!(app.job.is_none());
}

#[test]
fn module_plain_taints_parameter_validates_and_separates_results() {
    let mut app = app();
    app.select_plugin(Plugin::Modxview);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![10, 6]);
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[10] = "invalid".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    assert!(!app.analysis_options.plain_taints);
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[10] = "true".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert!(app.analysis_options.plain_taints);
    assert_ne!(before, app.request_key());
    assert!(app.job.is_none());
}

#[test]
fn lsmod_dump_dialog_accepts_empty_pid_and_focuses_directory() {
    let mut app = app();
    app.open_dump(Plugin::Lsmod, false);
    assert!(
        matches!(&app.dialog, Some(Dialog::Dump { mode: Plugin::Lsmod, field: 3, fields, .. }) if fields[0].is_empty())
    );
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(!matches!(&app.dialog, Some(Dialog::Dump { .. })));
    let (plugin, options) = app
        .dump_options
        .as_ref()
        .expect("Lsmod options must be saved");
    assert_eq!(*plugin, Plugin::Lsmod);
    assert_eq!(options.pid, 0);
    assert!(options.start.is_none() && options.end.is_none());
}

#[test]
fn linux_module_extract_dump_mode_requires_base_and_no_pid() {
    let mut app = app();
    app.open_dump(Plugin::Procdump, false);
    app.dialog_key(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::ALT));
    assert!(
        matches!(&app.dialog, Some(Dialog::Dump { mode: Plugin::ModuleExtract, field: 1, fields, .. }) if fields[0].is_empty() && fields[1].is_empty())
    );
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(matches!(&app.dialog, Some(Dialog::Dump { error, .. }) if error.contains("--base")));
    if let Some(Dialog::Dump { fields, .. }) = &mut app.dialog {
        fields[1] = "0xffffffffa00230f0".into();
    }
    // Saving an invalid PID must not start a worker.
    if let Some(Dialog::Dump { fields, .. }) = &mut app.dialog {
        fields[0] = "1".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(
        matches!(&app.dialog, Some(Dialog::Dump { error, .. }) if error.contains("不接受 PID"))
    );
    assert!(app.job.is_none());
}

#[test]
fn kallsyms_sources_validate_and_keep_results_separate() {
    let mut app = app();
    app.select_plugin(Plugin::Kallsyms);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![11, 12, 13, 14, 6]);
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[11] = "true".into();
        fields[12] = "invalid".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    assert!(!app.analysis_options.kallsyms.any());
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[12] = "true".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert_eq!(
        app.analysis_options.kallsyms.selected(),
        [true, true, false, false]
    );
    assert_ne!(before, app.request_key());
    assert!(app.job.is_none());
}

#[test]
fn regex_parameters_preserve_spaces_pid_lists_context_and_cache_identity() {
    let mut app = app();
    app.select_plugin(Plugin::VmaRegExScan);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![7, 2, 15, 6]);
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[7] = " AB ".into();
        fields[2] = "1, 2".into();
        fields[15] = "not-an-integer".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    assert!(app.analysis_options.pattern.is_none());
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[15] = "-1".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert_eq!(app.analysis_options.pattern.as_deref(), Some(" AB "));
    assert_eq!(app.analysis_options.pids, [1, 2]);
    assert_eq!(app.analysis_options.maxsize, Some(-1));
    assert_ne!(before, app.request_key());
    app.windows_parameters();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &app.dialog {
        assert_eq!(fields[2], "1,2");
        assert_eq!(fields[15], "-1");
    } else {
        panic!("parameter dialog missing");
    }
}

#[test]
fn callstack_parameters_save_pid_list_unresolved_and_keep_cache_keys_separate() {
    let mut app = app();
    app.select_plugin(Plugin::PsCallStack);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![2, 16, 6]);
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[2] = "1, 2".into();
        fields[16] = "invalid".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    assert!(!app.analysis_options.unresolved);
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[16] = "true".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert!(app.analysis_options.unresolved);
    assert_eq!(app.analysis_options.pids, [1, 2]);
    assert_ne!(before, app.request_key());
    app.windows_parameters();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &app.dialog {
        assert_eq!(fields[2], "1,2");
        assert_eq!(fields[16], "true");
    } else {
        panic!("no parameter dialog");
    }
}

#[test]
fn framebuffer_dump_is_optional_has_no_pid_and_validates_selector_without_running() {
    let mut app = app();
    app.select_plugin(Plugin::Fbdev);
    assert!(!app.plugin.is_dump());
    assert!(app.navigation_plugins().contains(&Plugin::Fbdev));
    assert_eq!(plugin_label(Plugin::Fbdev), "fbdev");
    let list_key = app.request_key();
    app.open_dump(Plugin::Procdump, false);
    app.dialog_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::ALT));
    assert!(
        matches!(&app.dialog, Some(Dialog::Dump {mode:Plugin::Fbdev,field:3,fields,..}) if fields[0].is_empty() && fields[1].is_empty() && fields[2].is_empty())
    );
    if let Some(Dialog::Dump { fields, .. }) = &mut app.dialog {
        fields[0] = "1".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(matches!(&app.dialog, Some(Dialog::Dump {error,..}) if error.contains("不接受 PID")));
    if let Some(Dialog::Dump { fields, .. }) = &mut app.dialog {
        fields[0].clear();
        fields[2] = "0x2000".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(matches!(&app.dialog, Some(Dialog::Dump {error,..}) if error.contains("不接受 End")));
    assert!(app.job.is_none());
    app.dump_options = Some((
        Plugin::Fbdev,
        DumpOptions {
            pid: 0,
            directory: "exports".into(),
            start: Some(0x1000),
            end: None,
        },
    ));
    assert_ne!(list_key, app.request_key());
    app.dialog = None;
    app.request_analysis(false);
    assert!(matches!(
        &app.dialog,
        Some(Dialog::Dump {
            mode: Plugin::Fbdev,
            ..
        })
    ));
    assert!(app.job.is_none());
}

#[test]
fn windows_vad_regex_parameters_preserve_spaces_pid_union_and_context_identity() {
    let mut app = app();
    app.windows = true;
    app.select_plugin(Plugin::WinVadRegExScan);
    app.windows_parameters();
    assert!(app.parameter_fields(false).contains(&15));
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[2] = "4,8".into();
        fields[7] = " AB ".into();
        fields[15] = "4".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert_eq!(app.analysis_options.pids, [4, 8]);
    assert_eq!(app.analysis_options.pattern.as_deref(), Some(" AB "));
    assert_eq!(app.analysis_options.maxsize, Some(4));
    assert_ne!(before, app.request_key());
    app.windows_parameters();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[7] = "(".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    assert_eq!(app.analysis_options.pattern.as_deref(), Some(" AB "));
}

#[test]
fn vadwalk_pid_list_is_available_without_regex_controls() {
    let mut app = app();
    app.windows = true;
    app.select_plugin(Plugin::WinVadWalk);
    app.windows_parameters();
    assert_eq!(plugin_label(Plugin::WinVadWalk), "vadwalk");
    assert_eq!(app.parameter_fields(false), vec![2, 6]);
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[2] = "468,7688".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert_eq!(app.analysis_options.pids, [468, 7688]);
    assert!(app.analysis_options.pattern.is_none());
    assert!(app.analysis_options.maxsize.is_none());
    assert_ne!(before, app.request_key());
}

#[test]
fn pe_symbol_parameters_validate_and_separate_query_views() {
    let mut app = app();
    app.select_os(crate::analysis::Os::Windows);
    app.select_plugin(Plugin::WinPESymbols);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![17, 18, 19, 20, 6]);
    let before = app.request_key();
    app.paste("processes");
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        assert_eq!(fields[17], "processes");
        fields[18] = "ntdll.dll".into();
        fields[19] = "NtClose;EtwEventWrite;NtClose".into();
        fields[20] = "0xffff800000001000,4096".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert_eq!(
        app.analysis_options.pe.names,
        ["NtClose", "EtwEventWrite", "NtClose"]
    );
    assert_eq!(
        app.analysis_options.pe.addresses,
        [0xffff800000001000, 4096]
    );
    assert_ne!(before, app.request_key());
    assert!(app.job.is_none());
}

#[test]
fn strings_parameters_keep_path_and_pid_union_in_the_plugin_draft() {
    let mut app = app();
    app.select_os(crate::analysis::Os::Windows);
    app.select_plugin(Plugin::WinStrings);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![21, 2, 6]);
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[21] = "strings.txt".into();
        fields[2] = "4,8".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert_eq!(app.analysis_options.pids, [4, 8]);
    let path = app.analysis_options.strings_file.clone().unwrap();
    assert!(path.is_absolute());
    assert!(path.ends_with("strings.txt"));
    app.select_plugin(Plugin::WinPslist);
    assert!(app.analysis_options.strings_file.is_none());
    app.select_plugin(Plugin::WinStrings);
    assert_eq!(app.analysis_options.strings_file, Some(path));
}

#[test]
fn syscall_detectors_scan_all_active_processes_and_clear_hidden_pid_drafts() {
    let mut app = app();
    app.windows = true;
    app.analysis_options.pid = Some(8);
    for plugin in [
        Plugin::WinDirectSystemCalls,
        Plugin::WinIndirectSystemCalls,
        Plugin::WinSkeletonKeyCheck,
    ] {
        app.select_plugin(plugin);
        assert_eq!(app.parameter_fields(false), vec![6]);
        app.windows_parameters();
        if let Some(Dialog::WindowsParameters { fields, field, .. }) = &mut app.dialog {
            assert_eq!(*field, 6);
            fields[2] = "stale invalid PID".into();
        }
        app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
        assert!(app.dialog.is_none());
        assert_eq!(app.analysis_options.pid, None);
    }
}

#[test]
fn truecrypt_minimum_has_a_plugin_draft_and_distinct_request_identity() {
    let mut app = app();
    app.select_os(crate::analysis::Os::Windows);
    app.select_plugin(Plugin::WinTruecryptPassphrase);
    app.windows_parameters();
    assert_eq!(app.parameter_fields(false), vec![22, 6]);
    if let Some(Dialog::WindowsParameters { fields, field, .. }) = &mut app.dialog {
        assert_eq!(*field, 22);
        assert_eq!(fields[22], "5");
        fields[22] = "not an integer".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_some());
    let before = app.request_key();
    if let Some(Dialog::WindowsParameters { fields, .. }) = &mut app.dialog {
        fields[22] = "4".into();
    }
    app.dialog_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL));
    assert!(app.dialog.is_none());
    assert_eq!(app.analysis_options.min_length, Some(4));
    assert_ne!(before, app.request_key());
    app.select_plugin(Plugin::WinPslist);
    assert!(app.analysis_options.min_length.is_none());
    app.select_plugin(Plugin::WinTruecryptPassphrase);
    assert_eq!(app.analysis_options.min_length, Some(4));
}
