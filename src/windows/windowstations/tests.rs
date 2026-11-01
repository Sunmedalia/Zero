use super::super::tests::{K, fixture, image, put};
use super::*;

#[test]
fn gui_tables_follow_the_reference_version_order() {
    assert_eq!(gui_table(10, 0, 22000), Some("gui-win10-19577-x64"));
    assert_eq!(gui_table(10, 0, 15063), Some("gui-win10-15063-x64"));
    assert_eq!(gui_table(10, 0, 10240), Some("gui-win8-x64"));
    assert_eq!(gui_table(6, 3, 9600), Some("gui-win8-x64"));
    assert_eq!(gui_table(6, 1, 7601), Some("gui-win7sp1-x64"));
    assert_eq!(gui_table(6, 1, 7600), Some("gui-win7sp0-x64"));
    assert_eq!(gui_table(5, 2, 3790), None);
    let layout = gui_layout("gui-win10-15063-x64");
    assert_eq!(layout.desktop_threads, 168);
    assert_eq!(layout.thread_link, 656);
    assert_eq!(layout.thread_process, 376);
    assert_eq!(gui_layout("gui-win10-17134-x64").thread_link, 728);
    assert_eq!(gui_layout("gui-win10-17763-x64").thread_link, 736);
}

#[test]
fn station_unicode_and_info_follow_fixed_reference_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/gui-stations.json"
    ))
    .unwrap();
    for c in vectors["strings"].as_array().unwrap() {
        let data: Vec<_> = c["hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(
            reference_unicode_name(&data),
            c["expected"].as_str().unwrap(),
            "{}",
            c["id"]
        );
    }
    for c in vectors["info"].as_array().unwrap() {
        let (mut bytes, mut isf) = fixture();
        isf.data["user_types"]["_QUAD"] = serde_json::json!({"size":8,"fields":{}});
        isf.data["user_types"]["_OBJECT_HEADER"] = serde_json::json!({"size":56,"fields":{"Body":{"offset":48,"type":{"kind":"struct","name":"_QUAD"}},"InfoMask":{"offset":26,"type":{"kind":"base","name":"u64"}}}});
        isf.data["user_types"]["_OBJECT_HEADER_NAME_INFO"] = serde_json::json!({"size":32,"fields":{"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
        isf.data["symbols"]["ObpInfoMaskToOffset"] = serde_json::json!({"address":0x500});
        bytes[0x8501] = 32;
        bytes[0x10fea] = 1; // Name bit is absent but the reference still indexes the table.
        bytes[0x11000..0x11004]
            .copy_from_slice(&(c["session"].as_u64().unwrap_or(256) as u32).to_le_bytes());
        let name: Vec<_> = c["name"]
            .as_str()
            .unwrap()
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes[0x10fb0..0x10fb2].copy_from_slice(&(name.len() as u16).to_le_bytes());
        bytes[0x10fb2..0x10fb4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        put(&mut bytes, 0x10fb8, K + 0xa000);
        bytes[0x12000..0x12000 + name.len()].copy_from_slice(&name);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let found = w
            .station_info(&w.vm, K + 0x9000)
            .map(|(name, sid)| serde_json::json!([name, sid]))
            .unwrap_or(serde_json::json!([null, null]));
        assert_eq!(found, c["expected"]);
    }
}

#[test]
fn station_names_require_readable_object_name_metadata() {
    let (bytes, isf) = fixture();
    let snapshot = image(&bytes);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert_eq!(windows.station_info(&windows.vm, K + 0x9000), None);
    assert!(windows.station_chain(&windows.vm, K + 0x9000).len() <= 15);
}

#[test]
fn partial_window_process_names_match_fixed_decoding_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/gui-process-names.json"
    ))
    .unwrap();
    for c in vectors["cases"].as_array().unwrap() {
        let (mut bytes, isf) = fixture();
        bytes[0xa030..0xa040].fill(0);
        let raw: Vec<_> = c["hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        assert!(raw.len() <= 16);
        bytes[0xa030..0xa030 + raw.len()].copy_from_slice(&raw);
        put(&mut bytes, 0xa020, 2743092250712); // Synthetic out-of-range PID remains an observed field.
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let (name, pid) = w.partial_process_identity(&w.vm, K + 0x2000).unwrap();
        assert_eq!(name, c["expected"].as_str().unwrap(), "{}", c["id"]);
        assert_eq!(pid, 2743092250712);
        let thread = K + 0x6000;
        drop(w);
        drop(img);
        put(&mut bytes, 0xe000 + 376, K + 0x7000);
        put(&mut bytes, 0xf000, K + 0x2000);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let found = w.window_process(&[], 0x1000, thread, 376).unwrap();
        assert_eq!(
            found,
            (name, pid),
            "first-choice and fallback must use identical decoding: {}",
            c["id"]
        );
    }
}
#[test]
fn partial_name_prefix_requires_a_real_first_byte_and_a_complete_pid() {
    let (mut bytes, isf) = fixture();
    let process = K + 0x1fc8;
    put(&mut bytes, 0x9fe8, 1234);
    bytes[0x9ff8..0xa000].copy_from_slice(b"prefixab");
    put(&mut bytes, 0x4010, 0);
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert_eq!(
        w.partial_process_identity(&w.vm, process),
        Some(("prefixab".into(), 1234))
    );
    assert!(w.partial_process_identity(&w.vm, K + 0x1fd8).is_none()); // No first name byte.
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x4008, 0); // PID absent, following name page readable.
    bytes[0xa008..0xa00d].copy_from_slice(b"name\0");
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert!(w.partial_process_identity(&w.vm, K + 0x1fd8).is_none());
}
#[test]
fn procedure_classification_matches_the_actual_reference_generator() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/gui-window-procedures.json"
    ))
    .unwrap();
    for c in vectors["cases"].as_array().unwrap() {
        let got = classify_window_procedure(c["value"].as_u64());
        assert_eq!(got.is_some(), c["retained"].as_bool().unwrap());
        assert_eq!(got.as_deref(), c["expected"].as_str());
    }
}
#[test]
fn unreadable_procedure_preserves_window_row_and_marks_partial() {
    let (mut bytes, isf) = fixture();
    let window = K + 0x10f80;
    put(&mut bytes, 0x18f90, K + 0x12000); // head.pti
    put(&mut bytes, 0x18f98, K + 0x14000); // head.rpdesk
    put(&mut bytes, 0x1a000 + 376, K + 0x13000); // pti.ppi
    put(&mut bytes, 0x1b000, K + 0x2000); // ppi.Process
    put(&mut bytes, 0x1c000 + 40, K + 0x15000); // desktop.rpwinstaParent
    bytes[0x1d000..0x1d004].copy_from_slice(&1u32.to_le_bytes());
    let layout = gui_layout("gui-win10-15063-x64");
    put(&mut bytes, 0x19020, 0); // lpfnWndProc, next page after head
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert_eq!(
        w.window_record(&[], 0x1000, window, &layout).unwrap().1,
        "0x0"
    );
    drop(w);
    drop(img);
    put(&mut bytes, 0x19020, 0x1000);
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert!(w.window_record(&[], 0x1000, window, &layout).is_none());
    drop(w);
    drop(img);
    put(&mut bytes, 0x4000 + 17 * 8, 0); // Procedure page absent; process and session remain readable.
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert_eq!(
        w.window_record(&[], 0x1000, window, &layout).unwrap().1,
        "N/A"
    );
    let mut result = w.result(Plugin::WinWindows);
    let mut seen = HashSet::new();
    let mut rows = 0;
    w.walk_window_field(WindowWalk {
        job: &Job::default(),
        result: &mut result,
        processes: &[],
        dtb: 0x1000,
        field: window,
        window,
        station_name: "WinSta0",
        session_id: 1,
        desktop_name: "Default",
        layout: &layout,
        seen: &mut seen,
        rows: &mut rows,
    })
    .unwrap();
    assert_eq!(rows, 1);
    assert_eq!(result.rows[0][5], "N/A");
    assert_eq!(result.rows[0][6], "child");
    assert!(!result.complete);
    assert!(result.diagnostics.iter().any(|d| d.contains("Procedure")));
    // Newer layouts read the procedure through subPointer. Missing targets are absent, not invalid values.
    let mut newer = gui_layout("gui-win10-17134-x64");
    newer.window_subprocedure = Some(40);
    assert_eq!(
        w.window_procedure(&w.vm, window, &newer),
        Some("N/A".into())
    );
    drop(w);
    drop(img);
    // Reference follows readable subPointer addresses without imposing a kernel-only range.
    put(&mut bytes, 0x1000, 0x2003);
    put(&mut bytes, 0x18fa8, 0x2000);
    put(&mut bytes, 0xa0a0, 0x1001);
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert_eq!(
        w.window_procedure(&w.vm, window, &newer),
        Some("0x1001".into())
    );
}
#[test]
fn an_unmapped_windows_version_is_rejected() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x8200, 3790);
    let snapshot = image(&bytes);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let error = windows.window_stations(&Job::default()).unwrap_err();
    assert!(error.to_string().contains("窗口站"), "{error:#}");
}
