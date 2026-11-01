use super::*;
use serde_json::json;
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn fixture() -> (Vec<u8>, Isf) {
    let (mut bytes, mut isf) = super::super::tests::fixture();
    let u64_field = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
    isf.data["user_types"]["module"] = json!({"size":144,"fields":{
        "list":{"offset":0,"type":{"kind":"struct","name":"list_head"}},
        "name":{"offset":16,"type":{"kind":"array","count":32,"subtype":{"kind":"base","name":"char"}}},
        "state":u64_field(48),
        "mkobj":{"offset":56,"type":{"kind":"struct","name":"module_kobject"}},
        "module_core":u64_field(96), "core_size":u64_field(104),
        "taints":u64_field(112), "core_text_size":u64_field(120), "init_size":u64_field(128)
    }});
    isf.data["user_types"]["module_kobject"] = json!({"size":40,"fields":{
        "kobj":{"offset":0,"type":{"kind":"struct","name":"kobject"}},
        "mod":u64_field(32)
    }});
    isf.data["user_types"]["kobject"] = json!({"size":24,"fields":{
        "entry":{"offset":0,"type":{"kind":"struct","name":"list_head"}}, "name":u64_field(16)
    }});
    isf.data["user_types"]["kset"] = json!({"size":16,"fields":{"list":{"offset":0,"type":{"kind":"struct","name":"list_head"}}}});
    for (name, address) in [
        ("modules", 0x31000),
        ("module_kset", 0x30000),
        ("module_addr_min", 0x30010),
        ("module_addr_max", 0x30018),
    ] {
        isf.data["symbols"][name] = json!({"address":address});
    }
    for (at, value) in [
        (0x31000, 0x34100),
        (0x31008, 0x34100),
        (0x34100, 0x31000),
        (0x34108, 0x31000),
        (0x30000, 0x30200),
        (0x30010, 0x34000),
        (0x30018, 0x37000),
        (0x30200, 0x34138),
        (0x30208, 0x36138),
        (0x34138, 0x36138),
        (0x34140, 0x30200),
        (0x36138, 0x30200),
        (0x36140, 0x34138),
    ] {
        put(&mut bytes, at, value);
    }
    for (module, name, string) in [
        (0x34100, b"listed".as_slice(), 0x38000),
        (0x35100, b"hidden".as_slice(), 0x38020),
        (0x36100, b"sysfs".as_slice(), 0x38040),
    ] {
        bytes[module + 16..module + 16 + name.len()].copy_from_slice(name);
        bytes[string..string + name.len()].copy_from_slice(name);
        put(&mut bytes, module + 72, string as u64);
        put(&mut bytes, module + 88, module as u64);
        put(&mut bytes, module + 96, 0x18000);
        put(&mut bytes, module + 104, 4096);
        put(&mut bytes, module + 120, 2048);
    }
    (bytes, isf)
}
#[test]
fn module_scanner_uses_member_width_and_known_alignment_fallback() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/module-scan-width.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let width = case["width"].as_u64().unwrap() as usize;
        let candidate = case["candidate"].as_u64().unwrap() as usize;
        let known_address = case["known"].as_u64().unwrap();
        let lower = case["lower"].as_u64().unwrap();
        let (mut bytes, mut isf) = fixture();
        isf.data["base_types"]["pointer"]["size"] = json!(width);
        isf.data["user_types"]["module_kobject"]["fields"]["mod"] =
            json!({"offset":32,"type":{"kind":"pointer"}});
        put(&mut bytes, 0x30010, lower);
        bytes[0x34000..0x37000].fill(0);
        bytes[candidate + 16..candidate + 22].copy_from_slice(b"hidden");
        put(&mut bytes, candidate + 96, 0x18000);
        put(&mut bytes, candidate + 104, 4096);
        let raw = (candidate as u64).to_le_bytes();
        bytes[candidate + 88..candidate + 88 + width].copy_from_slice(&raw[..width]);
        if width == 4 {
            bytes[candidate + 92..candidate + 96].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        }
        let image = super::super::tests::image(&bytes);
        let engine = super::super::tests::engine(&image, &isf);
        let mut result = engine.result(Plugin::HiddenModules);
        let found = engine
            .scan_module_objects(
                &[],
                &HashSet::from([known_address]),
                false,
                &mut result,
                &Job::default(),
            )
            .unwrap();
        let expected: Vec<u64> = case["found"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(found, expected, "{case}");
    }
}
#[test]
fn lsmod_array_metadata_failure_preserves_module_with_partial_diagnostic() {
    let (mut bytes, mut isf) = fixture();
    isf.data["user_types"]["module"]["size"] = json!(152);
    isf.data["user_types"]["module"]["fields"]["kp"] =
        json!({"offset":136,"type":{"kind":"pointer"}});
    isf.data["user_types"]["module"]["fields"]["num_kp"] =
        json!({"offset":144,"type":{"kind":"base","name":"u64"}});
    isf.data["symbols"]["param_array_get"] = json!({"address":0x16000});
    isf.data["user_types"]["kernel_param"] = json!({"size":24,"fields":{
        "name":{"offset":0,"type":{"kind":"pointer"}},
        "get":{"offset":8,"type":{"kind":"pointer"}},
        "arr":{"offset":16,"type":{"kind":"pointer"}}
    }});
    isf.data["user_types"]["kparam_array"] = json!({"size":8,"fields":{
        "num":{"offset":0,"type":{"kind":"pointer"}}
    }});
    for (at, value) in [
        (0x34100 + 136, 0x11000),
        (0x34100 + 144, 1),
        (0x11000, 0x12000),
        (0x11008, 0x16000),
        (0x11010, 0x40000),
    ] {
        put(&mut bytes, at, value);
    }
    bytes[0x12000..0x12004].copy_from_slice(b"arg\0");
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .run(Plugin::Lsmod, &Job::default())
        .unwrap();
    assert!(!result.complete);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][1], "listed");
    assert_eq!(result.rows[0][4], "N/A");
    assert!(
        result
            .diagnostics
            .iter()
            .any(|message| message.contains("parameters"))
    );
    assert!(
        result
            .diagnostics
            .iter()
            .all(|message| !message.contains("ISF 字段越界"))
    );
}

#[test]
fn module_names_match_actual_pinned_translation_layer_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/module-names.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let (mut bytes, mut isf) = fixture();
        put(&mut bytes, 0x3000, 0x4003);
        put(
            &mut bytes,
            0x4000,
            if case["first_present"] == true {
                0x8003
            } else {
                0
            },
        );
        put(
            &mut bytes,
            0x4008,
            if case["second_present"] == true {
                0x9003
            } else {
                0
            },
        );
        let hex = case["payload_hex"].as_str().unwrap();
        let payload: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes[0x8ff0..0x9000].copy_from_slice(&payload);
        bytes[0x9000..0xa000].fill(b'Z');
        isf.data["user_types"]["module"]["fields"]["name"]["offset"] = json!(0xff0);
        isf.data["user_types"]["module"]["fields"]["name"]["type"]["count"] = json!(64);
        isf.data["user_types"]["module"]["size"] = json!(0x1030);
        let image = super::super::tests::image(&bytes);
        let value = super::super::tests::engine(&image, &isf).module_name(0, &Job::default());
        if case["error"].is_null() {
            assert_eq!(
                value.unwrap(),
                case["expected"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        } else {
            assert!(value.is_err(), "{}", case["id"]);
        }
    }
}

#[test]
fn module_name_preserves_only_contiguous_mapped_prefix() {
    let (mut bytes, mut isf) = fixture();
    put(&mut bytes, 0x3000, 0x4003);
    for page in 0..64 {
        put(&mut bytes, 0x4000 + page * 8, (page * 4096) as u64 | 3);
    }
    put(&mut bytes, 0x4000 + 63 * 8, 0);
    isf.data["user_types"]["module"]["fields"]["name"] = json!({"offset":0xaef0,"type":{"kind":"array","count":64,"subtype":{"kind":"base","name":"char"}}});
    isf.data["user_types"]["module"]["size"] = json!(0xaf30);
    bytes[0x3eff0..0x3f000].copy_from_slice(b"abcdefghijklmnop");
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    assert_eq!(
        linux.module_name(0x34100, &Job::default()).unwrap(),
        "abcdefghijklmnop"
    );
}

#[test]
fn module_names_use_explicit_linux32_and_pae_translation_modes() {
    for pae in [false, true] {
        let (mut bytes, mut isf) = fixture();
        bytes[0x1000..0x4000].fill(0);
        isf.data["base_types"]["pointer"]["size"] = json!(4);
        if pae {
            put(&mut bytes, 0x1000, 0x2003);
            put(&mut bytes, 0x2000, 0x3003);
            put(&mut bytes, 0x3000 + 0x34 * 8, 0x34003);
        } else {
            bytes[0x1000..0x1004].copy_from_slice(&0x2003u32.to_le_bytes());
            bytes[0x2000 + 0x34 * 4..0x2004 + 0x34 * 4].copy_from_slice(&0x34003u32.to_le_bytes());
        }
        let image = super::super::tests::image(&bytes);
        let linux = Linux {
            vm: VirtualMemory::new_linux32(&image, 0x1000, pae),
            isf: &isf,
        };
        assert_eq!(
            linux.module_name(0x34100, &Job::default()).unwrap(),
            "listed",
            "pae={pae}"
        );
    }
}
#[test]
fn lsmod_names_preserve_controls_and_stop_at_replacement() {
    for (payload, expected) in [
        (b"a\x01b\0".as_slice(), "a\u{1}b"),
        (b"a\xffb\0".as_slice(), "a"),
        ("a\u{fffd}b\0".as_bytes(), "a"),
    ] {
        let (mut bytes, isf) = fixture();
        bytes[0x34110..0x34130].fill(0);
        bytes[0x34110..0x34110 + payload.len()].copy_from_slice(payload);
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .run(Plugin::Lsmod, &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows[0][1], expected);
    }
}

#[test]
fn lsmod_unreadable_name_never_becomes_a_prefix_row() {
    for name_offset in [0xbef0, 0xbf00] {
        let (mut bytes, mut isf) = fixture();
        isf.data["user_types"]["module"]["fields"]["name"] = json!({"offset":name_offset,"type":{"kind":"array","count":64,"subtype":{"kind":"base","name":"char"}}});
        isf.data["user_types"]["module"]["size"] = json!(name_offset + 64);
        if name_offset == 0xbef0 {
            bytes[0x3fff0..0x40000].copy_from_slice(b"abcdefghijklmnop");
        }
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .run(Plugin::Lsmod, &Job::default())
            .unwrap();
        assert!(result.rows.is_empty());
        assert!(!result.complete);
        assert!(!result.diagnostics.is_empty());
        assert!(
            result
                .diagnostics
                .iter()
                .all(|message| !message.contains("ISF 字段越界"))
        );
    }
}

#[test]
fn lsmod_forward_walk_ignores_prev_and_preserves_cycle_prefix() {
    for (successor, complete) in [
        (0x31000, true),
        (0x34100, false),
        (0, false),
        (0x50000, false),
    ] {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x34108, 0x50000);
        put(&mut bytes, 0x31008, 0);
        put(&mut bytes, 0x34100, successor);
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .run(Plugin::Lsmod, &Job::default())
            .unwrap();
        assert_eq!(result.rows.len(), 1, "{successor:#x}");
        assert_eq!(result.rows[0][1], "listed");
        assert_eq!(
            result.complete, complete,
            "{successor:#x}: {:?}",
            result.diagnostics
        );
    }
}

#[test]
fn lsmod_reads_four_byte_links_without_adjacent_bytes() {
    let (mut bytes, mut isf) = fixture();
    isf.data["base_types"]["pointer"]["size"] = json!(4);
    isf.data["user_types"]["list_head"] = json!({"size":8,"fields":{
        "next":{"offset":0,"type":{"kind":"pointer"}},
        "prev":{"offset":4,"type":{"kind":"pointer"}}
    }});
    for (at, next) in [(0x31000usize, 0x34100u32), (0x34100, 0x31000)] {
        bytes[at..at + 4].copy_from_slice(&next.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    }
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .run(Plugin::Lsmod, &Job::default())
        .unwrap();
    assert_eq!(result.rows.len(), 1, "{:?}", result.diagnostics);
    assert_eq!(result.rows[0][1], "listed");
    assert!(result.complete, "{:?}", result.diagnostics);
}

#[test]
fn lsmod_export_failure_preserves_rows_and_cancellation() {
    let (bytes, isf) = fixture();
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let directory = tempfile::tempdir().unwrap();
    let options = crate::dump::DumpOptions {
        pid: 0,
        start: None,
        end: None,
        directory: directory.path().into(),
    };
    options.validate(Plugin::Lsmod).unwrap();
    let result = linux.lsmod_with_dump(&options, &Job::default()).unwrap();
    assert!(!result.complete);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][1], "listed");
    assert_eq!(result.rows[0][5], "-");
    assert_eq!(
        result.kernel_identity["module_file_output_types"]["0x34100"],
        "NotAvailableValue"
    );
    assert!(!result.diagnostics.is_empty());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    let job = Job::default();
    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(linux.lsmod_with_dump(&options, &job).is_err());
}

#[test]
fn independent_module_views_and_taints() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x35100 + 112, 1 | (1 << 12));
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let result = linux.modxview(false, &Job::default()).unwrap();
    assert!(result.complete, "{:?}", result.diagnostics);
    assert_eq!(result.rows.len(), 3);
    assert_eq!(&result.rows[0][2..5], ["true", "true", "true"]);
    assert_eq!(&result.rows[1][2..5], ["false", "false", "true"]);
    assert_eq!(&result.rows[2][2..5], ["false", "true", "true"]);
    assert_eq!(result.rows[1][5], "PROPRIETARY_MODULE,OOT_MODULE");
    assert_eq!(
        linux.modxview(true, &Job::default()).unwrap().rows[1][5],
        "PGO"
    );
}
#[test]
fn modxview_preserves_readable_control_bytes_in_module_names() {
    let (mut bytes, isf) = fixture();
    bytes[0x34110..0x34118].copy_from_slice(b"mod\x01ule\0");
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let result = linux.modxview(false, &Job::default()).unwrap();
    // The unchanged kobject name deliberately disagrees with the modified name.
    assert!(!result.complete);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.contains("模块名称不一致"))
    );
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.contains("module 0x34100 name"))
    );
    let row = result.rows.iter().find(|r| r[1] == hex(0x34100)).unwrap();
    assert_eq!(row[0], "mod\u{1}ule");
}
#[test]
fn unreadable_view_is_unknown_and_other_views_survive() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x31000, u64::MAX);
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let result = linux.modxview(false, &Job::default()).unwrap();
    assert!(!result.complete);
    assert_eq!(result.rows.len(), 3);
    assert!(result.rows.iter().all(|r| r[2].is_empty()));
    assert_eq!(&result.rows[0][3..5], ["true", "true"]);
    let job = Job::default();
    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(linux.modxview(false, &job).is_err());
}
#[test]
fn scan_rejects_freed_allocations_and_does_not_infer_presence() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x34100 + 120, 0); // self-reference alone is insufficient
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .modxview(false, &Job::default())
        .unwrap();
    assert!(result.complete);
    assert_eq!(&result.rows[0][2..5], ["true", "true", "false"]);
}
#[test]
fn missing_scan_layout_keeps_known_objects_with_unknown_scan_status() {
    let (bytes, mut isf) = fixture();
    isf.data["user_types"]["module"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("core_text_size");
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .modxview(false, &Job::default())
        .unwrap();
    assert!(!result.complete);
    assert_eq!(result.rows.len(), 2);
    assert!(result.rows.iter().all(|r| r[4].is_empty()));
}
#[test]
fn modern_split_module_memory_sizes_drive_independent_validation() {
    let (mut bytes, mut isf) = fixture();
    let fields = isf.data["user_types"]["module"]["fields"]
        .as_object_mut()
        .unwrap();
    for field in ["module_core", "core_size", "core_text_size", "init_size"] {
        fields.remove(field);
    }
    fields.insert("mem".into(),json!({"offset":160,"type":{"kind":"array","count":7,"subtype":{"kind":"struct","name":"module_memory"}}}));
    isf.data["user_types"]["module"]["size"] = json!(272);
    isf.data["user_types"]["module_memory"] = json!({"size":16,"fields":{
        "base":{"offset":0,"type":{"kind":"pointer"}},
        "size":{"offset":8,"type":{"kind":"base","name":"u64"}}
    }});
    isf.data["enums"]["mod_mem_type"]["constants"] = json!({"MOD_TEXT":0,"MOD_DATA":1,"MOD_RODATA":2,"MOD_RO_AFTER_INIT":3,"MOD_INIT_TEXT":4,"MOD_INIT_DATA":5,"MOD_INIT_RODATA":6});
    for module in [0x34100, 0x35100, 0x36100] {
        put(&mut bytes, module + 160, 0x18000);
        put(&mut bytes, module + 168, 2048);
        put(&mut bytes, module + 184, 2048);
    }
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    assert_eq!(linux.module_sizes(0x34100).unwrap(), (2048, 4096, 0));
    let result = linux.modxview(false, &Job::default()).unwrap();
    assert!(result.complete, "{:?}", result.diagnostics);
    assert_eq!(result.rows.len(), 3);
    assert!(result.rows.iter().all(|row| row[4] == "true"));
}
#[test]
fn lsmod_layout_priority_matches_pinned_methods() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/module-layouts.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let (mut bytes, mut isf) = fixture();
        let id = case["id"].as_str().unwrap();
        if matches!(id, "core-layout-and-legacy" | "all-layouts") {
            isf.data["user_types"]["module"]["fields"]["core_layout"] =
                json!({"offset":144,"type":{"kind":"struct","name":"module_layout"}});
            isf.data["user_types"]["module"]["size"] = json!(160);
            isf.data["user_types"]["module_layout"] = json!({"size":16,"fields":{
                "base":{"offset":0,"type":{"kind":"pointer"}},
                "size":{"offset":8,"type":{"kind":"base","name":"u64"}}
            }});
            put(&mut bytes, 0x34100 + 144, 0x1a000);
            put(&mut bytes, 0x34100 + 152, 3072);
        }
        if matches!(id, "mem-and-legacy" | "all-layouts") {
            isf.data["user_types"]["module"]["fields"]["mem"] = json!({"offset":160,"type":{"kind":"array","count":4,"subtype":{"kind":"struct","name":"module_memory"}}});
            isf.data["user_types"]["module"]["size"] = json!(224);
            isf.data["user_types"]["module_memory"] = json!({"size":16,"fields":{
                "base":{"offset":0,"type":{"kind":"pointer"}},
                "size":{"offset":8,"type":{"kind":"base","name":"u64"}}
            }});
            isf.data["enums"]["mod_mem_type"]["constants"] =
                json!({"MOD_TEXT":0,"MOD_DATA":1,"MOD_RODATA":2,"MOD_RO_AFTER_INIT":3});
            put(&mut bytes, 0x34100 + 160, 0x19000);
            put(&mut bytes, 0x34100 + 168, 1024);
            put(&mut bytes, 0x34100 + 184, 1024);
        }
        isf.data["user_types"]["module"]["fields"]["init_layout"] =
            json!({"offset":280,"type":{"kind":"struct","name":"module_layout"}});
        isf.data["user_types"]["module"]["size"] = json!(296);
        isf.data["user_types"]["module_layout"] = json!({"size":16,"fields":{
            "base":{"offset":0,"type":{"kind":"pointer"}},
            "size":{"offset":8,"type":{"kind":"base","name":"u64"}}
        }});
        put(&mut bytes, 0x34100 + 128, 512);
        put(&mut bytes, 0x34100 + 288, 768);
        if matches!(id, "mem-and-legacy" | "all-layouts") {
            isf.data["user_types"]["module"]["fields"]["mem"]["type"]["count"] = json!(7);
            isf.data["enums"]["mod_mem_type"]["constants"]["MOD_INIT_TEXT"] = json!(4);
            isf.data["enums"]["mod_mem_type"]["constants"]["MOD_INIT_DATA"] = json!(5);
            isf.data["enums"]["mod_mem_type"]["constants"]["MOD_INIT_RODATA"] = json!(6);
            for (index, value) in [(4, 128), (5, 64), (6, 32)] {
                put(&mut bytes, 0x34100 + 160 + index * 16 + 8, value);
            }
        }
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .run(Plugin::Lsmod, &Job::default())
            .unwrap();
        assert!(result.complete, "{id}: {:?}", result.diagnostics);
        assert_eq!(
            result.kernel_identity["module_code_sizes"]["0x34100"], case["code_size"],
            "{id}"
        );
        assert_eq!(
            result.rows,
            vec![vec![
                "0x0000000000034100".to_owned(),
                "listed".to_owned(),
                case["code_size"].as_u64().unwrap().to_string(),
                String::new(),
                String::new(),
                "N/A".to_owned()
            ]],
            "{id}"
        );
    }
}

#[test]
fn lsmod_prefers_split_memory_over_legacy_fields() {
    let (mut bytes, mut isf) = fixture();
    isf.data["user_types"]["module"]["fields"]["mem"] = json!({"offset":160,"type":{"kind":"array","count":4,"subtype":{"kind":"struct","name":"module_memory"}}});
    isf.data["user_types"]["module"]["size"] = json!(224);
    isf.data["user_types"]["module_memory"] = json!({"size":16,"fields":{
        "base":{"offset":0,"type":{"kind":"pointer"}},
        "size":{"offset":8,"type":{"kind":"base","name":"u64"}}
    }});
    isf.data["enums"]["mod_mem_type"]["constants"] =
        json!({"MOD_TEXT":0,"MOD_DATA":1,"MOD_RODATA":2,"MOD_RO_AFTER_INIT":3});
    put(&mut bytes, 0x34100 + 160, 0x19000);
    put(&mut bytes, 0x34100 + 168, 1024);
    put(&mut bytes, 0x34100 + 184, 1024);
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .run(Plugin::Lsmod, &Job::default())
        .unwrap();
    assert!(!result.complete);
    assert_eq!(
        result.kernel_identity["module_ranges"]["0x34100"]["base"],
        "0x0000000000019000"
    );
    assert_eq!(result.rows[0][1], "listed");
    assert_eq!(result.rows[0][2], "N/A");
}

#[test]
fn lsmod_prefers_core_layout_over_legacy_fields() {
    let (mut bytes, mut isf) = fixture();
    isf.data["user_types"]["module"]["fields"]["core_layout"] =
        json!({"offset":160,"type":{"kind":"struct","name":"module_layout"}});
    isf.data["user_types"]["module"]["size"] = json!(176);
    isf.data["user_types"]["module_layout"] = json!({"size":16,"fields":{
        "base":{"offset":0,"type":{"kind":"pointer"}},
        "size":{"offset":8,"type":{"kind":"base","name":"u64"}}
    }});
    put(&mut bytes, 0x34100 + 160, 0x1a000);
    put(&mut bytes, 0x34100 + 168, 3072);
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .run(Plugin::Lsmod, &Job::default())
        .unwrap();
    assert!(result.complete, "{:?}", result.diagnostics);
    assert_eq!(
        result.rows,
        vec![vec!["0x0000000000034100", "listed", "3072", "", "", "N/A"]]
    );
}

#[test]
fn object_validation_has_an_independent_read_budget() {
    let (bytes, isf) = fixture();
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let mut budget = 0;
    assert!(
        linux
            .valid_module_allocation(0x34100, &Job::default(), &mut budget)
            .unwrap_err()
            .to_string()
            .contains("上限")
    );
    assert_eq!(budget, 0);
}
#[test]
fn unaligned_allocation_end_flushes_last_scan_page() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x30018, 0x35101);
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .modxview(false, &Job::default())
        .unwrap();
    assert!(result.complete, "{:?}", result.diagnostics);
    assert_eq!(result.rows.len(), 3);
    assert_eq!(result.rows[1][0], "hidden");
    assert_eq!(result.rows[1][4], "true");
    assert_eq!(result.rows[2][4], "false");
}
#[test]
fn missing_captured_scan_pages_are_coverage_diagnostics() {
    let (mut bytes, isf) = fixture();
    // PTE is present, but the corresponding physical page is absent from the capture.
    put(&mut bytes, 0x30018, 0x41000);
    let image = super::super::tests::image(&bytes);
    let result = super::super::tests::engine(&image, &isf)
        .modxview(false, &Job::default())
        .unwrap();
    assert_eq!(result.rows.len(), 3);
    assert!(!result.complete);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.contains("模块扫描覆盖"))
    );
}
#[test]
fn runtime_taint_definitions_override_static_flags_and_preserve_unknowns() {
    let (mut bytes, mut isf) = fixture();
    isf.data["symbols"]["taint_flags"] =
        json!({"address":0x39000,"type":{"kind":"array","count":2}});
    isf.data["user_types"]["taint_flag"] = json!({"size":3,"fields":{
        "c_true":{"offset":0,"type":{"kind":"base","name":"char"}},
        "c_false":{"offset":1,"type":{"kind":"base","name":"char"}},
        "module":{"offset":2,"type":{"kind":"base","name":"char"}}
    }});
    bytes[0x39000..0x39006].copy_from_slice(&[b'P', b'G', 1, b'Z', b' ', 1]);
    put(&mut bytes, 0x34100 + 112, 2);
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    assert_eq!(linux.module_taints(0x34100, true).unwrap(), "GZ");
    assert_eq!(
        linux.module_taints(0x34100, false).unwrap(),
        "<UNKNOWN_TAINT_CHAR_Z>"
    );
}
