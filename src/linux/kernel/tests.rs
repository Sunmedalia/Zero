use super::*;
use crate::linux::tests::{engine, fixture, image};
use serde_json::json;
fn put(bytes: &mut [u8], address: usize, value: u64) {
    bytes[address..address + 8].copy_from_slice(&value.to_le_bytes());
}
fn structure(fields: &[(&str, usize)], size: usize) -> serde_json::Value {
    let fields: serde_json::Map<_, _> = fields
        .iter()
        .map(|(name, offset)| {
            (
                name.to_string(),
                json!({"offset":offset,"type":{"kind":"base","name":"u64"}}),
            )
        })
        .collect();
    json!({"size":size,"fields":fields})
}
fn resources_fixture() -> (Vec<u8>, crate::symbols::Isf) {
    let (mut bytes, mut isf) = fixture();
    isf.data["symbols"]["iomem_resource"] = json!({"address":0x12000});
    isf.data["symbols"]["ioport_resource"] = json!({"address":0x12000});
    isf.data["user_types"]["resource"] = structure(
        &[
            ("name", 0),
            ("start", 8),
            ("end", 16),
            ("flags", 24),
            ("child", 32),
            ("sibling", 40),
        ],
        48,
    );
    for (address, name, start, end, child, sibling) in [
        (0x12000, "PCI mem", 0, 0xffff, 0x12100, 0),
        (0x12100, "System RAM", 0x1000, 0x3fff, 0x12200, 0x12300),
        (0x12200, "Kernel code", 0x1000, 0x1fff, 0, 0),
        (0x12300, "Reserved", 0x4000, 0x4fff, 0, 0),
    ] {
        let ptr = address + 64;
        bytes[ptr..ptr + name.len()].copy_from_slice(name.as_bytes());
        for (offset, value) in [
            (0, ptr as u64),
            (8, start),
            (16, end),
            (24, 0x200),
            (32, child),
            (40, sibling),
        ] {
            put(&mut bytes, address + offset, value);
        }
    }
    (bytes, isf)
}
#[test]
fn resource_tree_fields_order_relocation_and_limits() {
    let (bytes, isf) = resources_fixture();
    let im = image(&bytes);
    let linux = engine(&im, &isf);
    for plugin in [Plugin::Iomem, Plugin::Ioports] {
        let result = linux.run(plugin, &Job::default()).unwrap();
        assert!(result.complete);
        assert_eq!(
            result
                .rows
                .iter()
                .map(|r| (&r[0], &r[3]))
                .collect::<Vec<_>>(),
            vec![
                (&"PCI mem".into(), &"0".into()),
                (&"System RAM".into(), &"1".into()),
                (&"Kernel code".into(), &"2".into()),
                (&"Reserved".into(), &"1".into())
            ]
        );
        assert_eq!(&result.rows[2][1..3], &[hex(0x1000), hex(0x1fff)]);
    }
    let mut result = linux.result(Plugin::Iomem);
    linux
        .resources(0x12000, &mut result, &Job::default(), 2)
        .unwrap();
    assert!(!result.complete);
    assert_eq!(result.rows.len(), 2);
    assert!(result.diagnostics[0].contains("上限"));
    isf.slide
        .store(0x1000, std::sync::atomic::Ordering::Relaxed);
    // Shift a symbol, not an inferred struct layout, to the same physical root.
    let mut isf = isf;
    isf.data["symbols"]["iomem_resource"]["address"] = json!(0x11000);
    assert_eq!(
        engine(&im, &isf)
            .run(Plugin::Iomem, &Job::default())
            .unwrap()
            .rows
            .len(),
        4
    );
}
#[test]
fn corrupt_resource_children_names_and_ranges_keep_other_branches() {
    let (mut bytes, isf) = resources_fixture();
    put(&mut bytes, 0x12100, 0x800000); // missing name
    put(&mut bytes, 0x12220, 0x12100); // child points back to parent
    put(&mut bytes, 0x12208, 0x3000); // invalid start/end
    let im = image(&bytes);
    let r = engine(&im, &isf)
        .run(Plugin::Iomem, &Job::default())
        .unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows.len(), 3);
    assert_eq!(r.rows[1][0], "[unreadable]");
    assert_eq!(r.rows[2][0], "Reserved");
    assert!(r.diagnostics.iter().any(|s| s.contains("循环")));
    assert!(r.diagnostics.iter().any(|s| s.contains("倒置")));
    put(&mut bytes, 0x12120, 0x800000); // missing child also leaves sibling accessible
    let im = image(&bytes);
    assert_eq!(
        engine(&im, &isf)
            .run(Plugin::Iomem, &Job::default())
            .unwrap()
            .rows
            .last()
            .unwrap()[0],
        "Reserved"
    );
}
#[test]
fn resource_depth_limit_is_reported_without_recursive_stack_growth() {
    let (mut bytes, isf) = resources_fixture();
    bytes[0x3f000..0x3f002].copy_from_slice(b"r\0");
    for index in 0..1027 {
        let address = 0x12000 + index * 64;
        for (offset, value) in [
            (0, 0x3f000),
            (8, 0),
            (16, 1),
            (24, 0),
            (
                32,
                if index == 1026 {
                    0
                } else {
                    (address + 64) as u64
                },
            ),
            (40, 0),
        ] {
            put(&mut bytes, address + offset, value);
        }
    }
    let im = image(&bytes);
    let result = engine(&im, &isf)
        .run(Plugin::Iomem, &Job::default())
        .unwrap();
    assert!(!result.complete);
    assert_eq!(result.rows.len(), DEPTH_LIMIT + 1);
    assert!(result.diagnostics.iter().any(|s| s.contains("1024 层")));
}
fn ptrace_fixture() -> (Vec<u8>, crate::symbols::Isf) {
    let (mut bytes, mut isf) = fixture();
    isf.data["user_types"]["task_struct"]["size"] = json!(160);
    for (field, offset, ty) in [
        ("group_leader", 72, json!({"kind":"pointer"})),
        (
            "thread_group",
            80,
            json!({"kind":"struct","name":"list_head"}),
        ),
        ("ptrace", 96, json!({"kind":"base","name":"u64"})),
        ("parent", 104, json!({"kind":"pointer"})),
        ("ptraced", 112, json!({"kind":"struct","name":"list_head"})),
        (
            "ptrace_entry",
            128,
            json!({"kind":"struct","name":"list_head"}),
        ),
    ] {
        isf.data["user_types"]["task_struct"]["fields"][field] = json!({"offset":offset,"type":ty});
    }
    for a in [0xa000, 0xa100, 0xa200] {
        put(&mut bytes, a + 72, a as u64);
        for offset in [80, 112, 128] {
            put(&mut bytes, a + offset, (a + offset) as u64);
            put(&mut bytes, a + offset + 8, (a + offset) as u64);
        }
    }
    put(&mut bytes, 0xa210, 3); // TID 3 in process 1, not in global task list
    put(&mut bytes, 0xa218, 1);
    put(&mut bytes, 0xa220, 0x9000);
    bytes[0xa228..0xa22d].copy_from_slice(b"child");
    put(&mut bytes, 0xa248, 0xa000);
    for (at, next) in [
        (0xa050, 0xa250),
        (0xa058, 0xa250),
        (0xa250, 0xa050),
        (0xa258, 0xa050),
    ] {
        put(&mut bytes, at, next);
    }
    (bytes, isf)
}
#[test]
fn ptrace_includes_nonleader_tracees_and_tracers_and_normal_empty() {
    let (mut bytes, isf) = ptrace_fixture();
    let im = image(&bytes);
    let r = engine(&im, &isf)
        .run(Plugin::Ptrace, &Job::default())
        .unwrap();
    assert!(r.complete && r.rows.is_empty(), "{:?}", r.diagnostics);
    put(&mut bytes, 0xa260, 1);
    put(&mut bytes, 0xa268, 0xa100);
    for (at, next) in [
        (0xa170, 0xa280),
        (0xa178, 0xa280),
        (0xa280, 0xa170),
        (0xa288, 0xa170),
    ] {
        put(&mut bytes, at, next);
    }
    let im = image(&bytes);
    let r = engine(&im, &isf)
        .run(Plugin::Ptrace, &Job::default())
        .unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(
        r.rows,
        vec![
            vec![
                "kth".into(),
                "2".into(),
                "2".into(),
                "[none]".into(),
                "3".into(),
                hex(0)
            ],
            vec![
                "child".into(),
                "1".into(),
                "3".into(),
                "2".into(),
                "[none]".into(),
                hex(1)
            ]
        ]
    );
    put(&mut bytes, 0xa280, 0xa280); // loop must retain the already parsed relationship
    let im = image(&bytes);
    let r = engine(&im, &isf)
        .run(Plugin::Ptrace, &Job::default())
        .unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows.len(), 2);
    assert!(r.diagnostics.iter().any(|s| s.contains("循环")));
}
fn notifier_fixture() -> (Vec<u8>, crate::symbols::Isf) {
    let (mut bytes, mut isf) = fixture();
    for (name, address) in [
        ("keyboard_notifier_list", 0x12000),
        ("modules", 0x15000),
        ("_stext", 0x18000),
        ("_etext", 0x19000),
        ("keyboard_callback", 0x18000),
    ] {
        isf.data["symbols"][name] = json!({"address":address});
    }
    isf.data["user_types"]["atomic_notifier_head"] = structure(&[("head", 0)], 8);
    isf.data["user_types"]["notifier_block"] =
        structure(&[("notifier_call", 0), ("next", 8), ("priority", 16)], 24);
    isf.data["user_types"]["notifier_block"]["fields"]["priority"]["type"] =
        json!({"kind":"base","name":"int"});
    isf.data["base_types"]["int"] = json!({"size":4,"signed":true});
    isf.data["user_types"]["module"] = structure(
        &[
            ("list", 0),
            ("name", 16),
            ("module_core", 64),
            ("core_size", 72),
        ],
        128,
    );
    put(&mut bytes, 0x15000, 0x15100);
    put(&mut bytes, 0x15008, 0x15100);
    put(&mut bytes, 0x15100, 0x15000);
    put(&mut bytes, 0x15108, 0x15000);
    bytes[0x15110..0x15115].copy_from_slice(b"audit");
    put(&mut bytes, 0x15140, 0x1a000);
    put(&mut bytes, 0x15148, 0x1000);
    put(&mut bytes, 0x12000, 0x12100);
    for (address, callback, next) in [
        (0x12100, 0x18010, 0x12200),
        (0x12200, 0x1a010, 0x12300),
        (0x12300, 0x1f000, 0),
    ] {
        put(&mut bytes, address, callback);
        put(&mut bytes, address + 8, next);
        bytes[address + 16..address + 20].copy_from_slice(&(-2_i32).to_le_bytes());
    }
    (bytes, isf)
}
#[test]
fn notifiers_resolve_kernel_modules_unknown_and_signed_priority() {
    let (mut bytes, isf) = notifier_fixture();
    let im = image(&bytes);
    let r = engine(&im, &isf)
        .run(Plugin::KeyboardNotifiers, &Job::default())
        .unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(
        &r.rows[0][1..4],
        &["kernel", "keyboard_callback+0x10", "-2"]
    );
    assert_eq!(&r.rows[1][1..3], &["audit", "[unknown]"]);
    assert_eq!(&r.rows[2][1..3], &["[unknown]", "[unknown]"]);
    put(&mut bytes, 0x12308, 0x12100);
    let im = image(&bytes);
    let r = engine(&im, &isf)
        .run(Plugin::KeyboardNotifiers, &Job::default())
        .unwrap();
    assert!(!r.complete && r.rows.len() == 3);
    put(&mut bytes, 0x12000, 0);
    let im = image(&bytes);
    let r = engine(&im, &isf)
        .run(Plugin::KeyboardNotifiers, &Job::default())
        .unwrap();
    assert!(r.complete && r.rows.is_empty());
}
#[test]
fn unsupported_symbols_fields_and_cancellation_are_explicit() {
    let (bytes, isf) = fixture();
    let im = image(&bytes);
    for plugin in [
        Plugin::Iomem,
        Plugin::Ioports,
        Plugin::Ptrace,
        Plugin::KeyboardNotifiers,
    ] {
        let e = engine(&im, &isf).run(plugin, &Job::default()).unwrap_err();
        assert!(format!("{e:#}").contains("不支持"));
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            engine(&im, &isf)
                .run(plugin, &job)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
    }
}
