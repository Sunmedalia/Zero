use super::super::tests::{K, fixture, image, put};
use super::*;

fn prepare() -> (Vec<u8>, Isf, ServiceLayout) {
    let (mut b, isf) = fixture();
    put(&mut b, 0x1000, 0x2003);
    let layout = user_layout::service(Architecture::X64, [10, 0, 15063, 0]).unwrap();
    b[0x19000..0x19004].copy_from_slice(b"Sc27");
    put(&mut b, 0x19000 + layout.header_record as usize, 0x12000);
    for (field, value) in [("Order", 0), ("Start", 2), ("State", 4), ("Type", 16)] {
        let at = 0x1a000 + layout.fields[field] as usize;
        b[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    put(
        &mut b,
        0x1a000 + layout.fields["ServiceName"] as usize,
        0x13000,
    );
    put(
        &mut b,
        0x1a000 + layout.fields["DisplayName"] as usize,
        0x13200,
    );
    put(
        &mut b,
        0x1a000 + layout.fields["ServiceProcess"] as usize,
        0x15000,
    );
    put(&mut b, 0x1d000 + layout.binary as usize, 0x16000);
    b[0x1d000 + layout.pid as usize..0x1d004 + layout.pid as usize]
        .copy_from_slice(&1234u32.to_le_bytes());
    for (at, text) in [
        (0x1b000, "svc"),
        (0x1b200, "A service"),
        (0x1e000, "service.exe"),
    ] {
        let data: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        b[at..at + data.len()].copy_from_slice(&data);
    }
    (b, isf, layout)
}
fn scan(b: &[u8], isf: &Isf, layout: &ServiceLayout, end: u64, job: &Job) -> Result<Results> {
    let img = image(b);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(isf)?,
    };
    let mut r = w.result(Plugin::WinSvcList);
    let map = BTreeMap::from([("svc".into(), ["registry.exe".into(), "service.dll".into()])]);
    w.service_vad(&w.vm, 0x11000, end, layout, &map, &mut r, job)?;
    Ok(r)
}
#[test]
fn executable_header_yields_all_eleven_fields_and_zero_order() {
    let (b, isf, layout) = prepare();
    let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(
        r.rows,
        vec![vec![
            hex(0x12000),
            "0".into(),
            "1234".into(),
            "SERVICE_AUTO_START".into(),
            "SERVICE_RUNNING".into(),
            "SERVICE_WIN32_OWN_PROCESS".into(),
            "svc".into(),
            "A service".into(),
            "service.exe".into(),
            "registry.exe".into(),
            "service.dll".into()
        ]]
    );
}
#[test]
fn only_aligned_headers_in_requested_vad_are_enumerated_and_duplicates_preserved() {
    let (mut b, isf, layout) = prepare();
    let header = b[0x19000..0x19020].to_vec();
    b[0x19040..0x19060].copy_from_slice(&header);
    b[0x19101..0x19121].copy_from_slice(&header);
    assert_eq!(
        scan(&b, &isf, &layout, 0x11040, &Job::default())
            .unwrap()
            .rows
            .len(),
        1
    );
    assert_eq!(
        scan(&b, &isf, &layout, 0x12000, &Job::default())
            .unwrap()
            .rows
            .len(),
        2
    );
}
#[test]
fn backward_chain_reports_reference_pointer_storage_offsets() {
    let (mut b, isf, layout) = prepare();
    let record = b[0x1a000..0x1a100].to_vec();
    b[0x1c000..0x1c100].copy_from_slice(&record);
    put(&mut b, 0x1a000 + layout.previous.unwrap() as usize, 0x14000);
    let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(r.rows.len(), 2);
    assert_eq!(r.rows[0][0], hex(0x12000));
    assert_eq!(r.rows[1][0], hex(0x12000 + layout.previous.unwrap()));
    assert_eq!(r.rows[1][6], "svc");
}
#[test]
fn stopped_service_omits_pid_and_binary_but_keeps_registry() {
    let (mut b, isf, layout) = prepare();
    let at = 0x1a000 + layout.fields["State"] as usize;
    b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
    let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
    assert_eq!(r.rows[0][2], NA);
    assert_eq!(r.rows[0][8], NA);
    assert_eq!(r.rows[0][10], "service.dll");
}
#[test]
fn driver_binary_and_interactive_process_type_follow_reference() {
    let (mut b, isf, layout) = prepare();
    let at = 0x1a000 + layout.fields["Type"] as usize;
    b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
    put(
        &mut b,
        0x1a000 + layout.fields["DriverName"] as usize,
        0x16000,
    );
    let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
    assert_eq!(r.rows[0][2], NA);
    assert_eq!(r.rows[0][8], "service.exe");
    assert_eq!(
        types(0x111),
        "SERVICE_KERNEL_DRIVER|SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS"
    );
    assert_eq!(types(0x8000), "");
}
#[test]
fn cycles_and_missing_fields_preserve_other_fields() {
    let (mut b, isf, layout) = prepare();
    put(&mut b, 0x1a000 + layout.previous.unwrap() as usize, 0x12000);
    put(
        &mut b,
        0x1a000 + layout.fields["DisplayName"] as usize,
        0x40000,
    );
    let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0][7], NA);
    assert_eq!(r.rows[0][2], "1234");
    assert!(r.diagnostics.iter().any(|d| d.contains("循环")));
    assert!(r.diagnostics.iter().any(|d| d.contains("DisplayName")));
}
#[test]
fn missing_pages_and_invalid_records_are_explicit_and_cancel_propagates() {
    let (mut b, isf, layout) = prepare();
    put(&mut b, 0x4000 + 0x17 * 8, 0);
    let r = scan(&b, &isf, &layout, 0x18000, &Job::default()).unwrap();
    assert_eq!(r.rows.len(), 1);
    assert!(!r.complete);
    let at = 0x1a000 + layout.fields["Order"] as usize;
    b[at..at + 4].copy_from_slice(&65536u32.to_le_bytes());
    let r = scan(&b, &isf, &layout, 0x12000, &Job::default()).unwrap();
    assert!(r.rows.is_empty());
    assert!(!r.complete);
    let job = Job::default();
    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(scan(&b, &isf, &layout, 0x12000, &job).is_err());
}
#[test]
fn unsupported_builds_and_pid_filters_fail_explicitly() {
    let (mut b, isf, _) = prepare();
    b[0x8200..0x8204].copy_from_slice(&7601u32.to_le_bytes());
    let img = image(&b);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    assert!(
        w.service_list(&Options::default(), &Job::default())
            .unwrap_err()
            .to_string()
            .contains("15063")
    );
    assert!(
        w.service_list(
            &Options {
                pid: Some(4),
                ..Default::default()
            },
            &Job::default()
        )
        .unwrap_err()
        .to_string()
        .contains("PID")
    );
}
#[test]
fn diff_uses_case_sensitive_names_and_last_scanned_record() {
    let row = |name: &str, address: u64| {
        let mut row = vec![String::new(); 11];
        row[0] = hex(address);
        row[6] = name.into();
        row
    };
    let scan = vec![
        row("visible", 1),
        row("Hidden", 2),
        row("Hidden", 3),
        row("VISIBLE", 4),
    ];
    let list = vec![row("visible", 5)];
    assert_eq!(
        service_difference(&scan, &list),
        vec![row("Hidden", 3), row("VISIBLE", 4)]
    );
    assert!(service_difference(&scan, &scan).is_empty());
    assert_eq!(service_difference(&[], &list), Vec::<Vec<String>>::new());
}
#[test]
fn modern_scan_deduplicates_full_tuples_and_requires_aligned_headers() {
    let (mut b, isf, layout) = prepare();
    b[0x19000..0x19004].copy_from_slice(b"serH");
    let header = b[0x19000..0x19020].to_vec();
    b[0x19040..0x19060].copy_from_slice(&header);
    b[0x19101..0x19121].copy_from_slice(&header);
    let img = image(&b);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let mut r = w.result(Plugin::WinSvcScanV4);
    let stats = w
        .service_tag_vad(
            &w.vm,
            0x11000,
            0x12000,
            &layout,
            &BTreeMap::from([("svc".into(), [NA.into(), NA.into()])]),
            &mut r,
            &Job::default(),
            b"serH",
            false,
        )
        .unwrap();
    assert_eq!(stats, (2, 1, 0));
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.columns.len(), 11);

    // No registry entry creates fresh absent values in the reference.
    let mut absent = w.result(Plugin::WinSvcScanV4);
    w.service_tag_vad(
        &w.vm,
        0x11000,
        0x12000,
        &layout,
        &BinaryMap::new(),
        &mut absent,
        &Job::default(),
        b"serH",
        false,
    )
    .unwrap();
    assert_eq!(absent.rows.len(), 2);
    assert_eq!(absent.rows[0], absent.rows[1]);

    // Even shared registry metadata cannot deduplicate a fresh absent PID.
    drop(w);
    drop(img);
    let state = 0x1a000 + layout.fields["State"] as usize;
    b[state..state + 4].copy_from_slice(&1u32.to_le_bytes());
    let img = image(&b);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let mut stopped = w.result(Plugin::WinSvcScanV4);
    w.service_tag_vad(
        &w.vm,
        0x11000,
        0x12000,
        &layout,
        &BTreeMap::from([("svc".into(), ["registry.exe".into(), "svc.dll".into()])]),
        &mut stopped,
        &Job::default(),
        b"serH",
        false,
    )
    .unwrap();
    assert_eq!(stopped.rows.len(), 2);
    assert_eq!(stopped.rows[0][2], NA);
    assert_eq!(stopped.rows[0], stopped.rows[1]);
}
#[test]
fn direct_nt5_tags_cross_pages_and_do_not_follow_header_pointers() {
    let (mut b, isf, mut layout) = prepare();
    layout.previous = None;
    layout.fields.insert("Tag".into(), 0xffe);
    // The tag is split across two resident pages; the validated record is
    // at their first page start, without an indirect header pointer.
    b[0x1affe..0x1b002].copy_from_slice(b"sErv");
    let img = image(&b);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let mut r = w.result(Plugin::WinSvcScanV4);
    w.service_tag_vad(
        &w.vm,
        0x12000,
        0x14000,
        &layout,
        &BinaryMap::new(),
        &mut r,
        &Job::default(),
        b"sErv",
        true,
    )
    .unwrap();
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0][0], hex(0x12000));
    assert!(r.complete);
    // A missing page breaks the carry, never joining unrelated bytes.
    put(&mut b, 0x4000 + 0x13 * 8, 0);
    let img = image(&b);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let mut r = w.result(Plugin::WinSvcScanV4);
    w.service_tag_vad(
        &w.vm,
        0x12000,
        0x14000,
        &layout,
        &BinaryMap::new(),
        &mut r,
        &Job::default(),
        b"sErv",
        true,
    )
    .unwrap();
    assert!(r.rows.is_empty());
    assert!(!r.complete);
}
#[test]
fn registry_decode_is_strict_and_only_trims_trailing_nuls() {
    assert_eq!(
        registry_string(&[0xff, 0xfe, 65, 0, 0, 0, 66, 0, 0, 0]).unwrap(),
        "A\0B"
    );
    assert_eq!(registry_string(&[0xfe, 0xff, 0, 65, 0, 0]).unwrap(), "A");
    assert!(registry_string(&[65]).is_err());
    assert!(registry_string(&[0, 0xd8]).is_err());
}
