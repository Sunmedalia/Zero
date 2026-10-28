//! Generated VAD link/layout fixtures; no recovered memory is embedded here.
use super::regex::tests::prepared;
use super::tests::{K, image, put};
use super::*;
use serde_json::json;
fn engine<'a>(image: &'a Image, isf: &'a Isf) -> Windows<'a> {
    Windows {
        vm: Memory::new(image, 0x1000, isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(isf).unwrap(),
    }
}
#[test]
fn all_nine_fields_parent_tags_and_pid_union() {
    let (mut b, mut isf) = prepared();
    isf.data["user_types"]["_RTL_BALANCED_NODE"]["fields"]["ParentValue"] =
        json!({"offset":16,"type":{"kind":"base","name":"u64"}});
    put(&mut b, 0xb110, (K + 0x3000) | 3);
    let img = image(&b);
    let w = engine(&img, &isf);
    let r = w
        .run(
            Plugin::WinVadWalk,
            &Options {
                pid: Some(4),
                pids: vec![8],
                ..Default::default()
            },
            &Job::default(),
        )
        .unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(r.rows.len(), 2);
    assert_eq!(
        r.rows[0],
        vec![
            "8".into(),
            "child".into(),
            hex(K + 0x3000),
            hex(0),
            hex(0),
            hex(K + 0x3100),
            hex(4096),
            hex(8191),
            "VadS".into()
        ]
    );
    assert_eq!(r.rows[1][3], hex(K + 0x3000));
    assert_eq!(r.rows[1][6], hex(8192));
    assert_eq!(r.rows[1][7], hex(12287));
    assert_eq!(r.kernel_identity["vad_walk"]["pids"], json!([4, 8]));
    let r = w
        .run(
            Plugin::WinVadWalk,
            &Options {
                pid: Some(4),
                ..Default::default()
            },
            &Job::default(),
        )
        .unwrap();
    assert!(r.rows.is_empty());
}
#[test]
fn missing_parent_invalid_tag_cycles_and_cancellation_remain_explicit() {
    let (mut b, isf) = prepared();
    put(&mut b, 0xb100, K + 0x3000); // cycle retains the two independently valid objects
    let img = image(&b);
    let w = engine(&img, &isf);
    let job = Job::default();
    let r = w
        .run(
            Plugin::WinVadWalk,
            &Options {
                pid: Some(8),
                ..Default::default()
            },
            &job,
        )
        .unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows.len(), 2);
    assert!(r.rows.iter().all(|r| r[3] == "N/A"));
    assert!(r.diagnostics.iter().any(|d| d.contains("循环")));
    assert_eq!(
        r.kernel_identity["vad_walk"]["processes"][0]["unavailable_parent_fields"],
        2
    );
    b[0xb100 - 12..0xb100 - 8].fill(0);
    let img = image(&b);
    let r = engine(&img, &isf)
        .run(
            Plugin::WinVadWalk,
            &Options {
                pid: Some(8),
                ..Default::default()
            },
            &Job::default(),
        )
        .unwrap();
    assert_eq!(r.rows.len(), 1);
    assert!(!r.complete);
    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        w.run(Plugin::WinVadWalk, &Options::default(), &job)
            .is_err()
    );
}
#[test]
fn high_vpn_and_x86_direct_parent_four_byte_tags() {
    let (mut b, mut isf) = prepared();
    isf.data["user_types"]["_MMVAD_SHORT"]["fields"]["StartingVpnHigh"] =
        json!({"offset":48,"type":{"kind":"base","name":"u64"}});
    isf.data["user_types"]["_MMVAD_SHORT"]["fields"]["EndingVpnHigh"] =
        json!({"offset":56,"type":{"kind":"base","name":"u64"}});
    put(&mut b, 0xb030, 1);
    put(&mut b, 0xb038, 1);
    let img = image(&b);
    let r = engine(&img, &isf)
        .run(
            Plugin::WinVadWalk,
            &Options {
                pid: Some(8),
                ..Default::default()
            },
            &Job::default(),
        )
        .unwrap();
    assert_eq!(r.rows[0][6], hex(0x100000001000));
    assert_eq!(r.rows[0][7], hex(0x100000001fff));
    let (mut b, mut isf) = prepared();
    let k = 0x80000000;
    isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
    isf.data["base_types"]["pointer"]["size"] = json!(4);
    isf.data["base_types"]["u32"] = json!({"size":4});
    let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
    let n = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u32"}});
    isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"] = ptr(128);
    isf.data["user_types"]["_MMVAD_SHORT"] = json!({"size":20,"fields":{"Parent":ptr(0),"LeftChild":ptr(4),"RightChild":ptr(8),"StartingVpn":n(12),"EndingVpn":n(16)}});
    b[0x1000..0x5000].fill(0);
    b[0xb000..0xb200].fill(0);
    let mut write = |at: usize, value: u32| b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    write(0x1800, 0x2003);
    for i in 0..32 {
        write(0x2000 + i * 4, 0x8003 + i as u32 * 4096);
    }
    write(0xa080, k + 0x3000);
    write(0xb008, k + 0x3100);
    write(0xb00c, 1);
    write(0xb010, 1);
    write(0xb100, k + 0x3000);
    write(0xb10c, 2);
    write(0xb110, 2);
    b[0xaffc..0xb000].copy_from_slice(b"VadS");
    b[0xb0fc..0xb100].copy_from_slice(b"Vad ");
    let img = image(&b);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: u64::from(k),
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let process = Process {
        address: u64::from(k) + 0x2000,
        physical: false,
        pid: 8,
        ppid: 4,
        name: "child".into(),
        dtb: 0x1000,
        threads: 1,
        handles: None,
        created: 0,
        exited: 0,
    };
    let mut r = w.result(Plugin::WinVadWalk);
    let mut rows = Vec::new();
    let c = w
        .walk_tagged_vads(&process, &mut r, &Job::default(), |node, _| {
            rows.push((node.address, node.parent, node.start, node.end, node.tag));
            Ok(true)
        })
        .unwrap();
    assert!(r.complete, "{:?}", r.diagnostics);
    assert_eq!(c.yielded, 2);
    assert_eq!(
        rows[1],
        (
            u64::from(k) + 0x3100,
            Some(u64::from(k) + 0x3000),
            8192,
            12288,
            "Vad ".into()
        )
    );
}

#[test]
fn shared_visitor_can_stop_without_reading_the_remaining_tree() {
    let (b, isf) = prepared();
    let img = image(&b);
    let w = engine(&img, &isf);
    let process = w.process(K + 0x2000).unwrap();
    let mut result = w.result(Plugin::WinVadWalk);
    let mut seen = Vec::new();
    let c = w
        .walk_tagged_vads(&process, &mut result, &Job::default(), |node, _| {
            seen.push(node.address);
            Ok(false)
        })
        .unwrap();
    assert_eq!(seen, [K + 0x3000]);
    assert!(c.stopped);
    assert_eq!(c.yielded, 1);
    let job = Job::default();
    let run = w.walk_tagged_vads(&process, &mut result, &job, |_, _| {
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(true)
    });
    assert!(run.is_err());
}
