use super::*;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::Ordering;
pub(super) const K: u64 = 0xffff_8000_0000_0000;
pub(super) fn put(b: &mut [u8], offset: usize, value: u64) {
    b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn fixture() -> (Vec<u8>, Isf) {
    let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
    let uint = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
    let data = json!({"metadata":{"windows":{"pdb":{"database":"ntkrnlmp.pdb","GUID":"00112233445566778899AABBCCDDEEFF","age":1,"machine_type":34404}}},"base_types":{"pointer":{"size":8},"u64":{"size":8},"u16":{"size":2}},"symbols":{"PsInitialSystemProcess":{"address":0x380},"PsActiveProcessHead":{"address":0x400},"NtBuildNumber":{"address":0x200},"PsLoadedModuleList":{"address":0x700}},"user_types":{
        "_EPROCESS":{"size":0x100,"fields":{"ActiveProcessLinks":{"offset":16,"type":{"kind":"struct","name":"_LIST_ENTRY"}},"UniqueProcessId":pointer(32),"InheritedFromUniqueProcessId":pointer(40),"ImageFileName":{"offset":48,"type":{"kind":"array","count":16}},"ActiveThreads":uint(72),"ObjectTable":pointer(80),"CreateTime":uint(88),"ExitTime":uint(96),"Peb":pointer(104),"Pcb":{"offset":112,"type":{"kind":"struct","name":"_KPROCESS"}}}},
        "_KPROCESS":{"size":8,"fields":{"DirectoryTableBase":uint(0)}},
        "_LIST_ENTRY":{"size":16,"fields":{"Flink":pointer(0),"Blink":pointer(8)}},
        "_UNICODE_STRING":{"size":16,"fields":{"Length":{"offset":0,"type":{"kind":"base","name":"u16"}},"MaximumLength":{"offset":2,"type":{"kind":"base","name":"u16"}},"Buffer":pointer(8)}},
        "_MMPTE_PROTOTYPE":{"size":8,"fields":{"ProtoAddress":{"offset":0,"type":{"kind":"bitfield","bit_position":16,"bit_length":48,"type":{"kind":"base","name":"u64"}}}}}
    }});
    let isf = Isf::parse(
        &serde_json::to_vec(&data).unwrap(),
        "synthetic-windows.json".into(),
    )
    .unwrap();
    let mut b = vec![0; 0x40000];
    put(&mut b, 0x1000 + 256 * 8, 0x2003);
    put(&mut b, 0x1000 + 510 * 8, 0x1003);
    put(&mut b, 0x2000, 0x3003);
    put(&mut b, 0x3000, 0x4003);
    for i in 0..32 {
        put(&mut b, 0x4000 + i * 8, 0x8003 + i as u64 * 4096);
    }
    b[0x8000..0x8002].copy_from_slice(b"MZ");
    b[0x803c..0x8040].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x8080..0x8084].copy_from_slice(b"PE\0\0");
    b[0x8084..0x8086].copy_from_slice(&0x8664u16.to_le_bytes());
    b[0x8098..0x809a].copy_from_slice(&0x20bu16.to_le_bytes());
    b[0x80d0..0x80d4].copy_from_slice(&0x8000u32.to_le_bytes());
    b[0x8138..0x813c].copy_from_slice(&0x500u32.to_le_bytes());
    b[0x813c..0x8140].copy_from_slice(&28u32.to_le_bytes());
    b[0x850c..0x8510].copy_from_slice(&2u32.to_le_bytes());
    b[0x8514..0x8518].copy_from_slice(&0x600u32.to_le_bytes());
    b[0x8600..0x8604].copy_from_slice(b"RSDS");
    b[0x8604..0x8614].copy_from_slice(&[
        0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    b[0x8614..0x8618].copy_from_slice(&1u32.to_le_bytes());
    b[0x8618..0x8625].copy_from_slice(b"ntkrnlmp.pdb\0");
    put(&mut b, 0x8380, K + 0x1000);
    put(&mut b, 0x8400, K + 0x1010);
    put(&mut b, 0x8408, K + 0x2010);
    put(&mut b, 0x8700, K + 0x700);
    put(&mut b, 0x8708, K + 0x700);
    for (page, pid, parent, name) in [
        (0x9000, 4, 0, b"System".as_slice()),
        (0xa000, 8, 4, b"child".as_slice()),
    ] {
        put(&mut b, page + 32, pid);
        put(&mut b, page + 40, parent);
        b[page + 48..page + 48 + name.len()].copy_from_slice(name);
        put(&mut b, page + 72, 2);
        put(&mut b, page + 88, 130000000000000000);
        put(&mut b, page + 112, 0x1000);
    }
    put(&mut b, 0x9010, K + 0x2010);
    put(&mut b, 0x9018, K + 0x400);
    put(&mut b, 0xa010, K + 0x400);
    put(&mut b, 0xa018, K + 0x1010);
    (b, isf)
}
pub(super) fn image(bytes: &[u8]) -> Image {
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(bytes).unwrap();
    Image::from_file(f, "synthetic".into()).unwrap()
}
#[test]
fn bootstrap_validates_kernel_and_system() {
    let (b, isf) = fixture();
    let image = image(&b);
    assert_eq!(
        discover(&image, &isf, &Job::default()).unwrap(),
        (0x1000, K)
    );
    let mut bad = fixture().1;
    bad.data["metadata"]["windows"]["pdb"]["age"] = json!(2);
    assert!(discover(&image, &bad, &Job::default()).is_err());
}
#[test]
fn process_fields_filter_and_damaged_list() {
    let (mut b, isf) = fixture();
    let image_good = image(&b);
    let engine = Windows {
        vm: Memory {
            image: &image_good,
            root: 0x1000,
            isf: &isf,
        },
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let r = engine
        .run(Plugin::WinPslist, &Options::default(), &Job::default())
        .unwrap();
    assert!(r.complete);
    assert_eq!(r.rows.len(), 2);
    assert_eq!(&r.rows[1][..3], &["8", "4", "child"]);
    let r = engine
        .run(
            Plugin::WinPstree,
            &Options {
                pid: Some(8),
                ..Default::default()
            },
            &Job::default(),
        )
        .unwrap();
    assert_eq!(r.rows.len(), 1);
    put(&mut b, 0xa018, K + 0x400);
    let damaged = image(&b);
    let engine = Windows {
        vm: Memory {
            image: &damaged,
            root: 0x1000,
            isf: &isf,
        },
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let r = engine
        .run(Plugin::WinPslist, &Options::default(), &Job::default())
        .unwrap();
    assert!(!r.complete);
    assert_eq!(r.rows.len(), 2);
    assert!(!r.diagnostics.is_empty());
    let cache = tempfile::tempdir().unwrap();
    store::save(cache.path(), "partial", &r, &Job::default()).unwrap();
    assert!(store::load(cache.path(), "partial").is_none());
}
#[test]
fn transition_prototype_missing_and_linux_isolation() {
    let (mut b, isf) = fixture();
    put(&mut b, 0x4000 + 8, 0x9800);
    b[0x9000] = 42;
    let prototype = K + 0x5000;
    put(
        &mut b,
        0x4000 + 16,
        (prototype & 0xffffffffffff) << 16 | 1024,
    );
    put(&mut b, 0xd000, 0xe800);
    b[0xe000] = 19;
    let image = image(&b);
    let vm = Memory {
        image: &image,
        root: 0x1000,
        isf: &isf,
    };
    assert_eq!(vm.uint(K + 0x1000, 1).unwrap(), 42);
    assert_eq!(vm.uint(K + 0x2000, 1).unwrap(), 19);
    assert!(
        VirtualMemory {
            image: &image,
            root: 0x1000
        }
        .translate(K + 0x1000)
        .is_err()
    );
    assert!(vm.uint(K + 0x30000, 1).is_err());
    assert!(vm.uint(0x800000000000, 1).is_err());
}
#[test]
fn cancellation_and_unicode_bounds() {
    let (mut b, isf) = fixture();
    b[0xb000..0xb004].copy_from_slice(&[4, 0, 4, 0]);
    put(&mut b, 0xb008, K + 0x4000);
    b[0xc000..0xc004].copy_from_slice(&[0x2d, 0x4e, 0x87, 0x65]);
    let image = image(&b);
    let vm = Memory {
        image: &image,
        root: 0x1000,
        isf: &isf,
    };
    assert_eq!(vm.unicode(K + 0x3000).unwrap(), "中文");
    let job = Job::default();
    job.cancel.store(true, Ordering::Relaxed);
    assert!(discover(&image, &isf, &job).is_err());
}
#[test]
fn raw_guid_identity_and_remote_validation() {
    let (b, isf) = fixture();
    let identity = PdbIdentity::from_rsds(&b[0x8600..0x8625]).unwrap();
    assert_eq!(identity, PdbIdentity::from_isf(&isf).unwrap());
    assert_eq!(PdbIdentity::from_key(&identity.key()).unwrap(), identity);
    assert!(PdbIdentity::from_key("ntkrnlmp.pdb/中中中中中中中中中中中中中").is_err());
    assert!(
        PdbIdentity {
            name: "../evil.pdb".into(),
            ..identity.clone()
        }
        .url()
        .is_err()
    );
    assert!(crate::windows_symbols::convert(b"not a PDB", &identity, &Job::default()).is_err());
}
#[test]
fn range_dump_matches_source_and_never_commits_missing_pages() {
    let (b, isf) = fixture();
    let image = image(&b);
    let engine = Windows {
        vm: Memory {
            image: &image,
            root: 0x1000,
            isf: &isf,
        },
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let dir = tempfile::tempdir().unwrap();
    let options = DumpOptions {
        pid: 8,
        directory: dir.path().into(),
        start: Some(K + 0x3000),
        end: Some(K + 0x4000),
    };
    let r = engine
        .run_dump(Plugin::WinMemdump, &options, &Job::default())
        .unwrap();
    assert!(r.complete);
    assert_eq!(r.rows.len(), 1);
    assert_eq!(std::fs::read(&r.rows[0][6]).unwrap(), b[0xb000..0xc000]);
    let missing = DumpOptions {
        start: Some(K + 0x30000),
        end: Some(K + 0x31000),
        ..options
    };
    let r = engine
        .run_dump(Plugin::WinMemdump, &missing, &Job::default())
        .unwrap();
    assert!(!r.complete);
    assert!(r.rows.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
