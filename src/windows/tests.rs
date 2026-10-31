use super::*;
use crate::image::VirtualMemory;
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
    b[0x8510..0x8514].copy_from_slice(&37u32.to_le_bytes());
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
fn a_process_without_a_peb_has_no_user_view_and_is_not_partial() {
    // The fixture child (PID 8) has EPROCESS.Peb == 0, like Registry or
    // MemCompression: a definite read, so no rows and no diagnostic.
    let (b, isf) = fixture();
    let image = image(&b);
    let engine = Windows {
        vm: Memory::new(&image, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    for plugin in [
        Plugin::WinCmdline,
        Plugin::WinEnvars,
        Plugin::WinDlllist,
        Plugin::WinIat,
    ] {
        let r = engine
            .run(plugin, &Options::default(), &Job::default())
            .unwrap();
        assert!(r.complete, "{}: {:?}", plugin.name(), r.diagnostics);
        assert!(r.rows.is_empty(), "{}", plugin.name());
    }
}
#[test]
fn process_fields_filter_and_damaged_list() {
    let (mut b, isf) = fixture();
    let image_good = image(&b);
    let engine = Windows {
        vm: Memory::new(&image_good, 0x1000, &isf, None),
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
        vm: Memory::new(&damaged, 0x1000, &isf, None),
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
    store::save(
        cache.path(),
        "partial",
        &store::Owner::default(),
        &r,
        &Job::default(),
    )
    .unwrap();
    assert!(store::load(cache.path(), "partial").is_none());
    assert!(store::load_partial(cache.path(), "partial").is_none());
    // Partial results go to their own cache, never the successful one.
    store::save_any(
        cache.path(),
        "partial",
        &store::Owner::default(),
        &r,
        &Job::default(),
    )
    .unwrap();
    assert!(store::load(cache.path(), "partial").is_none());
    assert_eq!(
        store::load_partial(cache.path(), "partial").as_ref(),
        Some(&r)
    );
    assert!(!cache.path().join("partial.result.json").exists());
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
    let vm = Memory::new(&image, 0x1000, &isf, None);
    assert_eq!(vm.uint(K + 0x1000, 1).unwrap(), 42);
    assert_eq!(vm.uint(K + 0x2000, 1).unwrap(), 19);
    assert!(
        VirtualMemory::new(&image, 0x1000)
            .translate(K + 0x1000)
            .is_err()
    );
    assert!(vm.uint(K + 0x30000, 1).is_err());
    assert!(vm.uint(0x800000000000, 1).is_err());
}
#[test]
fn arm64_transition_prototype_and_recursive_page_rejection() {
    let (mut b, mut isf) = fixture();
    isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0xaa64);
    isf.data["user_types"]["_MMPTE_TRANSITION"] = json!({"size":8,"fields":{"PageFrameNumber":{"offset":0,"type":{"kind":"bitfield","bit_position":12,"bit_length":36,"type":{"kind":"base","name":"u64"}}}}});
    // Protection bit 7 in a transition PTE is not a hardware block bit.
    put(&mut b, 0x4008, 0x9880);
    put(&mut b, 0x4010, ((K + 0x5000) & 0xffffffffffff) << 16 | 1024);
    put(&mut b, 0xd000, 0xe880);
    b[0x9000] = 42;
    b[0xe000] = 19;
    let img = image(&b);
    let vm = Memory::new(&img, 0x1000, &isf, None);
    assert_eq!(vm.uint(K + 0x1000, 1).unwrap(), 42);
    assert_eq!(vm.uint(K + 0x2000, 1).unwrap(), 19);
    // A prototype pointer into its own unresolved virtual page must terminate.
    put(&mut b, 0x4010, ((K + 0x2000) & 0xffffffffffff) << 16 | 1024);
    let img = image(&b);
    let sources = paging::Sources::open(&Options::default(), &Job::default()).unwrap();
    let vm = Memory::new(&img, 0x1000, &isf, Some(&sources));
    assert!(vm.uint(K + 0x2000, 1).is_err());
    assert_eq!(vm.uint(K + 0x1000, 1).unwrap(), 42);
}
#[test]
fn x86_prototype_uses_split_address_and_four_byte_target() {
    let (mut b, mut isf) = fixture();
    isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
    isf.data["base_types"]["pointer"]["size"] = json!(4);
    isf.data["base_types"]["u32"] = json!({"size":4});
    let bit = |pos, len| json!({"offset":0,"type":{"kind":"bitfield","bit_position":pos,"bit_length":len,"type":{"kind":"base","name":"u32"}}});
    isf.data["user_types"]["_MMPTE_PROTOTYPE"] =
        json!({"size":4,"fields":{"ProtoAddressLow":bit(1,8),"ProtoAddressHigh":bit(11,21)}});
    let put32 = |b: &mut [u8], at: usize, n: u32| b[at..at + 4].copy_from_slice(&n.to_le_bytes());
    b[0x1000..0x2000].fill(0);
    b[0x3000..0x4000].fill(0);
    put32(&mut b, 0x1800, 0x3003);
    put32(&mut b, 0x3000 + 5 * 4, 0xd003);
    // Prototype at 0x8000500c: high=20, low=3.
    put32(&mut b, 0x3000 + 2 * 4, (20 << 11) | (3 << 1) | 1024);
    put32(&mut b, 0xd00c, 0xe883);
    b[0xe000] = 77;
    let img = image(&b);
    let vm = Memory::new(&img, 0x1000, &isf, None);
    assert_eq!(vm.uint(0x80002000, 1).unwrap(), 77);
}
#[test]
fn cancellation_and_unicode_bounds() {
    let (mut b, isf) = fixture();
    b[0xb000..0xb004].copy_from_slice(&[4, 0, 4, 0]);
    put(&mut b, 0xb008, K + 0x4000);
    b[0xc000..0xc004].copy_from_slice(&[0x2d, 0x4e, 0x87, 0x65]);
    let image = image(&b);
    let vm = Memory::new(&image, 0x1000, &isf, None);
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
        vm: Memory::new(&image, 0x1000, &isf, None),
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

#[test]
fn pointer_field_sizes_follow_windows_machine_width_at_structure_boundary() {
    let (_, mut isf) = fixture();
    isf.data["base_types"]["pointer"]["size"] = json!(4);
    isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
    isf.data["user_types"]["PAIR"] = json!({"size":8,"fields":{"left":{"offset":0,"type":{"kind":"pointer"}},"right":{"offset":4,"type":{"kind":"pointer"}}}});
    assert_eq!(isf.size("PAIR", "right").unwrap(), 4);
    assert_eq!(Architecture::from_isf(&isf).unwrap(), Architecture::X86);
    isf.data["base_types"]["pointer"]["size"] = json!(8);
    isf.invalidate_layouts();
    assert!(isf.size("PAIR", "right").is_err());
}

#[test]
fn session_reuses_windows_symbols_and_invalidates_changes() -> Result<()> {
    let (bytes, isf) = fixture();
    let dir = tempfile::tempdir()?;
    let image_path = dir.path().join("image.raw");
    let symbols_path = dir.path().join("kernel.json");
    std::fs::write(&image_path, &bytes)?;
    // A just-written image is prepared again on each request until it has
    // settled (see `image::settled`); evidence on disk is long settled.
    std::fs::File::options()
        .write(true)
        .open(&image_path)?
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60))?;
    std::fs::write(&symbols_path, serde_json::to_vec(&isf.data)?)?;
    let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = messages.clone();
    let job = Job::new(move |s| log.lock().unwrap().push(s));
    let mut session = crate::linux::Session::default();
    let request = Request {
        image: &image_path,
        symbols: &symbols_path,
        choice: None,
        plugin: Plugin::WinPslist,
        cache: dir.path(),
        use_cache: false,
        network: false,
    };
    let run = |session: &mut crate::linux::Session| -> Result<Results> {
        match crate::analysis::analyze(session, &request, None, &Options::default(), &job)? {
            Outcome::Ready(r) => Ok(r),
            _ => anyhow::bail!("unexpected ambiguity"),
        }
    };
    let first = run(&mut session)?;
    messages.lock().unwrap().clear();
    assert_eq!(run(&mut session)?, first);
    assert!(
        messages
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("复用精确匹配"))
    );
    messages.lock().unwrap().clear();
    std::fs::write(&symbols_path, serde_json::to_vec_pretty(&isf.data)?)?;
    assert_eq!(run(&mut session)?.rows, first.rows);
    assert!(
        !messages
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("复用精确匹配"))
    );
    std::fs::write(&symbols_path, b"invalid symbols")?;
    assert!(run(&mut session).is_err());
    Ok(())
}
#[test]
fn kernel_roots_persist_only_for_the_same_content_and_are_revalidated() {
    let (b, isf) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.raw");
    let cache = dir.path().join("cache");
    std::fs::write(&path, &b).unwrap();
    let job = Job::default();
    let first = Image::open(&path, &cache, &job).unwrap();
    assert!(first.persisted_roots.is_empty());
    assert_eq!(discover(&first, &isf, &job).unwrap(), (0x1000, K));
    drop(first);

    // The next session reuses the validated root for the same content.
    let reopened = Image::open(&path, &cache, &job).unwrap();
    assert_eq!(
        reopened.persisted_roots.get(&isf.digest),
        Some(&(0x1000, K))
    );
    assert_eq!(discover(&reopened, &isf, &job).unwrap(), (0x1000, K));
    drop(reopened);

    // A tampered hint fails validation and falls back to the full scan.
    let manifest = std::fs::read_dir(cache.join("identification"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    value["windows_roots"] = json!([[isf.digest, 0x5000, K + 0x1000]]);
    std::fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    let tampered = Image::open(&path, &cache, &job).unwrap();
    assert_eq!(
        tampered.persisted_roots.get(&isf.digest),
        Some(&(0x5000, K + 0x1000))
    );
    assert_eq!(discover(&tampered, &isf, &job).unwrap(), (0x1000, K));
    drop(tampered);

    // Different content (same size, new mtime) drops every Windows hint.
    let mut changed = b.clone();
    changed[0x3f000] = 0x41;
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(&path, &changed).unwrap();
    let other = Image::open(&path, &cache, &job).unwrap();
    assert!(other.persisted_roots.is_empty());
    assert_eq!(discover(&other, &isf, &job).unwrap(), (0x1000, K));
}
#[test]
fn identification_binds_windows_signatures_to_the_file_and_reuses_them() {
    let (b, _) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.raw");
    let cache = dir.path().join("cache");
    std::fs::write(&path, &b).unwrap();
    assert_eq!(crate::image::bound_identity(&path, &cache), None);
    let job = Job::default();
    let first = Image::open(&path, &cache, &job).unwrap();
    let keys = |image: &Image| {
        image
            .windows_candidates(&Job::default())
            .unwrap()
            .iter()
            .map(|c| (c.offset, c.pdb.key()))
            .collect::<Vec<_>>()
    };
    let found = keys(&first);
    assert_eq!(found.len(), 1);
    drop(first);
    let bound = crate::image::bound_identity(&path, &cache).unwrap();
    assert_eq!(bound.system, "windows");
    assert_eq!(bound.kernels, vec![format!("Windows PDB {}", found[0].1)]);

    let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = messages.clone();
    let recording = Job::new(move |message| log.lock().unwrap().push(message));
    let reused = |messages: &std::sync::Mutex<Vec<String>>| {
        messages
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.starts_with("复用持久化 Windows 内核签名"))
    };
    // Identification in a new session reuses the bound records, re-read once.
    let identified = Image::open_identified(&path, &cache, &recording).unwrap();
    assert!(reused(&messages));
    assert!(
        identified.digest.is_empty(),
        "identification never claims a digest"
    );
    assert_eq!(keys(&identified), found);
    drop(identified);

    // A record that no longer re-reads to the same identity is not trusted.
    let manifest = std::fs::read_dir(cache.join("identification"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    value["windows"][0][0] = json!(0x8000);
    std::fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    messages.lock().unwrap().clear();
    let rescanned = Image::open_identified(&path, &cache, &recording).unwrap();
    assert!(!reused(&messages));
    assert_eq!(keys(&rescanned), found);
    drop(rescanned);

    // Changing the file unbinds the identity until it is identified again.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let mut changed = b.clone();
    changed[0x3f000] = 0x41;
    std::fs::write(&path, &changed).unwrap();
    assert_eq!(crate::image::bound_identity(&path, &cache), None);
}
#[test]
fn a_recorded_digest_is_reused_only_when_settings_opt_in() {
    let (b, _) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.raw");
    let cache = dir.path().join("cache");
    let backdate = |path: &std::path::Path| {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60))
            .unwrap();
    };
    std::fs::write(&path, &b).unwrap();
    backdate(&path);
    let open = || {
        let job = Job::default();
        let image = Image::open(&path, &cache, &job).unwrap();
        (image.digest.clone(), job.prepared_image())
    };
    let (digest, prepared) = open();
    assert!(prepared && digest.len() == 64);
    // Default settings: every session reads the whole image again.
    assert_eq!(open(), (digest.clone(), true));

    let mut settings = store::settings(&cache).unwrap();
    assert!(
        !settings.reuse_recorded_digest,
        "full verification is the default"
    );
    settings.reuse_recorded_digest = true;
    store::save_settings(&cache, &settings).unwrap();
    assert_eq!(
        open(),
        (digest.clone(), false),
        "settled, unchanged file reuses"
    );

    // Changed content changes the metadata stamp: the digest is computed again.
    let mut changed = b.clone();
    changed[0x3f000] ^= 0x41;
    std::fs::write(&path, &changed).unwrap();
    let (fresh, prepared) = open();
    assert!(prepared);
    assert_ne!(fresh, digest);
    // Recorded while the file had not settled: not reusable even when unchanged.
    assert_eq!(open(), (fresh.clone(), true));
    backdate(&path);
    let (settled, prepared) = open();
    assert!(prepared && settled == fresh);
    assert_eq!(open(), (fresh, false));
}
#[test]
fn one_pdb_identity_found_at_several_offsets_is_one_match() {
    let (mut b, _) = fixture();
    // A second copy of the kernel's RSDS record, as kernel images often leave.
    let record = b[0x8600..0x8625].to_vec();
    b[0x30000..0x30025].copy_from_slice(&record);
    let image = image(&b);
    let job = Job::default();
    assert_eq!(image.windows_candidates(&job).unwrap().len(), 2);
    let dir = tempfile::tempdir().unwrap();
    let matches = crate::symbols::remote_matches(&image, dir.path(), false, &job).unwrap();
    assert_eq!(matches.len(), 1, "{matches:?}");
    assert!(matches[0].banner.starts_with("Windows PDB ntkrnlmp.pdb/"));
}

#[test]
fn module_range_survives_missing_path_text() {
    let (mut bytes, mut isf) = fixture();
    isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":64,"fields":{
        "InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},
        "BaseDllName":{"offset":16,"type":{"kind":"struct","name":"_UNICODE_STRING"}},
        "FullDllName":{"offset":32,"type":{"kind":"struct","name":"_UNICODE_STRING"}},
        "DllBase":{"offset":48,"type":{"kind":"pointer"}},
        "SizeOfImage":{"offset":56,"type":{"kind":"base","name":"u64"}}
    }});
    put(&mut bytes, 0x8700, K + 0x800);
    put(&mut bytes, 0x8708, K + 0x800);
    put(&mut bytes, 0x8800, K + 0x700);
    put(&mut bytes, 0x8808, K + 0x700);
    // Base name is resident; a malformed full path must not erase DllBase/size.
    put(&mut bytes, 0x8810, 4 | (4 << 16));
    put(&mut bytes, 0x8818, K + 0x900);
    bytes[0x8900..0x8904].copy_from_slice(&[b'n', 0, b't', 0]);
    put(&mut bytes, 0x8820, 4 | (2 << 16));
    put(&mut bytes, 0x8830, K);
    put(&mut bytes, 0x8838, 0x8000);
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let mut result = w.result(Plugin::WinModules);
    let modules = w.modules_partial(&Job::default(), &mut result).unwrap();
    assert_eq!(modules.len(), 1);
    assert_eq!((modules[0].base, modules[0].size), (K, 0x8000));
    assert_eq!(modules[0].name, "nt");
    assert!(modules[0].path.is_empty());
    assert!(!result.complete);
    assert_eq!(result.diagnostics.len(), 1);
}

pub(super) fn suspended_fixture(path: &str) -> (Vec<u8>, Isf) {
    let (mut b, mut isf) = fixture();
    let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
    let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
    isf.data["user_types"]["_EPROCESS"]["fields"]["ThreadListHead"] =
        json!({"offset":144,"type":{"kind":"struct","name":"_LIST_ENTRY"}});
    isf.data["user_types"]["_ETHREAD"] = json!({"size":80,"fields":{
            "ThreadListEntry":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},
            "Cid":{"offset":16,"type":{"kind":"struct","name":"_CLIENT_ID"}},
            "Tcb":{"offset":32,"type":{"kind":"struct","name":"_KTHREAD"}},
            "StartAddress":ptr(56),"Win32StartAddress":ptr(64)}});
    isf.data["user_types"]["_CLIENT_ID"] =
        json!({"size":16,"fields":{"UniqueProcess":ptr(0),"UniqueThread":ptr(8)}});
    isf.data["user_types"]["_KTHREAD"] =
        json!({"size":24,"fields":{"SuspendCount":number(0),"State":number(8),"Process":ptr(16)}});
    isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"] =
        json!({"offset":128,"type":{"kind":"struct","name":"_RTL_AVL_TREE"}});
    isf.data["user_types"]["_RTL_AVL_TREE"] = json!({"size":8,"fields":{"Root":ptr(0)}});
    isf.data["user_types"]["_RTL_BALANCED_NODE"] =
        json!({"size":24,"fields":{"Left":ptr(0),"Right":ptr(8)}});
    isf.data["user_types"]["_MMVAD_SHORT"] = json!({"size":64,"fields":{
            "VadNode":{"offset":0,"type":{"kind":"struct","name":"_RTL_BALANCED_NODE"}},
            "StartingVpn":number(24),"EndingVpn":number(32),"u":{"offset":40,"type":{"kind":"struct","name":"_MMVAD_FLAGS"}}}});
    isf.data["user_types"]["_MMVAD_FLAGS"] = json!({"size":8,"fields":{
            "Protection":{"offset":0,"type":{"kind":"bitfield","bit_position":0,"bit_length":5,"type":{"kind":"base","name":"u64"}}},
            "PrivateMemory":{"offset":0,"type":{"kind":"bitfield","bit_position":5,"bit_length":1,"type":{"kind":"base","name":"u64"}}}}});
    isf.data["user_types"]["_MMVAD"] = json!({"size":64,"fields":{"ControlArea":ptr(48)}});
    isf.data["user_types"]["_CONTROL_AREA"] = json!({"size":8,"fields":{"FilePointer":ptr(0)}});
    isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":16,"fields":{"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
    // Empty System thread list; two live suspended child threads.
    put(&mut b, 0x9090, K + 0x1090);
    put(&mut b, 0x9098, K + 0x1090);
    put(&mut b, 0xa090, K + 0x3000);
    put(&mut b, 0xa098, K + 0x3100);
    for (at, previous, next, tid) in [
        (0xb000, K + 0x2090, K + 0x3100, 99),
        (0xb100, K + 0x3000, K + 0x2090, 100),
    ] {
        for (offset, value) in [
            (0, next),
            (8, previous),
            (16, 8),
            (24, tid),
            (32, 1),
            (40, 5),
            (48, K + 0x2000),
            (56, 0x1234),
            (64, 0),
        ] {
            put(&mut b, at + offset, value);
        }
    }
    put(&mut b, 0xa080, K + 0x4000);
    for (at, value) in [
        (0xc018, 1),
        (0xc020, 1),
        (0xc028, 4),
        (0xc030, K + 0x5000),
        (0xd000, K + 0x6000),
    ] {
        put(&mut b, at, value);
    }
    let text: Vec<_> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    b[0xe000..0xe002].copy_from_slice(&(text.len() as u16).to_le_bytes());
    b[0xe002..0xe004].copy_from_slice(&(text.len() as u16).to_le_bytes());
    put(&mut b, 0xe008, K + 0x7000);
    b[0xf000..0xf000 + text.len()].copy_from_slice(&text);
    (b, isf)
}

pub(super) fn thread_exports_fixture(path: &str) -> (Vec<u8>, Isf) {
    let (mut b, isf) = suspended_fixture(path);
    // Map a user-mode PE independently of the kernel/process objects.
    put(&mut b, 0x1000, 0x2003);
    put(&mut b, 0xc018, 16);
    put(&mut b, 0xc020, 16);
    for at in [0xb000, 0xb100] {
        put(&mut b, at + 56, 0x10500);
        put(&mut b, at + 64, 0x10500);
    }
    let pe = &mut b[0x18000..0x19000];
    pe[..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    for (at, value) in [
        (0xd0, 0x1000u32),
        (0x104, 16),
        (0x108, 0x300),
        (0x10c, 0x40),
        (0x314, 1),
        (0x318, 1),
        (0x31c, 0x400),
        (0x320, 0x410),
        (0x324, 0x420),
        (0x400, 0x500),
        (0x410, 0x440),
    ] {
        pe[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    pe[0x440..0x446].copy_from_slice(b"Entry\0");
    (b, isf)
}

#[test]
fn captured_table_rejection_is_independent_of_cache_budget() {
    for budget in [0, 1, 1025] {
        for uniform in [false, true] {
            let (mut bytes, isf) = fixture();
            if uniform {
                for at in (0x4000..0x5000).step_by(8) {
                    put(&mut bytes, at, 0x8003);
                }
            }
            let mut img = image(&bytes);
            img.limits.page_cache_entries = budget;
            let vm = Memory::new(&img, 0x1000, &isf, None);
            for _ in 0..3 {
                for address in [K, K + 0x1000, K + 0x2000, K] {
                    let mut captured = [0];
                    let mut recovered = [0];
                    if uniform {
                        assert!(vm.translate(address).is_err());
                        assert!(vm.read_captured(address, &mut captured).is_err());
                        assert!(vm.read(address, &mut recovered).is_err());
                    } else {
                        assert_eq!(vm.translate(address).unwrap(), 0x8000 + address - K);
                        vm.read_captured(address, &mut captured).unwrap();
                        vm.read(address, &mut recovered).unwrap();
                        assert_eq!(captured, recovered);
                    }
                }
            }
        }
    }
}
