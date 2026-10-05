use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::{
    fs,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zero_tui::{
    Job,
    image::{Image, VirtualMemory},
    linux::{Linux, Plugin},
    store,
    symbols::{Isf, matching},
};

fn image(bytes: &[u8]) -> Image {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    Image::from_file(file, "synthetic".into()).unwrap()
}
fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn mapped() -> Vec<u8> {
    let mut b = vec![0; 0x12000];
    put(&mut b, 0x1000, 0x2003);
    put(&mut b, 0x2000, 0x3003);
    put(&mut b, 0x3000, 0x4003);
    put(&mut b, 0x4000 + 8, 0x8003);
    put(&mut b, 0x4000 + 16, 0xa003);
    b
}
fn symbols() -> Isf {
    let integer = |offset| json!({"offset":offset,"type":{"kind":"base","name":"int"}});
    let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
    let data = json!({"base_types":{"pointer":{"size":8},"int":{"size":4}},"symbols":{"linux_banner":{"address":0x1100,"constant_data":STANDARD.encode(b"Linux version synthetic\n\0")},"init_task":{"address":0x1200},"init_level4_pgt":{"address":0x1000},"modules":{"address":0x1500}},"user_types":{"list_head":{"size":16,"fields":{"next":pointer(0),"prev":pointer(8)}},"task_struct":{"size":80,"fields":{"tasks":{"offset":0,"type":{"kind":"struct","name":"list_head"}},"pid":integer(16),"tgid":integer(20),"real_parent":pointer(24),"comm":{"offset":32,"type":{"kind":"array","count":16}}}},"module":{"size":80,"fields":{"list":{"offset":0,"type":{"kind":"struct","name":"list_head"}},"name":{"offset":16,"type":{"kind":"array","count":16}},"module_core":pointer(32),"core_size":integer(40)}}}});
    Isf::parse(&serde_json::to_vec(&data).unwrap(), "synthetic.json".into()).unwrap()
}
fn linked() -> Vec<u8> {
    let mut b = mapped();
    // Virtual page 0x1000 maps to physical 0x8000.
    put(&mut b, 0x8200, 0x1300);
    put(&mut b, 0x8208, 0x1400);
    b[0x8220..0x8227].copy_from_slice(b"swapper");
    put(&mut b, 0x8300, 0x1400);
    put(&mut b, 0x8308, 0x1200);
    b[0x8310..0x8314].copy_from_slice(&1u32.to_le_bytes());
    b[0x8314..0x8318].copy_from_slice(&1u32.to_le_bytes());
    put(&mut b, 0x8318, 0x1200);
    b[0x8320..0x8324].copy_from_slice(b"init");
    put(&mut b, 0x8400, 0x1200);
    put(&mut b, 0x8408, 0x1300);
    b[0x8410..0x8414].copy_from_slice(&2u32.to_le_bytes());
    b[0x8414..0x8418].copy_from_slice(&2u32.to_le_bytes());
    put(&mut b, 0x8418, 0x1300);
    b[0x8420..0x8425].copy_from_slice(b"child");
    put(&mut b, 0x8500, 0x1600);
    put(&mut b, 0x8508, 0x1600);
    put(&mut b, 0x8600, 0x1500);
    put(&mut b, 0x8608, 0x1500);
    b[0x8610..0x8614].copy_from_slice(b"test");
    put(&mut b, 0x8620, 0x9000);
    b[0x8628..0x862c].copy_from_slice(&4096u32.to_le_bytes());
    b
}
#[test]
fn normal_pages_cross_page_and_missing() {
    let mut b = mapped();
    b[0x8ffe..0x9000].copy_from_slice(&[1, 2]);
    b[0xa000..0xa002].copy_from_slice(&[3, 4]);
    let image = image(&b);
    let vm = VirtualMemory {
        image: &image,
        root: 0x1000,
    };
    assert_eq!(vm.translate(0x1234).unwrap(), 0x8234);
    let mut out = [0; 4];
    vm.read(0x1ffe, &mut out).unwrap();
    assert_eq!(out, [1, 2, 3, 4]);
    assert!(
        vm.translate(0x3000)
            .unwrap_err()
            .to_string()
            .contains("缺页")
    );
    assert!(vm.translate(0x0001_0000_0000_0000).is_err());
    assert!(image.read(u64::MAX, &mut out).is_err());
}
#[test]
fn large_pages() {
    let mut b = mapped();
    put(&mut b, 0x2000 + 8, 0x4000_0083);
    put(&mut b, 0x3000 + 8, 0x20_0083);
    let image = image(&b);
    let vm = VirtualMemory {
        image: &image,
        root: 0x1000,
    };
    assert_eq!(vm.translate(0x4000_1234).unwrap(), 0x4000_1234);
    assert_eq!(vm.translate(0x20_1234).unwrap(), 0x20_1234);
}
#[test]
fn lime_holes_and_truncation() {
    let mut b = vec![];
    for (start, end, data) in [
        (0x1000u64, 0x1003u64, [1u8, 2, 3, 4]),
        (0x2000, 0x2003, [5, 6, 7, 8]),
    ] {
        b.extend_from_slice(&0x4c694d45u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&start.to_le_bytes());
        b.extend_from_slice(&end.to_le_bytes());
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&data);
    }
    let image = image(&b);
    assert_eq!(image.format, "LiME");
    let mut out = [0; 4];
    image.read(0x1000, &mut out).unwrap();
    assert_eq!(out, [1, 2, 3, 4]);
    assert!(image.read(0x1002, &mut out).is_err());
    b.pop();
    let mut f = tempfile::tempfile().unwrap();
    f.write_all(&b).unwrap();
    assert!(Image::from_file(f, String::new()).is_err());
}
#[test]
fn closed_lists_and_parent_fields() {
    let image = image(&linked());
    let isf = symbols();
    let linux = Linux {
        vm: VirtualMemory {
            image: &image,
            root: 0x1000,
        },
        isf: &isf,
    };
    let r = linux.run(Plugin::Pslist, &Job::default()).unwrap();
    assert!(r.complete);
    assert_eq!(r.rows.len(), 2);
    assert_eq!(
        r.rows[1],
        vec!["2", "2", "1", "child", "0x0000000000001400"]
    );
    let m = linux.run(Plugin::Lsmod, &Job::default()).unwrap();
    assert!(m.complete);
    assert_eq!(m.rows[0], vec!["test", "0x0000000000009000", "4096"]);
}
#[test]
fn corrupt_and_cyclic_lists_are_partial_uncached() {
    let mut b = linked();
    put(&mut b, 0x8400, 0x1300);
    let image = image(&b);
    let isf = symbols();
    let r = Linux {
        vm: VirtualMemory {
            image: &image,
            root: 0x1000,
        },
        isf: &isf,
    }
    .run(Plugin::Pslist, &Job::default())
    .unwrap();
    assert!(!r.complete);
    assert!(r.diagnostics[0].contains("链表"));
    let cache = tempfile::tempdir().unwrap();
    store::save(cache.path(), "test", &r, &Job::default()).unwrap();
    assert!(store::load(cache.path(), "test").is_none());
}
#[test]
fn full_banner_match_and_mismatch() -> Result<()> {
    let mut b = mapped();
    let isf = symbols();
    b[0x8100..0x8100 + isf.banner.len()].copy_from_slice(&isf.banner);
    let img = image(&b);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("isf.json");
    fs::write(&path, serde_json::to_vec(&isf.data)?)?;
    assert_eq!(matching(&path, &img, &Job::default())?.len(), 1);
    b[0x8100 + 14] = b'!';
    assert!(matching(&path, &image(&b), &Job::default()).is_err());
    Ok(())
}
#[test]
fn gzip_cancel_and_repair() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("cache");
    let path = dir.path().join("image.gz");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&vec![7; 16 * 1024 * 1024])?;
    fs::write(&path, encoder.finish()?)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let toggle = cancelled.clone();
    let mut job = Job::new(move |s| {
        if s.starts_with("解压") {
            toggle.store(true, Ordering::Relaxed);
        }
    });
    job.cancel = cancelled;
    assert!(Image::open(&path, &cache, &job).is_err());
    assert_eq!(
        fs::read_dir(&cache)?
            .filter(|e| e.as_ref().unwrap().file_name() != "cache.lock")
            .count(),
        0
    );
    let image = Image::open(&path, &cache, &Job::default())?;
    let digest = image.digest.clone();
    let prepared = fs::read_dir(&cache)?
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|s| s == "image"))
        .unwrap();
    fs::write(prepared, b"bad")?;
    assert_eq!(Image::open(&path, &cache, &Job::default())?.digest, digest);
    Ok(())
}
#[test]
fn cache_key_invalidation_and_filtered_export() -> Result<()> {
    assert_ne!(
        store::key("a", "s", "pslist"),
        store::key("b", "s", "pslist")
    );
    assert_ne!(
        store::key("a", "s", "pslist"),
        store::key("a", "t", "pslist")
    );
    assert_ne!(
        store::key("a", "s", "pslist"),
        store::key("a", "s", "pstree")
    );
    let img = image(&linked());
    let isf = symbols();
    let r = Linux {
        vm: VirtualMemory {
            image: &img,
            root: 0x1000,
        },
        isf: &isf,
    }
    .run(Plugin::Pslist, &Job::default())?;
    let dir = tempfile::tempdir()?;
    let key = store::key("a", "s", "pslist");
    store::save(dir.path(), &key, &r, &Job::default())?;
    assert_eq!(store::load(dir.path(), &key), Some(r.clone()));
    let path = dir.path().join("filtered.csv");
    store::export(&path, &r, r.filtered("CHILD"))?;
    let history = store::history(&path)?;
    assert!(history.historical);
    assert!(!history.complete);
    assert_eq!(history.rows.len(), 1);
    Ok(())
}

fn discoverable() -> (Vec<u8>, Isf) {
    let mut b = linked();
    put(&mut b, 0x4000 + 9 * 8, 0x8003);
    for physical in [
        0x8200, 0x8208, 0x8300, 0x8308, 0x8318, 0x8400, 0x8408, 0x8418, 0x8500, 0x8508, 0x8600,
        0x8608,
    ] {
        let old = u64::from_le_bytes(b[physical..physical + 8].try_into().unwrap());
        put(&mut b, physical, old + 0x8000);
    }
    let mut isf = symbols();
    isf.data["symbols"]["linux_banner"]["address"] = json!(0x9100);
    isf.data["symbols"]["init_task"]["address"] = json!(0x9200);
    isf.data["symbols"]["init_level4_pgt"]["address"] = json!(0x2000);
    isf.data["symbols"]["modules"]["address"] = json!(0x9500);
    b[0x8100..0x8100 + isf.banner.len()].copy_from_slice(&isf.banner);
    isf.locations = vec![0x8100];
    (b, isf)
}
#[test]
fn page_table_discovery_rejects_wrong_symbols() -> Result<()> {
    let (b, mut isf) = discoverable();
    let img = image(&b);
    assert_eq!(
        zero_tui::linux::discover(&img, &isf, &Job::default())?,
        0x1000
    );
    isf.data["symbols"]["init_task"]["address"] = json!(0x9300);
    assert!(zero_tui::linux::discover(&img, &isf, &Job::default()).is_err());
    Ok(())
}
#[test]
fn xz_zip_and_ambiguous_symbols() -> Result<()> {
    use zero_tui::linux::{self, Outcome};
    let (b, isf) = discoverable();
    let dir = tempfile::tempdir()?;
    let img_path = dir.path().join("image.raw");
    fs::write(&img_path, &b)?;
    let json = serde_json::to_vec(&isf.data)?;
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&json)?;
    let compressed = encoder.finish()?;
    let xz = dir.path().join("symbol.json.xz");
    fs::write(&xz, &compressed)?;
    assert_eq!(matching(&xz, &image(&b), &Job::default())?.len(), 1);
    let zip = dir.path().join("symbols.zip");
    let mut archive = zip::ZipWriter::new(fs::File::create(&zip)?);
    archive.start_file("linux/one.json", zip::write::SimpleFileOptions::default())?;
    archive.write_all(&json)?;
    archive.start_file(
        "linux/two.json.xz",
        zip::write::SimpleFileOptions::default(),
    )?;
    archive.write_all(&compressed)?;
    archive.finish()?;
    let cache = dir.path().join("cache");
    let Outcome::Choose(labels) = linux::analyze(
        &img_path,
        &zip,
        None,
        Plugin::Pslist,
        &cache,
        true,
        &Job::default(),
    )?
    else {
        panic!("ambiguous candidates must require selection")
    };
    assert_eq!(labels.len(), 2);
    let Outcome::Ready(result) = linux::analyze(
        &img_path,
        &zip,
        Some(&labels[1]),
        Plugin::Pslist,
        &cache,
        true,
        &Job::default(),
    )?
    else {
        panic!()
    };
    assert!(result.complete);
    assert_eq!(result.rows.len(), 2);
    Ok(())
}
#[test]
fn gzip_truncation_does_not_commit() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let cache = dir.path().join("cache");
    let path = dir.path().join("broken.gz");
    fs::write(&path, [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 3])?;
    assert!(Image::open(&path, &cache, &Job::default()).is_err());
    assert_eq!(
        fs::read_dir(cache)?
            .filter(|e| e.as_ref().unwrap().file_name() != "cache.lock")
            .count(),
        0
    );
    Ok(())
}
#[test]
fn cli_exports_native_result() -> Result<()> {
    let (b, isf) = discoverable();
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("image.raw"), b)?;
    fs::write(
        dir.path().join("symbols.json"),
        serde_json::to_vec(&isf.data)?,
    )?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zero-tui"))
        .current_dir(dir.path())
        .args([
            "analyze",
            "--image",
            "image.raw",
            "--symbols",
            "symbols.json",
            "--plugin",
            "pslist",
            "--output",
            "result.json",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: store::Results =
        serde_json::from_slice(&fs::read(dir.path().join("result.json"))?)?;
    assert!(result.complete);
    assert_eq!(result.rows.len(), 2);
    Ok(())
}

#[test]
fn scan_crosses_chunk_and_contiguous_lime_ranges() -> Result<()> {
    let mut b = vec![0; 4 * 1024 * 1024 + 128];
    let needle = b"Linux version cross-boundary\n\0";
    let start = 4 * 1024 * 1024 - 8;
    b[start..start + needle.len()].copy_from_slice(needle);
    assert_eq!(image(&b).scan(needle, &Job::default())?, vec![start as u64]);
    let mut lime = Vec::new();
    for (start, data) in [(0x1000u64, &needle[..8]), (0x1008, &needle[8..])] {
        lime.extend_from_slice(&0x4c694d45u32.to_le_bytes());
        lime.extend_from_slice(&1u32.to_le_bytes());
        lime.extend_from_slice(&start.to_le_bytes());
        lime.extend_from_slice(&(start + data.len() as u64 - 1).to_le_bytes());
        lime.extend_from_slice(&[0; 8]);
        lime.extend_from_slice(data);
    }
    assert_eq!(image(&lime).scan(needle, &Job::default())?, vec![0x1000]);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("cross-segment.lime");
    fs::write(&path, &lime)?;
    let fused = Image::open(&path, &dir.path().join("cache"), &Job::default())?;
    assert_eq!(
        fused.banners(&Job::default())?,
        vec![(0x1000, needle.to_vec())]
    );
    Ok(())
}
#[test]
fn malformed_addresses_return_diagnostics() -> Result<()> {
    let (b, mut isf) = discoverable();
    isf.data["symbols"]["init_task"]["address"] = json!(u64::MAX - 4);
    assert!(zero_tui::linux::discover(&image(&b), &isf, &Job::default()).is_err());
    let mut b = linked();
    put(&mut b, 0x8300, u64::MAX - 4);
    let isf = symbols();
    let img = image(&b);
    let result = Linux {
        vm: VirtualMemory {
            image: &img,
            root: 0x1000,
        },
        isf: &isf,
    }
    .run(Plugin::Pslist, &Job::default())?;
    assert!(!result.complete);
    assert!(result.diagnostics[0].contains("溢出"));
    Ok(())
}
#[test]
fn obsolete_python_configuration_is_ignored() -> Result<()> {
    let (b, isf) = discoverable();
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("zero"))?;
    let config = "import os\nos.system('touch executed')\nEXPORT_DIR = 'exports'\nRESULTS_CACHE_DIR = 'history'\nENABLE_DISK_CACHE = False\nAI_API_KEY = 'preserved-but-unused'\n";
    fs::write(dir.path().join("zero/config.py"), config)?;
    fs::write(dir.path().join("image.raw"), b)?;
    fs::write(
        dir.path().join("symbols.json"),
        serde_json::to_vec(&isf.data)?,
    )?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zero-tui"))
        .current_dir(dir.path())
        .args([
            "analyze",
            "--image",
            "image.raw",
            "--symbols",
            "symbols.json",
            "--plugin",
            "pslist",
            "--output",
            "result.csv",
        ])
        .output()?;
    assert!(output.status.success());
    assert!(!dir.path().join("executed").exists());
    assert!(!dir.path().join(".zero/rust/migration").exists());
    let settings: store::Settings =
        serde_json::from_slice(&fs::read(dir.path().join(".zero/rust/settings.json"))?)?;
    assert_eq!(settings.export_dir, "exports");
    assert_eq!(settings.history_dir, "exports");
    assert!(settings.enable_cache);
    Ok(())
}

#[test]
fn single_banner_scan_remote_links_and_cached_download_validation() -> Result<()> {
    use sha2::{Digest, Sha256};
    use zero_tui::symbols::{self, RemoteMatch};
    let (b, isf) = discoverable();
    let img = image(&b);
    let dir = tempfile::tempdir()?;
    let job = Job::default();
    let banner = String::from_utf8_lossy(&isf.banner)
        .trim_end_matches(['\0', '\n'])
        .to_string();
    let path = "Debian/amd64/3.2/test+build.json.xz";
    let index = json!({banner.clone():[path,"Ubuntu/arm64/a.json.xz"]});
    let matches = symbols::lookup_index(&index, &img.banners(&job)?)?;
    assert_eq!(matches.len(), 1);
    assert!(matches[0].url.ends_with("test%2Bbuild.json.xz"));
    assert!(
        symbols::lookup_index(
            &json!({banner.clone():["../bad.json.xz"]}),
            &img.banners(&job)?
        )
        .is_err()
    );
    assert!(symbols::repository_url("https://elsewhere/a.json.xz").is_err());
    assert!(symbols::repository_url("Debian/amd64/no.json").is_err());
    store::atomic_write(
        &dir.path().join("symbols/banners_plain.json"),
        &serde_json::to_vec(&index)?,
    )?;
    assert_eq!(
        symbols::remote_matches(&img, dir.path(), false, &job)?.len(),
        1
    );
    let key = format!("{:x}", Sha256::digest(path.as_bytes()));
    let target = dir
        .path()
        .join("symbols/isf")
        .join(format!("{key}.json.xz"));
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&serde_json::to_vec(&isf.data)?)?;
    store::atomic_write(&target, &encoder.finish()?)?;
    assert_eq!(
        symbols::download(&matches[0], &img, dir.path(), false, &job)?.locations,
        vec![0x8100]
    );
    let false_banner = RemoteMatch {
        banner: "Linux version other".into(),
        ..matches[0].clone()
    };
    assert!(symbols::download(&false_banner, &img, dir.path(), false, &job).is_err());
    let injected = RemoteMatch {
        url: "https://elsewhere/a.json.xz".into(),
        ..matches[0].clone()
    };
    assert!(symbols::download(&injected, &img, dir.path(), false, &job).is_err());
    fs::write(&target, b"truncated xz")?;
    assert!(symbols::download(&matches[0], &img, dir.path(), false, &job).is_err());
    let job = Job::default();
    job.cancel.store(true, Ordering::Relaxed);
    assert!(symbols::remote_matches(&img, dir.path(), true, &job).is_err());
    let empty = tempfile::tempdir()?;
    assert!(symbols::remote_matches(&img, empty.path(), false, &Job::default()).is_err());
    Ok(())
}
#[test]
fn session_reuses_preparation_and_invalidates_changes() -> Result<()> {
    use zero_tui::linux::{Outcome, Request, Session};
    let (mut b, mut isf) = discoverable();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("image.raw");
    let symbols = dir.path().join("symbols.json");
    fs::write(&path, &b)?;
    fs::write(&symbols, serde_json::to_vec(&isf.data)?)?;
    let progress = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = progress.clone();
    let job = Job::new(move |s| sink.lock().unwrap().push(s));
    let mut session = Session::default();
    let request = |plugin| Request {
        image: &path,
        symbols: &symbols,
        choice: None,
        plugin,
        cache: dir.path(),
        use_cache: false,
        network: false,
    };
    session.analyze(&request(Plugin::Pslist), &job)?;
    progress.lock().unwrap().clear();
    session.analyze(&request(Plugin::Lsmod), &job)?;
    assert!(
        progress
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("复用"))
    );
    assert!(
        !progress
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("计算镜像") || s.starts_with("扫描 banner"))
    );
    b[0x8320] = b'Z';
    fs::write(&path, &b)?;
    progress.lock().unwrap().clear();
    let Outcome::Ready(result) = session.analyze(&request(Plugin::Pslist), &job)? else {
        panic!("ambiguous")
    };
    assert_eq!(result.rows[0][3], "Znit");
    assert!(
        progress
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("计算镜像"))
    );
    isf.data["metadata"] = json!({"changed":true});
    fs::write(&symbols, serde_json::to_vec(&isf.data)?)?;
    progress.lock().unwrap().clear();
    session.analyze(&request(Plugin::Lsmod), &job)?;
    assert!(
        progress
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("读取本地 ISF"))
    );
    // Downloaded symbols also participate in same-session invalidation.
    let downloaded = dir.path().join("symbols/isf");
    fs::create_dir_all(&downloaded)?;
    let cached_isf = downloaded.join("cached.json");
    fs::rename(&symbols, &cached_isf)?;
    session.analyze(&request(Plugin::Pslist), &job)?;
    isf.data["metadata"] = json!({"changed":"downloaded"});
    fs::write(&cached_isf, serde_json::to_vec(&isf.data)?)?;
    progress.lock().unwrap().clear();
    session.analyze(&request(Plugin::Pslist), &job)?;
    assert!(
        !progress
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("复用"))
    );
    let link = dir.path().join("link.raw");
    std::os::unix::fs::symlink(&path, &link)?;
    assert_eq!(
        session.prepare_image(&link, dir.path(), &job)?.format,
        "RAW"
    );
    Ok(())
}

#[test]
fn fused_identification_cache_is_only_a_hint_and_crosses_boundaries() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("raw");
    let cache = dir.path().join("cache");
    let mut data = vec![0; 4 * 1024 * 1024 + 100];
    let banner = b"Linux version original\n\0";
    let offset = 4 * 1024 * 1024 - 8;
    data[offset..offset + banner.len()].copy_from_slice(banner);
    fs::write(&path, &data)?;
    let events = Arc::new(std::sync::Mutex::new(vec![]));
    let sink = events.clone();
    let job = Job::new(move |s| sink.lock().unwrap().push(s));
    let first = Image::open(&path, &cache, &job)?;
    assert_eq!(first.banners(&job)?, vec![(offset as u64, banner.to_vec())]);
    let digest = first.digest.clone();
    drop(first);
    events.lock().unwrap().clear();
    let same = Image::open(&path, &cache, &job)?;
    assert_eq!(same.digest, digest);
    drop(same);
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("缓存内核候选") && s.contains("尚待验证"))
    );
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("计算镜像摘要"))
    );
    // Same length and a forged matching metadata stamp cannot bypass the hash.
    data[offset + 14] = b'X';
    fs::write(&path, &data)?;
    let manifest = fs::read_dir(cache.join("identification"))?
        .next()
        .unwrap()?
        .path();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
    let stamp = zero_tui::image::metadata_stamp(&fs::metadata(&path)?)?;
    value["source_stamp"] = json!(stamp);
    value["prepared_stamp"] = value["source_stamp"].clone();
    fs::write(manifest, serde_json::to_vec(&value)?)?;
    events.lock().unwrap().clear();
    let changed = Image::open(&path, &cache, &job)?;
    assert_ne!(changed.digest, digest);
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.starts_with("缓存内核候选"))
    );
    assert_eq!(
        changed.banners(&job)?[0].1,
        data[offset..offset + banner.len()]
    );
    Ok(())
}

#[test]
fn arm64_discovery_validates_nonzero_slide_and_configuration() -> Result<()> {
    use zero_tui::linux;
    let (mut bytes, mut isf) = discoverable();
    let slide = 0x200000;
    // Four-level ARM tables have table/page descriptor bit 1 set.
    put(&mut bytes, 0x3008, 0x4003);
    for offset in [
        0x8200, 0x8208, 0x8300, 0x8308, 0x8318, 0x8400, 0x8408, 0x8418, 0x8500, 0x8508, 0x8600,
        0x8608,
    ] {
        let value = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        put(&mut bytes, offset, value + slide);
    }
    put(&mut bytes, 0x8218, 0x9200 + slide);
    isf.data["metadata"]["zero"] = json!({"architecture":"aarch64","page_shift":12,"va_bits":48});
    isf.data["symbols"]["swapper_pg_dir"] = json!({"address":0x2000});
    let img = image(&bytes);
    let root = linux::discover(&img, &isf, &Job::default())?;
    assert_eq!(root, 0x1000);
    assert_eq!(isf.address("init_task")?, 0x9200 + slide);
    let results = Linux {
        vm: VirtualMemory { image: &img, root },
        isf: &isf,
    }
    .run(Plugin::Pslist, &Job::default())?;
    assert!(results.complete, "{:?}", results.diagnostics);
    assert_eq!(results.rows[0][4], "0x0000000000209300");
    bytes[0x8100] ^= 1;
    assert!(linux::discover(&image(&bytes), &isf, &Job::default()).is_err());
    isf.data["metadata"]["zero"]["va_bits"] = json!(304);
    assert!(linux::discover(&img, &isf, &Job::default()).is_err());
    Ok(())
}

#[test]
fn new_state_and_capability_plugins_use_isf_and_preserve_partial_results() -> Result<()> {
    let mut bytes = linked();
    let mut isf = symbols();
    isf.data["base_types"]["u64"] = json!({"size":8});
    for (name, offset, kind) in [
        ("state", 48, "int"),
        ("exit_state", 52, "int"),
        ("flags", 56, "u64"),
    ] {
        isf.data["user_types"]["task_struct"]["fields"][name] =
            json!({"offset":offset,"type":{"kind":"base","name":kind}});
    }
    isf.data["user_types"]["task_struct"]["fields"]["cred"] =
        json!({"offset":64,"type":{"kind":"pointer"}});
    let mut fields = serde_json::Map::new();
    for (i, name) in [
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bset",
    ]
    .iter()
    .enumerate()
    {
        fields.insert(name.to_string(),json!({"offset":i*8,"type":{"kind":"array","count":2,"subtype":{"kind":"base","name":"int"}}}));
        put(&mut bytes, 0x8600 + i * 8, 0x1234567800000000 + i as u64);
    }
    isf.data["user_types"]["cred"] = json!({"size":32,"fields":fields});
    for address in [0x8300, 0x8400] {
        bytes[address + 48..address + 52].copy_from_slice(&2u32.to_le_bytes());
        put(&mut bytes, address + 56, 0xabcdef);
        put(&mut bytes, address + 64, 0x1600);
    }
    let memory = image(&bytes);
    let linux = Linux {
        vm: VirtualMemory {
            image: &memory,
            root: 0x1000,
        },
        isf: &isf,
    };
    let states = linux.run(Plugin::Psstate, &Job::default())?;
    assert!(states.complete);
    assert_eq!(states.rows.len(), 2);
    assert_eq!(states.rows[0][2], "0x0000000000000002");
    let caps = linux.run(Plugin::Capabilities, &Job::default())?;
    assert!(caps.complete);
    assert_eq!(caps.rows[0][2], "0x1234567800000000");
    assert_eq!(caps.rows[0][5], "0x1234567800000003");
    put(&mut bytes, 0x8400 + 64, 0);
    let memory = image(&bytes);
    let linux = Linux {
        vm: VirtualMemory {
            image: &memory,
            root: 0x1000,
        },
        isf: &isf,
    };
    let caps = linux.run(Plugin::Capabilities, &Job::default())?;
    assert!(!caps.complete);
    assert_eq!(caps.rows.len(), 1);
    assert!(caps.diagnostics.iter().any(|s| s.contains("PID 2")));
    assert!(
        Linux {
            vm: VirtualMemory {
                image: &memory,
                root: 0x1000
            },
            isf: &symbols()
        }
        .run(Plugin::Psstate, &Job::default())
        .is_err()
    );
    Ok(())
}

#[test]
fn catalog_manual_search_and_offline_download_without_an_image() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let isf = symbols();
    let banner = String::from_utf8_lossy(&isf.banner)
        .trim_end_matches(['\0', '\n'])
        .to_string();
    let path = "Debian/amd64/test/Synthetic_3.2.json.xz";
    store::atomic_write(
        &dir.path().join("symbols/banners_plain.json"),
        &serde_json::to_vec(&json!({banner: [path],"Darwin kernel": ["macOS/wrong.json.xz"]}))?,
    )?;
    let found =
        zero_tui::symbols::catalog_search(dir.path(), "debian synthetic", false, &Job::default())?;
    assert_eq!(found.len(), 1);
    assert!(
        zero_tui::symbols::catalog_search(dir.path(), "unmatched", false, &Job::default())?
            .is_empty()
    );
    let target = dir
        .path()
        .join("symbols/isf")
        .join(zero_tui::symbols::cache_filename(path)?);
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&serde_json::to_vec(&isf.data)?)?;
    store::atomic_write(&target, &encoder.finish()?)?;
    let downloaded =
        zero_tui::symbols::download_catalog(&found[0], dir.path(), false, &Job::default())?;
    assert!(downloaded.locations.is_empty());
    assert_eq!(downloaded.banner, isf.banner);
    let mut mismatch = found[0].clone();
    mismatch.banner = "Linux version mismatched".into();
    assert!(
        zero_tui::symbols::download_catalog(&mismatch, dir.path(), false, &Job::default()).is_err()
    );
    Ok(())
}

fn dump_fixture() -> (Image, Isf) {
    let mut bytes = linked();
    let mut isf = symbols();
    isf.data["user_types"]["task_struct"]["fields"]["mm"] =
        json!({"offset":48,"type":{"kind":"pointer"}});
    isf.data["user_types"]["mm_struct"] = json!({"size":16,"fields":{
        "pgd":{"offset":0,"type":{"kind":"pointer"}},
        "mmap":{"offset":8,"type":{"kind":"pointer"}}
    }});
    isf.data["user_types"]["vm_area_struct"] = json!({"size":32,"fields":{
        "vm_start":{"offset":0,"type":{"kind":"pointer"}},
        "vm_end":{"offset":8,"type":{"kind":"pointer"}},
        "vm_flags":{"offset":16,"type":{"kind":"pointer"}},
        "vm_next":{"offset":24,"type":{"kind":"pointer"}}
    }});
    put(&mut bytes, 0x8330, 0x1700); // Only PID 1 has this address space.
    put(&mut bytes, 0x8700, 0x2000); // Kernel VA 0x2000 -> physical PGD 0xa000.
    put(&mut bytes, 0x8708, 0x1800);
    put(&mut bytes, 0x8800, 0x4000);
    put(&mut bytes, 0x8808, 0x6000);
    put(&mut bytes, 0x8810, 1);
    put(&mut bytes, 0xa000, 0xb003);
    put(&mut bytes, 0xb000, 0xc003);
    put(&mut bytes, 0xc000, 0xd003);
    put(&mut bytes, 0xd020, 0xe003);
    put(&mut bytes, 0xd028, 0xf003);
    bytes[0xe000..0xe007].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[0xeffc..0xf004].copy_from_slice(b"Evidence");
    (image(&bytes), isf)
}
#[test]
fn targeted_dump_matches_process_bytes_hash_and_manifest() -> Result<()> {
    use sha2::{Digest, Sha256};
    use zero_tui::dump::DumpOptions;
    let (image, isf) = dump_fixture();
    let engine = Linux {
        vm: VirtualMemory {
            image: &image,
            root: 0x1000,
        },
        isf: &isf,
    };
    let dir = tempfile::tempdir()?;
    let mut options = DumpOptions {
        pid: 1,
        directory: dir.path().canonicalize()?.join("nested/output"),
        start: Some(0x4ffc),
        end: Some(0x5004),
    };
    let result = engine.run_dump(Plugin::Memdump, &options, &Job::default())?;
    assert!(result.complete, "{:?}", result.diagnostics);
    assert_eq!(result.rows.len(), 1);
    let row = &result.rows[0];
    assert_eq!(
        &row[..5],
        ["1", "init", "0x0000000000004ffc", "0x0000000000005004", "8"]
    );
    assert_eq!(fs::read(&row[6])?, b"Evidence");
    assert_eq!(row[5], format!("{:x}", Sha256::digest(b"Evidence")));
    // Reruns create another evidence directory, leaving the previous file intact.
    let repeat = engine.run_dump(Plugin::Memdump, &options, &Job::default())?;
    assert_ne!(repeat.rows[0][6], row[6]);
    assert_eq!(fs::read(&row[6])?, b"Evidence");
    options.start = None;
    options.end = None;
    let process = engine.run_dump(Plugin::Procdump, &options, &Job::default())?;
    assert!(process.complete);
    assert_eq!(process.rows.len(), 1);
    assert!(process.rows.iter().all(|r| r[0] == "1"));
    assert_eq!(fs::metadata(&process.rows[0][6])?.len(), 8192);
    let elf = engine.run_dump(Plugin::Elfdump, &options, &Job::default())?;
    assert!(elf.complete);
    assert_eq!(elf.rows.len(), 1);
    assert_eq!(&fs::read(&elf.rows[0][6])?[..4], b"\x7fELF");
    options.pid = 2;
    assert!(
        engine
            .run_dump(Plugin::Procdump, &options, &Job::default())
            .err()
            .unwrap()
            .to_string()
            .contains("内核线程")
    );
    options.pid = 99;
    assert!(
        engine
            .run_dump(Plugin::Procdump, &options, &Job::default())
            .err()
            .unwrap()
            .to_string()
            .contains("未找到 PID")
    );
    Ok(())
}
#[test]
fn failed_dump_keeps_no_partial_binary_and_cancel_stops_writes() -> Result<()> {
    use zero_tui::dump::DumpOptions;
    let (image, isf) = dump_fixture();
    let engine = Linux {
        vm: VirtualMemory {
            image: &image,
            root: 0x1000,
        },
        isf: &isf,
    };
    let dir = tempfile::tempdir()?;
    let options = DumpOptions {
        pid: 1,
        directory: dir.path().canonicalize()?.join("failed"),
        start: Some(0x5ffc),
        end: Some(0x6004),
    };
    let result = engine.run_dump(Plugin::Memdump, &options, &Job::default())?;
    assert!(!result.complete);
    assert!(result.rows.is_empty());
    assert!(result.diagnostics[0].contains("PID 1"));
    for sub in fs::read_dir(&options.directory)? {
        assert_eq!(fs::read_dir(sub?.path())?.count(), 0); // Failed temporary file was removed.
    }
    let cancel = Job::default();
    cancel.cancel.store(true, Ordering::Relaxed);
    let fresh = DumpOptions {
        directory: dir.path().join("cancelled"),
        ..options
    };
    assert!(engine.run_dump(Plugin::Memdump, &fresh, &cancel).is_err());
    assert!(!fresh.directory.exists());
    Ok(())
}
#[test]
fn cancellation_during_dump_does_not_commit_evidence() -> Result<()> {
    use zero_tui::dump::DumpOptions;
    let (image, isf) = dump_fixture();
    let engine = Linux {
        vm: VirtualMemory {
            image: &image,
            root: 0x1000,
        },
        isf: &isf,
    };
    let dir = tempfile::tempdir()?;
    let options = DumpOptions {
        pid: 1,
        directory: dir.path().canonicalize()?.join("cancel"),
        start: Some(0x4000),
        end: Some(0x6000),
    };
    let flag = Arc::new(AtomicBool::new(false));
    let report_flag = flag.clone();
    let mut job = Job::new(move |message| {
        if message.starts_with("dump ") {
            report_flag.store(true, Ordering::Relaxed);
        }
    });
    job.cancel = flag;
    assert!(engine.run_dump(Plugin::Memdump, &options, &job).is_err());
    for sub in fs::read_dir(options.directory)? {
        assert_eq!(fs::read_dir(sub?.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn cli_dump_requires_parameters_before_opening_image() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zero-tui"))
        .current_dir(dir.path())
        .args([
            "--offline",
            "analyze",
            "--image",
            "absent.raw",
            "--plugin",
            "procdump",
            "--output",
            "manifest.json",
        ])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--pid"));
    assert!(!dir.path().join("manifest.json").exists());
    assert!(!dir.path().join(".zero/rust/dumps").exists());
    Ok(())
}

#[test]
fn local_symbol_library_matches_complete_banner_and_reports_corruption() -> Result<()> {
    use zero_tui::symbols::match_local_files;
    let (bytes, isf) = discoverable();
    let dir = tempfile::tempdir()?;
    let exact = dir.path().join("exact.json");
    let duplicate = dir.path().join("duplicate.json");
    let wrong = dir.path().join("same-version.json");
    let broken = dir.path().join("broken.json");
    let json = serde_json::to_vec(&isf.data)?;
    fs::write(&exact, &json)?;
    fs::write(&duplicate, &json)?;
    let mut different = isf.data.clone();
    different["symbols"]["linux_banner"]["constant_data"] =
        json!(STANDARD.encode(b"Linux version synthetic different-build\n\0"));
    fs::write(&wrong, serde_json::to_vec(&different)?)?;
    fs::write(&broken, b"invalid-json")?;
    let report = match_local_files(
        &[exact.clone(), duplicate, wrong, broken],
        &image(&bytes),
        &Job::default(),
    )?;
    assert_eq!(report.matched.len(), 1);
    assert_eq!(report.matched[&exact].len(), 1);
    assert_eq!(report.diagnostics.len(), 1);
    assert!(report.diagnostics[0].contains("broken.json"));
    assert!(
        match_local_files(&[], &image(&bytes), &Job::default())?
            .matched
            .is_empty()
    );
    Ok(())
}
#[test]
fn unified_dump_cli_exports_explicit_range() -> Result<()> {
    let (img, mut isf) = dump_fixture();
    // Use the discoverable kernel alias while preserving the separate process PGD.
    let mut bytes = vec![0; 0x12000];
    img.read(0, &mut bytes)?;
    put(&mut bytes, 0x4000 + 9 * 8, 0x8003);
    for physical in [
        0x8200, 0x8208, 0x8300, 0x8308, 0x8318, 0x8400, 0x8408, 0x8418,
    ] {
        let old = u64::from_le_bytes(bytes[physical..physical + 8].try_into().unwrap());
        put(&mut bytes, physical, old + 0x8000);
    }
    isf.data["symbols"]["linux_banner"]["address"] = json!(0x9100);
    isf.data["symbols"]["init_task"]["address"] = json!(0x9200);
    isf.data["symbols"]["init_level4_pgt"]["address"] = json!(0x2000);
    bytes[0x8100..0x8100 + isf.banner.len()].copy_from_slice(&isf.banner);
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("image.raw"), bytes)?;
    fs::write(
        dir.path().join("symbols.json"),
        serde_json::to_vec(&isf.data)?,
    )?;
    let command = |extra: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_zero-tui"))
            .current_dir(dir.path())
            .args([
                "--offline",
                "dump",
                "--image",
                "image.raw",
                "--symbols",
                "symbols.json",
                "--mode",
                "range",
                "--pid",
                "1",
                "--dump-dir",
                "evidence",
                "--output",
                "manifest.json",
            ])
            .args(extra)
            .output()
    };
    let invalid = command(&[])?;
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("--start"));
    let output = command(&["--start", "0x4ffc", "--end", "0x5004"])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: store::Results =
        serde_json::from_slice(&fs::read(dir.path().join("manifest.json"))?)?;
    assert!(result.complete);
    assert_eq!(result.rows.len(), 1);
    let evidence = dir.path().join(&result.rows[0][6]);
    assert_eq!(fs::read(evidence)?, b"Evidence");
    Ok(())
}
