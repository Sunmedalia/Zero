use super::*;
use std::{
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// Complete tiny kernel: compressed kallsyms, BTF, VMCOREINFO, task and page tables.
pub(crate) fn fixture() -> Vec<u8> {
    let base = START_KERNEL_MAP;
    let strings = b"\0int\0char\0list_head\0next\0prev\0task_struct\0tasks\0pid\0comm\0";
    let offset = |name: &str| -> u32 {
        u32::try_from(
            strings
                .windows(name.len() + 1)
                .position(|s| s.starts_with(name.as_bytes()) && s.last() == Some(&0))
                .unwrap(),
        )
        .unwrap()
    };
    let mut types = Vec::new();
    let mut record = |words: &[u32]| {
        for word in words {
            types.extend_from_slice(&word.to_le_bytes());
        }
    };
    record(&[offset("int"), 1 << 24, 4, (1 << 24) | 32]); // 1
    record(&[offset("char"), 1 << 24, 1, (1 << 24) | 8]); // 2
    record(&[0, 2 << 24, 4]); // 3 pointer -> list_head
    record(&[offset("list_head"), (4 << 24) | 2, 16]); // 4
    record(&[offset("next"), 3, 0, offset("prev"), 3, 64]);
    record(&[0, 3 << 24, 0, 2, 1, 16]); // 5 char[16]
    record(&[offset("task_struct"), (4 << 24) | 3, 40]); // 6
    record(&[
        offset("tasks"),
        4,
        0,
        offset("pid"),
        1,
        128,
        offset("comm"),
        5,
        160,
    ]);
    let mut btf = vec![0x9f, 0xeb, 1, 0];
    for word in [
        24,
        0,
        types.len() as u32,
        types.len() as u32,
        strings.len() as u32,
    ] {
        btf.extend_from_slice(&word.to_le_bytes());
    }
    btf.extend_from_slice(&types);
    btf.extend_from_slice(strings);
    let mut symbols = vec![
        ("Dkallsyms_num_syms", base + 0x100, true),
        ("Dkallsyms_names", base + 0x108, true),
        ("Dkallsyms_markers", base + 0x200, true),
        ("Dkallsyms_token_table", base + 0x300, true),
        ("Dkallsyms_offsets", base + 0x800, true),
        ("Dinit_top_pgt", base + 0x4000, true),
        ("Dinit_task", base + 0x7000, true),
        ("Dlinux_banner", base + 0x8000, true),
        ("D__start_BTF", base + 0x9000, true),
        ("D__stop_BTF", base + 0x9000 + btf.len() as u64, true),
    ];
    // Two marker blocks disambiguate u32 and unsigned-long marker layouts.
    for i in 0..260u64 {
        symbols.push((
            Box::leak(format!("tfunc_{i}").into_boxed_str()),
            base + 0xb000 + i * 16,
            true,
        ));
    }
    let (_, locations) = image_kallsyms::tests::kallsyms_fixture(base, &symbols);
    for ((_, address, _), (_, physical)) in symbols.iter_mut().zip(locations) {
        *address = base + physical;
    }
    symbols.sort_by_key(|(_, address, _)| *address);
    let (mut bytes, _) = image_kallsyms::tests::kallsyms_fixture(base, &symbols);
    bytes.resize(0x10000, 0);
    let mut put = |at: usize, value: u64| {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(0x4000 + 511 * 8, 0x5003);
    put(0x5000 + 510 * 8, 0x6003);
    put(0x6000, 0x83);
    put(0x7000, base + 0x7000);
    put(0x7008, base + 0x7000);
    bytes[0x7014..0x701c].copy_from_slice(b"swapper\0");
    let banner = b"Linux version x (fixture)\n\0";
    bytes[0x8000..0x8000 + banner.len()].copy_from_slice(banner);
    bytes[0x9000..0x9000 + btf.len()].copy_from_slice(&btf);
    let note = format!(
        "OSRELEASE=x\nSYMBOL(init_top_pgt)={:x}\nKERNELOFFSET=0\n\0",
        base + 0x4000
    );
    bytes[0xa000..0xa000 + note.len()].copy_from_slice(note.as_bytes());
    bytes
}

fn setup() -> (tempfile::TempDir, Image) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.raw");
    fs::write(&path, fixture()).unwrap();
    let image = Image::open(&path, &dir.path().join("cache"), &Job::default()).unwrap();
    (dir, image)
}

fn logging() -> (Job, Arc<Mutex<Vec<String>>>) {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let output = logs.clone();
    (
        Job::new(move |line| output.lock().unwrap().push(line)),
        logs,
    )
}

#[test]
fn fresh_generation_and_verified_reuse_skip_decoding_and_preserve_provenance() {
    let (dir, image) = setup();
    let cache = dir.path().join("cache");
    let (job, logs) = logging();
    let path = generate(&image, &cache, &job).unwrap();
    let bytes = fs::read(&path).unwrap();
    let source = fs::read(path.with_extension("source.json")).unwrap();
    let reopened = Image::open(&dir.path().join("memory.raw"), &cache, &Job::default()).unwrap();
    logs.lock().unwrap().clear();
    assert_eq!(generate(&reopened, &cache, &job).unwrap(), path);
    let logs = logs.lock().unwrap();
    assert!(logs.iter().any(|s| s.contains("复用已验证")), "{logs:?}");
    assert!(
        !logs.iter().any(|s| s.starts_with("BTF 转换:")
            || s.contains("从镜像定位")
            || s.contains("扫描候选"))
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        fs::read(path.with_extension("source.json")).unwrap(),
        source
    );
}

#[test]
fn corrupt_artifacts_and_indexes_regenerate_instead_of_trusting_file_existence() {
    for broken in [
        "isf",
        "source",
        "index",
        "version",
        "identity",
        "slide",
        "path",
        "missing_isf",
        "missing_source",
    ] {
        let (dir, image) = setup();
        let cache = dir.path().join("cache");
        let (job, logs) = logging();
        let path = generate(&image, &cache, &job).unwrap();
        let index = artifact::build_path(&image, &cache).join("index.json");
        match broken {
            "isf" => fs::write(&path, b"corrupt").unwrap(),
            "source" => fs::write(path.with_extension("source.json"), b"{}").unwrap(),
            "index" => fs::write(&index, b"{").unwrap(),
            "missing_isf" => fs::remove_file(&path).unwrap(),
            "missing_source" => fs::remove_file(path.with_extension("source.json")).unwrap(),
            "slide" => {
                let sidecar = path.with_extension("source.json");
                let mut source: Value =
                    serde_json::from_slice(&fs::read(&sidecar).unwrap()).unwrap();
                source["provenance"]["page_table"]["slide"] = json!("0x1000");
                fs::write(&sidecar, serde_json::to_vec(&source).unwrap()).unwrap();
                let mut data: Value = serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
                data["source_sha256"] =
                    json!(format!("{:x}", Sha256::digest(fs::read(sidecar).unwrap())));
                fs::write(&index, serde_json::to_vec(&data).unwrap()).unwrap();
            }
            field => {
                let mut data: Value = serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
                let (key, value) = match field {
                    "version" => ("generator", "old"),
                    "identity" => ("image_sha256", "other"),
                    _ => ("isf_sha256", "../../escape"),
                };
                data[key] = json!(value);
                fs::write(&index, serde_json::to_vec(&data).unwrap()).unwrap();
            }
        }
        logs.lock().unwrap().clear();
        assert_eq!(generate(&image, &cache, &job).unwrap(), path, "{broken}");
        assert!(
            logs.lock().unwrap().iter().any(|s| s.contains("重新生成")),
            "{broken}"
        );
        logs.lock().unwrap().clear();
        assert_eq!(generate(&image, &cache, &job).unwrap(), path);
        assert!(
            logs.lock()
                .unwrap()
                .iter()
                .any(|s| s.contains("复用已验证")),
            "{broken}"
        );
    }
}

#[test]
fn cancellation_at_each_stage_never_publishes_a_success_index() {
    for stage in [
        "扫描 kallsyms",
        "BTF 解析",
        "BTF 转换",
        "构建 ISF",
        "用生成的 ISF",
        "压缩并保存",
    ] {
        let (dir, image) = setup();
        let cache = dir.path().join("cache");
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let mut job = Job::new(move |s| {
            if s.contains(stage) {
                signal.store(true, Ordering::Relaxed);
            }
        });
        job.cancel = cancel;
        let error = generate(&image, &cache, &job).unwrap_err();
        assert!(
            format!("{error:#}").contains("cancelled"),
            "{stage}: {error:#}"
        );
        assert!(
            !artifact::build_path(&image, &cache)
                .join("index.json")
                .exists()
        );
        let isf = cache.join("symbols/isf");
        if isf.exists() {
            assert!(fs::read_dir(isf).unwrap().all(|e| {
                e.unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "lock")
            }));
        }
    }
}

#[test]
fn generation_lock_and_changed_image_are_rejected() {
    let (dir, image) = setup();
    let cache = dir.path().join("cache");
    let job = Job::default();
    let build = artifact::build_path(&image, &cache);
    let lock = crate::prepare::stages::artifact_lock(&build.join("generation.lock"), "busy", &job)
        .unwrap();
    assert!(
        generate(&image, &cache, &job)
            .unwrap_err()
            .to_string()
            .contains("正在生成")
    );
    drop(lock);
    let path = dir.path().join("memory.raw");
    let mutation = path.clone();
    let changed = Job::new(move |s| {
        if s.contains("构建 ISF") {
            use std::io::Write;
            fs::OpenOptions::new()
                .append(true)
                .open(&mutation)
                .unwrap()
                .write_all(b"changed")
                .unwrap();
        }
    });
    assert!(format!("{:#}", generate(&image, &cache, &changed).unwrap_err()).contains("发生变化"));
    assert!(!build.join("index.json").exists());
}

#[test]
fn changed_image_cannot_reuse_an_old_open_handle_or_digest() {
    use std::io::Write;
    let (dir, image) = setup();
    let cache = dir.path().join("cache");
    generate(&image, &cache, &Job::default()).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join("memory.raw"))
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    assert!(
        generate(&image, &cache, &Job::default())
            .unwrap_err()
            .to_string()
            .contains("重新打开")
    );
}

#[test]
fn cancelling_a_cache_hit_preserves_all_previous_artifacts() {
    let (dir, image) = setup();
    let cache = dir.path().join("cache");
    let path = generate(&image, &cache, &Job::default()).unwrap();
    let index = artifact::build_path(&image, &cache).join("index.json");
    let paths = [path.clone(), path.with_extension("source.json"), index];
    let before: Vec<_> = paths.iter().map(|p| fs::read(p).unwrap()).collect();
    let signal = Arc::new(AtomicBool::new(false));
    let cancel = signal.clone();
    let mut job = Job::new(move |line| {
        if line.contains("校验镜像符号生成缓存") {
            cancel.store(true, Ordering::Relaxed);
        }
    });
    job.cancel = signal;
    assert!(
        generate(&image, &cache, &job)
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    for (p, b) in paths.iter().zip(before) {
        assert_eq!(fs::read(p).unwrap(), b);
    }
}

#[test]
fn lime_segments_generate_and_library_survives_cache_clear() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let bytes = fixture();
    let path = dir.path().join("memory.lime");
    let mut file = fs::File::create(&path).unwrap();
    // Split both the kallsyms region and the BTF section across LiME headers.
    for (start, end) in [(0usize, 0x580usize), (0x580, 0x9010), (0x9010, bytes.len())] {
        for word in [0x0000_0001_4c69_4d45, start as u64, end as u64 - 1, 0] {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
        file.write_all(&bytes[start..end]).unwrap();
    }
    drop(file);
    let cache = dir.path().join("cache");
    let library = dir.path().join("library");
    let job = Job::default();
    let image = Image::open(&path, &cache, &job).unwrap();
    let service = crate::prepare::Generation {
        image: &image,
        library: &library,
        cache: &cache,
        network: false,
        tool: None,
        job: &job,
    };
    let saved = service.run(crate::prepare::GenerationInput::Image).unwrap();
    assert!(saved.is_file());
    assert_eq!(
        service.run(crate::prepare::GenerationInput::Image).unwrap(),
        saved
    );
    assert!(
        crate::prepare::local_generated(&image, &library, &cache, &job)
            .unwrap()
            .is_none()
    );
    let entries = crate::cache::inventory(&cache).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.path.ends_with("index.json") && e.scope == crate::cache::Scope::Symbols)
    );
    drop(image);
    let report = crate::cache::clear(&cache, &[crate::cache::Scope::Symbols]).unwrap();
    assert!(report.failures.is_empty());
    assert!(saved.is_file() && saved.with_extension("source.json").is_file());
}

#[test]
fn rebuilding_a_damaged_isf_preserves_valid_existing_provenance() {
    let (dir, image) = setup();
    let cache = dir.path().join("cache");
    let path = generate(&image, &cache, &Job::default()).unwrap();
    let sidecar = path.with_extension("source.json");
    let mut source: Value = serde_json::from_slice(&fs::read(&sidecar).unwrap()).unwrap();
    source["annotation"] = json!("retain original evidence record");
    let original = serde_json::to_vec_pretty(&source).unwrap();
    fs::write(&sidecar, &original).unwrap();
    fs::write(&path, b"damaged").unwrap();
    assert_eq!(generate(&image, &cache, &Job::default()).unwrap(), path);
    assert_eq!(fs::read(sidecar).unwrap(), original);
}

/// A trusted local reference and a capture whose kallsyms lacks the BTF anchors.
fn local_reference_without_image_prerequisites() -> (tempfile::TempDir, Image, PathBuf) {
    let (dir, original) = setup();
    let job = Job::default();
    let path = generate(&original, &dir.path().join("reference-cache"), &job).unwrap();
    let bytes =
        crate::symbols::decode(fs::File::open(&path).unwrap(), "reference.json.xz", &job).unwrap();
    let mut data: Value = serde_json::from_slice(&bytes).unwrap();
    data["metadata"]["zero"]["source"] = json!("local-debug-reference");
    let library = dir.path().join("library");
    fs::create_dir(&library).unwrap();
    fs::write(
        library.join("reference.json"),
        serde_json::to_vec(&data).unwrap(),
    )
    .unwrap();
    fs::write(
        library.join("reference.source.json"),
        b"{\"origin\":\"preserve-me\"}",
    )
    .unwrap();
    drop(original);
    let mut capture = fixture();
    let at = capture
        .windows(b"__start_BTF".len())
        .position(|b| b == b"__start_BTF")
        .unwrap();
    capture[at + 8] = b'X';
    let image_path = dir.path().join("without-global.raw");
    fs::write(&image_path, capture).unwrap();
    let image = Image::open(&image_path, &dir.path().join("fallback-cache"), &job).unwrap();
    (dir, image, library)
}

#[test]
fn unsupported_capture_reuses_only_a_verified_local_isf_and_preserves_source() {
    let (dir, image, library) = local_reference_without_image_prerequisites();
    let cache = dir.path().join("fallback-cache");
    let (job, logs) = logging();
    let reference = library.join("reference.json");
    let before = fs::read(&reference).unwrap();
    let source = fs::read(library.join("reference.source.json")).unwrap();
    let result = crate::prepare::Generation {
        image: &image,
        library: &library,
        cache: &cache,
        network: false,
        tool: None,
        job: &job,
    }
    .run(crate::prepare::GenerationInput::Image)
    .unwrap();
    assert_eq!(result, reference.canonicalize().unwrap());
    assert_eq!(fs::read(reference).unwrap(), before);
    assert_eq!(
        fs::read(library.join("reference.source.json")).unwrap(),
        source
    );
    assert!(
        logs.lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("复用本地精确符号："))
    );
    assert!(
        !artifact::build_path(&image, &cache)
            .join("index.json")
            .exists()
    );
}

#[test]
fn local_fallback_refuses_ambiguity_page_table_failures_and_cancellation() {
    for failure in ["ambiguous", "invalid-root", "cancel"] {
        let (dir, image, library) = local_reference_without_image_prerequisites();
        let cache = dir.path().join("fallback-cache");
        let reference = library.join("reference.json");
        let mut data: Value = serde_json::from_slice(&fs::read(&reference).unwrap()).unwrap();
        let (mut job, _) = logging();
        if failure == "ambiguous" {
            data["metadata"]["other"] = json!(true);
            fs::write(
                library.join("other.json"),
                serde_json::to_vec(&data).unwrap(),
            )
            .unwrap();
        } else if failure == "invalid-root" {
            data["symbols"]["init_top_pgt"]["address"] = json!(START_KERNEL_MAP + 0x3000);
            fs::write(&reference, serde_json::to_vec(&data).unwrap()).unwrap();
        } else {
            let signal = Arc::new(AtomicBool::new(false));
            let cancel = signal.clone();
            job = Job::new(move |s| {
                if s.contains("不支持从此镜像") {
                    cancel.store(true, Ordering::Relaxed);
                }
            });
            job.cancel = signal;
        }
        let error = crate::prepare::Generation {
            image: &image,
            library: &library,
            cache: &cache,
            network: false,
            tool: None,
            job: &job,
        }
        .run(crate::prepare::GenerationInput::Image)
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains(match failure {
                "ambiguous" => "多个不同",
                "invalid-root" => "页表验证",
                _ => "cancelled",
            }),
            "{failure}: {text}"
        );
    }
}
