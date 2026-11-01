use super::super::tests::{K, fixture, image, put};
use super::*;
#[test]
fn crash_segments_and_reads_match_actual_reference_containers() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/crash-mappings.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let mut bytes = vec![0; case["length"].as_u64().unwrap() as usize];
        let width = case["width"].as_u64().unwrap();
        bytes[..8].copy_from_slice(if width == 4 { b"PAGEDUMP" } else { b"PAGEDU64" });
        for write in case["writes"].as_array().unwrap() {
            let at = write[0].as_u64().unwrap() as usize;
            let value = write[1].as_u64().unwrap();
            let size = write[2].as_u64().unwrap() as usize;
            bytes[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
        }
        let header = case["header"].as_u64().unwrap() as usize;
        let offset = case["data_offset"].as_u64().unwrap() as usize;
        if case["kind"] == 5 {
            bytes[header..header + 8].copy_from_slice(b"SDMPDUMP");
            for page in case["pages"].as_array().unwrap() {
                let page = page.as_u64().unwrap() as usize;
                bytes[header + 56 + page / 8] |= 1 << (page % 8);
            }
        }
        for (index, page) in case["pages"].as_array().unwrap().iter().enumerate() {
            bytes[offset + index * 4096..offset + (index + 1) * 4096]
                .fill((page.as_u64().unwrap() % 251) as u8);
        }
        let img = image(&bytes);
        let actual: Vec<_> = img
            .segments
            .iter()
            .map(|segment| [segment.start, segment.end, segment.file_offset])
            .collect();
        assert_eq!(
            serde_json::json!(actual),
            case["expected_segments"],
            "{}",
            case["id"]
        );
        for query in case["queries"].as_array().unwrap() {
            let mut data = vec![0; query["length"].as_u64().unwrap() as usize];
            let read = img.read(query["address"].as_u64().unwrap(), &mut data);
            if query["expected_hex"].is_null() {
                assert!(read.is_err(), "{} {query}", case["id"]);
            } else {
                read.unwrap();
                let hex: String = data.iter().map(|byte| format!("{byte:02x}")).collect();
                assert_eq!(
                    hex,
                    query["expected_hex"].as_str().unwrap(),
                    "{} {query}",
                    case["id"]
                );
            }
        }
    }
}

fn full(raw: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 8192];
    b[..8].copy_from_slice(b"PAGEDU64");
    put(&mut b, 16, 0x1000);
    put(&mut b, 32, K + 0x700);
    put(&mut b, 40, K + 0x400);
    b[48..52].copy_from_slice(&0x8664u32.to_le_bytes());
    b[136..140].copy_from_slice(&1u32.to_le_bytes());
    put(&mut b, 152, 0);
    put(&mut b, 160, (raw.len() / 4096) as u64);
    b[3992..3996].copy_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(raw);
    b
}
#[test]
fn triage_virtual_blocks_and_contexts_preserve_holes_across_architectures() {
    for (arch, width, header, kind_offset) in [
        (Architecture::X86, 4usize, 4096usize, 3976usize),
        (Architecture::X64, 8, 8192, 3992),
        (Architecture::Arm64, 8, 8192, 3992),
    ] {
        let mut b = vec![0; header + 1024];
        b[..8].copy_from_slice(if width == 4 { b"PAGEDUMP" } else { b"PAGEDU64" });
        let machine_at = if width == 4 { 32 } else { 48 };
        b[machine_at..machine_at + 4].copy_from_slice(&(arch.machine() as u32).to_le_bytes());
        b[kind_offset..kind_offset + 4].copy_from_slice(&4u32.to_le_bytes());
        let size = b.len() as u32;
        b[header + 4..header + 8].copy_from_slice(&size.to_le_bytes());
        let tail = 72 + width + 8 + width + if width == 8 { 16 } else { 0 };
        b[header + tail + 8..header + tail + 12]
            .copy_from_slice(&((header + 160) as u32).to_le_bytes());
        b[header + tail + 12..header + tail + 16].copy_from_slice(&1u32.to_le_bytes());
        let address = if width == 4 {
            0x81234000u64
        } else {
            K + 0x1234000
        };
        b[header + 160..header + 160 + width].copy_from_slice(&address.to_le_bytes()[..width]);
        b[header + 160 + width..header + 164 + width]
            .copy_from_slice(&((header + 512) as u32).to_le_bytes());
        b[header + 164 + width..header + 168 + width].copy_from_slice(&16u32.to_le_bytes());
        b[header + 512..header + 528].fill(0x5a);
        b[header + 12..header + 16].copy_from_slice(&((header + 192) as u32).to_le_bytes());
        let (flags_at, flags, pc_at) = match arch {
            Architecture::X86 => (0, 0x10001u32, 184),
            Architecture::X64 => (48, 0x100001, 248),
            _ => (0, 0x400001, 264),
        };
        b[header + 192 + flags_at..header + 196 + flags_at].copy_from_slice(&flags.to_le_bytes());
        b[header + 192 + pc_at..header + 192 + pc_at + width]
            .copy_from_slice(&address.to_le_bytes()[..width]);
        b[header + 48..header + 52].copy_from_slice(&((header + 560) as u32).to_le_bytes());
        b[header + 52..header + 56].copy_from_slice(&1u32.to_le_bytes());
        b[header + 56..header + 60].copy_from_slice(&((header + 900) as u32).to_le_bytes());
        b[header + 60..header + 64].copy_from_slice(&100u32.to_le_bytes());
        b[header + 560..header + 564].copy_from_slice(&((header + 900) as u32).to_le_bytes());
        let base_at = header + 560 + if width == 8 { 56 } else { 28 };
        b[base_at..base_at + width].copy_from_slice(&address.to_le_bytes()[..width]);
        b[base_at + 2 * width..base_at + 3 * width]
            .copy_from_slice(&4096u64.to_le_bytes()[..width]);
        b[header + 900..header + 904].copy_from_slice(&6u32.to_le_bytes());
        let name: Vec<u8> = "driver".encode_utf16().flat_map(u16::to_le_bytes).collect();
        b[header + 904..header + 904 + name.len()].copy_from_slice(&name);
        b[header + 16..header + 20].copy_from_slice(&((header + 720) as u32).to_le_bytes());
        b[header + 720..header + 724].copy_from_slice(&0xc0000005u32.to_le_bytes());
        let exception_at = header + 720 + if width == 8 { 16 } else { 12 };
        b[exception_at..exception_at + width].copy_from_slice(&address.to_le_bytes()[..width]);
        let img = image(&b);
        let meta = img.windows_container.as_ref().unwrap();
        assert!(meta.kernel_virtual);
        assert!(!meta.virtual_memory);
        assert_eq!(meta.contexts.len(), 1);
        assert_eq!(meta.modules[0].name, "driver");
        assert_eq!(
            meta.crash.as_ref().unwrap().exception_address,
            Some(address)
        );
        let mut saved = [0; 16];
        img.read(address, &mut saved).unwrap();
        assert_eq!(saved, [0x5a; 16]);
        assert!(img.read(address + 16, &mut [0]).is_err());
        assert!(img.read(0, &mut [0]).is_err());
        // Identical virtual mappings merge; separately stored copies require equal bytes.
        let stride = width + 8;
        b[header + tail + 12..header + tail + 16].copy_from_slice(&2u32.to_le_bytes());
        let second = header + 160 + stride;
        b[second..second + width].copy_from_slice(&(address + 8).to_le_bytes()[..width]);
        b[second + width..second + width + 4]
            .copy_from_slice(&((header + 520) as u32).to_le_bytes());
        b[second + width + 4..second + width + 8].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(image(&b).segments.len(), 1);
        // A separate copy of the same overlap is legitimate (real Server 2016 triage).
        b[header + 920..header + 928].fill(0x5a);
        b[second + width..second + width + 4]
            .copy_from_slice(&((header + 920) as u32).to_le_bytes());
        assert_eq!(image(&b).segments.len(), 1);
        // A new tail keeps its own file offset, while matching overlapping bytes.
        b[header + 928..header + 932].fill(0x6b);
        b[second + width + 4..second + width + 8].copy_from_slice(&12u32.to_le_bytes());
        let copies = image(&b);
        let mut tail_bytes = [0; 4];
        copies.read(address + 16, &mut tail_bytes).unwrap();
        assert_eq!(tail_bytes, [0x6b; 4]);
        b[second + width + 4..second + width + 8].copy_from_slice(&8u32.to_le_bytes());
        b[second + width..second + width + 4]
            .copy_from_slice(&((header + 521) as u32).to_le_bytes());
        let mut conflict = tempfile::tempfile().unwrap();
        use std::io::Write;
        conflict.write_all(&b).unwrap();
        assert!(Image::from_file(conflict, "conflict-triage".into()).is_err());
        b[second + width..second + width + 4]
            .copy_from_slice(&((header + 520) as u32).to_le_bytes());
        b[header + 164 + width..header + 168 + width].copy_from_slice(&0xffffu32.to_le_bytes());
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&b).unwrap();
        assert!(Image::from_file(f, "bad-triage".into()).is_err());
    }
}
#[test]
fn full_crash_maps_physical_runs_and_bootstraps() {
    let (raw, isf) = fixture();
    let b = full(&raw);
    let img = image(&b);
    assert_eq!(img.format, "Windows crash");
    assert_eq!(
        img.windows_container.as_ref().unwrap().architecture,
        Architecture::X64
    );
    assert_eq!(img.u64(0x8380).unwrap(), K + 0x1000);
    assert_eq!(discover(&img, &isf, &Job::default()).unwrap(), (0x1000, K));
    let mut f = tempfile::tempfile().unwrap();
    use std::io::Write;
    f.write_all(&b[..b.len() - 1]).unwrap();
    assert!(Image::from_file(f, "short".into()).is_err());
}
#[test]
fn bitmap_gaps_are_not_zero_filled() {
    let (raw, _) = fixture();
    let mut b = full(&[]);
    b[3992..3996].copy_from_slice(&5u32.to_le_bytes());
    b.resize(12288, 0);
    b[8192..8200].copy_from_slice(b"SDMPDUMP");
    put(&mut b, 8192 + 32, 12288);
    put(&mut b, 8192 + 40, 2);
    put(&mut b, 8192 + 48, 3);
    b[8192 + 56] = 5;
    b.extend_from_slice(&raw[..4096]);
    b.extend_from_slice(&raw[8192..12288]);
    let img = image(&b);
    assert_eq!(img.segments.len(), 2);
    assert!(img.u64(4096).is_err());
    assert_eq!(
        img.u64(8192).unwrap(),
        u64::from_le_bytes(raw[8192..8200].try_into().unwrap())
    );
    b[8192 + 40] = 3;
    let mut f = tempfile::tempfile().unwrap();
    use std::io::Write;
    f.write_all(&b).unwrap();
    assert!(Image::from_file(f, "bad count".into()).is_err());
}
fn mini() -> Vec<u8> {
    let mut b = vec![0; 8192];
    b[..4].copy_from_slice(b"MDMP");
    b[4..8].copy_from_slice(&0xa793u32.to_le_bytes());
    b[8..12].copy_from_slice(&3u32.to_le_bytes());
    b[12..16].copy_from_slice(&32u32.to_le_bytes());
    for (i, kind, size, off) in [(0, 7u32, 56u32, 128u32), (1, 15, 24, 192), (2, 9, 32, 224)] {
        let p = 32 + i * 12;
        b[p..p + 4].copy_from_slice(&kind.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&size.to_le_bytes());
        b[p + 8..p + 12].copy_from_slice(&off.to_le_bytes());
    }
    b[128..130].copy_from_slice(&9u16.to_le_bytes());
    b[144..148].copy_from_slice(&19041u32.to_le_bytes());
    b[192..196].copy_from_slice(&24u32.to_le_bytes());
    b[196..200].copy_from_slice(&1u32.to_le_bytes());
    b[200..204].copy_from_slice(&42u32.to_le_bytes());
    put(&mut b, 224, 1);
    put(&mut b, 232, 4096);
    put(&mut b, 240, 0x123000);
    put(&mut b, 248, 4096);
    b[4096..].fill(0x5a);
    b
}
#[test]
fn minidump_virtual_mapping_capabilities_and_atomic_range() {
    let b = mini();
    let img = image(&b);
    assert!(img.windows_container.as_ref().unwrap().virtual_memory);
    assert_eq!(img.u64(0x123000).unwrap(), 0x5a5a5a5a5a5a5a5a);
    assert!(img.u64(0).is_err());
    let out = tempfile::tempdir().unwrap();
    let req = Request {
        image: std::path::Path::new("fixture"),
        symbols: std::path::Path::new("missing"),
        choice: None,
        plugin: Plugin::WinMemdump,
        cache: out.path(),
        use_cache: false,
        network: false,
    };
    let opts = DumpOptions {
        pid: 42,
        directory: out.path().join("dump"),
        start: Some(0x123000),
        end: Some(0x124000),
    };
    let r = analyze(
        &img,
        &req,
        Some(&opts),
        &Options::default(),
        &Job::default(),
    )
    .unwrap();
    assert!(r.complete);
    assert_eq!(r.rows.len(), 1);
    assert_eq!(std::fs::read(&r.rows[0][6]).unwrap(), vec![0x5a; 4096]);
    let wrong = DumpOptions { pid: 43, ..opts };
    assert!(
        analyze(
            &img,
            &req,
            Some(&wrong),
            &Options::default(),
            &Job::default()
        )
        .is_err()
    );
    let req = Request {
        plugin: Plugin::WinModules,
        ..req
    };
    assert!(analyze(&img, &req, None, &Options::default(), &Job::default()).is_err());
    let mut bad = b;
    put(&mut bad, 240, u64::MAX);
    let mut f = tempfile::tempfile().unwrap();
    use std::io::Write;
    f.write_all(&bad).unwrap();
    assert!(Image::from_file(f, "overflow".into()).is_err());
}
