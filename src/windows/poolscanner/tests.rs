use super::super::tests::{K, fixture, image, put};
use super::*;
use serde_json::json;
#[test]
fn virtual_pool_ranges_match_actual_windows_intel_mapping() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-mappings.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let (_, mut isf) = fixture();
        let arch = case["arch"].as_str().unwrap();
        let width = case["width"].as_u64().unwrap() as usize;
        if arch != "x64" {
            isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
            isf.data["base_types"]["pointer"]["size"] = json!(4);
            if arch == "pae" {
                isf.data["metadata"]["windows"]["paging"] = json!("pae");
            }
        }
        if arch == "x64" {
            // Real ISFs can expose the software flag as part of a 40-bit
            // transition PFN. The pinned Intel layer still uses raw 45-bit
            // physical extraction, independent of that field width.
            isf.data["user_types"]["_MMPTE_TRANSITION"] = json!({"size":8,"fields":{
                    "PageFrameNumber":{"offset":0,"type":{"kind":"bitfield","bit_position":12,
                        "bit_length":40,"type":{"kind":"base","name":"u64"}}}}});
        }
        let mut bytes = vec![0; case["length"].as_u64().unwrap() as usize];
        for write in case["writes"].as_array().unwrap() {
            let at = write[0].as_u64().unwrap() as usize;
            bytes[at..at + width]
                .copy_from_slice(&write[1].as_u64().unwrap().to_le_bytes()[..width]);
        }
        if case["patterned"].as_bool().unwrap_or(false) {
            for page in (0x400000..bytes.len()).step_by(4096) {
                bytes[page..page + 4096].fill(((page / 4096) % 251) as u8);
            }
        }
        for write in case["data_writes"].as_array().unwrap() {
            let at = write[0].as_u64().unwrap() as usize;
            let value = write[1].as_str().unwrap();
            for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                bytes[at + index] =
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
        }
        let mut snapshot = image(&bytes);
        snapshot.segments.clear();
        let mut start = 0;
        for hole in case["holes"].as_array().unwrap() {
            let end = hole[0].as_u64().unwrap();
            if start < end {
                snapshot.segments.push(crate::image::Segment {
                    start,
                    end,
                    file_offset: start,
                });
            }
            start = hole[1].as_u64().unwrap();
        }
        snapshot.segments.push(crate::image::Segment {
            start,
            end: bytes.len() as u64,
            file_offset: start,
        });
        let windows = Windows {
            vm: Memory::new(&snapshot, case["root"].as_u64().unwrap(), &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        for query in case["queries"].as_array().unwrap() {
            let address = query["address"].as_u64().unwrap();
            let translated = windows.vm.translate(address);
            match query["physical"].as_u64() {
                Some(expected) => {
                    assert_eq!(translated.unwrap(), expected, "{} {query}", case["id"])
                }
                None => assert!(translated.is_err(), "{} {query}", case["id"]),
            }
            let mut byte = vec![0xff; query["length"].as_u64().unwrap_or(1) as usize];
            let read = windows.vm.read(address, &mut byte);
            if let Some(expected) = query["read_hex"].as_str() {
                read.unwrap();
                assert_eq!(
                    byte.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    expected,
                    "{} {query}",
                    case["id"]
                );
                let mut captured = vec![0xff; byte.len()];
                windows.vm.read_captured(address, &mut captured).unwrap();
                assert_eq!(captured, byte);
            } else {
                assert!(read.is_err(), "{} {query}", case["id"]);
                assert!(
                    windows.vm.read_captured(address, &mut byte).is_err(),
                    "{} {query}",
                    case["id"]
                );
            }
        }
        let ranges = windows.pool_virtual_ranges(&Job::default()).unwrap();
        for &(at, length, physical) in &ranges {
            // For reserved PFN bits, the reference whole-range mapping
            // assumes linearity while direct translation ORs each start.
            // Both actual API observations are tested independently.
            if case["id"].as_str().unwrap().contains("reserved-bit") {
                continue;
            }
            assert_eq!(
                windows.vm.translate(at).unwrap(),
                physical,
                "{} at={at:#x}",
                case["id"]
            );
            assert_eq!(
                windows.vm.translate(at + length - 1).unwrap(),
                physical + length - 1,
                "{} tail",
                case["id"]
            );
        }
        let masked: Vec<_> = ranges
            .into_iter()
            .map(|(at, size, physical)| [at & windows.driver_address_mask(), size, physical])
            .collect();
        assert_eq!(json!(masked), case["expected"], "{}", case["id"]);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        // A valid mapping must reach the callback's cancellation check.
        if !masked.is_empty() {
            assert!(windows.pool_virtual_ranges(&job).is_err());
        }
    }
}

#[test]
fn pool_chunk_plans_and_overlap_match_actual_layer_iterators() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-chunks.json"
    ))
    .unwrap();
    assert_eq!(vectors["chunk_size"], POOL_SCAN_CHUNK);
    assert_eq!(vectors["overlap"], POOL_SCAN_OVERLAP);
    for case in vectors["plans"].as_array().unwrap() {
        let ranges = case["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|range| (range[0].as_u64().unwrap(), range[1].as_u64().unwrap()))
            .collect();
        let chunks: Vec<_> = PoolScanChunks::new(ranges, case["translated"].as_bool().unwrap())
            .map(|(at, size)| [at, size])
            .collect();
        assert_eq!(json!(chunks), case["expected"], "{}", case["id"]);
    }
    for case in vectors["scans"].as_array().unwrap() {
        let length = case["length"].as_u64().unwrap();
        let mut bytes = vec![0; length as usize];
        for at in case["tags"].as_array().unwrap() {
            let at = at.as_u64().unwrap() as usize;
            bytes[at..at + 4].copy_from_slice(b"Driv");
        }
        let mut found = Vec::new();
        let mut chunks = Vec::new();
        for (start, length) in
            PoolScanChunks::new(vec![(0, length)], case["translated"].as_bool().unwrap())
        {
            chunks.push(vec![[start, length]]);
            if case["fault_chunks"].as_array().unwrap().iter().any(|bad| {
                let bad = bad.as_u64().unwrap() * POOL_SCAN_CHUNK;
                start <= bad && bad < start + length
            }) {
                continue;
            }
            let data = &bytes[start as usize..(start + length) as usize];
            for (_, at) in PoolTagMatches::new(data, [b"Driv".as_slice()]).unwrap() {
                if at as u64 >= POOL_SCAN_CHUNK {
                    break;
                }
                found.push(start + at as u64);
            }
        }
        assert_eq!(json!(chunks), case["chunks"], "{}", case["id"]);
        assert_eq!(json!(found), case["expected"], "{}", case["id"]);
    }
}

#[test]
fn shared_carver_handles_chunk_crossings_and_reference_raw_tail_repeats() {
    for (length, tag, copies) in [
        (
            POOL_SCAN_CHUNK + POOL_SCAN_OVERLAP + 16,
            POOL_SCAN_CHUNK - 2,
            1,
        ),
        (POOL_SCAN_CHUNK + 100, POOL_SCAN_CHUNK - 20, 2),
    ] {
        let (mut bytes, isf, base, _) =
            super::super::driver_irp::tests::driver_fixture(false, false, false);
        bytes.resize(length as usize, 0);
        let header = tag as usize - 4;
        bytes[header..header + 2].copy_from_slice(&32u16.to_le_bytes());
        bytes[header + 2..header + 4].copy_from_slice(&2u16.to_le_bytes());
        bytes[tag as usize..tag as usize + 4].copy_from_slice(b"Wind");
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let constraint = Constraint::new(b"Wind", "station", None, 0x90, 3, true, &[]);
        let (_, bodies, notes) = windows
            .scan_pool_objects(&[&constraint], 32, &Job::default())
            .unwrap();
        assert_eq!(bodies, vec![header as u64 + 16; copies]);
        assert!(notes.is_empty(), "{notes:?}");
    }
    let (mut bytes, isf, base, _) =
        super::super::driver_irp::tests::driver_fixture(false, false, false);
    bytes.extend_from_slice(b"Wind");
    let snapshot = image(&bytes);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let ranges = windows.pool_scan_ranges(false, &Job::default()).unwrap();
    assert_eq!(ranges, [(0, bytes.len() as u64 - 1)]);
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-chunks.json"
    ))
    .unwrap();
    let length = vectors["default_section"]["length"].as_u64().unwrap() as usize;
    let data = b"....Driv";
    let found: Vec<_> = PoolTagMatches::new(&data[..length], [b"Driv".as_slice()])
        .unwrap()
        .map(|(_, at)| at)
        .collect();
    assert_eq!(json!(found), vectors["default_section"]["expected"]);
}

#[test]
fn pool_header_constraints_read_only_required_fields_across_scan_slices() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-boundaries.json"
    ))
    .unwrap();
    for x86 in [false, true] {
        for virtual_scan in [false, true] {
            for case in vectors["cases"].as_array().unwrap() {
                let (mut bytes, mut isf, base, _) =
                    super::super::driver_irp::tests::driver_fixture(x86, virtual_scan, false);
                let physical = 0x18000;
                let address = if virtual_scan {
                    base + 0x10000
                } else {
                    physical as u64
                };
                let payload: Vec<_> = case["payload_hex"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect();
                bytes[physical..physical + payload.len()].copy_from_slice(&payload);
                let mut snapshot = image(&bytes);
                let mut missing: Vec<_> = case["missing"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|at| physical as u64 + at.as_u64().unwrap() - 0x1000)
                    .collect();
                missing.sort_unstable();
                // Backing-byte holes are real Image segments, so fallback
                // cannot accidentally read them from the scan buffer.
                let mut begin = 0;
                snapshot.segments.clear();
                for at in missing {
                    if at > begin {
                        snapshot.segments.push(crate::image::Segment {
                            start: begin,
                            end: at,
                            file_offset: begin,
                        });
                    }
                    begin = at + 1;
                }
                snapshot.segments.push(crate::image::Segment {
                    start: begin,
                    end: bytes.len() as u64,
                    file_offset: begin,
                });
                // Both pointer widths use the fixed vector's explicit
                // alignment; these isolate header reads, not carving.
                isf.data["user_types"]["_POOL_HEADER"]["size"] = json!(16);
                let windows = Windows {
                    vm: Memory::new(&snapshot, 0x1000, &isf, None),
                    base,
                    pdb: PdbIdentity::from_isf(&isf).unwrap(),
                };
                let constraint = Constraint::new(b"Wind", "station", None, 0x90, 3, true, &[]);
                let local = case["scan_start"].as_u64().unwrap() as usize - 0x1000;
                let length = case["scan_length"].as_u64().unwrap() as usize;
                let matched = windows
                    .pool_header_block(
                        &constraint,
                        address,
                        PoolHeaderRead {
                            start: address + local as u64,
                            data: &payload[local..local + length],
                            virtual_scan,
                            alignment: 16,
                            vista: case["vista"].as_bool().unwrap(),
                        },
                    )
                    .unwrap();
                assert_eq!(
                    matched.is_some(),
                    !case["expected"].as_array().unwrap().is_empty(),
                    "{} x86={x86} virtual={virtual_scan}",
                    case["id"]
                );
                if let Some(size) = matched {
                    assert_eq!(size, 512);
                }
            }
        }
    }
}

#[test]
fn carved_pool_tag_at_segment_start_does_not_require_unused_header_tail() {
    let (mut bytes, isf, base, _) =
        super::super::driver_irp::tests::driver_fixture(false, false, false);
    bytes[0xb000..0xb008].fill(0); // Remove unrelated driver tag.
    bytes[0x18000..0x18002].copy_from_slice(&32u16.to_le_bytes());
    bytes[0x18002..0x18004].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x18004..0x18008].copy_from_slice(b"Wind");
    let mut snapshot = image(&bytes);
    snapshot.segments = vec![
        crate::image::Segment {
            start: 0,
            end: 0x18004,
            file_offset: 0,
        },
        crate::image::Segment {
            start: 0x18004,
            end: 0x18008,
            file_offset: 0x18004,
        },
        crate::image::Segment {
            start: 0x18010,
            end: bytes.len() as u64,
            file_offset: 0x18010,
        },
    ];
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let constraint = Constraint::new(b"Wind", "station", None, 0x90, 3, true, &[]);
    let (_, bodies, notes) = windows
        .scan_pool_objects(&[&constraint], 32, &Job::default())
        .unwrap();
    assert_eq!(bodies, [0x18010]);
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn merged_pool_tags_match_actual_reference_order_and_non_overlap() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-order.json"
    ))
    .unwrap();
    let decode = |text: &str| -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
            .collect()
    };
    for case in vectors["cases"].as_array().unwrap() {
        let data = decode(case["data_hex"].as_str().unwrap());
        let tags: Vec<_> = case["tags_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tag| decode(tag.as_str().unwrap()))
            .collect();
        let matches: Vec<_> = PoolTagMatches::new(&data, tags.iter().map(Vec::as_slice))
            .unwrap()
            .map(|(index, at)| [at, index])
            .collect();
        assert_eq!(
            serde_json::json!(matches),
            case["expected_matches"],
            "{}",
            case["id"]
        );
        let headers: Vec<_> = matches
            .iter()
            .filter(|entry| {
                !case["rejected_indices"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!(entry[1]))
            })
            .map(|entry| [0x1000 + entry[0] - 4, entry[1]])
            .collect();
        assert_eq!(
            serde_json::json!(headers),
            case["expected_headers"],
            "{}",
            case["id"]
        );
    }
    assert!(PoolTagMatches::new(b"Driv", [b"Driv".as_slice(), b"Driv".as_slice()]).is_err());
    assert!(PoolTagMatches::new(b"", std::iter::empty()).is_err());
}

#[test]
fn driverscan_requires_eight_captured_bytes_and_a_strict_start_boundary() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/driver-scan.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let width = case["width"].as_u64().unwrap();
        let (mut bytes, isf, base, _) =
            super::super::driver_irp::tests::driver_fixture(width == 4, false, false);
        let available = case["available_bytes"].as_u64().unwrap() as usize;
        let descriptor = 0x3f000;
        put(&mut bytes, descriptor, case["raw"].as_u64().unwrap());
        bytes.truncate(descriptor + available);
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let found = windows
            .reference_driver_start(
                (descriptor - 16) as u64,
                false,
                case["threshold"].as_u64().unwrap(),
            )
            .unwrap_or(false);
        assert_eq!(found, case["expected"].as_bool().unwrap(), "{}", case["id"]);
    }
}

#[test]
fn process_and_thread_validity_match_pinned_calendar_name_and_pointer_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-validity.json"
    ))
    .unwrap();
    for case in vectors["process"].as_array().unwrap() {
        let (mut bytes, mut isf) = fixture();
        isf.data["user_types"]["_EPROCESS"]["fields"]["ThreadListHead"] =
            json!({"offset":128,"type":{"kind":"struct","name":"_LIST_ENTRY"}});
        if !case["pid_pointer"].as_bool().unwrap() {
            isf.data["user_types"]["_EPROCESS"]["fields"]["UniqueProcessId"]["type"] =
                json!({"kind":"base","name":"u64"});
        }
        if case["dtb_array"].as_bool().unwrap() {
            isf.data["user_types"]["_KPROCESS"]["fields"]["DirectoryTableBase"]["type"] =
                json!({"kind":"array","count":8});
        }
        bytes[0xc000..0xc100].fill(0);
        let name: Vec<_> = case["name_hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        bytes[0xc030..0xc030 + name.len()].copy_from_slice(&name);
        for (offset, key) in [(32, "pid"), (112, "dtb"), (128, "flink"), (136, "blink")] {
            put(&mut bytes, 0xc000 + offset, case[key].as_u64().unwrap());
        }
        for (offset, key) in [(88, "created"), (96, "exited")] {
            put(
                &mut bytes,
                0xc000 + offset,
                case[key].as_i64().unwrap() as u64,
            );
        }
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            windows
                .pool_process_valid(0xc000, false, Some(case["year"].as_i64().unwrap()))
                .unwrap(),
            case["expected"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
    for case in vectors["thread"].as_array().unwrap() {
        let (mut bytes, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_ETHREAD"] = json!({"size":64,"fields":{"Cid":{"offset":0,"type":{"kind":"struct","name":"_CLIENT_ID"}},"CreateTime":{"offset":16,"type":{"kind":"base","name":"u64"}}}});
        isf.data["user_types"]["_CLIENT_ID"] =
            json!({"size":16,"fields":{"UniqueProcess":pointer(0),"UniqueThread":pointer(8)}});
        if case["legacy"].as_bool().unwrap() {
            isf.data["user_types"]["_ETHREAD"]["fields"]["ThreadsProcess"] = pointer(24);
        }
        bytes[0xc000..0xc040].fill(0);
        put(&mut bytes, 0xc000, case["pid"].as_u64().unwrap());
        put(&mut bytes, 0xc008, case["tid"].as_u64().unwrap());
        put(&mut bytes, 0xc010, case["created"].as_i64().unwrap() as u64);
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            windows
                .pool_thread_valid(0xc000, false, Some(case["year"].as_i64().unwrap()))
                .unwrap(),
            case["expected"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn recursive_kernel_page_aliases_match_fixed_intel_mapping() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x1000, 0x2003);
    let snapshot = image(&bytes);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-types.json"
    ))
    .unwrap();
    let alias =
        windows.pool_reference_pointer(vectors["recursive_mapping"]["address"].as_u64().unwrap());
    let expected_physical = vectors["recursive_mapping"]["mappings"][0][2]
        .as_u64()
        .unwrap();
    let mut found = None;
    let mut user = None;
    windows
        .walk_kernel_pages(
            windows.vm.root,
            0,
            0,
            &windows.vm.paging().unwrap(),
            &mut |va, physical, shift| {
                if alias >= va && alias < va + (1 << shift) {
                    found = Some(physical + alias - va);
                }
                if va == 0 {
                    user = Some(physical);
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(found, Some(expected_physical));
    assert_eq!(user, vectors["user_mapping"]["mappings"][0][2].as_u64());
}

#[test]
fn pool_pointer_values_match_reference_native_layer_mask() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-types.json"
    ))
    .unwrap();
    for case in vectors["pointer_cases"].as_array().unwrap() {
        let (bytes, mut isf) = fixture();
        let width = case["width"].as_u64().unwrap();
        if width == 4 {
            isf.data["base_types"]["pointer"]["size"] = json!(4);
            isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
        }
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let value = windows.pool_reference_pointer(case["raw"].as_u64().unwrap());
        let mask = if width == 4 {
            0xffff_ffff
        } else {
            0xffff_ffff_ffff
        };
        assert_eq!(value & mask, case["expected"].as_u64().unwrap());
        assert!(windows.vm.paging().unwrap().canonical(value));
    }
}

#[test]
fn top_down_missing_window_tail_matches_pinned_padded_carving() {
    let (bytes, mut isf) = fixture();
    isf.data["base_types"]["u8"] = json!({"size":1});
    isf.data["user_types"]["_POOL_HEADER"] = json!({"size":16,"fields":{}});
    isf.data["user_types"]["_OBJECT_HEADER"] = json!({"size":56,"fields":{"Body":{"offset":48,"type":{"kind":"base","name":"u64"}},"InfoMask":{"offset":26,"type":{"kind":"base","name":"u8"}},"PointerCount":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
    let mut truncated = bytes[..0x2000].to_vec();
    truncated[0x1fc0..].fill(0);
    let snapshot = image(&truncated);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let constraint = Constraint::new(
        b"Wind",
        "tagWINDOWSTATION",
        Some("WindowStation"),
        0,
        3,
        true,
        &[],
    );
    let bodies = windows
        .pool_bodies(
            &constraint,
            0x1fc0,
            PoolCarve {
                block: 128,
                alignment: 16,
                type_size: 152,
                top_down: true,
                optional: &[(false, 32), (true, 4)],
                virtual_scan: false,
            },
            &Job::default(),
        )
        .unwrap();
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/gui-pool-padding.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::json!(bodies),
        vectors["missing_tail"]["expected_bodies"]
    );
    // A successful prefix is retained; padding replaces only absent bytes.
    truncated[0x1ffe..].copy_from_slice(&[0x41, 0x42]);
    let snapshot = image(&truncated);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let mut read = [0xff; 4];
    windows.pool_read_padded(0x1ffe, &mut read, false).unwrap();
    assert_eq!(read, [0x41, 0x42, 0, 0]);
}

#[test]
fn pool_type_map_matches_pinned_sentinel_limit_and_missing_names() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-types.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let (mut bytes, mut isf) = fixture();
        isf.data["user_types"]["_OBJECT_HEADER"] = json!({"size":56,"fields":{"TypeIndex":{"offset":24,"type":{"kind":"base","name":"u16"}}}});
        isf.data["user_types"]["_OBJECT_TYPE"] = json!({"size":16,"fields":{"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
        isf.data["symbols"]["ObTypeIndexTable"] = json!({"address":0x500});
        bytes[0x8500..0x8500 + 102 * 8].fill(0);
        for (index, entry) in case["entries"].as_array().unwrap().iter().enumerate() {
            let Some(name) = entry.as_str() else { continue };
            let descriptor = 0x12000 + index * 32;
            let buffer = 0x16000 + index * 32;
            put(
                &mut bytes,
                0x8500 + index * 8,
                K + (descriptor - 0x8000) as u64,
            );
            let encoded: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            bytes[descriptor..descriptor + 2]
                .copy_from_slice(&(encoded.len() as u16).to_le_bytes());
            put(
                &mut bytes,
                descriptor + 8,
                if name == "!unreadable" {
                    K + 0x30000
                } else {
                    K + (buffer - 0x8000) as u64
                },
            );
            bytes[buffer..buffer + encoded.len()].copy_from_slice(&encoded);
        }
        if !case["table_valid"].as_bool().unwrap() {
            isf.data["symbols"]["ObTypeIndexTable"] = json!({"address":0x30000});
        }
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            serde_json::json!(windows.pool_reference_type_map().unwrap()),
            case["expected"],
            "{}",
            case["id"]
        );
    }
}

#[test]
fn nonexecutive_hives_keep_raw_observations_without_signature_validation() {
    let (bytes, mut isf) = fixture();
    isf.data["user_types"]["_POOL_HEADER"] = json!({"size":16,"fields":{}});
    let snapshot = image(&bytes);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let constraint = CONSTRAINTS.iter().find(|c| c.tag == b"CM10").unwrap();
    let bodies = windows
        .pool_bodies(
            constraint,
            0x1000,
            PoolCarve {
                block: 800,
                alignment: 16,
                type_size: 816,
                top_down: true,
                optional: &[],
                virtual_scan: false,
            },
            &Job::default(),
        )
        .unwrap();
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-types.json"
    ))
    .unwrap();
    assert_eq!(serde_json::json!(bodies), reference["nonexecutive_bodies"]);
    let mut result = windows.result(Plugin::WinPoolScanner);
    let mut diagnostics = 0;
    for body in bodies {
        assert!(
            windows
                .pool_object_valid(
                    constraint,
                    body,
                    false,
                    &PoolValidation {
                        types: BTreeMap::new(),
                    },
                    &mut result,
                    &mut diagnostics
                )
                .unwrap()
        );
    }
    assert_eq!(diagnostics, 0);
}

#[test]
fn missing_file_name_tail_skips_only_that_file() {
    let (mut bytes, mut isf) = fixture();
    isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":160,"fields":{"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
    put(&mut bytes, 0x1000, 0x2003); // The native kernel DTB also maps user addresses.
    put(&mut bytes, 0x4000 + 2 * 8, 0); // Missing second name page.
    bytes[0xc000..0xc002].copy_from_slice(&4u16.to_le_bytes());
    put(&mut bytes, 0xc008, K + 0x1ffe);
    bytes[0x9ffe..0xa000].copy_from_slice(&[b'x', 0]);
    bytes[0xc100..0xc102].copy_from_slice(&4u16.to_le_bytes());
    put(&mut bytes, 0xc108, 0xd100000000006000);
    bytes[0xe000..0xe004].copy_from_slice(&[b'o', 0, b'k', 0]);
    let snapshot = image(&bytes);
    let windows = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let file = CONSTRAINTS.iter().find(|c| c.tag == b"File").unwrap();
    assert!(windows.address_readable(K + 0x1ffe));
    assert!(windows.address_readable(0xd100000000006000));
    assert_eq!(
        windows.pool_scanner_name(file, 0xc000, false).unwrap(),
        None
    );
    let names: Vec<_> = [0xc000, 0xc100]
        .into_iter()
        .filter_map(|at| windows.pool_scanner_name(file, at, false).unwrap())
        .collect();
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-headers.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::json!(names),
        reference["file_name_fault"]["expected_names"]
    );
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/gui-stations.json"
    ))
    .unwrap();
    for case in vectors["strings"].as_array().unwrap() {
        let data: Vec<_> = case["hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|word| u8::from_str_radix(std::str::from_utf8(word).unwrap(), 16).unwrap())
            .collect();
        let mut named = bytes.clone();
        named[0xc100..0xc102].copy_from_slice(&(data.len() as u16).to_le_bytes());
        named[0xe000..0xe000 + data.len()].copy_from_slice(&data);
        let snapshot = image(&named);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert_eq!(
            serde_json::json!(windows.pool_scanner_name(file, 0xc100, false).unwrap()),
            case["expected"],
            "{case}"
        );
    }
}

#[test]
fn gui_tag_matches_keep_the_exact_unaligned_header_address() {
    let (mut bytes, mut isf) = fixture();
    let field =
        |offset, name| serde_json::json!({"offset":offset,"type":{"kind":"base","name":name}});
    for (name, size) in [("u16", 2), ("u8", 1), ("u32", 4)] {
        isf.data["base_types"][name] = serde_json::json!({"size":size});
    }
    isf.data["user_types"]["_POOL_HEADER"] = serde_json::json!({"size":16,"fields":{"BlockSize":field(0,"u16"),"PoolType":field(2,"u16"),"PoolTag":field(4,"u32")}});
    isf.data["user_types"]["_QUAD"] = serde_json::json!({"size":8,"fields":{}});
    isf.data["user_types"]["_OBJECT_HEADER"] = serde_json::json!({"size":56,"fields":{"Body":{"offset":48,"type":{"kind":"struct","name":"_QUAD"}},"InfoMask":field(26,"u8"),"PointerCount":field(0,"u64")}});
    isf.data["user_types"]["_OBJECT_HEADER_NAME_INFO"] = serde_json::json!({"size":32,"fields":{}});
    put(&mut bytes, 0x8200, 15063);
    let at = 0xc003;
    bytes[at..at + 64].fill(0);
    bytes[at..at + 2].copy_from_slice(&16u16.to_le_bytes());
    bytes[at + 2..at + 4].copy_from_slice(&1u16.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(b"Wind");
    let img = image(&bytes);
    let w = Windows {
        vm: Memory::new(&img, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let (virtual_scan, bodies, _) = w
        .scan_gui_pool(b"Wind", 152, 0x90, &Job::default())
        .unwrap();
    assert!(virtual_scan);
    assert!(bodies.contains(&(K + 0x4003 + 16 + 48)), "{bodies:x?}");
    assert!(
        !bodies.contains(&(K + 0x4000 + 16 + 48)),
        "must not carve at a different header: {bodies:x?}"
    );
}
#[test]
fn top_down_padding_matches_pinned_signed_subtraction_and_comparison() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/gui-pool-padding.json"
    ))
    .unwrap();
    for c in vectors["cases"].as_array().unwrap() {
        let (mut bytes, mut isf) = fixture();
        isf.data["base_types"]["u8"] = serde_json::json!({"size":1});
        isf.data["user_types"]["_POOL_HEADER"] = serde_json::json!({"size":16,"fields":{}});
        isf.data["user_types"]["_QUAD"] = serde_json::json!({"size":8,"fields":{}});
        isf.data["user_types"]["_OBJECT_HEADER"] = serde_json::json!({"size":56,"fields":{"Body":{"offset":48,"type":{"kind":"struct","name":"_QUAD"}},"InfoMask":{"offset":26,"type":{"kind":"base","name":"u8"}},"PointerCount":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
        bytes[0xc000..0xc080].fill(0);
        bytes[0xc01c..0xc020]
            .copy_from_slice(&(c["encoded_padding"].as_u64().unwrap() as u32).to_le_bytes());
        bytes[0xc03a] = 2;
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let constraint = Constraint::new(
            b"Wind",
            "tagWINDOWSTATION",
            Some("WindowStation"),
            0,
            3,
            true,
            &[],
        );
        let found = w
            .pool_bodies(
                &constraint,
                K + 0x4000,
                PoolCarve {
                    block: 128,
                    alignment: 16,
                    type_size: 152,
                    top_down: true,
                    optional: &[(false, 32), (true, 4)],
                    virtual_scan: true,
                },
                &Job::default(),
            )
            .unwrap();
        let relative: Vec<_> = found.into_iter().map(|at| at - (K + 0x4000)).collect();
        assert_eq!(serde_json::json!(relative), c["expected_bodies"]);
    }
}
#[test]
fn physical_pool_scan_keeps_valid_process_and_reports_unreadable_ranges() {
    let (mut bytes, mut isf) = fixture();
    let field = |offset, name| json!({"offset":offset,"type":{"kind":"base","name":name}});
    for (name, size) in [("u32", 4), ("u16", 2), ("u8", 1)] {
        isf.data["base_types"][name] = json!({"size":size});
    }
    isf.data["symbols"]["NtBuildNumber"] = json!({"address":0x200});
    put(&mut bytes, 0x8200, 3790);
    for (name, size, fields) in [
        (
            "_POOL_HEADER",
            16,
            json!({"BlockSize":field(0,"u16"),"PoolType":field(2,"u16"),"PoolTag":field(4,"u32")}),
        ),
        (
            "_OBJECT_HEADER",
            16,
            json!({"Body":{"offset":8,"type":{"kind":"struct","name":"_QUAD"}}}),
        ),
        (
            "_RTL_ATOM_TABLE",
            208,
            json!({"NumberOfBuckets":field(0,"u32")}),
        ),
        (
            "_EPROCESS",
            640,
            json!({"UniqueProcessId":field(32,"u64"),"ImageFileName":{"offset":48,"type":{"kind":"array","count":16}},"CreateTime":field(88,"u64"),"ExitTime":field(96,"u64"),"Pcb":{"offset":112,"type":{"kind":"struct","name":"_KPROCESS"}},"ThreadListHead":{"offset":128,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}),
        ),
        (
            "_ETHREAD",
            640,
            json!({"Cid":{"offset":0,"type":{"kind":"struct","name":"_CLIENT_ID"}},"CreateTime":field(32,"u64")}),
        ),
        (
            "_CLIENT_ID",
            16,
            json!({"UniqueProcess":field(0,"u64"),"UniqueThread":field(8,"u64")}),
        ),
        (
            "_FILE_OBJECT",
            160,
            json!({"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}),
        ),
        ("_KMUTANT", 64, json!({"Header":field(0,"u64")})),
        ("_DRIVER_OBJECT", 256, json!({"DriverStart":field(0,"u64")})),
        (
            "_DRIVER_EXTENSION",
            16,
            json!({"DriverObject":field(0,"u64")}),
        ),
        (
            "_LDR_DATA_TABLE_ENTRY",
            80,
            json!({"DllBase":field(0,"u64")}),
        ),
        (
            "_OBJECT_SYMBOLIC_LINK",
            80,
            json!({"CreationTime":field(0,"u64")}),
        ),
        (
            "_CMHIVE",
            816,
            json!({"Hive":{"offset":0,"type":{"kind":"struct","name":"_HHIVE"}}}),
        ),
        ("_HHIVE", 8, json!({"Signature":field(0,"u32")})),
        ("_QUAD", 8, json!({})),
    ] {
        isf.data["user_types"][name] = json!({"size":size,"fields":fields});
    }
    bytes[0xc000..0xc002].copy_from_slice(&41u16.to_le_bytes());
    bytes[0xc002..0xc004].copy_from_slice(&1u16.to_le_bytes());
    bytes[0xc004..0xc008].copy_from_slice(&[b'P', b'r', b'o', 0xe3]);
    bytes[0xc000 + 16 + 32..0xc000 + 16 + 40].copy_from_slice(&4u64.to_le_bytes());
    bytes[0xc000 + 16 + 48..0xc000 + 16 + 54].copy_from_slice(b"System");
    bytes[0xc000 + 16 + 112..0xc000 + 16 + 120].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0xc000 + 16 + 128..0xc000 + 16 + 136].copy_from_slice(&(K + 0x1000).to_le_bytes());
    bytes[0xc000 + 16 + 136..0xc000 + 16 + 144].copy_from_slice(&(K + 0x1000).to_le_bytes());
    let image = image(&bytes);
    let windows = Windows {
        vm: Memory::new(&image, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let result = windows.pool_scanner(&Job::default()).unwrap();
    assert_eq!(result.rows.len(), 1, "{:#?}", result);
    assert_eq!(result.rows[0][0], "symbol_table_name1!_EPROCESS");
    assert_eq!(result.rows[0][2], "memory_layer");
    assert_eq!(result.rows[0][3], "System");
    assert!(result.columns == ["Tag", "Offset", "Layer", "Name"]);
    assert!(result.complete);
    // A later atom tag must not jump ahead of the earlier process merely
    // because its constraint appears first in the builtin list.
    let mut mixed = bytes.clone();
    mixed[0xc400..0xc402].copy_from_slice(&13u16.to_le_bytes());
    mixed[0xc404..0xc408].copy_from_slice(b"AtmT");
    let snapshot = super::super::tests::image(&mixed);
    let native = Windows {
        vm: Memory::new(&snapshot, 0x1000, &isf, None),
        base: K,
        pdb: PdbIdentity::from_isf(&isf).unwrap(),
    };
    let ordered = native.pool_scanner(&Job::default()).unwrap();
    assert_eq!(
        ordered
            .rows
            .iter()
            .map(|row| row[0].as_str())
            .collect::<Vec<_>>(),
        [
            "symbol_table_name1!_EPROCESS",
            "symbol_table_name1!_RTL_ATOM_TABLE"
        ]
    );

    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/pool-headers.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let offset = case["header_offset"].as_u64().unwrap() as usize;
        let mut shifted = bytes.clone();
        shifted[0xc000..0xc400].fill(0);
        let expected_type = if case["tag_hex"] == "50726fe3" {
            shifted[0xc000 + offset..0xc300 + offset].copy_from_slice(&bytes[0xc000..0xc300]);
            "symbol_table_name1!_EPROCESS"
        } else {
            shifted[0xc000 + offset..0xc002 + offset].copy_from_slice(&13u16.to_le_bytes());
            shifted[0xc004 + offset..0xc008 + offset].copy_from_slice(b"AtmT");
            "symbol_table_name1!_RTL_ATOM_TABLE"
        };
        let snapshot = super::super::tests::image(&shifted);
        let native = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        }
        .pool_scanner(&Job::default())
        .unwrap();
        let expected: Vec<_> = case["expected_headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|at| hex(0xc000 + at.as_u64().unwrap()))
            .collect();
        assert_eq!(
            native.rows.iter().map(|r| r[1].clone()).collect::<Vec<_>>(),
            expected,
            "{case}"
        );
        assert!(native.rows.iter().all(|r| r[0] == expected_type));
    }
}
