//! Native byte-regex scans over process VADs, backed by shared resident-range scans.
use super::*;
use crate::{analysis::Options, byte_regex::ByteRegex, regex_scan};
impl Windows<'_> {
    pub(super) fn vad_regex_scan(&self, options: &Options, job: &Job) -> Result<Results> {
        let pattern = options
            .pattern
            .as_deref()
            .context("此插件需要 --pattern 字节正则")?;
        let regex = ByteRegex::compile(pattern, true)?;
        let display = ByteRegex::compile(pattern, false)?;
        // Both pinned canonical generators read MAXSIZE_DEFAULT, not config.maxsize.
        let maxsize = regex_scan::REFERENCE_CONTEXT_SIZE;
        ensure!(options.pids.len() <= 4096, "PID 列表超过 4096 项");
        let pids: std::collections::BTreeSet<_> = options
            .pids
            .iter()
            .copied()
            .chain(options.pid)
            .map(u64::from)
            .collect();
        let mut result = self.result(Plugin::WinVadRegExScan);
        let (tasks, diagnostics) = self.processes_partial(job)?;
        result.complete &= diagnostics.is_empty();
        result.diagnostics.extend(diagnostics);
        let mut process_reports = Vec::new();
        let mut recovered_hits = Vec::new();
        let mut recovered_hit_overflow = false;
        let mut metadata_truncated = false;
        let mut output_bytes = 0usize;
        let mut output_limit = false;
        for task in tasks {
            job.check()?;
            let pid = task.pid;
            if !pids.is_empty() && !pids.contains(&pid) {
                continue;
            }
            let mut context_missing = 0u64;
            let scanned = (|| -> Result<Option<regex_scan::Coverage>> {
                let vm = self.process_memory(&task)?;
                let regions = self.vad_scan_ranges(&task, &mut result, job)?;
                let mut visit = |at| {
                    if result.rows.len() >= 100_000 {
                        output_limit = true;
                        return Ok(false);
                    }
                    let shown =
                        regex_scan::display_match(&display, at, maxsize, job, |address, bytes| {
                            vm.read_reference(address, bytes)
                        })?;
                    context_missing += shown.unreadable_bytes;
                    let text = shown.text;
                    let encoded = shown.hex;
                    let size = text.len() + encoded.len() + task.name.len() + 64;
                    if output_bytes + size > 128 * 1024 * 1024 {
                        output_limit = true;
                        return Ok(false);
                    }
                    output_bytes += size;
                    if vm.translate(at).is_err() && vm.read_reference(at, &mut [0]).is_ok() {
                        if recovered_hits.len() < 65536 {
                            let origin = if vm.paging()?.arch != Architecture::Arm64 {
                                "reference_pagefile"
                            } else if vm.prototype(at).is_ok() {
                                "prototype"
                            } else {
                                "software_or_compressed"
                            };
                            recovered_hits.push(serde_json::json!({"pid":pid,"offset":hex(at),"start_page_origin":origin}));
                        } else {
                            recovered_hit_overflow = true;
                        }
                    }
                    result.rows.push(vec![
                        pid.to_string(),
                        task.name.clone(),
                        hex(at),
                        text,
                        encoded,
                    ]);
                    Ok(true)
                };
                let mut budget = regex_scan::Budget::default();
                let coverage = vm.scan_reference(&regex, &regions, &mut budget, job, &mut visit)?;
                Ok(Some(coverage))
            })();
            match scanned {
                Ok(Some(coverage)) => {
                    if !coverage.complete() || context_missing > 0 {
                        crate::report::partial(
                            &mut result,
                            format!("PID {pid} 正则扫描"),
                            anyhow::anyhow!(
                                "扫描 {} / {} 字节；缺页 {} 字节；区间合并省略 {} 字节；上下文补零 {} 字节；{}",
                                coverage.scanned_bytes,
                                coverage.requested_bytes,
                                coverage.unreadable_bytes,
                                coverage.reference_coalescing_omitted_bytes,
                                context_missing,
                                coverage.stop_reason.as_deref().unwrap_or("扫描结束")
                            ),
                        );
                    }
                    if process_reports.len() < 65536 {
                        process_reports.push(serde_json::json!({"pid":pid,"coverage":coverage,"context_unreadable_bytes":context_missing}));
                    } else {
                        metadata_truncated = true;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    job.check()?;
                    crate::report::partial(&mut result, format!("PID {pid} 正则扫描"), error);
                }
            }
            if output_limit {
                break;
            }
        }
        if metadata_truncated || recovered_hit_overflow {
            crate::report::partial(
                &mut result,
                "扫描覆盖元数据",
                anyhow::anyhow!("进程覆盖记录达到 65536 项上限"),
            );
        }
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        result.kernel_identity["vad_regex_scan"] = serde_json::json!({"read_policy":if self.vm.paging()?.arch == Architecture::Arm64 {"native_arm64_recovery"} else {"pinned_windows_intel"},"engine":"PCRE2 bytes; no UTF/UCP/JIT","mapping_policy":if self.vm.paging()?.arch==Architecture::Arm64 {"native_arm64"}else{"pinned_intel"},"scan_dotall":true,"display_dotall":false,"maxsize":maxsize,"requested_maxsize":options.maxsize,"pids":pids,"chunk_bytes":16*1024*1024,"overlap_bytes":4096,"match_limit":crate::byte_regex::MATCH_LIMIT,"depth_limit":crate::byte_regex::DEPTH_LIMIT,"heap_kib":crate::byte_regex::HEAP_KIB,"subject_work_limit":crate::byte_regex::WORK_LIMIT,"output_limit":output_limit,"metadata_truncated":metadata_truncated,"recovered_hit_overflow":recovered_hit_overflow,"recovered_start_page_hits":recovered_hits,"processes":process_reports});
        Ok(result)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    pub(in crate::windows) fn prepared() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"] =
            json!({"offset":128,"type":{"kind":"struct","name":"_RTL_AVL_TREE"}});
        isf.data["user_types"]["_RTL_AVL_TREE"] = json!({"size":8,"fields":{"Root":pointer(0)}});
        isf.data["user_types"]["_RTL_BALANCED_NODE"] =
            json!({"size":24,"fields":{"Left":pointer(0),"Right":pointer(8)}});
        isf.data["user_types"]["_MMVAD_SHORT"] = json!({"size":64,"fields":{"VadNode":{"offset":0,"type":{"kind":"struct","name":"_RTL_BALANCED_NODE"}},"StartingVpn":number(24),"EndingVpn":number(32),"u":{"offset":40,"type":{"kind":"struct","name":"_MMVAD_FLAGS"}}}});
        isf.data["user_types"]["_MMVAD_FLAGS"] = json!({"size":8,"fields":{"Protection":{"offset":0,"type":{"kind":"bitfield","bit_position":0,"bit_length":5,"type":{"kind":"base","name":"u64"}}},"PrivateMemory":{"offset":0,"type":{"kind":"bitfield","bit_position":5,"bit_length":1,"type":{"kind":"base","name":"u64"}}}}});
        put(&mut b, 0xa080, K + 0x3000);
        for at in [0xb000, 0xb100] {
            b[at - 12..at - 8].copy_from_slice(b"VadS");
        }
        put(&mut b, 0xb008, K + 0x3100);
        for (node, vpn) in [(0xb000, 1), (0xb100, 2)] {
            put(&mut b, node + 24, vpn);
            put(&mut b, node + 32, vpn);
            put(&mut b, node + 40, 32); // no access protection still scanned
        }
        for (at, value) in [
            (0x1000, 0x5003),
            (0x5000, 0x6003),
            (0x6000, 0x7003),
            (0x7008, 0x20003),
            (0x7010, 0x25003),
        ] {
            put(&mut b, at, value);
        }
        b[0x20ffe..0x21000].copy_from_slice(b"AB");
        b[0x25000..0x25002].copy_from_slice(b"AB");
        (b, isf)
    }
    fn run(b: &[u8], isf: &Isf, options: &Options) -> Results {
        let image = image(b);
        Windows {
            vm: Memory::new(&image, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        }
        .run(Plugin::WinVadRegExScan, options, &Job::default())
        .unwrap()
    }
    fn resident_match() -> (Vec<u8>, Isf) {
        let (mut bytes, isf) = prepared();
        bytes[0x20010..0x20014].copy_from_slice(b"ABAB");
        (bytes, isf)
    }
    #[test]
    fn leading_empty_subject_hit_is_not_a_recovered_page() {
        let (bytes, isf) = prepared();
        let result = run(
            &bytes,
            &isf,
            &Options {
                pattern: Some("^$".into()),
                pid: Some(8),
                ..Default::default()
            },
        );
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][2], hex(0));
        assert_eq!(result.rows[0][3], "\0".repeat(128));
        assert_eq!(
            result.kernel_identity["vad_regex_scan"]["recovered_start_page_hits"],
            json!([])
        );
        assert!(!result.complete);
    }

    #[test]
    fn canonical_scan_reads_explicit_reference_pagefile_and_tracks_origin() {
        let (mut bytes, isf) = prepared();
        put(&mut bytes, 0x7010, (1 << 32) | 0x80);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pagefile.sys");
        let mut data = vec![0; 8192];
        data[4096..4100].copy_from_slice(b"ZXCV");
        std::fs::write(&path, data).unwrap();
        let options = Options {
            pattern: Some("ZXCV".into()),
            pid: Some(8),
            pagefiles: vec![paging::Attachment { index: 0, path }],
            ..Default::default()
        };
        let sources = paging::Sources::open(&options, &Job::default()).unwrap();
        let image = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&image, 0x1000, &isf, Some(&sources)),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let result = windows.vad_regex_scan(&options, &Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(
            result.rows,
            [vec![
                "8",
                "child",
                "0x0000000000002000",
                "ZXCV",
                "5a 58 43 56"
            ]]
        );
        assert_eq!(
            result.kernel_identity["vad_regex_scan"]["recovered_start_page_hits"],
            json!([{"pid":8,"offset":hex(0x2000),"start_page_origin":"reference_pagefile"}])
        );
    }

    #[test]
    fn display_context_matches_actual_pinned_generator_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/regex-context.json"
        ))
        .unwrap();
        for case in vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["system"] == "windows")
        {
            let data: Vec<u8> = case["data_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let options = Options {
                pattern: Some(case["pattern"].as_str().unwrap().into()),
                pid: Some(42),
                maxsize: case["maxsize"].as_i64(),
                ..Default::default()
            };
            let (mut bytes, isf) = prepared();
            bytes[0x20000..0x21000].fill(0);
            bytes[0x25000..0x26000].fill(0);
            bytes[0x20000..0x20000 + data.len()].copy_from_slice(&data);
            put(&mut bytes, 0xa020, 42);
            bytes[0xa030..0xa040].fill(0);
            bytes[0xa030..0xa036].copy_from_slice(b"sample");
            let actual = run(&bytes, &isf, &options);

            let mut expected = case["expected"].clone();
            for row in expected.as_array_mut().unwrap() {
                let address = u64::from_str_radix(&row[2].as_str().unwrap()[2..], 16).unwrap();
                row[2] = serde_json::json!(format!("0x{address:016x}"));
            }
            assert_eq!(serde_json::json!(actual.rows), expected, "{}", case["id"]);
            assert_eq!(actual.kernel_identity["vad_regex_scan"]["maxsize"], 128);
            assert!(
                case["reads"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|read| read[1] == 128 && read[2] == true)
            );
        }
    }

    #[test]
    fn all_five_fields_adjacent_vads_noncontiguous_pages_and_pid_union() {
        let (b, isf) = resident_match();
        let options = Options {
            pattern: Some("(?P<p>AB)(?P=p)".into()),
            pid: Some(4),
            pids: vec![8],
            ..Default::default()
        };
        let r = run(&b, &isf, &options);
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [vec![
                "8",
                "child",
                "0x0000000000001010",
                "ABAB",
                "41 42 41 42"
            ]]
        );
        assert_eq!(r.kernel_identity["vad_regex_scan"]["pids"], json!([4, 8]));
        assert_eq!(
            r.kernel_identity["vad_regex_scan"]["processes"][1]["coverage"]["scanned_bytes"],
            8192
        );
        let r = run(
            &b,
            &isf,
            &Options {
                pid: Some(4),
                pids: vec![],
                ..options
            },
        );
        assert!(r.rows.is_empty());
    }
    #[test]
    fn vad_prefix_survives_tree_damage_and_holes_never_form_search_subjects() {
        let (mut b, isf) = prepared();
        put(&mut b, 0xb100, 0x123); // unreadable/invalid child, retain valid node
        put(&mut b, 0x7010, 0); // second user page missing
        let options = Options {
            pattern: Some("AB".into()),
            pids: vec![8],
            maxsize: Some(4),
            ..Default::default()
        };
        let r = run(&b, &isf, &options);
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(&r.rows[0][3..], ["AB", "41 42"]);
        let evidence = &r.kernel_identity["vad_regex_scan"]["processes"][0];
        assert_eq!(evidence["coverage"]["unreadable_bytes"], 4096);
        assert_eq!(evidence["context_unreadable_bytes"], 126);
        let r = run(
            &b,
            &isf,
            &Options {
                pattern: Some("AB\\x00\\x00".into()),
                ..options
            },
        );
        assert!(r.rows.is_empty());
        assert!(!r.complete);
    }
    #[test]
    fn maxsize_display_rescan_invalid_regex_and_cancellation() {
        let (mut b, isf) = prepared();
        b[0x20000..0x20005].copy_from_slice(b"A\nBxx");
        let options = Options {
            pattern: Some("A.B".into()),
            pid: Some(8),
            maxsize: Some(5),
            ..Default::default()
        };
        let r = run(&b, &isf, &options);
        assert!(r.rows[0][3].starts_with("A\nBxx"));
        assert_eq!(r.rows[0][3].len(), 128);
        assert_eq!(r.rows[0][4].split_whitespace().count(), 128);
        let image = image(&b);
        let w = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(
            w.run(
                Plugin::WinVadRegExScan,
                &Options {
                    pattern: Some("(".into()),
                    ..options.clone()
                },
                &Job::default()
            )
            .is_err()
        );
        for size in [i64::MIN, -1, 0, 1, 4097, i64::MAX] {
            let same = w
                .run(
                    Plugin::WinVadRegExScan,
                    &Options {
                        maxsize: Some(size),
                        ..options.clone()
                    },
                    &Job::default(),
                )
                .unwrap();
            assert_eq!(same.rows, r.rows, "maxsize={size}");
        }
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(w.run(Plugin::WinVadRegExScan, &options, &job).is_err());
    }
    #[test]
    fn huge_reserved_vad_uses_proven_empty_tables_and_keeps_later_resident_hits() {
        let (mut b, isf) = prepared();
        put(&mut b, 0xb108, K + 0x3200);
        put(&mut b, 0xb208, K + 0x3300);
        for (at, start, end) in [
            (0xb200, 3, (1u64 << 27) - 1),
            (0xb300, 1u64 << 27, 1u64 << 27),
        ] {
            b[at - 12..at - 8].copy_from_slice(b"VadS");
            put(&mut b, at + 24, start);
            put(&mut b, at + 32, end);
            put(&mut b, at + 40, 32);
        }
        put(&mut b, 0x1008, 0x5003);
        put(&mut b, 0x7000, 0x27003);
        b[0x27000..0x27006].copy_from_slice(b"needle");
        let r = run(
            &b,
            &isf,
            &Options {
                pattern: Some("needle".into()),
                pid: Some(8),
                ..Default::default()
            },
        );
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][2], hex(1u64 << 39));
        let c = &r.kernel_identity["vad_regex_scan"]["processes"][0]["coverage"];
        assert!(c["page_attempts"].as_u64().unwrap() < 3000);
        assert!(c["unreadable_bytes"].as_u64().unwrap() > 500 * 1024 * 1024 * 1024);
        assert!(c["stop_reason"].is_null());
        assert_eq!(c["read_bytes"], 12288);
        let img = image(&b);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        assert!(vm.absent_end(0x1000, u64::MAX).is_none()); // valid mapping
        drop(vm);
        put(&mut b, 0x7018, 1 << 10); // nonzero software/prototype PTE is not a zero span
        let img = image(&b);
        let vm = Memory::new(&img, 0x1000, &isf, None);
        assert!(vm.absent_end(0x3000, u64::MAX).is_none());
    }
    #[test]
    fn scanner_uses_tagged_bounds_without_unneeded_file_fields_and_keeps_parent_warnings() {
        let (b, mut isf) = resident_match();
        isf.data["user_types"]
            .as_object_mut()
            .unwrap()
            .remove("_MMVAD_FLAGS");
        isf.data["user_types"]["_RTL_BALANCED_NODE"]["fields"]["ParentValue"] =
            serde_json::json!({"offset":16,"type":{"kind":"base","name":"u64"}});
        let options = Options {
            pattern: Some("ABAB".into()),
            pid: Some(8),
            ..Default::default()
        };
        let r = run(&b, &isf, &options);
        assert_eq!(r.rows.len(), 1);
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("父指针")));
        let mut b = b;
        b[0xb000 - 12..0xb000 - 8].fill(0);
        let r = run(&b, &isf, &options);
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("tag")));
    }
    #[test]
    fn session_cache_distinguishes_pid_union_and_display_size() {
        let (b, isf) = resident_match();
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("windows.raw");
        let symbols = dir.path().join("windows.json");
        let cache = dir.path().join("cache");
        std::fs::write(&image, b).unwrap();
        std::fs::write(&symbols, serde_json::to_vec(&isf.data).unwrap()).unwrap();
        let request = Request {
            image: &image,
            symbols: &symbols,
            choice: None,
            plugin: Plugin::WinVadRegExScan,
            cache: &cache,
            use_cache: true,
            network: false,
        };
        let mut session = crate::linux::Session::default();
        let mut execute = |options: &Options, expected_cached| {
            let job = Job::default();
            let Outcome::Ready(result) =
                crate::analysis::analyze(&mut session, &request, None, options, &job).unwrap()
            else {
                panic!("unexpected ambiguity")
            };
            assert_eq!(job.served_from_cache(), expected_cached);
            result
        };
        let union = Options {
            pid: Some(4),
            pids: vec![8],
            pattern: Some("ABAB".into()),
            maxsize: Some(4),
            ..Default::default()
        };
        let first = execute(&union, false);
        assert_eq!(first.rows.len(), 1);
        assert_eq!(first.rows[0][0], "8");
        let only = execute(
            &Options {
                pids: vec![],
                ..union.clone()
            },
            false,
        );
        assert!(only.rows.is_empty());
        let small = Options {
            pattern: Some("ABAB.{4}".into()),
            ..union.clone()
        };
        let a = execute(&small, false);
        assert_eq!(a.rows[0][3].len(), 8);
        let large = execute(
            &Options {
                maxsize: Some(8),
                ..small
            },
            false,
        );
        assert_eq!(large.rows, a.rows);
        assert_eq!(execute(&union, true).rows, first.rows);
    }
    #[test]
    fn canonical_scan_excludes_prototype_pages_and_native_recovery_still_reads_them() {
        let (mut b, isf) = prepared();
        let prototype = K + 0x6000;
        put(
            &mut b,
            0x7010,
            ((prototype & 0x0000_ffff_ffff_ffff) << 16) | (1 << 10),
        );
        put(&mut b, 0xe000, 0x25003);
        let r = run(
            &b,
            &isf,
            &Options {
                pattern: Some("AB".into()),
                pid: Some(8),
                ..Default::default()
            },
        );
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(
            r.kernel_identity["vad_regex_scan"]["recovered_start_page_hits"],
            serde_json::json!([])
        );
        let image = image(&b);
        let vm = Memory::new(&image, 0x1000, &isf, None);
        let mut bytes = [0; 2];
        vm.read(0x2000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"AB");
        assert!(vm.read_reference(0x2000, &mut bytes).is_err());
    }
}
