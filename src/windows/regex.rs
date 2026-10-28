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
        let maxsize = options.maxsize.unwrap_or(128);
        ensure!((1..=4096).contains(&maxsize), "maxsize 必须为 1..4096");
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
                let coverage = regex_scan::scan_sparse(
                    &regex,
                    &regions,
                    &mut Default::default(),
                    job,
                    |at, bytes| vm.read(at, bytes),
                    |at| {
                        if result.rows.len() >= 100_000 {
                            output_limit = true;
                            return Ok(false);
                        }
                        let shown = regex_scan::display_match(
                            &display,
                            at,
                            maxsize,
                            job,
                            |address, bytes| vm.read(address, bytes),
                        )?;
                        context_missing += shown.unreadable_bytes;
                        let text = shown.text;
                        let encoded = shown.hex;
                        let size = text.len() + encoded.len() + task.name.len() + 64;
                        if output_bytes + size > 128 * 1024 * 1024 {
                            output_limit = true;
                            return Ok(false);
                        }
                        output_bytes += size;
                        if vm.translate(at).is_err() {
                            if recovered_hits.len() < 65536 {
                                let origin = if vm.prototype(at).is_ok() {
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
                    },
                    |at, end| vm.absent_end(at, end),
                )?;
                Ok(Some(coverage))
            })();
            match scanned {
                Ok(Some(coverage)) => {
                    if !coverage.complete() || context_missing > 0 {
                        crate::report::partial(
                            &mut result,
                            format!("PID {pid} 正则扫描"),
                            anyhow::anyhow!(
                                "扫描 {} / {} 字节；缺页 {} 字节；上下文补零 {} 字节；{}",
                                coverage.scanned_bytes,
                                coverage.requested_bytes,
                                coverage.unreadable_bytes,
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
        result.kernel_identity["vad_regex_scan"] = serde_json::json!({"engine":"PCRE2 bytes; no UTF/UCP/JIT","scan_dotall":true,"display_dotall":false,"maxsize":maxsize,"pids":pids,"chunk_bytes":16*1024*1024,"overlap_bytes":4096,"match_limit":crate::byte_regex::MATCH_LIMIT,"depth_limit":crate::byte_regex::DEPTH_LIMIT,"heap_kib":crate::byte_regex::HEAP_KIB,"subject_work_limit":crate::byte_regex::WORK_LIMIT,"output_limit":output_limit,"metadata_truncated":metadata_truncated,"recovered_hit_overflow":recovered_hit_overflow,"recovered_start_page_hits":recovered_hits,"processes":process_reports});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    fn prepared() -> (Vec<u8>, Isf) {
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
    #[test]
    fn all_five_fields_adjacent_vads_noncontiguous_pages_and_pid_union() {
        let (b, isf) = prepared();
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
                "0x0000000000001ffe",
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
        assert_eq!(evidence["context_unreadable_bytes"], 2);
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
        assert_eq!(&r.rows[0][3..], ["A\nBxx", "41 0a 42 78 78"]);
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
        assert!(
            w.run(
                Plugin::WinVadRegExScan,
                &Options {
                    maxsize: Some(0),
                    ..options.clone()
                },
                &Job::default()
            )
            .is_err()
        );
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
        assert!(c["proven_unmapped_bytes"].as_u64().unwrap() > 500 * 1024 * 1024 * 1024);
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
        let (b, mut isf) = prepared();
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
        b[0xb100 - 12..0xb100 - 8].fill(0);
        let r = run(&b, &isf, &options);
        assert!(r.rows.is_empty());
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|d| d.contains("tag")));
    }
    #[test]
    fn session_cache_distinguishes_pid_union_and_display_size() {
        let (b, isf) = prepared();
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
        assert_eq!(a.rows[0][3].len(), 4);
        let large = execute(
            &Options {
                maxsize: Some(8),
                ..small
            },
            false,
        );
        assert_eq!(large.rows[0][3].len(), 8);
        assert_eq!(execute(&union, true).rows, first.rows);
    }
    #[test]
    fn prototype_backed_hits_keep_page_origin_evidence() {
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
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(
            r.kernel_identity["vad_regex_scan"]["recovered_start_page_hits"],
            serde_json::json!([{"pid":8,"offset":hex(0x2000),"start_page_origin":"prototype"}])
        );
    }
}
