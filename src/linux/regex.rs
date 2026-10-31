//! Native byte-regex scans over task VMAs, backed by shared resident-range scans.
use super::*;
use crate::{analysis::Options, byte_regex::ByteRegex, regex_scan};
impl Linux<'_> {
    pub(super) fn vma_regex_scan(&self, options: &Options, job: &Job) -> Result<Results> {
        let pattern = options
            .pattern
            .as_deref()
            .context("此插件需要 --pattern 字节正则")?;
        let regex = ByteRegex::compile(pattern, true)?;
        let display = ByteRegex::compile(pattern, false)?;
        // Both pinned canonical generators read MAXSIZE_DEFAULT, not config.maxsize.
        let maxsize = regex_scan::REFERENCE_CONTEXT_SIZE;
        ensure!(options.pids.len() <= 4096, "PID 列表超过 4096 项");
        let pids: std::collections::BTreeSet<_> =
            options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.tasks(Plugin::VmaRegExScan, job)?;
        let mut process_reports = Vec::new();
        let mut metadata_truncated = false;
        let mut output_bytes = 0usize;
        let mut output_limit = false;
        for task in tasks {
            job.check()?;
            let pid = self.number(task.address, "task_struct", "tgid")? as u32;
            if !pids.is_empty() && !pids.contains(&task.pid.parse::<u32>()?) {
                continue;
            }
            let mut context_missing = 0u64;
            let scanned = (|| -> Result<Option<regex_scan::Coverage>> {
                let mm = self.number(task.address, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(None);
                }
                let vm = self
                    .process_vm(task.address)?
                    .context("进程没有用户地址空间")?;
                let mut regions = Vec::new();
                for node in self.vma_nodes(mm, job)? {
                    regions.push((
                        self.number(node, "vm_area_struct", "vm_start")?,
                        self.number(node, "vm_area_struct", "vm_end")?,
                    ));
                }
                let coverage = regex_scan::scan(
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
                        result.rows.push(vec![
                            pid.to_string(),
                            task.name.clone(),
                            hex(at),
                            text,
                            encoded,
                        ]);
                        Ok(true)
                    },
                )?;
                Ok(Some(coverage))
            })();
            match scanned {
                Ok(Some(coverage)) => {
                    if !coverage.complete() || context_missing > 0 {
                        partial(
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
                    partial(&mut result, format!("PID {pid} 正则扫描"), error);
                }
            }
            if output_limit {
                break;
            }
        }
        if metadata_truncated {
            partial(
                &mut result,
                "扫描覆盖元数据",
                anyhow::anyhow!("进程覆盖记录达到 65536 项上限"),
            );
        }
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        result.kernel_identity["vma_regex_scan"] = serde_json::json!({"engine":"PCRE2 bytes; no UTF/UCP/JIT","scan_dotall":true,"display_dotall":false,"maxsize":maxsize,"requested_maxsize":options.maxsize,"pids":pids,"chunk_bytes":16*1024*1024,"overlap_bytes":4096,"match_limit":crate::byte_regex::MATCH_LIMIT,"depth_limit":crate::byte_regex::DEPTH_LIMIT,"heap_kib":crate::byte_regex::HEAP_KIB,"subject_work_limit":crate::byte_regex::WORK_LIMIT,"output_limit":output_limit,"metadata_truncated":metadata_truncated,"processes":process_reports});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, fixture, image};
    use super::*;
    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn prepared() -> (Vec<u8>, Isf) {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0xb028, 0xc800);
        put(&mut bytes, 0xc808, 0x200000);
        put(&mut bytes, 0xc810, 0x202000);
        // Scan all VMAs, including a mapping without VM_READ in its flags.
        put(&mut bytes, 0xc818, 0);
        bytes[0x20ffe..0x21000].copy_from_slice(b"AB");
        bytes[0x25000..0x25002].copy_from_slice(b"AB");
        (bytes, isf)
    }
    #[test]
    fn pid_selection_uses_task_pid_while_output_uses_tgid() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/regex-context.json"
        ))
        .unwrap();
        let (mut bytes, isf) = prepared();
        put(&mut bytes, 0xa010, 43);
        put(&mut bytes, 0xa018, 42);
        let image = image(&bytes);
        for case in vectors["pid_filters"].as_array().unwrap() {
            let options = Options {
                pattern: Some("ABAB".into()),
                pids: case["pids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u32)
                    .collect(),
                ..Default::default()
            };
            let actual = engine(&image, &isf)
                .vma_regex_scan(&options, &Job::default())
                .unwrap();
            assert_eq!(
                actual.rows.is_empty(),
                case["excluded"].as_bool().unwrap(),
                "{case}"
            );
            if !actual.rows.is_empty() {
                assert_eq!(actual.rows[0][0], "42");
            }
        }
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
            .filter(|c| c["system"] == "linux")
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
                pid: Some(43),
                maxsize: case["maxsize"].as_i64(),
                ..Default::default()
            };
            let (mut bytes, isf) = prepared();
            bytes[0x20000..0x21000].fill(0);
            bytes[0x20000..0x20000 + data.len()].copy_from_slice(&data);
            put(&mut bytes, 0xa010, 43);
            put(&mut bytes, 0xa018, 42);
            bytes[0xa028..0xa030].copy_from_slice(b"sample\0\0");
            put(&mut bytes, 0xc810, 0x200000 + data.len() as u64);
            let image = image(&bytes);
            let actual = engine(&image, &isf)
                .vma_regex_scan(&options, &Job::default())
                .unwrap();

            let mut expected = case["expected"].clone();
            for row in expected.as_array_mut().unwrap() {
                let address = u64::from_str_radix(&row[2].as_str().unwrap()[2..], 16).unwrap();
                row[2] = serde_json::json!(format!("0x{address:016x}"));
            }
            assert_eq!(serde_json::json!(actual.rows), expected, "{}", case["id"]);
            assert_eq!(actual.kernel_identity["vma_regex_scan"]["maxsize"], 128);
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
    fn regex_matches_across_noncontiguous_physical_pages_and_preserves_fields() {
        let (bytes, isf) = prepared();
        let image = image(&bytes);
        let options = Options {
            pattern: Some(r"(?P<p>AB)(?P=p)".into()),
            pid: Some(1),
            ..Default::default()
        };
        let r = engine(&image, &isf)
            .vma_regex_scan(&options, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            vec![vec![
                "1",
                "init",
                "0x0000000000200ffe",
                "ABAB",
                "41 42 41 42"
            ]]
        );
        assert_eq!(
            r.kernel_identity["vma_regex_scan"]["processes"][0]["coverage"]["scanned_bytes"],
            8192
        );
        let mut options = options;
        options.maxsize = Some(3);
        let r = engine(&image, &isf)
            .vma_regex_scan(&options, &Job::default())
            .unwrap();
        assert_eq!(&r.rows[0][3..], &["ABAB", "41 42 41 42"]);
        assert_eq!(r.kernel_identity["vma_regex_scan"]["maxsize"], 128);
        assert_eq!(r.kernel_identity["vma_regex_scan"]["requested_maxsize"], 3);
    }
    #[test]
    fn pid_list_is_applied_before_user_memory_and_display_rechecks_lookbehind() {
        let (mut bytes, isf) = prepared();
        put(&mut bytes, 0xa130, 0xb000);
        put(&mut bytes, 0xa178, 0xb000);
        let image = image(&bytes);
        let options = Options {
            pattern: Some(r"(?<=AB)AB".into()),
            pids: vec![1, 2, 1],
            maxsize: Some(4),
            ..Default::default()
        };
        let r = engine(&image, &isf)
            .vma_regex_scan(&options, &Job::default())
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        // Context starts at the match, so the display re-match has no lookbehind.
        // It falls back to 128 bytes, regardless of the configured maxsize.
        assert!(r.rows[0][3].starts_with("ABc\0d\0"));
        assert_eq!(r.rows[0][3].len(), 128);
        assert_eq!(r.rows[0][4].split_whitespace().count(), 128);
        let options = Options {
            pids: vec![999],
            ..options
        };
        assert!(
            engine(&image, &isf)
                .vma_regex_scan(&options, &Job::default())
                .unwrap()
                .rows
                .is_empty()
        );
    }
    #[test]
    fn missing_pages_and_padded_context_are_explicit_and_cancel_is_not_swallowed() {
        let (mut bytes, isf) = prepared();
        put(&mut bytes, 0x7008, 0);
        let image = image(&bytes);
        let options = Options {
            pattern: Some("AB".into()),
            ..Default::default()
        };
        let r = engine(&image, &isf)
            .vma_regex_scan(&options, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(!r.complete);
        assert_eq!(
            r.kernel_identity["vma_regex_scan"]["processes"][0]["context_unreadable_bytes"],
            126
        );
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(engine(&image, &isf).vma_regex_scan(&options, &job).is_err());
    }
}
