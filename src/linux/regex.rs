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
        let maxsize = options.maxsize.unwrap_or(128);
        ensure!((1..=4096).contains(&maxsize), "maxsize 必须为 1..4096");
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
            if !pids.is_empty() && !pids.contains(&pid) {
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
                        let (bytes, missing) =
                            regex_scan::context(at, maxsize, job, |address, bytes| {
                                vm.read(address, bytes)
                            })?;
                        context_missing += missing;
                        // The fixed reference rescans with re.match (without the
                        // scan engine's implicit DOTALL) to determine display bytes.
                        let matched = display.anchored(&bytes, job)?;
                        let bytes = matched
                            .as_ref()
                            .map_or(bytes.as_slice(), |range| &bytes[range.clone()]);
                        let text = String::from_utf8_lossy(bytes).into_owned();
                        let encoded = bytes
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
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
        result.kernel_identity["vma_regex_scan"] = serde_json::json!({"engine":"PCRE2 bytes; no UTF/UCP/JIT","scan_dotall":true,"display_dotall":false,"maxsize":maxsize,"pids":pids,"chunk_bytes":16*1024*1024,"overlap_bytes":4096,"match_limit":crate::byte_regex::MATCH_LIMIT,"depth_limit":crate::byte_regex::DEPTH_LIMIT,"heap_kib":crate::byte_regex::HEAP_KIB,"subject_work_limit":crate::byte_regex::WORK_LIMIT,"output_limit":output_limit,"metadata_truncated":metadata_truncated,"processes":process_reports});
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
        assert_eq!(&r.rows[0][3..], &["ABA", "41 42 41"]);
    }
    #[test]
    fn pid_list_is_applied_before_user_memory_and_display_rechecks_lookbehind() {
        let (mut bytes, isf) = prepared();
        put(&mut bytes, 0xa130, 0xb000);
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
        // It falls back to the full configured context, exactly as the reference.
        assert_eq!(&r.rows[0][3..], &["ABc\0", "41 42 63 00"]);
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
