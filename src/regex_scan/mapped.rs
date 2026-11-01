use super::*;

pub(crate) fn scan_mapped(
    regex: &ByteRegex,
    regions: &[(u64, u64)],
    budget: &mut Budget,
    job: &Job,
    mappings: impl FnMut(u64, u64) -> Result<Vec<(u64, u64)>>,
    read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    visit: impl FnMut(u64) -> Result<bool>,
) -> Result<Coverage> {
    scan_mapped_impl::<CHUNK, OVERLAP>(regex, regions, budget, job, mappings, read, visit)
}

fn scan_mapped_impl<const CHUNK: usize, const OVERLAP: usize>(
    regex: &ByteRegex,
    regions: &[(u64, u64)],
    budget: &mut Budget,
    job: &Job,
    mut mappings: impl FnMut(u64, u64) -> Result<Vec<(u64, u64)>>,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    mut visit: impl FnMut(u64) -> Result<bool>,
) -> Result<Coverage> {
    let (regions, mut report) = prepare_regions(regions)?;
    let mut emit = |bytes: &[u8], base: u64, report: &mut Coverage| -> Result<bool> {
        let mut stopped = false;
        let matches = regex.for_each(bytes, job, |found| {
            if found.start >= CHUNK {
                return Ok(false);
            }
            if !visit(
                base.checked_add(found.start as u64)
                    .context("扫描命中地址溢出")?,
            )? {
                stopped = true;
                return Ok(false);
            }
            Ok(true)
        });
        if let Err(error) = matches {
            job.check()?;
            report.stop_reason = Some(format!("{error:#}"));
            return Ok(false);
        }
        if stopped {
            report.stop_reason = Some("命中/输出上限".into());
            return Ok(false);
        }
        Ok(true)
    };
    for (start, end) in regions {
        job.check()?;
        let maps = mappings(start, end)?;
        let mut previous = start;
        let mut mapped = 0u64;
        for &(at, limit) in &maps {
            ensure!(
                at >= previous
                    && (at < limit || (start == end && at == start && limit == end))
                    && limit <= end,
                "扫描器收到无效映射块"
            );
            mapped += limit - at;
            previous = limit;
        }
        report.unreadable_bytes += end - start - mapped;
        if end - start > mapped {
            report
                .first_read_error
                .get_or_insert_with(|| "部分地址未映射到可读底层".into());
        }
        // TranslationLayerInterface begins each section with chunk_position=0.
        if maps.first().is_some_and(|&(at, _)| at > 0) && !emit(&[], 0, &mut report)? {
            return Ok(report);
        }
        for (mut at, limit) in maps {
            while at < limit {
                job.check()?;
                let count = usize::try_from((limit - at).min((CHUNK + OVERLAP) as u64))?;
                let attempts = ((at & 4095) + count as u64).div_ceil(4096);
                if budget.resident_bytes < count as u64 || budget.page_attempts < attempts {
                    report.stop_reason = Some("映射扫描达到字节／页面尝试上限".into());
                    return Ok(report);
                }
                budget.resident_bytes -= count as u64;
                budget.page_attempts -= attempts;
                report.page_attempts += attempts;
                let mut bytes = vec![0; count];
                let scanned = count.min(CHUNK) as u64;
                match read(at, &mut bytes) {
                    Ok(()) => {
                        report.read_bytes += count as u64;
                        report.scanned_bytes += scanned;
                    }
                    Err(error) => {
                        job.check()?;
                        report.unreadable_bytes += scanned;
                        report
                            .first_read_error
                            .get_or_insert_with(|| format!("{at:#x}: {error:#}"));
                        bytes.clear();
                    }
                }
                // A failed block is still passed as an empty subject at chunk_end.
                let base = at + count as u64 - bytes.len() as u64;
                if !emit(&bytes, base, &mut report)? {
                    return Ok(report);
                }
                at = at
                    .checked_add((CHUNK as u64).min(limit - at))
                    .context("扫描块地址溢出")?;
            }
        }
    }
    job.check()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resource_stop_preserves_reference_prefix_and_cancel_propagates() {
        let regex = ByteRegex::compile("^x", true).unwrap();
        let job = Job::default();
        let mut budget = Budget {
            resident_bytes: 16,
            page_attempts: 100,
        };
        let mut hits = Vec::new();
        let report = scan_mapped_impl::<8, 4>(
            &regex,
            &[(0, 16)],
            &mut budget,
            &job,
            |a, b| Ok(vec![(a, b)]),
            |_, out| {
                out.fill(b'x');
                Ok(())
            },
            |at| {
                hits.push(at);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(hits, vec![0]);
        assert_eq!(report.scanned_bytes, 8);
        assert!(!report.complete() && report.stop_reason.is_some());
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            scan_mapped_impl::<8, 4>(
                &regex,
                &[(0, 16)],
                &mut Budget::default(),
                &job,
                |_, _| panic!("cancelled before mapping"),
                |_, _| Ok(()),
                |_| Ok(true)
            )
            .is_err()
        );
    }
    #[test]
    fn chunk_events_match_actual_translation_layer_methods() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/regex-sections.json"
        ))
        .unwrap();
        for case in vectors["scans"]
            .as_array()
            .unwrap()
            .iter()
            .chain(vectors["mapping_cases"].as_array().unwrap())
        {
            let data: Vec<u8> = case["data_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect();
            let regions: Vec<_> = case["sections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    let at = v[0].as_u64().unwrap();
                    (at, at + v[1].as_u64().unwrap())
                })
                .collect();
            let mut hits = Vec::new();
            scan_mapped_impl::<8, 4>(
                &ByteRegex::compile(case["pattern"].as_str().unwrap(), true).unwrap(),
                &regions,
                &mut Budget::default(),
                &Job::default(),
                |start, end| {
                    Ok(if let Some(maps) = case["maps"].as_array() {
                        maps.iter()
                            .map(|m| {
                                let at = m[0].as_u64().unwrap();
                                (at, at + m[1].as_u64().unwrap())
                            })
                            .collect()
                    } else {
                        if start == end {
                            vec![]
                        } else {
                            vec![(start, end)]
                        }
                    })
                },
                |at, out| {
                    ensure!(at as usize + out.len() <= data.len(), "backing read fault");
                    out.copy_from_slice(&data[at as usize..at as usize + out.len()]);
                    Ok(())
                },
                |at| {
                    hits.push(at);
                    Ok(true)
                },
            )
            .unwrap();
            assert_eq!(serde_json::json!(hits), case["expected"], "{}", case["id"]);
        }
    }
}
