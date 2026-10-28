//! Shared resident virtual range scanning. Holes break subjects; no scan bytes
//! are fabricated. Like the fixed reference, chunks are 16 MiB + 4 KiB overlap.
use crate::{Job, byte_regex::ByteRegex};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
const CHUNK: usize = 16 * 1024 * 1024;
const OVERLAP: usize = 4096;
const PAGE: u64 = 4096;
#[derive(Default, Serialize, Debug)]
pub struct Coverage {
    pub requested_bytes: u64,
    pub read_bytes: u64,
    pub scanned_bytes: u64,
    pub unreadable_bytes: u64,
    pub page_attempts: u64,
    pub first_read_error: Option<String>,
    pub stop_reason: Option<String>,
}
impl Coverage {
    pub fn complete(&self) -> bool {
        self.stop_reason.is_none()
            && self.unreadable_bytes == 0
            && self.scanned_bytes == self.requested_bytes
    }
}
/// A per-process work budget, shared over all coalesced VMAs.
pub struct Budget {
    pub resident_bytes: u64,
    pub page_attempts: u64,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            resident_bytes: 256 * 1024 * 1024,
            page_attempts: 1_000_000,
        }
    }
}
/// Coalesce neighboring VMAs, preserving reference matching across adjacent VMAs.
pub fn ranges(regions: &[(u64, u64)]) -> Result<Vec<(u64, u64)>> {
    let mut regions = regions.to_vec();
    regions.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (start, end) in regions {
        ensure!(start <= end, "虚拟区域倒置");
        if start == end {
            continue;
        }
        if let Some(last) = out.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            out.push((start, end));
        }
    }
    Ok(out)
}
pub fn scan(
    regex: &ByteRegex,
    regions: &[(u64, u64)],
    budget: &mut Budget,
    job: &Job,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    mut visit: impl FnMut(u64) -> Result<bool>,
) -> Result<Coverage> {
    let regions = ranges(regions)?;
    let mut report = Coverage::default();
    for (start, end) in &regions {
        report.requested_bytes = report
            .requested_bytes
            .checked_add(end - start)
            .context("虚拟扫描范围溢出")?;
    }
    let mut buffer = Vec::with_capacity(CHUNK + OVERLAP);
    let mut flush = |buffer: &[u8], base: u64, report: &mut Coverage| -> Result<bool> {
        let mut stopped = false;
        let result = regex.for_each(buffer, job, |found| {
            if buffer.len() > CHUNK && found.start >= CHUNK {
                return Ok(false);
            }
            if !visit(
                base.checked_add(found.start as u64)
                    .context("正则命中地址溢出")?,
            )? {
                stopped = true;
                return Ok(false);
            }
            Ok(true)
        });
        if let Err(error) = result {
            job.check()?;
            report.stop_reason = Some(format!("{error:#}"));
            return Ok(false);
        }
        if stopped {
            report.stop_reason = Some("命中/输出上限".into());
            return Ok(false);
        }
        report.scanned_bytes += buffer.len().min(CHUNK) as u64;
        Ok(true)
    };
    for (start, end) in regions {
        buffer.clear();
        let mut base = start;
        let mut cursor = start;
        while cursor < end {
            job.check()?;
            if budget.page_attempts == 0 {
                if !buffer.is_empty() {
                    finish(&mut buffer, &mut base, &mut report, &mut flush)?;
                }
                report
                    .stop_reason
                    .get_or_insert_with(|| "页面尝试次数上限".into());
                return Ok(report);
            }
            let count = ((PAGE - (cursor & (PAGE - 1))).min(end - cursor) as usize)
                .min(CHUNK + OVERLAP - buffer.len());
            if budget.resident_bytes < count as u64 {
                if !buffer.is_empty() {
                    finish(&mut buffer, &mut base, &mut report, &mut flush)?;
                }
                report
                    .stop_reason
                    .get_or_insert_with(|| "驻留扫描字节上限".into());
                return Ok(report);
            }
            budget.page_attempts -= 1;
            report.page_attempts += 1;
            let previous = buffer.len();
            buffer.resize(previous + count, 0);
            match read(cursor, &mut buffer[previous..]) {
                Ok(()) => {
                    budget.resident_bytes -= count as u64;
                    report.read_bytes += count as u64;
                }
                Err(error) => {
                    job.check()?;
                    buffer.truncate(previous);
                    if !buffer.is_empty()
                        && !finish(&mut buffer, &mut base, &mut report, &mut flush)?
                    {
                        return Ok(report);
                    }
                    buffer.clear();
                    report.unreadable_bytes += count as u64;
                    report
                        .first_read_error
                        .get_or_insert_with(|| format!("{cursor:#x}: {error:#}"));
                    cursor += count as u64;
                    base = cursor;
                    continue;
                }
            }
            cursor += count as u64;
            if buffer.len() == CHUNK + OVERLAP {
                if !flush(&buffer, base, &mut report)? {
                    return Ok(report);
                }
                buffer.drain(..CHUNK);
                base += CHUNK as u64;
            }
        }
        if !buffer.is_empty() && !finish(&mut buffer, &mut base, &mut report, &mut flush)? {
            return Ok(report);
        }
    }
    job.check()?;
    Ok(report)
}
/// Finish a resident run, including a final tail shorter than the overlap.
fn finish(
    buffer: &mut Vec<u8>,
    base: &mut u64,
    report: &mut Coverage,
    flush: &mut impl FnMut(&[u8], u64, &mut Coverage) -> Result<bool>,
) -> Result<bool> {
    while !buffer.is_empty() {
        if !flush(buffer, *base, report)? {
            return Ok(false);
        }
        let count = buffer.len().min(CHUNK);
        buffer.drain(..count);
        *base = base.checked_add(count as u64).context("扫描范围溢出")?;
    }
    Ok(true)
}
/// Output context follows the reference's padded reads, but every unavailable
/// byte is counted separately. Padding is never fed into the search engine.
pub fn context(
    at: u64,
    length: usize,
    job: &Job,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<(Vec<u8>, u64)> {
    ensure!((1..=4096).contains(&length), "正则上下文长度必须为 1..4096");
    let mut out = vec![0; length];
    let mut offset = 0;
    let mut missing = 0;
    while offset < length {
        job.check()?;
        let address = at.checked_add(offset as u64).context("上下文地址溢出")?;
        let count = ((PAGE - (address & (PAGE - 1))) as usize).min(length - offset);
        if read(address, &mut out[offset..offset + count]).is_err() {
            job.check()?;
            out[offset..offset + count].fill(0);
            missing += count as u64;
        }
        offset += count;
    }
    Ok((out, missing))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adjacent_regions_page_boundaries_and_holes_have_distinct_subjects() {
        let mut bytes = vec![0; 4 * 4096];
        bytes[4094..4100].copy_from_slice(b"needle");
        bytes[8190..8196].copy_from_slice(b"needle");
        bytes[12300..12306].copy_from_slice(b"needle");
        let regex = ByteRegex::compile("needle", true).unwrap();
        let mut hits = Vec::new();
        let c = scan(
            &regex,
            &[(0, 4096), (4096, 16384)],
            &mut Budget::default(),
            &Job::default(),
            |at, out| {
                ensure!(at != 8192, "hole");
                out.copy_from_slice(&bytes[at as usize..at as usize + out.len()]);
                Ok(())
            },
            |at| {
                hits.push(at);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(hits, [4094, 12300]);
        assert_eq!(c.unreadable_bytes, 4096);
        assert!(!c.complete());
        assert_eq!(c.scanned_bytes, 12288);
    }
    #[test]
    fn chunk_overlap_keeps_crossing_matches_once() {
        let mut bytes = vec![0; CHUNK + 2 * 4096];
        bytes[CHUNK - 2..CHUNK + 4].copy_from_slice(b"needle");
        bytes[CHUNK + 100..CHUNK + 106].copy_from_slice(b"needle");
        let mut hits = Vec::new();
        let c = scan(
            &ByteRegex::compile("needle", true).unwrap(),
            &[(0, bytes.len() as u64)],
            &mut Budget::default(),
            &Job::default(),
            |at, out| {
                out.copy_from_slice(&bytes[at as usize..at as usize + out.len()]);
                Ok(())
            },
            |at| {
                hits.push(at);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(hits, [CHUNK as u64 - 2, CHUNK as u64 + 100]);
        assert!(c.complete());
    }
    #[test]
    fn context_padding_is_explicit_and_not_scannable_data() {
        let (bytes, missing) = context(4094, 5, &Job::default(), |at, out| {
            ensure!(at < 4096, "hole");
            out.fill(b'A');
            Ok(())
        })
        .unwrap();
        assert_eq!(bytes, b"AA\0\0\0");
        assert_eq!(missing, 3);
    }
    #[test]
    fn resource_stops_keep_prefix_and_never_claim_complete() {
        let regex = ByteRegex::compile("a", true).unwrap();
        let mut n = 0;
        let c = scan(
            &regex,
            &[(0, 4096)],
            &mut Budget::default(),
            &Job::default(),
            |_, out| {
                out.fill(b'a');
                Ok(())
            },
            |_| {
                n += 1;
                Ok(n < 3)
            },
        )
        .unwrap();
        assert_eq!(n, 3);
        assert!(!c.complete());
        assert!(c.stop_reason.is_some());
        let c = scan(
            &regex,
            &[(0, 8192)],
            &mut Budget {
                resident_bytes: 4096,
                page_attempts: 1,
            },
            &Job::default(),
            |_, out| {
                out.fill(b'b');
                Ok(())
            },
            |_| Ok(true),
        )
        .unwrap();
        assert_eq!(c.read_bytes, 4096);
        assert!(!c.complete());
    }
}

#[cfg(test)]
mod short_tail_tests {
    use super::*;
    #[test]
    fn unaligned_subject_and_short_final_overlap_are_not_lost() {
        let mut bytes = vec![0; CHUNK + 256];
        bytes[CHUNK + 100..CHUNK + 106].copy_from_slice(b"needle");
        let mut hits = Vec::new();
        let report = scan(
            &ByteRegex::compile("needle", true).unwrap(),
            &[(1, bytes.len() as u64)],
            &mut Budget::default(),
            &Job::default(),
            |at, out| {
                out.copy_from_slice(&bytes[at as usize..at as usize + out.len()]);
                Ok(())
            },
            |at| {
                hits.push(at);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(hits, [CHUNK as u64 + 100]);
        assert!(report.complete(), "{report:?}");
    }
}
