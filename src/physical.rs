//! Shared, bounded physical pointer scans and ISF-driven embedded object reads.
//! Pointer fields are read physically; dereferences remain the caller's VM choice.
use crate::{Job, image::Image, symbols::Isf};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::BTreeSet;
const CHUNK: usize = 4 * 1024 * 1024;
const HIT_LIMIT: u64 = 1_000_000;
#[derive(Default, Serialize)]
pub(crate) struct Coverage {
    pub scope: &'static str,
    pub pointer_width: usize,
    pub needle_count: usize,
    pub captured_segments: usize,
    pub captured_bytes: u64,
    pub scanned_bytes: u64,
    pub gap_count: usize,
    pub gap_bytes: u64,
    pub hits: u64,
    pub accepted: u64,
    pub read_failures: u64,
    pub first_read_failure: Option<String>,
    pub limit_reached: bool,
}
impl Coverage {
    pub fn complete(&self) -> bool {
        self.read_failures == 0 && !self.limit_reached && self.scanned_bytes == self.captured_bytes
    }
}
pub(crate) enum Decision {
    Accept,
    Reject,
    Stop,
}
pub(crate) fn pointers(
    image: &Image,
    values: &[u64],
    width: usize,
    job: &Job,
    visit: impl FnMut(u64, u64) -> Result<Decision>,
) -> Result<Coverage> {
    pointers_bounded(image, values, width, job, visit, HIT_LIMIT)
}
fn pointers_bounded(
    image: &Image,
    values: &[u64],
    width: usize,
    job: &Job,
    mut visit: impl FnMut(u64, u64) -> Result<Decision>,
    limit: u64,
) -> Result<Coverage> {
    ensure!(matches!(width, 4 | 8), "物理指针扫描宽度必须为 4 或 8");
    let values: BTreeSet<u64> = values.iter().copied().collect();
    ensure!(
        !values.is_empty() && values.len() <= 256,
        "物理指针扫描模式数量无效/超过 256 项"
    );
    ensure!(
        width == 8 || values.iter().all(|v| *v <= u32::MAX as u64),
        "32 位指针值溢出"
    );
    let patterns: Vec<_> = values
        .iter()
        .map(|value| value.to_le_bytes()[..width].to_vec())
        .collect();
    let finders: Vec<_> = patterns.iter().map(memchr::memmem::Finder::new).collect();
    let mut coverage = Coverage {
        scope: "captured physical segments",
        pointer_width: width,
        needle_count: values.len(),
        captured_segments: image.segments.len(),
        ..Default::default()
    };
    for segment in &image.segments {
        coverage.captured_bytes = coverage
            .captured_bytes
            .checked_add(
                segment
                    .end
                    .checked_sub(segment.start)
                    .context("物理区段倒置")?,
            )
            .context("物理覆盖总量溢出")?;
    }
    for pair in image.segments.windows(2) {
        let gap = pair[1]
            .start
            .checked_sub(pair[0].end)
            .context("物理区段重叠或未排序")?;
        if gap > 0 {
            coverage.gap_count += 1;
            coverage.gap_bytes = coverage
                .gap_bytes
                .checked_add(gap)
                .context("空洞范围溢出")?;
        }
    }
    let mut tail = Vec::new();
    let mut previous_end = None;
    let mut reported = 0;
    'scan: for segment in &image.segments {
        if previous_end != Some(segment.start) {
            tail.clear();
        }
        let mut position = segment.start;
        while position < segment.end {
            job.check()?;
            let count = (segment.end - position).min(CHUNK as u64) as usize;
            let overlap = tail.len();
            tail.resize(overlap + count, 0);
            if let Err(error) = image.read(position, &mut tail[overlap..]) {
                coverage.read_failures += 1;
                if coverage.first_read_failure.is_none() {
                    coverage.first_read_failure = Some(format!(
                        "{position:#x}..{:#x}: {error:#}",
                        position + count as u64
                    ));
                }
                tail.clear();
                position += count as u64;
                continue;
            }
            coverage.scanned_bytes += count as u64;
            for (value, finder) in values.iter().zip(&finders) {
                let mut offset = 0;
                while offset + width <= tail.len() {
                    let Some(found) = finder.find(&tail[offset..]) else {
                        break;
                    };
                    let index = offset + found;
                    if coverage.hits >= limit {
                        coverage.limit_reached = true;
                        break 'scan;
                    }
                    job.check()?;
                    coverage.hits += 1;
                    let address = position
                        .checked_sub(overlap as u64)
                        .and_then(|v| v.checked_add(index as u64))
                        .context("物理命中地址溢出")?;
                    match visit(address, *value)? {
                        Decision::Accept => coverage.accepted += 1,
                        Decision::Reject => {}
                        Decision::Stop => {
                            coverage.limit_reached = true;
                            break 'scan;
                        }
                    }
                    // Advance one byte: even self-overlapping pointer bytes are enumerated.
                    offset = index + 1;
                }
            }
            let keep = (width - 1).min(tail.len());
            tail.drain(..tail.len() - keep);
            position += count as u64;
            if coverage.scanned_bytes - reported >= 64 * 1024 * 1024 {
                reported = coverage.scanned_bytes;
                job.report(format!(
                    "物理指针扫描: {} / {} MiB",
                    coverage.scanned_bytes >> 20,
                    coverage.captured_bytes >> 20
                ));
            }
        }
        previous_end = Some(segment.end);
    }
    job.check()?;
    Ok(coverage)
}

pub(crate) struct Object<'a> {
    pub image: &'a Image,
    pub isf: &'a Isf,
    pub address: u64,
}
impl Object<'_> {
    pub fn number(&self, structure: &str, field: &str) -> Result<u64> {
        let layout = self.isf.layout(structure, field)?;
        ensure!(matches!(layout.size, 1 | 2 | 4 | 8), "物理字段整数宽度无效");
        let mut bytes = [0; 8];
        self.image.read(
            self.address
                .checked_add(layout.offset)
                .context("物理对象字段溢出")?,
            &mut bytes[..layout.size as usize],
        )?;
        let value = u64::from_le_bytes(bytes);
        if let Some((position, length)) = layout.bits {
            let position = position.context("物理 bit position 无效")?;
            let length = length.context("物理 bit length 无效")?;
            ensure!(
                length > 0
                    && position
                        .checked_add(length)
                        .is_some_and(|end| end <= layout.size * 8),
                "物理 bitfield 越界"
            );
            Ok((value >> position) & (u64::MAX >> (64 - length)))
        } else {
            Ok(value)
        }
    }
    pub fn signed(&self, structure: &str, field: &str) -> Result<i64> {
        let value = self.number(structure, field)?;
        Ok(match self.isf.size(structure, field)? {
            1 => value as i8 as i64,
            2 => value as i16 as i64,
            4 => value as i32 as i64,
            8 => value as i64,
            _ => unreachable!(),
        })
    }
    pub fn string(&self, structure: &str, field: &str) -> Result<String> {
        let length = self.isf.size(structure, field)?;
        ensure!((1..=4096).contains(&length), "物理对象字符串长度无效");
        let mut bytes = vec![0; length];
        self.image.read(
            self.address
                .checked_add(self.isf.offset(structure, field)?)
                .context("物理字符串地址溢出")?,
            &mut bytes,
        )?;
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Segment;
    use std::io::Write;
    fn image(bytes: &[u8]) -> Image {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        Image::from_file(file, "physical-fixture".into()).unwrap()
    }
    #[test]
    fn chunk_boundaries_and_duplicate_needles() {
        let pointer = 0x123456789abcdef0u64;
        let mut bytes = vec![0; CHUNK + 32];
        bytes[CHUNK - 3..CHUNK + 5].copy_from_slice(&pointer.to_le_bytes());
        let image = image(&bytes);
        let mut hits = Vec::new();
        let coverage = pointers(
            &image,
            &[pointer, pointer],
            8,
            &Job::default(),
            |at, value| {
                hits.push((at, value));
                Ok(Decision::Accept)
            },
        )
        .unwrap();
        assert_eq!(hits, [(CHUNK as u64 - 3, pointer)]);
        assert!(coverage.complete());
        assert_eq!(coverage.needle_count, 1);
        assert_eq!(coverage.accepted, 1);
    }
    #[test]
    fn adjacent_physical_segments_ignore_file_headers_but_never_bridge_holes() {
        let bytes = [1u8, 2, 3, 99, 99, 4, 5, 6, 7, 8];
        let mut image = image(&bytes);
        image.segments = vec![
            Segment {
                start: 0x1000,
                end: 0x1003,
                file_offset: 0,
            },
            Segment {
                start: 0x1003,
                end: 0x1008,
                file_offset: 5,
            },
        ];
        let needle = u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut hits = Vec::new();
        let coverage = pointers(&image, &[needle], 8, &Job::default(), |at, _| {
            hits.push(at);
            Ok(Decision::Accept)
        })
        .unwrap();
        assert_eq!(hits, [0x1000]);
        assert!(coverage.complete());
        image.segments[1].start += 1;
        image.segments[1].end += 1;
        let coverage = pointers(&image, &[needle], 8, &Job::default(), |_, _| {
            panic!("bridged physical hole")
        })
        .unwrap();
        assert!(coverage.complete());
        assert_eq!(
            (coverage.hits, coverage.gap_count, coverage.gap_bytes),
            (0, 1, 1)
        );
    }
    #[test]
    fn overlapping_hits_limits_and_consumer_stop_preserve_prefix() {
        let image = image(&[1; 16]);
        let pointer = u64::from_le_bytes([1; 8]);
        let all = pointers(&image, &[pointer], 8, &Job::default(), |_, _| {
            Ok(Decision::Accept)
        })
        .unwrap();
        assert_eq!(all.hits, 9);
        assert!(all.complete());
        let limited = pointers_bounded(
            &image,
            &[pointer],
            8,
            &Job::default(),
            |_, _| Ok(Decision::Accept),
            3,
        )
        .unwrap();
        assert_eq!((limited.hits, limited.accepted), (3, 3));
        assert!(!limited.complete());
        let stopped = pointers(&image, &[pointer], 8, &Job::default(), |_, _| {
            Ok(Decision::Stop)
        })
        .unwrap();
        assert_eq!((stopped.hits, stopped.accepted), (1, 0));
        assert!(!stopped.complete());
    }
    #[test]
    fn unreadable_segment_does_not_hide_later_segments_or_fabricate_zero_hits() {
        let mut image = image(&[0x55; 16]);
        image.segments = vec![
            Segment {
                start: 0x1000,
                end: 0x1010,
                file_offset: 1000,
            },
            Segment {
                start: 0x2000,
                end: 0x2010,
                file_offset: 0,
            },
        ];
        let mut hits = Vec::new();
        let coverage = pointers(
            &image,
            &[0, u64::from_le_bytes([0x55; 8])],
            8,
            &Job::default(),
            |at, _| {
                hits.push(at);
                Ok(Decision::Accept)
            },
        )
        .unwrap();
        assert_eq!(hits, (0x2000..=0x2008).collect::<Vec<_>>());
        assert_eq!(coverage.read_failures, 1);
        assert_eq!(coverage.scanned_bytes, 16);
        assert!(!coverage.complete());
        assert!(coverage.first_read_failure.unwrap().contains("0x1000"));
    }
    #[test]
    fn cancellation_and_invalid_pointer_widths_fail_explicitly() {
        let image = image(&[0; 16]);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(pointers(&image, &[1], 8, &job, |_, _| Ok(Decision::Reject)).is_err());
        for (values, width) in [(vec![1], 3), (vec![], 8), (vec![u64::MAX], 4)] {
            assert!(
                pointers(&image, &values, width, &Job::default(), |_, _| Ok(
                    Decision::Reject
                ))
                .is_err()
            );
        }
        let c = pointers(&image, &[0], 4, &Job::default(), |_, _| {
            Ok(Decision::Accept)
        })
        .unwrap();
        assert_eq!(c.hits, 13);
    }
}
