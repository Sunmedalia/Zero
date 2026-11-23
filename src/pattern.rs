//! Literal and hex byte patterns for the memory scanning plugins.
//!
//! `text` searches ASCII/UTF-8 bytes, `wide:text` searches UTF-16LE, and
//! `hex:4d5a??00` searches bytes with `??` single-byte wildcards. Patterns are
//! data only: nothing is compiled or executed.
use crate::{Job, bytes::Checked as _};
use anyhow::{Context, Result, bail, ensure};
use memchr::memmem::Finder;

const MAX_LENGTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    length: usize,
    /// Longest wildcard-free run, used to find candidates quickly.
    anchor: (usize, Vec<u8>),
    /// Fixed bytes outside the anchor.
    checks: Vec<(usize, u8)>,
    source: String,
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Self> {
        let bytes: Vec<Option<u8>> = if let Some(hex) = text.strip_prefix("hex:") {
            let digits: String = hex
                .chars()
                .filter(|c| !c.is_whitespace())
                .take(MAX_LENGTH * 2 + 1)
                .collect();
            ensure!(digits.is_ascii(), "hex 模式只接受 ASCII 十六进制字符和 ??");
            ensure!(digits.len() <= MAX_LENGTH * 2, "模式超过 {MAX_LENGTH} 字节");
            ensure!(digits.len().is_multiple_of(2), "hex 模式长度必须为偶数");
            (0..digits.len())
                .step_by(2)
                .map(|i| match digits.at(i..i + 2)? {
                    "??" => Ok(None),
                    pair => u8::from_str_radix(pair, 16)
                        .map(Some)
                        .with_context(|| format!("无效 hex 字节 {pair}")),
                })
                .collect::<Result<_>>()?
        } else if let Some(wide) = text.strip_prefix("wide:") {
            wide.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .map(Some)
                .collect()
        } else {
            text.strip_prefix("text:")
                .unwrap_or(text)
                .bytes()
                .map(Some)
                .collect()
        };
        ensure!(!bytes.is_empty(), "模式不能为空");
        ensure!(bytes.len() <= MAX_LENGTH, "模式超过 {MAX_LENGTH} 字节");
        let mut best = (0, 0);
        let mut start = 0;
        for (i, byte) in bytes.iter().chain(std::iter::once(&None)).enumerate() {
            if byte.is_none() {
                if i - start > best.1 - best.0 {
                    best = (start, i);
                }
                start = i + 1;
            }
        }
        if best.1 - best.0 < 2 {
            bail!("模式至少需要连续 2 个确定字节");
        }
        let anchor = bytes
            .at(best.0..best.1)?
            .iter()
            .flatten()
            .copied()
            .collect();
        let checks = bytes
            .iter()
            .copied()
            .enumerate()
            .filter(|(i, _)| !(best.0..best.1).contains(i))
            .filter_map(|(i, byte)| byte.map(|byte| (i, byte)))
            .collect();
        Ok(Self {
            length: bytes.len(),
            anchor: (best.0, anchor),
            checks,
            source: text.to_owned(),
        })
    }
    pub fn len(&self) -> usize {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// The text the pattern was parsed from, for cache keys and reports.
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Start offsets of every match fully inside `haystack`.
    pub fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        self.matches(haystack, &Finder::new(&self.anchor.1))
            .collect()
    }

    fn matches<'a>(
        &'a self,
        haystack: &'a [u8],
        finder: &'a Finder<'_>,
    ) -> impl Iterator<Item = usize> + 'a {
        let last_start = haystack.len().checked_sub(self.len());
        let mut cursor = 0;
        std::iter::from_fn(move || {
            let last_start = last_start?;
            while cursor <= last_start {
                let start = cursor + finder.find(haystack.get(cursor + self.anchor.0..)?)?;
                if start > last_start {
                    break;
                }
                cursor = start + 1;
                let Some(&(offset, byte)) = self
                    .checks
                    .iter()
                    .find(|&&(offset, byte)| haystack.get(start + offset) != Some(&byte))
                else {
                    return Some(start);
                };
                // Every intervening candidate fails at this same fixed offset.
                let next_bytes = haystack.get(cursor + offset..=last_start + offset)?;
                cursor += memchr::memchr(byte, next_bytes)?;
            }
            None
        })
    }
}

/// Printable context around a hit: hex, then ASCII with dots.
pub fn context(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4 + 3);
    crate::bytes::push_spaced_hex(&mut out, bytes);
    out.push_str(" |");
    out.extend(bytes.iter().map(|&byte| {
        if byte.is_ascii_graphic() || byte == b' ' {
            char::from(byte)
        } else {
            '.'
        }
    }));
    out.push('|');
    out
}

const PAGE_SIZE: usize = 4096;
const PAGE: u64 = PAGE_SIZE as u64;
/// Regions larger than this are reservations (CFG bitmaps, stacks) and are
/// skipped with a diagnostic rather than walked page by page.
pub const REGION_LIMIT: u64 = 1024 * 1024 * 1024;
pub(crate) const HIT_LIMIT: usize = 100_000;
const CONTEXT: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    HitLimit,
    ByteLimit,
}
impl StopReason {
    pub(crate) fn diagnostic(self) -> String {
        match self {
            Self::HitLimit => format!("命中数达到 {HIT_LIMIT} 上限"),
            Self::ByteLimit => "扫描读取达到上限".into(),
        }
    }
}

/// Per-region hits and coverage, including any work limit that stopped the scan.
#[derive(Debug, Default, PartialEq)]
pub struct RegionScan {
    pub hits: Vec<(u64, Vec<u8>)>,
    pub unreadable: u64,
    pub stop_reason: Option<StopReason>,
}

/// Scan `[start, end)` page by page through `read`, carrying the last
/// `len - 1` bytes across contiguous readable pages so matches spanning a
/// page boundary are found; an unreadable page breaks the carry. `budget`
/// bounds the bytes read and `limit` the hits kept.
pub fn scan_region(
    pattern: &Pattern,
    start: u64,
    end: u64,
    budget: &mut u64,
    limit: usize,
    job: &Job,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<RegionScan> {
    let mut out = RegionScan::default();
    job.check()?;
    if start >= end {
        return Ok(out);
    }
    if limit == 0 {
        out.stop_reason = Some(StopReason::HitLimit);
        return Ok(out);
    }
    let finder = Finder::new(&pattern.anchor.1);
    let mut carry = Vec::with_capacity(PAGE_SIZE + pattern.len() - 1);
    let mut page = start & !(PAGE - 1);
    let mut bytes = [0; PAGE_SIZE];
    while page < end {
        job.check()?;
        if *budget < PAGE {
            out.stop_reason = Some(StopReason::ByteLimit);
            return Ok(out);
        }
        let result = read(page, &mut bytes);
        job.check()?;
        let next_page = page.saturating_add(PAGE);
        if result.is_err() {
            out.unreadable += 1;
            carry.clear();
            page = next_page;
            continue;
        }
        // Only resident bytes count against the budget.
        *budget -= PAGE;
        let base = page - carry.len() as u64;
        carry.extend_from_slice(&bytes);
        for offset in pattern.matches(&carry, &finder) {
            let address = base + offset as u64;
            if address < start || end.saturating_sub(address) < pattern.len() as u64 {
                continue;
            }
            if out.hits.len() >= limit {
                out.stop_reason = Some(StopReason::HitLimit);
                return Ok(out);
            }
            let stop = carry.len().min(offset + CONTEXT);
            out.hits.push((address, carry.at(offset..stop)?.to_vec()));
        }
        let keep = pattern.len().saturating_sub(1).min(carry.len());
        carry.drain(..carry.len() - keep);
        page = next_page;
    }
    job.check()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_wide_and_hex_patterns_find_every_match() {
        let haystack = b"xxMZ\x90\x00yyMZ\x00\x00zz";
        let hex = Pattern::parse("hex:4d5a??00").unwrap();
        assert_eq!(hex.find_all(haystack), [2, 8]);
        assert_eq!(Pattern::parse("yyMZ").unwrap().find_all(haystack), [6]);
        let wide = Pattern::parse("wide:ab").unwrap();
        assert_eq!(wide.find_all(b"..a\0b\0.."), [2]);
        assert_eq!(wide.len(), 4);
        // Wildcards at the start are anchored on the fixed run after them.
        assert_eq!(
            Pattern::parse("hex:??5a90").unwrap().find_all(haystack),
            [2]
        );
    }

    #[test]
    fn invalid_or_weak_patterns_are_rejected() {
        for bad in [
            "",
            "hex:4",
            "hex:a中",
            "hex:zz11",
            "hex:????",
            "hex:41??42",
            &"a".repeat(257),
        ] {
            assert!(Pattern::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Pattern::parse("text:hex:x").unwrap().source(), "text:hex:x");
        assert_eq!(
            Pattern::parse("hex:41\u{3000}42").unwrap().find_all(b"AB"),
            [0]
        );
    }

    #[test]
    fn overlapping_anchors_and_wildcard_matches_are_kept() {
        assert_eq!(Pattern::parse("ABA").unwrap().find_all(b"ABABA"), [0, 2]);
        let pattern = Pattern::parse("hex:4141??42").unwrap();
        // The first AA anchor fails the wildcard pattern; the next overlaps it.
        assert_eq!(pattern.find_all(b"AAAXB"), [1]);
    }

    #[test]
    fn failed_fixed_offsets_skip_candidates_without_skipping_matches() {
        let pattern = Pattern::parse("hex:42??414141??43").unwrap();
        let haystack = b"xxAAAAAAABxAAAxDBxAAAxC";
        assert_eq!(pattern.find_all(haystack), [16]);

        let dense = Pattern::parse(&format!("hex:{}??42", "00".repeat(128))).unwrap();
        let mut page = [0; PAGE_SIZE];
        assert!(dense.find_all(&page).is_empty());
        page[200] = b'B';
        page[PAGE_SIZE - 1] = b'B';
        assert_eq!(dense.find_all(&page), [71, PAGE_SIZE - 130]);
    }

    #[test]
    fn context_shows_hex_and_printable_text() {
        assert_eq!(context(b"MZ\x00"), "4d 5a 00 |MZ.|");
    }

    #[test]
    fn region_scans_cross_page_boundaries_but_not_holes() {
        let pattern = Pattern::parse("needle").unwrap();
        // Page 0 ends with "nee", page 1 starts with "dle"; page 2 is
        // unreadable and page 3 starts with "dle" after it.
        let mut memory = vec![0u8; 4 * 4096];
        memory[4093..4096].copy_from_slice(b"nee");
        memory[4096..4099].copy_from_slice(b"dle");
        memory[3 * 4096 + 100..3 * 4096 + 106].copy_from_slice(b"needle");
        memory[3 * 4096 - 3..3 * 4096].copy_from_slice(b"nee");
        memory[3 * 4096..3 * 4096 + 3].copy_from_slice(b"dle");
        let mut budget = 1 << 20;
        let scan = scan_region(
            &pattern,
            0,
            4 * 4096,
            &mut budget,
            100,
            &Job::default(),
            |at, out: &mut [u8]| {
                ensure!(at != 2 * 4096, "缺页");
                out.copy_from_slice(&memory[at as usize..at as usize + 4096]);
                Ok(())
            },
        )
        .unwrap();
        let addresses: Vec<u64> = scan.hits.iter().map(|(a, _)| *a).collect();
        assert_eq!(addresses, [4093, 3 * 4096 + 100]);
        assert!(scan.hits[0].1.starts_with(b"needle"));
        assert_eq!(scan.unreadable, 1);
        assert_eq!(budget, (1 << 20) - 3 * 4096);
    }

    #[test]
    fn hit_limit_distinguishes_a_full_result_from_truncation() {
        for (limit, reason) in [(1, Some(StopReason::HitLimit)), (2, None), (3, None)] {
            let mut budget = PAGE;
            let scan = scan_region(
                &Pattern::parse("ABA").unwrap(),
                0,
                5,
                &mut budget,
                limit,
                &Job::default(),
                |_, bytes| {
                    bytes[..5].copy_from_slice(b"ABABA");
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(scan.stop_reason, reason);
            assert_eq!(scan.hits.len(), limit.min(2));
        }
    }

    #[test]
    fn exhausted_byte_budget_keeps_hits_and_avoids_another_read() {
        let mut budget = PAGE;
        let scan = scan_region(
            &Pattern::parse("AB").unwrap(),
            0,
            2 * PAGE,
            &mut budget,
            10,
            &Job::default(),
            |at, bytes| {
                assert_eq!(at, 0);
                bytes[..2].copy_from_slice(b"AB");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(budget, 0);
        assert_eq!(scan.stop_reason, Some(StopReason::ByteLimit));
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].0, 0);
    }

    #[test]
    fn cancellation_during_a_failed_read_stops_before_the_next_page() {
        let job = Job::default();
        let mut budget = 2 * PAGE;
        let error = scan_region(
            &Pattern::parse("AB").unwrap(),
            0,
            2 * PAGE,
            &mut budget,
            10,
            &job,
            |at, _| {
                assert_eq!(at, 0);
                job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                bail!("缺页")
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
    }
}
