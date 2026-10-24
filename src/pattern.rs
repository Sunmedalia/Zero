//! Literal and hex byte patterns for the memory scanning plugins.
//!
//! `text` searches ASCII/UTF-8 bytes, `wide:text` searches UTF-16LE, and
//! `hex:4d5a??00` searches bytes with `??` single-byte wildcards. Patterns are
//! data only: nothing is compiled or executed.
use anyhow::{Context, Result, bail, ensure};

const MAX_LENGTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    /// `None` is a wildcard byte.
    bytes: Vec<Option<u8>>,
    /// Longest wildcard-free run, used to find candidates quickly.
    anchor: (usize, Vec<u8>),
    source: String,
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Self> {
        let bytes: Vec<Option<u8>> = if let Some(hex) = text.strip_prefix("hex:") {
            let digits: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
            ensure!(digits.len().is_multiple_of(2), "hex 模式长度必须为偶数");
            (0..digits.len())
                .step_by(2)
                .map(|i| match &digits[i..i + 2] {
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
        let anchor = bytes[best.0..best.1].iter().map(|b| b.unwrap()).collect();
        Ok(Self {
            bytes,
            anchor: (best.0, anchor),
            source: text.to_owned(),
        })
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// The text the pattern was parsed from, for cache keys and reports.
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Start offsets of every match fully inside `haystack`.
    pub fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        let (offset, anchor) = &self.anchor;
        memchr::memmem::find_iter(haystack, anchor)
            .filter_map(|hit| hit.checked_sub(*offset))
            .filter(|start| {
                haystack
                    .get(*start..start + self.bytes.len())
                    .is_some_and(|window| {
                        window
                            .iter()
                            .zip(&self.bytes)
                            .all(|(byte, want)| want.is_none_or(|want| *byte == want))
                    })
            })
            .collect()
    }
}

/// Printable context around a hit: hex, then ASCII with dots.
pub fn context(bytes: &[u8]) -> String {
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let ascii: String = bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{} |{ascii}|", hex.join(" "))
}

const PAGE: u64 = 4096;
/// Regions larger than this are reservations (CFG bitmaps, stacks) and are
/// skipped with a diagnostic rather than walked page by page.
pub const REGION_LIMIT: u64 = 1024 * 1024 * 1024;
const CONTEXT: usize = 32;
/// Per-region scan result: hit addresses with context, and pages skipped.
#[derive(Debug, Default, PartialEq)]
pub struct RegionScan {
    pub hits: Vec<(u64, Vec<u8>)>,
    pub unreadable: u64,
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
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<RegionScan> {
    let mut out = RegionScan::default();
    let mut carry: Vec<u8> = Vec::new();
    let mut page = start & !(PAGE - 1);
    let mut bytes = vec![0u8; PAGE as usize];
    while page < end {
        if read(page, &mut bytes).is_err() {
            out.unreadable += 1;
            carry.clear();
            page += PAGE;
            continue;
        }
        // Only resident bytes count against the budget.
        ensure!(*budget >= PAGE, "扫描读取达到上限");
        *budget -= PAGE;
        let base = page - carry.len() as u64;
        carry.extend_from_slice(&bytes);
        for offset in pattern.find_all(&carry) {
            let address = base + offset as u64;
            if address < start || address + pattern.len() as u64 > end {
                continue;
            }
            if out.hits.len() >= limit {
                return Ok(out);
            }
            let stop = carry.len().min(offset + CONTEXT);
            out.hits.push((address, carry[offset..stop].to_vec()));
        }
        let keep = pattern.len().saturating_sub(1).min(carry.len());
        carry.drain(..carry.len() - keep);
        page += PAGE;
    }
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
            "hex:zz11",
            "hex:????",
            "hex:41??42",
            &"a".repeat(257),
        ] {
            assert!(Pattern::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Pattern::parse("text:hex:x").unwrap().source(), "text:hex:x");
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
        let mut tiny = 4096;
        assert!(scan_region(&pattern, 0, 8192, &mut tiny, 100, |_, _| Ok(())).is_err());
    }
}
