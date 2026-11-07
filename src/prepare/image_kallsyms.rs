//! Locate and decode the core kallsyms tables in physical memory without symbols.
//!
//! The token table is anchored on its single-character digit tokens, then every
//! neighbouring table is accepted only when it agrees exactly with the others:
//! the token index must reproduce every token offset, every marker must equal
//! the offset of its 256-symbol block while the names are decoded, and the
//! address table must decode to a sorted, canonical kernel layout. Nothing is
//! guessed from symbol names; ambiguity is reported, never resolved silently.
use crate::{
    Job,
    bytes::{Checked as _, le_u16, le_u32, le_u64},
    image::Image,
};
use anyhow::{Context, Result, ensure};

const DIGITS: &[u8] = b"0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00";
/// Index of the `'0'` token: single-character tokens keep their own byte value.
const DIGIT_TOKEN: usize = 0x30;
const MAX_SYMBOLS: usize = 1 << 21;
const MAX_MARKERS: usize = MAX_SYMBOLS / 256;
/// Upper bound of one compressed name entry (two length bytes + KSYM_NAME_LEN tokens).
const MAX_ENTRY: usize = 2 + 512;

#[derive(Clone, Debug)]
pub(super) struct Symbol {
    /// Address as the running kernel sees it.
    pub runtime: u64,
    /// Whether KASLR relocates this address (absolute per-cpu entries are not).
    pub relocated: bool,
    pub kind: char,
    pub name: String,
}

#[derive(Clone, Debug)]
pub(super) struct Tables {
    pub num_syms: u64,
    pub names: u64,
    pub markers: u64,
    pub token_table: u64,
    pub token_index: u64,
    pub offsets: u64,
    pub relative_base_at: u64,
    pub relative_base: u64,
    /// Element width of `kallsyms_markers` (4 since 6.x, unsigned long before).
    pub marker_width: u64,
    /// Byte lengths of the variable-length tables.
    pub names_len: u64,
    pub token_table_len: u64,
    pub layout: &'static str,
    pub percpu: &'static str,
    pub symbols: Vec<Symbol>,
}

/// Physical span `[start, end)` of the run of abutting segments holding `address`.
fn run(image: &Image, address: u64) -> Option<(u64, u64)> {
    let index = image
        .segments
        .iter()
        .position(|s| s.start <= address && address < s.end)?;
    let (mut start, mut end) = image.segments.get(index).map(|s| (s.start, s.end))?;
    let mut i = index;
    while let Some(previous) = i.checked_sub(1).and_then(|p| image.segments.get(p)) {
        if previous.end != start {
            break;
        }
        start = previous.start;
        i -= 1;
    }
    for next in image.segments.iter().skip(index + 1) {
        if next.start != end {
            break;
        }
        end = next.end;
    }
    Some((start, end))
}

/// Bytes of `[from, to)` clipped to the contiguous run around `anchor`.
fn window(image: &Image, anchor: u64, from: u64, to: u64) -> Result<(u64, Vec<u8>)> {
    let (start, end) = run(image, anchor).context("锚点不在镜像段内")?;
    let from = from.max(start);
    let to = to.min(end);
    ensure!(from <= anchor && anchor <= to, "窗口无效");
    let mut bytes = vec![0; usize::try_from(to - from)?];
    image.read(from, &mut bytes)?;
    Ok((from, bytes))
}

fn printable(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// The NUL-terminated string at `at`, returned with the offset after its NUL.
fn token(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let tail = bytes.get(at..)?;
    let end = tail.iter().position(|b| *b == 0)?;
    let text = tail.get(..end)?;
    printable(text).then_some((text, at + end + 1))
}

struct TokenTable {
    table: u64,
    /// First byte after the last token's NUL.
    index_end_of_table: u64,
    index: u64,
    tokens: Vec<Vec<u8>>,
}

/// Validate a digit-sequence hit as `kallsyms_token_table` + `kallsyms_token_index`.
fn token_table(image: &Image, hit: u64) -> Result<Option<TokenTable>> {
    let Ok((base, bytes)) = window(
        image,
        hit,
        hit.saturating_sub(8192),
        hit.saturating_add(8192),
    ) else {
        return Ok(None);
    };
    let anchor = usize::try_from(hit - base)?;
    // Tokens from '0' onwards, relative to the '0' token.
    let mut relative = Vec::with_capacity(256 - DIGIT_TOKEN);
    let mut at = anchor;
    for _ in DIGIT_TOKEN..256 {
        let Some((_, next)) = token(&bytes, at) else {
            return Ok(None);
        };
        relative.push(at - anchor);
        at = next;
    }
    let end = at;
    for pad in 0..16 {
        let index = end + pad;
        let Some(first) = le_u16(&bytes, index) else {
            break;
        };
        if first != 0 {
            continue;
        }
        let Some(digit) = le_u16(&bytes, index + 2 * DIGIT_TOKEN) else {
            break;
        };
        let digit = usize::from(digit);
        if digit > anchor || digit < 2 * DIGIT_TOKEN {
            continue;
        }
        let table = anchor - digit;
        let mut offsets = Vec::with_capacity(256);
        for i in 0..256 {
            match le_u16(&bytes, index + 2 * i) {
                Some(v) => offsets.push(usize::from(v)),
                None => return Ok(None),
            }
        }
        let tail_matches = offsets
            .iter()
            .skip(DIGIT_TOKEN)
            .zip(&relative)
            .all(|(offset, rel)| offset.checked_sub(digit) == Some(*rel));
        if !tail_matches {
            continue;
        }
        let mut tokens = Vec::with_capacity(256);
        let mut valid = true;
        for i in 0..256 {
            let start = table + offsets.at(i)?;
            match token(&bytes, start) {
                Some((text, next))
                    if offsets.get(i + 1).is_none_or(|o| table + o == next)
                        && (i + 1 < 256 || next == end) =>
                {
                    tokens.push(text.to_vec());
                }
                _ => {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            return Ok(Some(TokenTable {
                table: base + u64::try_from(table)?,
                index_end_of_table: base + u64::try_from(end)?,
                index: base + u64::try_from(index)?,
                tokens,
            }));
        }
    }
    Ok(None)
}

struct Markers {
    start: u64,
    width: u64,
    values: Vec<u64>,
}

/// Marker arrays ending just before the token table, for u32 and unsigned-long widths.
fn markers(image: &Image, table: u64) -> Result<Vec<Markers>> {
    let span = u64::try_from(MAX_MARKERS * 8 + 64)?;
    let Ok((base, bytes)) = window(image, table, table.saturating_sub(span), table) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for width in [4u64, 8] {
        let aligned = table & !(width - 1);
        if (aligned..table).any(|a| {
            usize::try_from(a - base)
                .ok()
                .and_then(|i| bytes.get(i))
                .is_none_or(|b| *b != 0)
        }) {
            continue;
        }
        let read = |address: u64| -> Option<u64> {
            let at = usize::try_from(address.checked_sub(base)?).ok()?;
            if width == 4 {
                le_u32(&bytes, at).map(u64::from)
            } else {
                le_u64(&bytes, at)
            }
        };
        for pad in 0..=(8 / width) {
            let Some(mut end) = aligned.checked_sub(pad * width) else {
                continue;
            };
            if (end..aligned)
                .step_by(usize::try_from(width)?)
                .any(|a| read(a) != Some(0))
            {
                continue;
            }
            let mut values = Vec::new();
            let mut previous = None;
            while values.len() < MAX_MARKERS {
                let Some(address) = end.checked_sub(width) else {
                    break;
                };
                let Some(value) = read(address) else {
                    break;
                };
                if previous.is_some_and(|p| value >= p) {
                    break;
                }
                values.push(value);
                previous = Some(value);
                end = address;
                if value == 0 {
                    break;
                }
            }
            if values.last() == Some(&0) {
                values.reverse();
                out.push(Markers {
                    start: end,
                    width,
                    values,
                });
            }
        }
    }
    Ok(out)
}

/// Decode `count` names starting at `at`, checking every block marker; returns the end.
fn decode_names(
    bytes: &[u8],
    at: usize,
    count: usize,
    markers: &[u64],
    tokens: &[Vec<u8>],
    out: &mut Vec<(char, String)>,
    job: &Job,
) -> Result<Option<usize>> {
    let mut position = at;
    out.clear();
    for i in 0..count {
        if i % 256 == 0 {
            if i % (256 * 1024) == 0 {
                job.check()?;
            }
            let Some(marker) = markers.get(i / 256) else {
                return Ok(None);
            };
            if u64::try_from(position - at)? != *marker {
                return Ok(None);
            }
        }
        let Some(first) = bytes.get(position) else {
            return Ok(None);
        };
        let (length, header) = if first & 0x80 != 0 {
            let Some(second) = bytes.get(position + 1) else {
                return Ok(None);
            };
            ((usize::from(first & 0x7f)) | (usize::from(*second) << 7), 2)
        } else {
            (usize::from(*first), 1)
        };
        if length == 0 || length + header > MAX_ENTRY {
            return Ok(None);
        }
        let Some(compressed) = bytes.get(position + header..position + header + length) else {
            return Ok(None);
        };
        let mut name = Vec::new();
        for byte in compressed {
            name.extend_from_slice(tokens.at(usize::from(*byte))?);
        }
        let Some((kind, rest)) = name.split_first() else {
            return Ok(None);
        };
        if !(kind.is_ascii_alphabetic() || *kind == b'?') || !printable(rest) {
            return Ok(None);
        }
        out.push((
            char::from(*kind),
            String::from_utf8_lossy(rest).into_owned(),
        ));
        position += header + length;
    }
    Ok(Some(position))
}

struct Names {
    num_syms: u64,
    start: u64,
    end: u64,
    names: Vec<(char, String)>,
}

/// Find `kallsyms_num_syms` + `kallsyms_names` immediately before the markers.
fn names(image: &Image, markers: &Markers, tokens: &[Vec<u8>], job: &Job) -> Result<Vec<Names>> {
    let count = markers.values.len();
    let last = *markers.values.last().context("标记为空")?;
    let span = last
        .checked_add(u64::try_from(256 * MAX_ENTRY + 64)?)
        .context("名称表跨度溢出")?;
    let Ok((base, bytes)) = window(
        image,
        markers.start,
        markers.start.saturating_sub(span),
        markers.start,
    ) else {
        return Ok(Vec::new());
    };
    let Some(highest) = markers.start.checked_sub(last.saturating_add(1)) else {
        return Ok(Vec::new());
    };
    let lowest = markers.start.saturating_sub(span).max(base + 8);
    let mut out = Vec::new();
    let mut decoded = Vec::new();
    let mut start = highest & !3;
    while start >= lowest {
        job.check()?;
        let at = usize::try_from(start - base)?;
        let candidates = [
            (start - 4, le_u32(&bytes, at - 4).map(u64::from)),
            (start - 8, le_u64(&bytes, at - 8)),
        ];
        for (position, value) in candidates {
            let Some(n) = value.and_then(|v| usize::try_from(v).ok()) else {
                continue;
            };
            if n == 0 || n > MAX_SYMBOLS || n.div_ceil(256) != count {
                continue;
            }
            let Some(end) =
                decode_names(&bytes, at, n, &markers.values, tokens, &mut decoded, job)?
            else {
                continue;
            };
            let end = base + u64::try_from(end)?;
            if end <= markers.start && markers.start - end < 8 {
                out.push(Names {
                    num_syms: position,
                    start,
                    end,
                    names: std::mem::take(&mut decoded),
                });
            }
        }
        if !out.is_empty() {
            break;
        }
        start -= 4;
    }
    Ok(out)
}

/// Decoded addresses for the two base-relative encodings, when exactly one is consistent.
fn addresses(
    offsets: &[i32],
    base: u64,
    names: &[(char, String)],
) -> Option<(Vec<(u64, bool)>, &'static str)> {
    let canonical = |a: u64| a >> 47 == 0x1ffff;
    if !canonical(base) {
        return None;
    }
    let decode = |absolute_percpu: bool| -> Option<Vec<(u64, bool)>> {
        let mut out = Vec::with_capacity(offsets.len());
        for offset in offsets {
            let entry = if absolute_percpu {
                if *offset >= 0 {
                    (u64::from(offset.unsigned_abs()), false)
                } else {
                    let value = i128::from(base) - 1 - i128::from(*offset);
                    (u64::try_from(value).ok()?, true)
                }
            } else {
                (base.checked_add(u64::from(offset.cast_unsigned()))?, true)
            };
            out.push(entry);
        }
        let sorted = out.windows(2).all(|pair| match pair {
            [a, b] => a.0 <= b.0,
            _ => true,
        });
        let relocated_ok = out
            .iter()
            .filter(|(_, relocated)| *relocated)
            .all(|(a, _)| canonical(*a) && *a >= base);
        let banner = names
            .iter()
            .zip(&out)
            .any(|((_, name), (_, relocated))| name == "linux_banner" && *relocated);
        (sorted && relocated_ok && banner).then_some(out)
    };
    match (decode(true), decode(false)) {
        (Some(a), None) => Some((a, "absolute-percpu")),
        (None, Some(r)) => Some((r, "base-relative")),
        _ => None,
    }
}

fn offsets_at(image: &Image, at: u64, count: usize) -> Option<Vec<i32>> {
    let mut bytes = vec![0; count.checked_mul(4)?];
    image.read(at, &mut bytes).ok()?;
    Some(
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| i32::from_le_bytes(*c))
            .collect(),
    )
}

/// Every complete, self-consistent core kallsyms table set in the image.
pub(super) fn locate(image: &Image, job: &Job) -> Result<Vec<Tables>> {
    let mut found: Vec<Tables> = Vec::new();
    for hit in image.scan(DIGITS, job)? {
        job.check()?;
        let Some(tokens) = token_table(image, hit)? else {
            continue;
        };
        if found.iter().any(|t| t.token_table == tokens.table) {
            continue;
        }
        job.report(format!("kallsyms 词表候选 @ 物理 {:#x}", tokens.table));
        for marker in markers(image, tokens.table)? {
            for names in names(image, &marker, &tokens.tokens, job)? {
                let count = names.names.len();
                let layouts = [
                    // 6.x: offsets and relative base follow the token index.
                    (tokens.index + 512, None, "token-index"),
                    // Older kernels: offsets and relative base precede num_syms.
                    (0, Some(0), "before-num-syms"),
                    (0, Some(4), "before-num-syms"),
                ];
                for (after, before, layout) in layouts {
                    let (offsets, base_at) = match before {
                        None => {
                            let offsets = (after + 3) & !3;
                            let end = offsets + u64::try_from(count * 4)?;
                            (offsets, (end + 7) & !7)
                        }
                        Some(pad) => {
                            let Some(base_at) = names.num_syms.checked_sub(8).map(|a| a & !7)
                            else {
                                continue;
                            };
                            let Some(offsets) = base_at
                                .checked_sub(u64::try_from(count * 4)?)
                                .and_then(|a| a.checked_sub(pad))
                            else {
                                continue;
                            };
                            (offsets, base_at)
                        }
                    };
                    let Ok(base) = image.u64(base_at) else {
                        continue;
                    };
                    let Some(values) = offsets_at(image, offsets, count) else {
                        continue;
                    };
                    let Some((decoded, percpu)) = addresses(&values, base, &names.names) else {
                        continue;
                    };
                    found.push(Tables {
                        num_syms: names.num_syms,
                        names: names.start,
                        markers: marker.start,
                        token_table: tokens.table,
                        token_index: tokens.index,
                        offsets,
                        relative_base_at: base_at,
                        relative_base: base,
                        marker_width: marker.width,
                        names_len: names.end - names.start,
                        token_table_len: tokens.index_end_of_table - tokens.table,
                        layout,
                        percpu,
                        symbols: names
                            .names
                            .iter()
                            .zip(decoded)
                            .map(|((kind, name), (runtime, relocated))| Symbol {
                                runtime,
                                relocated,
                                kind: *kind,
                                name: name.clone(),
                            })
                            .collect(),
                    });
                    job.report(format!(
                        "kallsyms 已解码: {count} 个核心符号 · 标记宽度 {} · {layout} · {percpu}",
                        marker.width
                    ));
                    break;
                }
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic kernel image page holding complete 6.x kallsyms tables.
    pub(in crate::prepare) fn kallsyms_fixture(
        base: u64,
        symbols: &[(&str, u64, bool)],
    ) -> (Vec<u8>, Vec<(&'static str, u64)>) {
        // Single-character tokens only: token i is the byte i for printable i,
        // other slots get a unique two-character filler.
        let mut table = Vec::new();
        let mut index = Vec::new();
        for i in 0u16..256 {
            index.push(u16::try_from(table.len()).unwrap());
            let byte = u8::try_from(i).unwrap();
            if (0x21..=0x7e).contains(&byte) {
                table.push(byte);
            } else {
                table.extend_from_slice(&[b'~', b'!' + (byte % 64)]);
            }
            table.push(0);
        }
        let mut names = Vec::new();
        let mut markers = Vec::new();
        for (i, (name, _, _)) in symbols.iter().enumerate() {
            if i % 256 == 0 {
                markers.push(u32::try_from(names.len()).unwrap());
            }
            names.push(u8::try_from(name.len()).unwrap());
            names.extend_from_slice(name.as_bytes());
        }
        let mut image = vec![0u8; 0x1000];
        let mut put = |at: usize, bytes: &[u8]| {
            image.resize(image.len().max(at + bytes.len()), 0);
            image[at..at + bytes.len()].copy_from_slice(bytes);
        };
        let num_syms = 0x100;
        put(num_syms, &(symbols.len() as u64).to_le_bytes());
        let names_at = num_syms + 8;
        put(names_at, &names);
        let markers_at = (names_at + names.len() + 7) & !7;
        let marker_bytes: Vec<u8> = markers.iter().flat_map(|m| m.to_le_bytes()).collect();
        put(markers_at, &marker_bytes);
        let table_at = (markers_at + marker_bytes.len() + 7) & !7;
        put(table_at, &table);
        let index_at = (table_at + table.len() + 7) & !7;
        let index_bytes: Vec<u8> = index.iter().flat_map(|v| v.to_le_bytes()).collect();
        put(index_at, &index_bytes);
        let offsets_at = index_at + 512;
        let offsets: Vec<u8> = symbols
            .iter()
            .flat_map(|(_, address, relocated)| {
                let value = if *relocated {
                    i32::try_from(-1 - i64::try_from(address - base).unwrap()).unwrap()
                } else {
                    i32::try_from(*address).unwrap()
                };
                value.to_le_bytes()
            })
            .collect();
        put(offsets_at, &offsets);
        let base_at = (offsets_at + offsets.len() + 7) & !7;
        put(base_at, &base.to_le_bytes());
        image.resize((image.len() + 4095) & !4095, 0);
        (
            image,
            vec![
                ("num_syms", num_syms as u64),
                ("names", names_at as u64),
                ("markers", markers_at as u64),
                ("token_table", table_at as u64),
                ("offsets", offsets_at as u64),
            ],
        )
    }

    fn image_of(bytes: Vec<u8>) -> Image {
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, &bytes).unwrap();
        Image::from_file(file, "fixture".into()).unwrap()
    }

    #[test]
    fn decodes_absolute_percpu_tables_and_rejects_corruption() {
        let base = 0xffff_ffff_8100_0000;
        let mut symbols = vec![
            ("Afixed_percpu_data", 0, false),
            ("Arunqueues", 0x35ec0, false),
        ];
        for i in 0..300u64 {
            symbols.push((
                Box::leak(format!("tfunc_{i}").into_boxed_str()),
                base + 0x100 * i,
                true,
            ));
        }
        symbols.push(("Dlinux_banner", base + 0x200000, true));
        symbols.push(("Dkallsyms_num_syms", base + 0x200100, true));
        let (bytes, at) = kallsyms_fixture(base, &symbols);
        let image = image_of(bytes.clone());
        let found = locate(&image, &crate::Job::default()).unwrap();
        assert_eq!(found.len(), 1);
        let tables = &found[0];
        assert_eq!(tables.percpu, "absolute-percpu");
        assert_eq!(tables.layout, "token-index");
        assert_eq!(tables.num_syms, at[0].1);
        assert_eq!(tables.names, at[1].1);
        assert_eq!(tables.markers, at[2].1);
        assert_eq!(tables.token_table, at[3].1);
        assert_eq!(tables.offsets, at[4].1);
        assert_eq!(tables.marker_width, 4);
        let names_len: usize = symbols.iter().map(|(name, _, _)| 1 + name.len()).sum();
        assert_eq!(tables.names_len, names_len as u64);
        // 94 printable one-byte tokens + 162 two-byte fillers, each NUL-terminated.
        assert_eq!(tables.token_table_len, 94 * 2 + 162 * 3);
        assert_eq!(tables.symbols.len(), symbols.len());
        let runqueues = &tables.symbols[1];
        assert_eq!(
            (
                runqueues.name.as_str(),
                runqueues.runtime,
                runqueues.relocated
            ),
            ("runqueues", 0x35ec0, false)
        );
        let banner = tables
            .symbols
            .iter()
            .find(|s| s.name == "linux_banner")
            .unwrap();
        assert_eq!(
            (banner.kind, banner.runtime, banner.relocated),
            ('D', base + 0x200000, true)
        );

        // A corrupted second-block marker makes the names unverifiable.
        let mut broken = bytes;
        let marker = usize::try_from(at[2].1).unwrap() + 4;
        broken[marker] ^= 1;
        assert!(
            locate(&image_of(broken), &crate::Job::default())
                .unwrap()
                .is_empty()
        );
    }
}
