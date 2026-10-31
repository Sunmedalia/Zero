//! Pinned Intel mapping events for selected virtual scan sections.
use crate::{Job, image::Image, resources::Lru};
use anyhow::{Context, Result, ensure};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Linux64,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Linux32 discovery is not yet connected; pinned layer vectors validate this foundation"
        )
    )]
    Linux32,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Linux PAE discovery is not yet connected; pinned layer vectors validate this foundation"
        )
    )]
    LinuxPae,
    Windows64,
    Windows32,
    WindowsPae,
}
impl Kind {
    fn shifts(self) -> &'static [u32] {
        match self {
            Self::Windows32 | Self::Linux32 => &[22, 12],
            Self::WindowsPae | Self::LinuxPae => &[30, 21, 12],
            _ => &[39, 30, 21, 12],
        }
    }
    fn width(self) -> usize {
        if matches!(self, Self::Windows32 | Self::Linux32) {
            4
        } else {
            8
        }
    }
    fn bits(self) -> u32 {
        match self {
            Self::Windows32 | Self::Linux32 => 32,
            Self::WindowsPae | Self::LinuxPae => 40,
            Self::Windows64 => 45,
            Self::Linux64 => 52,
        }
    }
    fn va_bits(self) -> u32 {
        if matches!(
            self,
            Self::Windows32 | Self::Linux32 | Self::WindowsPae | Self::LinuxPae
        ) {
            32
        } else {
            48
        }
    }
    fn valid(self, e: u64) -> bool {
        e & 1 != 0
            || (!matches!(self, Self::Linux64 | Self::Linux32 | Self::LinuxPae)
                && e & (1 << 11) != 0
                && e & (1 << 10) == 0)
    }
    fn large(self, shift: u32) -> bool {
        match self {
            Self::Windows32 | Self::Linux32 => shift == 22,
            Self::WindowsPae | Self::LinuxPae => shift == 21,
            _ => matches!(shift, 21 | 30),
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct Fault {
    bits: u32,
    entry: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Mapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub backing: u8,
}
pub(crate) struct Mapper<'a> {
    image: &'a Image,
    root: u64,
    kind: Kind,
    tables: Lru<u64, Option<Arc<[u8; 4096]>>>,
    attempts: usize,
}
impl<'a> Mapper<'a> {
    pub(crate) fn new(image: &'a Image, root: u64, kind: Kind) -> Self {
        Self {
            image,
            root,
            kind,
            tables: Lru::new(image.limits.page_cache_entries.min(1025)),
            attempts: 0,
        }
    }
    fn table(&mut self, at: u64) -> Option<Arc<[u8; 4096]>> {
        if let Some(cached) = self.tables.get(&at) {
            return cached.clone();
        }
        let mut bytes = [0u8; 4096];
        let width = self.kind.width();
        let valid = self.image.read(at, &mut bytes).is_ok()
            && !bytes
                .chunks_exact(width)
                .all(|part| part == &bytes[..width]);
        let result = valid.then(|| Arc::new(bytes));
        self.tables.insert(at, result.clone(), 1);
        result
    }
    fn translate(&mut self, at: u64) -> std::result::Result<(u64, u64), Fault> {
        let at = at & ((1u64 << self.kind.va_bits()) - 1);
        let mut entry = self.root | 1;
        let mut previous = self.kind.va_bits();
        let mask = (1u64 << self.kind.bits()) - 1;
        for (level, &shift) in self.kind.shifts().iter().enumerate() {
            if !self.kind.valid(entry) {
                return Err(Fault {
                    bits: previous,
                    entry,
                });
            }
            let size = if matches!(self.kind, Kind::WindowsPae | Kind::LinuxPae) && level == 0 {
                2
            } else {
                if matches!(self.kind, Kind::Windows32 | Kind::Linux32) {
                    10
                } else {
                    9
                }
            };
            let align = size + if self.kind.width() == 4 { 2 } else { 3 };
            let table_at = entry & mask & !((1u64 << align) - 1);
            let table = self.table(table_at).ok_or(Fault {
                bits: previous,
                entry,
            })?;
            let index = ((at >> shift) & ((1u64 << size) - 1)) as usize * self.kind.width();
            let mut word = [0; 8];
            word[..self.kind.width()].copy_from_slice(&table[index..index + self.kind.width()]);
            entry = u64::from_le_bytes(word);
            previous = shift;
            if self.kind.large(shift) && entry & 128 != 0 {
                entry &= !(1 << 12);
                break;
            }
        }
        if !self.kind.valid(entry) {
            return Err(Fault {
                bits: previous,
                entry,
            });
        }
        let span = 1u64 << previous;
        Ok(((entry & mask & !4095) | (at & (span - 1)), span))
    }
    fn captured(&self, at: u64, length: u64) -> bool {
        let Some(end) = at.checked_add(length) else {
            return false;
        };
        let mut cursor = at;
        for segment in &self.image.segments {
            if segment.end <= cursor {
                continue;
            }
            if segment.start > cursor {
                return false;
            }
            cursor = segment.end.min(end);
            if cursor == end {
                return true;
            }
        }
        false
    }
    pub(crate) fn read(
        &mut self,
        mut at: u64,
        mut out: &mut [u8],
        mut swap_read: impl FnMut(u8, u64, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        if !out.is_empty() {
            at.checked_add(out.len() as u64 - 1)
                .context("Intel 读取地址溢出")?;
        }
        while !out.is_empty() {
            let (backing, offset, span) = match self.translate(at) {
                Ok((offset, span)) => (0, offset, span),
                Err(fault) => {
                    let bit = if matches!(self.kind, Kind::Windows32 | Kind::Linux32) {
                        12
                    } else {
                        32
                    };
                    let page = fault.entry >> bit;
                    ensure!(
                        !matches!(self.kind, Kind::Linux64 | Kind::Linux32 | Kind::LinuxPae)
                            && fault.entry & ((1 << 11) | (1 << 10) | 1) == 0
                            && fault.entry & 128 != 0
                            && page != 0
                            && page <= u64::MAX >> fault.bits,
                        "Intel 读取缺页"
                    );
                    (
                        1 + ((fault.entry >> 1) & 15) as u8,
                        page << fault.bits,
                        1u64 << fault.bits,
                    )
                }
            };
            let count = (span - (at & (span - 1))).min(out.len() as u64) as usize;
            if backing == 0 {
                self.image.read(offset, &mut out[..count])?;
            } else {
                swap_read(backing - 1, offset, &mut out[..count])?;
            }
            out = &mut out[count..];
            if !out.is_empty() {
                at = at.checked_add(count as u64).context("Intel 读取地址溢出")?;
            }
        }
        Ok(())
    }
    pub(crate) fn mappings(
        &mut self,
        start: u64,
        end: u64,
        job: &Job,
        mut swap_valid: impl FnMut(u8, u64, u64) -> bool,
    ) -> Result<Vec<Mapping>> {
        ensure!(start <= end, "扫描区间倒置");
        let mut at = start;
        let mut maps: Vec<Mapping> = Vec::new();
        let mut zero_pending = start == end;
        while at < end || zero_pending {
            zero_pending = false;
            job.check()?;
            self.attempts += 1;
            ensure!(self.attempts <= 1_000_000, "Intel 扫描映射次数超过上限");
            let translated = self.translate(at);
            let candidate = match translated {
                Ok((offset, span)) => Ok((0, offset, span)),
                Err(fault) => {
                    let bit = if matches!(self.kind, Kind::Windows32 | Kind::Linux32) {
                        12
                    } else {
                        32
                    };
                    let page = fault.entry >> bit;
                    if !matches!(self.kind, Kind::Linux64 | Kind::Linux32 | Kind::LinuxPae)
                        && fault.entry & ((1 << 11) | (1 << 10) | 1) == 0
                        && fault.entry & 128 != 0
                        && page != 0
                        && page <= u64::MAX >> fault.bits
                    {
                        Ok((
                            1 + ((fault.entry >> 1) & 15) as u8,
                            page << fault.bits,
                            1u64 << fault.bits,
                        ))
                    } else {
                        Err(fault)
                    }
                }
            };
            match candidate {
                Ok((backing, offset, span)) => {
                    let count = (span - (at & (span - 1))).min(end - at);
                    // The pinned zero-length branch checks the translated byte,
                    // then emits a zero-length event rather than reading a page.
                    let valid_length = count.max(1);
                    let valid = if backing == 0 {
                        self.captured(offset, valid_length)
                    } else {
                        swap_valid(backing - 1, offset, valid_length)
                    };
                    if valid {
                        if let Some(last) = maps.last_mut()
                            && last.backing == backing
                            && last.end == at
                            && last.offset + (last.end - last.start) == offset
                        {
                            last.end = at + count;
                        } else {
                            ensure!(maps.len() < 1_000_000, "扫描映射区间超过上限");
                            maps.push(Mapping {
                                start: at,
                                end: at + count,
                                offset,
                                backing,
                            });
                        }
                        at += count;
                    } else if count != 0 {
                        let mask = count - 1;
                        at = at
                            .checked_add(count - (at & mask))
                            .context("扫描映射跳过溢出")?
                            .min(end);
                    }
                }
                Err(fault) => {
                    if start == end {
                        break;
                    }
                    let mask = (1u64 << fault.bits) - 1;
                    at = at
                        .checked_add(mask + 1 - (at & mask))
                        .context("扫描映射缺页跳过溢出")?
                        .min(end);
                }
            }
        }
        Ok(maps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::io::Write;
    #[test]
    fn selected_mappings_and_reads_match_actual_intel_layers() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../tests/reference/parity/fixtures/intel-scan.json"
        ))
        .unwrap();
        let linux32: Value = serde_json::from_str(include_str!(
            "../tests/reference/parity/fixtures/linux32-layers.json"
        ))
        .unwrap();
        for case in vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .chain(linux32["cases"].as_array().unwrap())
        {
            let kind = match case["arch"].as_str().unwrap() {
                "linux32" => Kind::Linux32,
                "linux-pae" => Kind::LinuxPae,
                "linux" => Kind::Linux64,
                "x64" => Kind::Windows64,
                "pae" => Kind::WindowsPae,
                _ => Kind::Windows32,
            };
            let width = case["width"].as_u64().unwrap() as usize;
            let mut bytes = vec![0u8; case["data_length"].as_u64().unwrap() as usize];
            for write in case["writes"].as_array().unwrap() {
                let at = write[0].as_u64().unwrap() as usize;
                let value = write[1].as_u64().unwrap().to_le_bytes();
                bytes[at..at + width].copy_from_slice(&value[..width]);
            }
            for range in case["patterned_ranges"].as_array().unwrap() {
                for (at, byte) in bytes
                    .iter_mut()
                    .enumerate()
                    .take(range[1].as_u64().unwrap() as usize)
                    .skip(range[0].as_u64().unwrap() as usize)
                {
                    *byte = ((at * 17 + 3) % 251) as u8;
                }
            }
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(&bytes).unwrap();
            let mut image = Image::from_file(file, "synthetic-intel".into()).unwrap();
            image.segments.clear();
            let mut start = 0;
            for hole in case["holes"].as_array().unwrap() {
                let end = hole[0].as_u64().unwrap();
                if end > start {
                    image.segments.push(crate::image::Segment {
                        start,
                        end,
                        file_offset: start,
                    });
                }
                start = hole[1].as_u64().unwrap();
            }
            image.segments.push(crate::image::Segment {
                start,
                end: bytes.len() as u64,
                file_offset: start,
            });
            let attached = case["attached"].as_u64().map(|i| i as u8);
            let swap: Vec<u8> = (0..case["pagefile_length"].as_u64().unwrap())
                .map(|i| ((i * 13 + 7) % 251) as u8)
                .collect();
            let mut mapper = Mapper::new(&image, 0x1000, kind);
            for query in case["mapping_queries"].as_array().unwrap() {
                let actual = mapper
                    .mappings(
                        query["start"].as_u64().unwrap(),
                        query["end"].as_u64().unwrap(),
                        &Job::default(),
                        |index, offset, len| {
                            attached == Some(index)
                                && offset
                                    .checked_add(len)
                                    .is_some_and(|end| end <= swap.len() as u64)
                        },
                    )
                    .unwrap();
                let values: Vec<_> = actual
                    .iter()
                    .map(|m| json!([m.start, m.end, m.offset, m.backing]))
                    .collect();
                assert_eq!(json!(values), query["expected"], "{} {query}", case["id"]);
            }
            for query in case["queries"].as_array().unwrap() {
                let mut out = vec![0u8; query["length"].as_u64().unwrap() as usize];
                let actual = mapper.read(
                    query["address"].as_u64().unwrap(),
                    &mut out,
                    |index, offset, out| {
                        ensure!(attached == Some(index), "missing swap index");
                        let end = offset
                            .checked_add(out.len() as u64)
                            .context("swap overflow")?;
                        ensure!(end <= swap.len() as u64, "swap bounds");
                        out.copy_from_slice(&swap[offset as usize..end as usize]);
                        Ok(())
                    },
                );
                if query["error"].is_null() {
                    actual.unwrap_or_else(|e| panic!("{} {query}: {e:#}", case["id"]));
                    let encoded: String = out.iter().map(|b| format!("{b:02x}")).collect();
                    assert_eq!(
                        encoded,
                        query["expected_hex"].as_str().unwrap(),
                        "{} {query}",
                        case["id"]
                    );
                } else {
                    assert!(actual.is_err(), "{} {query}", case["id"]);
                }
            }
        }
    }
}
