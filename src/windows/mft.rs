//! NTFS MFT records carved from physical memory.
use super::*;
use crate::bytes::{le_u16, le_u32, le_u64};

const RECORD: usize = 1024;
const SECTOR: usize = 512;
const RECORD_LIMIT: usize = 1_000_000;
const STANDARD_INFORMATION: u32 = 0x10;
const FILE_NAME: u32 = 0x30;
const DATA: u32 = 0x80;

/// One decoded `$DATA` attribute (unnamed resident data or named ADS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DataStream {
    pub name: String,
    pub resident: bool,
    pub data: Vec<u8>,
}

/// Format bytes as a compact single-line hex + ASCII preview for MFT data streams.
fn format_hexdump(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let hex_part: String = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let ascii_part: String = bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    format!("{hex_part}  |{ascii_part}|")
}

impl Record {
    fn mft_type(&self) -> &'static str {
        match (self.in_use, self.directory) {
            (true, true) => "InUse & Directory",
            (true, false) => "InUse & File",
            (false, true) => "Removed & Directory",
            (false, false) => "Removed & File",
        }
    }
}

/// One decoded MFT record.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Record {
    pub number: u32,
    pub directory: bool,
    pub in_use: bool,
    pub name: String,
    pub parent: u64,
    /// $STANDARD_INFORMATION created / modified.
    pub si: (u64, u64),
    /// $FILE_NAME created / modified.
    pub fn_times: (u64, u64),
    pub size: u64,
}

/// Apply the update-sequence fixups of an on-disk image of a record.
///
/// NTFS keeps cached MFT records with the fixups already applied, so the
/// sector tails then hold real data: only when every tail still carries the
/// USN is the record in on-disk form and patched here.
pub(super) fn fixup(record: &mut [u8]) -> Result<()> {
    let header = |at| le_u16(record, at).map(usize::from).context("USA 大小无效");
    let (offset, count) = (header(4)?, header(6)?);
    ensure!(
        count == record.len() / SECTOR + 1 && offset + count * 2 <= record.len(),
        "USA 大小无效"
    );
    let usn = le_u16(record, offset).context("USA 大小无效")?;
    let on_disk = (1..count).all(|sector| le_u16(record, sector * SECTOR - 2) == Some(usn));
    if on_disk {
        for sector in 1..count {
            let end = sector * SECTOR - 2;
            let value = le_u16(record, offset + sector * 2).context("USA 大小无效")?;
            record
                .get_mut(end..end + 2)
                .context("USA 大小无效")?
                .copy_from_slice(&value.to_le_bytes());
        }
    }
    Ok(())
}

pub(super) fn parse_record(bytes: [u8; RECORD]) -> Result<Record> {
    parse_record_with_data(bytes).map(|(record, _)| record)
}

pub(super) fn parse_record_with_data(mut bytes: [u8; RECORD]) -> Result<(Record, Vec<DataStream>)> {
    ensure!(bytes.starts_with(b"FILE"), "非 MFT 记录");
    fixup(&mut bytes)?;
    let u16_at = |b: &[u8], at: usize| le_u16(b, at).context("MFT u16 字段截断");
    let u32_at = |b: &[u8], at: usize| le_u32(b, at).context("MFT u32 字段截断");
    let u64_at = |b: &[u8], at: usize| le_u64(b, at).context("MFT u64 字段截断");
    let flags = u16_at(&bytes, 22)?;
    let mut record = Record {
        number: u32_at(&bytes, 44)?,
        in_use: flags & 1 != 0,
        directory: flags & 2 != 0,
        ..Default::default()
    };
    let mut streams = Vec::new();
    // Win32 (1) and Win32+DOS (3) names beat POSIX (0) beat DOS-only (2).
    let mut rank = -1;
    let mut at = usize::from(u16_at(&bytes, 20)?);
    ensure!((48..RECORD).contains(&at), "首属性偏移无效");
    while at < RECORD {
        let kind = u32_at(&bytes, at)?;
        if kind == 0xffff_ffff {
            break;
        }
        let length = u32_at(&bytes, at + 4)? as usize;
        ensure!(length >= 16 && at + length <= RECORD, "属性长度无效");
        // All field offsets below are relative to this attribute, never to the
        // rest of the record: a short header cannot borrow the next one's bytes.
        let attribute = bytes.at(at..at + length)?;
        let resident = attribute.get(8) == Some(&0);
        if resident && matches!(kind, STANDARD_INFORMATION | FILE_NAME) {
            ensure!(attribute.len() >= 24, "常驻属性头被截断");
            let size = u32_at(attribute, 16)? as usize;
            let offset = usize::from(u16_at(attribute, 20)?);
            ensure!(offset >= 24, "属性内容与常驻属性头重叠");
            let content = attribute
                .get(offset..offset + size)
                .context("属性内容越界")?;
            if kind == STANDARD_INFORMATION {
                ensure!(content.len() >= 32, "$STANDARD_INFORMATION 内容截断");
                record.si = (u64_at(content, 0)?, u64_at(content, 8)?);
            } else {
                ensure!(content.len() >= 66, "$FILE_NAME 内容截断");
                let characters = usize::from(*content.at(64)?);
                let namespace = *content.at(65)?;
                let name = content.get(66..66 + characters * 2).context("文件名越界")?;
                let score = match namespace {
                    1 | 3 => 2,
                    0 => 1,
                    _ => 0,
                };
                if score > rank {
                    rank = score;
                    record.name = crate::bytes::utf16_lossy(name);
                    record.parent = u64_at(content, 0)? & 0xffff_ffff_ffff;
                    record.fn_times = (u64_at(content, 8)?, u64_at(content, 16)?);
                    record.size = u64_at(content, 48)?;
                }
            }
        } else if kind == DATA {
            let name_len = usize::from(*attribute.at(9)?);
            let name = if name_len > 0 {
                let name_offset = usize::from(u16_at(attribute, 10)?);
                ensure!(name_offset >= 16, "$DATA 名称偏移与属性头重叠");
                let name_end = name_offset
                    .checked_add(name_len * 2)
                    .context("$DATA 名称长度溢出")?;
                let raw_name = attribute
                    .get(name_offset..name_end)
                    .context("$DATA 名称越界")?;
                crate::bytes::utf16_lossy(raw_name)
            } else {
                String::new()
            };
            if resident {
                ensure!(attribute.len() >= 24, "常驻 $DATA 属性头被截断");
                let size = u32_at(attribute, 16)? as usize;
                let offset = usize::from(u16_at(attribute, 20)?);
                ensure!(offset >= 24, "$DATA 内容与常驻属性头重叠");
                let content_end = offset.checked_add(size).context("$DATA 内容长度溢出")?;
                let content = attribute
                    .get(offset..content_end)
                    .context("$DATA 内容越界")?;
                streams.push(DataStream {
                    name,
                    resident: true,
                    data: content.to_vec(),
                });
            } else if !name.is_empty() {
                streams.push(DataStream {
                    name,
                    resident: false,
                    data: Vec::new(),
                });
            }
        }
        at += length;
    }
    ensure!(rank >= 0, "记录没有常驻 $FILE_NAME");
    Ok((record, streams))
}

impl Windows<'_> {
    /// windows.mftscan: 1 KiB-aligned FILE records with a resident name.
    pub(super) fn mftscan(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinMftscan);
        for hit in self.vm.image.scan(b"FILE", job)? {
            job.check()?;
            if !hit.is_multiple_of(RECORD as u64) {
                continue;
            }
            let mut bytes = [0u8; RECORD];
            if self.vm.image.read(hit, &mut bytes).is_err() {
                continue;
            }
            if let Ok(record) = parse_record(bytes) {
                ensure!(
                    r.rows.len() < RECORD_LIMIT,
                    "MFT 记录超过 {RECORD_LIMIT} 条上限"
                );
                r.rows.push(vec![
                    format!("physical:{hit:#x}"),
                    record.number.to_string(),
                    if record.directory {
                        "Directory"
                    } else {
                        "File"
                    }
                    .into(),
                    record.in_use.to_string(),
                    record.name,
                    record.parent.to_string(),
                    filetime(record.si.0),
                    filetime(record.si.1),
                    filetime(record.fn_times.0),
                    filetime(record.fn_times.1),
                    record.size.to_string(),
                ]);
            }
            if r.rows.len().is_multiple_of(4096) {
                job.report(format!("mftscan: {} 条", r.rows.len()));
            }
        }
        if let Some(identity) = r.kernel_identity.as_object_mut() {
            identity.insert("coverage".into(), serde_json::json!(
            "1 KiB-aligned resident FILE records in physical memory; on-disk and cache-resident (fixups applied) forms; non-resident names are skipped"
        ));
        }
        Ok(r)
    }

    /// `windows.mftscan.ADS` and `windows.mftscan.ResidentData`.
    pub(super) fn mftscan_streams(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(plugin);
        let want_ads = plugin == Plugin::WinMftscanAds;
        for hit in self.vm.image.scan(b"FILE", job)? {
            job.check()?;
            if !hit.is_multiple_of(RECORD as u64) {
                continue;
            }
            let mut bytes = [0u8; RECORD];
            if self.vm.image.read(hit, &mut bytes).is_err() {
                continue;
            }
            let Ok((record, streams)) = parse_record_with_data(bytes) else {
                continue;
            };
            let mft_type = record.mft_type();
            for stream in streams {
                if want_ads {
                    if stream.name.is_empty() {
                        continue;
                    }
                    ensure!(
                        r.rows.len() < RECORD_LIMIT,
                        "MFT ADS 记录超过 {RECORD_LIMIT} 条上限"
                    );
                    r.rows.push(vec![
                        format!("physical:{hit:#x}"),
                        "FILE".into(),
                        record.number.to_string(),
                        mft_type.into(),
                        record.name.clone(),
                        stream.name,
                        if stream.resident {
                            format_hexdump(&stream.data)
                        } else {
                            String::new()
                        },
                    ]);
                } else {
                    if !stream.name.is_empty() || !stream.resident {
                        continue;
                    }
                    ensure!(
                        r.rows.len() < RECORD_LIMIT,
                        "MFT ResidentData 记录超过 {RECORD_LIMIT} 条上限"
                    );
                    r.rows.push(vec![
                        format!("physical:{hit:#x}"),
                        "FILE".into(),
                        record.number.to_string(),
                        mft_type.into(),
                        record.name.clone(),
                        format_hexdump(&stream.data),
                    ]);
                }
            }
            if r.rows.len().is_multiple_of(4096) && !r.rows.is_empty() {
                job.report(format!("{}: {} 条", plugin.name(), r.rows.len()));
            }
        }
        Ok(r)
    }
}

/// One MBR partition entry: (bootable, type, start LBA, sector count).
pub(super) type Partition = (bool, u8, u32, u32);

/// Validate a 512-byte sector as an MBR and return its disk signature and
/// non-empty partitions. A sector qualifies only when every entry has a
/// valid status byte and at least one partition is defined.
pub(super) fn parse_mbr(sector: &[u8]) -> Option<(u32, Vec<Partition>)> {
    if sector.len() < SECTOR || sector.get(510..512) != Some(&[0x55, 0xaa][..]) {
        return None;
    }
    let mut partitions = Vec::new();
    for entry in sector.get(446..510)?.as_chunks::<16>().0 {
        if !matches!(entry[0], 0x00 | 0x80) {
            return None;
        }
        let kind = entry[4];
        let start = le_u32(entry, 8)?;
        let count = le_u32(entry, 12)?;
        if kind == 0 {
            if count != 0 {
                return None;
            }
            continue;
        }
        if count == 0 || start == 0 {
            return None;
        }
        partitions.push((entry[0] == 0x80, kind, start, count));
    }
    if partitions.is_empty() {
        return None;
    }
    Some((le_u32(sector, 440)?, partitions))
}

impl Windows<'_> {
    /// windows.mbrscan: master boot records cached in physical memory.
    pub(super) fn mbrscan(&self, job: &Job) -> Result<Results> {
        use sha2::Digest;
        let mut r = self.result(Plugin::WinMbrscan);
        let mut sector = [0u8; SECTOR];
        for hit in self.vm.image.scan(&[0x55, 0xaa], job)? {
            job.check()?;
            let Some(start) = hit.checked_sub(510) else {
                continue;
            };
            if !start.is_multiple_of(SECTOR as u64)
                || self.vm.image.read(start, &mut sector).is_err()
            {
                continue;
            }
            let Some((signature, partitions)) = parse_mbr(&sector) else {
                continue;
            };
            let boot = format!("{:x}", sha2::Sha256::digest(&sector[..440]));
            for (index, (bootable, kind, first, count)) in partitions.into_iter().enumerate() {
                r.rows.push(vec![
                    format!("physical:{start:#x}"),
                    format!("{signature:08x}"),
                    index.to_string(),
                    bootable.to_string(),
                    format!("{kind:#04x}"),
                    first.to_string(),
                    count.to_string(),
                    boot.clone(),
                ]);
            }
            ensure!(r.rows.len() <= RECORD_LIMIT, "MBR 记录超过上限");
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, namespace: u8) -> [u8; RECORD] {
        let mut b = [0u8; RECORD];
        b[..4].copy_from_slice(b"FILE");
        b[4..6].copy_from_slice(&48u16.to_le_bytes()); // USA offset
        b[6..8].copy_from_slice(&3u16.to_le_bytes()); // USN + two sectors
        b[48..50].copy_from_slice(&7u16.to_le_bytes());
        b[50..52].copy_from_slice(&0xaaaau16.to_le_bytes());
        b[52..54].copy_from_slice(&0xbbbbu16.to_le_bytes());
        b[510..512].copy_from_slice(&7u16.to_le_bytes());
        b[1022..1024].copy_from_slice(&7u16.to_le_bytes());
        b[20..22].copy_from_slice(&56u16.to_le_bytes());
        b[22..24].copy_from_slice(&1u16.to_le_bytes());
        b[44..48].copy_from_slice(&42u32.to_le_bytes());
        // $STANDARD_INFORMATION at 56, 0x60 long, content at +24.
        let si = 56;
        b[si..si + 4].copy_from_slice(&0x10u32.to_le_bytes());
        b[si + 4..si + 8].copy_from_slice(&0x60u32.to_le_bytes());
        b[si + 16..si + 20].copy_from_slice(&48u32.to_le_bytes());
        b[si + 20..si + 22].copy_from_slice(&24u16.to_le_bytes());
        b[si + 24..si + 32].copy_from_slice(&100u64.to_le_bytes());
        b[si + 32..si + 40].copy_from_slice(&200u64.to_le_bytes());
        // $FILE_NAME at 152.
        let at = si + 0x60;
        let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let content = 66 + units.len();
        let length = (24 + content + 7) & !7;
        b[at..at + 4].copy_from_slice(&0x30u32.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&(length as u32).to_le_bytes());
        b[at + 16..at + 20].copy_from_slice(&(content as u32).to_le_bytes());
        b[at + 20..at + 22].copy_from_slice(&24u16.to_le_bytes());
        let c = at + 24;
        b[c..c + 8].copy_from_slice(&(5u64 | 3 << 48).to_le_bytes());
        b[c + 8..c + 16].copy_from_slice(&300u64.to_le_bytes());
        b[c + 16..c + 24].copy_from_slice(&400u64.to_le_bytes());
        b[c + 48..c + 56].copy_from_slice(&4096u64.to_le_bytes());
        b[c + 64] = name.encode_utf16().count() as u8;
        b[c + 65] = namespace;
        b[c + 66..c + 66 + units.len()].copy_from_slice(&units);
        let end = at + length;
        b[end..end + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        b
    }

    #[test]
    fn mbr_sectors_need_valid_status_bytes_and_a_partition() {
        let mut sector = [0u8; SECTOR];
        sector[440..444].copy_from_slice(&0x1234_abcdu32.to_le_bytes());
        sector[446] = 0x80;
        sector[450] = 0x07;
        sector[454..458].copy_from_slice(&2048u32.to_le_bytes());
        sector[458..462].copy_from_slice(&1_000_000u32.to_le_bytes());
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
        assert_eq!(
            parse_mbr(&sector),
            Some((0x1234_abcd, vec![(true, 0x07, 2048, 1_000_000)]))
        );
        let mut bad_status = sector;
        bad_status[462] = 0x13;
        assert!(parse_mbr(&bad_status).is_none());
        let mut empty = [0u8; SECTOR];
        empty[510..512].copy_from_slice(&[0x55, 0xaa]);
        assert!(parse_mbr(&empty).is_none());
        let mut unsigned = sector;
        unsigned[511] = 0;
        assert!(parse_mbr(&unsigned).is_none());
    }

    #[test]
    fn records_apply_fixups_and_keep_both_timestamp_sets() {
        let parsed = parse_record(record("notes.txt", 1)).unwrap();
        assert_eq!(
            parsed,
            Record {
                number: 42,
                directory: false,
                in_use: true,
                name: "notes.txt".into(),
                parent: 5,
                si: (100, 200),
                fn_times: (300, 400),
                size: 4096,
            }
        );
    }

    #[test]
    fn truncated_resident_header_after_a_valid_name_is_rejected() {
        let mut b = record("X", 1);
        let end = 152 + le_u32(&b, 156).unwrap() as usize;
        // An opaque nonresident attribute places the next header at EOF - 16.
        b[end..end + 16].fill(0);
        b[end..end + 4].copy_from_slice(&0x80u32.to_le_bytes());
        b[end + 4..end + 8].copy_from_slice(&((1008 - end) as u32).to_le_bytes());
        b[end + 8] = 1;
        b[1008..1024].fill(0);
        b[1008..1012].copy_from_slice(&STANDARD_INFORMATION.to_le_bytes());
        b[1012..1016].copy_from_slice(&16u32.to_le_bytes());
        let error = parse_record(b).unwrap_err();
        assert!(error.to_string().contains("常驻属性头"), "{error:#}");
    }

    #[test]
    fn short_trailing_headers_are_not_silently_skipped() {
        for at in [1016usize, 1020] {
            let mut b = record("X", 1);
            let end = 152 + le_u32(&b, 156).unwrap() as usize;
            b[end..].fill(0);
            b[end..end + 4].copy_from_slice(&0x80u32.to_le_bytes());
            b[end + 4..end + 8].copy_from_slice(&((at - end) as u32).to_le_bytes());
            b[end + 8] = 1;
            b[at..at + 4].copy_from_slice(&STANDARD_INFORMATION.to_le_bytes());
            if at + 8 <= RECORD {
                b[at + 4..at + 8].copy_from_slice(&8u32.to_le_bytes());
            }
            assert!(parse_record(b).is_err(), "accepted short header at {at}");
            // The four-byte end marker is valid even at the end of a record.
            b[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert_eq!(parse_record(b).unwrap().name, "X");
        }
    }

    #[test]
    fn resident_content_must_not_overlap_its_header_or_be_truncated() {
        for offset in [0u16, 16, 23] {
            let mut b = record("X", 1);
            b[76..78].copy_from_slice(&offset.to_le_bytes());
            assert!(
                parse_record(b).is_err(),
                "accepted header overlap at {offset}"
            );
        }
        // A later valid name must not hide a truncated timestamp or name value.
        for (kind, size) in [(STANDARD_INFORMATION, 31u32), (FILE_NAME, 65)] {
            let mut b = record("X", 1);
            b[56..60].copy_from_slice(&kind.to_le_bytes());
            b[72..76].copy_from_slice(&size.to_le_bytes());
            assert!(parse_record(b).is_err(), "accepted short {kind:#x} value");
        }
        let mut b = record("X", 1);
        b[72..76].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_record(b).is_err());
    }

    #[test]
    fn cached_records_with_applied_fixups_parse_and_missing_names_are_rejected() {
        // Cache-resident form: the sector tails already hold the real bytes.
        let mut cached = record("cached.log", 3);
        cached[510..512].copy_from_slice(&0xaaaau16.to_le_bytes());
        cached[1022..1024].copy_from_slice(&0xbbbbu16.to_le_bytes());
        assert_eq!(parse_record(cached).unwrap().name, "cached.log");
        let mut nameless = record("a", 1);
        nameless[152..156].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(parse_record(nameless).is_err());
        assert!(parse_record([0; RECORD]).is_err());
    }

    #[test]
    fn parses_resident_data_and_alternate_data_streams() {
        let mut b = record("payload.txt", 1);
        let mut at = 152 + le_u32(&b, 156).unwrap() as usize;

        // 1. Unnamed resident $DATA: "hello"
        let payload = b"hello";
        let res_len = (24 + payload.len() + 7) & !7;
        b[at..at + 4].copy_from_slice(&DATA.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&(res_len as u32).to_le_bytes());
        b[at + 8] = 0; // resident
        b[at + 9] = 0; // unnamed
        b[at + 16..at + 20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        b[at + 20..at + 22].copy_from_slice(&24u16.to_le_bytes());
        b[at + 24..at + 24 + payload.len()].copy_from_slice(payload);
        at += res_len;

        // 2. Named resident ADS: "Zone.Identifier" -> "[ZoneTransfer]"
        let ads_name = "Zone.Identifier";
        let ads_name_bytes: Vec<u8> = ads_name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ads_data = b"[ZoneTransfer]";
        let name_off = 24usize;
        let data_off = (name_off + ads_name_bytes.len() + 7) & !7;
        let ads_len = (data_off + ads_data.len() + 7) & !7;
        b[at..at + 4].copy_from_slice(&DATA.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&(ads_len as u32).to_le_bytes());
        b[at + 8] = 0; // resident
        b[at + 9] = ads_name.encode_utf16().count() as u8;
        b[at + 10..at + 12].copy_from_slice(&(name_off as u16).to_le_bytes());
        b[at + 16..at + 20].copy_from_slice(&(ads_data.len() as u32).to_le_bytes());
        b[at + 20..at + 22].copy_from_slice(&(data_off as u16).to_le_bytes());
        b[at + name_off..at + name_off + ads_name_bytes.len()].copy_from_slice(&ads_name_bytes);
        b[at + data_off..at + data_off + ads_data.len()].copy_from_slice(ads_data);
        at += ads_len;

        // 3. Named non-resident ADS: "big.bin"
        let big_name = "big.bin";
        let big_name_bytes: Vec<u8> = big_name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let big_len = (64 + big_name_bytes.len() + 7) & !7;
        b[at..at + 4].copy_from_slice(&DATA.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&(big_len as u32).to_le_bytes());
        b[at + 8] = 1; // non-resident
        b[at + 9] = big_name.encode_utf16().count() as u8;
        b[at + 10..at + 12].copy_from_slice(&64u16.to_le_bytes());
        b[at + 64..at + 64 + big_name_bytes.len()].copy_from_slice(&big_name_bytes);
        at += big_len;

        b[at..at + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());

        let (rec, streams) = parse_record_with_data(b).unwrap();
        assert_eq!(rec.name, "payload.txt");
        assert_eq!(rec.mft_type(), "InUse & File");
        assert_eq!(streams.len(), 3);
        assert_eq!(streams[0].name, "");
        assert!(streams[0].resident);
        assert_eq!(streams[0].data, payload);
        assert_eq!(streams[1].name, "Zone.Identifier");
        assert!(streams[1].resident);
        assert_eq!(streams[1].data, ads_data);
        assert_eq!(streams[2].name, "big.bin");
        assert!(!streams[2].resident);
        assert!(streams[2].data.is_empty());
        assert_eq!(format_hexdump(&streams[0].data), "68 65 6c 6c 6f  |hello|");
    }
}
