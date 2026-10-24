//! NTFS MFT records carved from physical memory.
use super::*;

const RECORD: usize = 1024;
const SECTOR: usize = 512;
const RECORD_LIMIT: usize = 1_000_000;
const STANDARD_INFORMATION: u32 = 0x10;
const FILE_NAME: u32 = 0x30;

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
    let offset = usize::from(u16::from_le_bytes([record[4], record[5]]));
    let count = usize::from(u16::from_le_bytes([record[6], record[7]]));
    ensure!(
        count == record.len() / SECTOR + 1 && offset + count * 2 <= record.len(),
        "USA 大小无效"
    );
    let usn = [record[offset], record[offset + 1]];
    let on_disk = (1..count).all(|sector| {
        let end = sector * SECTOR - 2;
        record[end..end + 2] == usn
    });
    if on_disk {
        for sector in 1..count {
            let end = sector * SECTOR - 2;
            let fix = offset + sector * 2;
            let value = [record[fix], record[fix + 1]];
            record[end..end + 2].copy_from_slice(&value);
        }
    }
    Ok(())
}

pub(super) fn parse_record(mut bytes: [u8; RECORD]) -> Result<Record> {
    ensure!(&bytes[..4] == b"FILE", "非 MFT 记录");
    fixup(&mut bytes)?;
    let u16_at = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    let u32_at = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let u64_at = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let flags = u16_at(&bytes, 22);
    let mut record = Record {
        number: u32_at(&bytes, 44),
        in_use: flags & 1 != 0,
        directory: flags & 2 != 0,
        ..Default::default()
    };
    // Win32 (1) and Win32+DOS (3) names beat POSIX (0) beat DOS-only (2).
    let mut rank = -1;
    let mut at = usize::from(u16_at(&bytes, 20));
    ensure!(at >= 48 && at < RECORD, "首属性偏移无效");
    while at + 16 <= RECORD {
        let kind = u32_at(&bytes, at);
        if kind == 0xffff_ffff {
            break;
        }
        let length = u32_at(&bytes, at + 4) as usize;
        ensure!(length >= 16 && at + length <= RECORD, "属性长度无效");
        let resident = bytes[at + 8] == 0;
        if resident && matches!(kind, STANDARD_INFORMATION | FILE_NAME) {
            let size = u32_at(&bytes, at + 16) as usize;
            let offset = usize::from(u16_at(&bytes, at + 20));
            ensure!(offset + size <= length, "属性内容越界");
            let content = &bytes[at + offset..at + offset + size];
            if kind == STANDARD_INFORMATION && size >= 32 {
                record.si = (u64_at(content, 0), u64_at(content, 8));
            } else if kind == FILE_NAME && size >= 66 {
                let characters = usize::from(content[64]);
                let namespace = content[65];
                ensure!(66 + characters * 2 <= size, "文件名越界");
                let score = match namespace {
                    1 | 3 => 2,
                    0 => 1,
                    _ => 0,
                };
                if score > rank {
                    rank = score;
                    record.name = String::from_utf16_lossy(
                        &content[66..66 + characters * 2]
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    );
                    record.parent = u64_at(content, 0) & 0xffff_ffff_ffff;
                    record.fn_times = (u64_at(content, 8), u64_at(content, 16));
                    record.size = u64_at(content, 48);
                }
            }
        }
        at += length;
    }
    ensure!(rank >= 0, "记录没有常驻 $FILE_NAME");
    Ok(record)
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
            match parse_record(bytes) {
                Ok(record) => {
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
                Err(_) => {}
            }
            if r.rows.len().is_multiple_of(4096) {
                job.report(format!("mftscan: {} 条", r.rows.len()));
            }
        }
        r.kernel_identity["coverage"] = serde_json::json!(
            "1 KiB-aligned resident FILE records in physical memory; on-disk and cache-resident (fixups applied) forms; non-resident names are skipped"
        );
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
}
