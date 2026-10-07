//! Read only the official ZIP directory and exact ISF entry using bounded HTTPS ranges.
use crate::{
    Job,
    resources::Lru,
    symbols::{self, Isf},
    windows_symbols::PdbIdentity,
};
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub const URL: &str = "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip";
const BLOCK: u64 = 1024 * 1024;
const MAX_ARCHIVE: u64 = 4 * 1024 * 1024 * 1024;
const MAX_REQUESTS: usize = 64;
const MAX_MEMBER: u64 = 256 * 1024 * 1024;

struct RangeReader<F> {
    fetch: F,
    tail: symbols::RangeResponse,
    position: u64,
    blocks: Lru<u64, Vec<u8>>,
    requests: usize,
}
impl<F: FnMut(&str) -> Result<symbols::RangeResponse>> RangeReader<F> {
    fn open(mut fetch: F) -> Result<Self> {
        let tail = fetch("-65557")?;
        ensure!(
            tail.total <= MAX_ARCHIVE
                && tail.start.checked_add(tail.bytes.len() as u64) == Some(tail.total),
            "官方 ZIP 尾部范围或大小无效"
        );
        ensure!(tail.bytes.len() <= 65557, "官方 ZIP 尾部过大");
        Ok(Self {
            fetch,
            tail,
            position: 0,
            blocks: Lru::new(8 * BLOCK as usize),
            requests: 1,
        })
    }
}
impl<F: FnMut(&str) -> Result<symbols::RangeResponse>> Read for RangeReader<F> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() || self.position >= self.tail.total {
            return Ok(0);
        }
        let (bytes, offset) = if self.position >= self.tail.start {
            (&self.tail.bytes, (self.position - self.tail.start) as usize)
        } else {
            let start = self.position / BLOCK * BLOCK;
            if self.blocks.get(&start).is_none() {
                ensure_range(self.requests < MAX_REQUESTS, "官方 ZIP 按需请求超过限制")?;
                self.requests += 1;
                let end = (start + BLOCK).min(self.tail.total) - 1;
                let response =
                    (self.fetch)(&format!("{start}-{end}")).map_err(std::io::Error::other)?;
                ensure_range(
                    response.start == start
                        && response.total == self.tail.total
                        && response.bytes.len() as u64 == end - start + 1,
                    "官方 ZIP Range 不一致或文件发生变化",
                )?;
                self.blocks
                    .insert(start, response.bytes, (end - start + 1) as usize);
            }
            (
                self.blocks.get(&start).expect("bounded block inserted"),
                (self.position - start) as usize,
            )
        };
        let count = out.len().min(bytes.len() - offset);
        out[..count].copy_from_slice(&bytes[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}
fn ensure_range(condition: bool, message: &str) -> std::io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(message))
    }
}
impl<F> Seek for RangeReader<F> {
    fn seek(&mut self, seek: SeekFrom) -> std::io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::Current(p) => self.position.checked_add_signed(p),
            SeekFrom::End(p) => self.tail.total.checked_add_signed(p),
        }
        .ok_or_else(|| std::io::Error::other("ZIP seek 溢出"))?;
        ensure_range(position <= self.tail.total, "ZIP seek 超过文件边界")?;
        self.position = position;
        Ok(position)
    }
}
fn member_matches(name: &str, identity: &PdbIdentity) -> bool {
    let name = name.replace('\\', "/").to_ascii_lowercase();
    let Some((directory, file)) = name.rsplit_once('/') else {
        return false;
    };
    if directory.rsplit('/').next() != Some(identity.name.as_str()) {
        return false;
    }
    let stem = file
        .strip_suffix(".json.xz")
        .or_else(|| file.strip_suffix(".json"));
    // Official ZIP filenames use GUID-age; metadata is still the authority.
    stem.is_some_and(|s| {
        s == format!("{}-{}", identity.guid.to_ascii_lowercase(), identity.age)
            || s == format!("{}-{:x}", identity.guid.to_ascii_lowercase(), identity.age)
    })
}
fn extract<R: Read + Seek>(
    reader: R,
    identity: &PdbIdentity,
    target: &Path,
    job: &Job,
) -> Result<(Isf, Vec<u8>, String)> {
    let mut zip = zip::ZipArchive::new(reader).context("官方符号包 ZIP 目录无效")?;
    ensure!(zip.len() <= 100_000, "官方符号包条目过多");
    let names: Vec<_> = zip
        .file_names()
        .filter(|name| member_matches(name, identity))
        .map(str::to_owned)
        .collect();
    ensure!(
        !names.is_empty(),
        "官方符号包未包含精确 ISF：{}；需导入精确符号",
        identity.key()
    );
    ensure!(
        names.len() == 1,
        "官方符号包存在多个精确候选；需手动选择本地 ISF"
    );
    job.check()?;
    let name = &names[0];
    let member = zip.by_name(name)?;
    ensure!(
        member.size() <= MAX_MEMBER && member.compressed_size() <= MAX_MEMBER,
        "官方 ISF 条目超过大小限制"
    );
    let decoded = symbols::decode(member, name, job)?;
    let isf = Isf::parse(&decoded, target.display().to_string())?;
    ensure!(
        PdbIdentity::from_isf(&isf)? == *identity,
        "官方 ISF 元数据与请求的 PDB 身份不一致"
    );
    job.check()?;
    Ok((isf, decoded, name.clone()))
}
pub(crate) fn acquire(
    identity: &PdbIdentity,
    target: &Path,
    job: &Job,
) -> Result<(Isf, Vec<u8>, String)> {
    job.report(format!(
        "微软无此 PDB；从 Volatility 官方符号包查找 {}",
        identity.key()
    ));
    let reader = RangeReader::open(|range: &str| {
        job.check()?;
        job.report(format!("官方符号包按需读取 bytes={range}"));
        symbols::fetch_range(URL, range, BLOCK as usize, job)
    })?;
    extract(reader, identity, target, job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        io::{Cursor, Write},
        rc::Rc,
    };
    fn identity() -> PdbIdentity {
        PdbIdentity {
            name: "ntkrnlmp.pdb".into(),
            guid: "00112233445566778899AABBCCDDEEFF".into(),
            age: 2,
        }
    }
    fn isf(id: &PdbIdentity) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"metadata":{"windows":{"pdb":{"database":id.name,"GUID":id.guid,"age":id.age}}},"base_types":{"pointer":{"size":8}},"symbols":{},"user_types":{}})).unwrap()
    }
    fn archive(name: &str, data: &[u8], duplicate: bool) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("unrelated-padding", options).unwrap();
        writer.write_all(&vec![0; BLOCK as usize + 1000]).unwrap();
        writer.start_file(name, options).unwrap();
        writer.write_all(data).unwrap();
        if duplicate {
            writer
                .start_file(format!("alternate/{name}"), options)
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
    fn response(bytes: &[u8], range: &str) -> symbols::RangeResponse {
        let (start, end) = if let Some(suffix) = range.strip_prefix('-') {
            (
                bytes.len().saturating_sub(suffix.parse::<usize>().unwrap()),
                bytes.len(),
            )
        } else {
            let (start, end) = range.split_once('-').unwrap();
            (
                start.parse::<usize>().unwrap(),
                end.parse::<usize>().unwrap() + 1,
            )
        };
        symbols::RangeResponse {
            bytes: bytes[start..end].to_vec(),
            start: start as u64,
            total: bytes.len() as u64,
        }
    }
    #[test]
    fn exact_member_ranges_and_metadata_are_validated() -> Result<()> {
        let id = identity();
        let name = format!("windows/{}/{}-{}.json.xz", id.name, id.guid, id.age);
        let data = isf(&id);
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 6);
        xz.write_all(&data)?;
        let bytes = archive(&name, &xz.finish()?, false);
        let calls = Rc::new(Cell::new(0));
        let count = calls.clone();
        let reader = RangeReader::open(|range: &str| {
            count.set(count.get() + 1);
            Ok(response(&bytes, range))
        })?;
        let (parsed, decoded, entry) =
            extract(reader, &id, Path::new("exact.json"), &Job::default())?;
        assert_eq!(PdbIdentity::from_isf(&parsed)?, id);
        assert_eq!(decoded, data);
        assert_eq!(entry, name);
        assert!(
            calls.get() <= 3,
            "unrelated members should not be downloaded"
        );
        let mut wrong = id.clone();
        wrong.age += 1;
        assert!(
            extract(
                Cursor::new(&bytes),
                &wrong,
                Path::new("exact.json"),
                &Job::default()
            )
            .err()
            .expect("expected missing exact member")
            .to_string()
            .contains("未包含精确")
        );
        let name = format!("windows/{}/{}-{}.json", id.name, id.guid, id.age);
        let mismatch = archive(&name, &isf(&wrong), false);
        assert!(
            extract(
                Cursor::new(mismatch),
                &id,
                Path::new("exact.json"),
                &Job::default()
            )
            .is_err()
        );
        let duplicates = archive(&name, &data, true);
        assert!(
            extract(
                Cursor::new(duplicates),
                &id,
                Path::new("exact.json"),
                &Job::default()
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn ranges_reject_changed_size_excess_requests_and_bad_zip() -> Result<()> {
        let bytes = vec![0; 2 * BLOCK as usize];
        let mut reader = RangeReader::open(|range: &str| {
            let mut result = response(&bytes, range);
            if !range.starts_with('-') {
                result.total += 1;
            }
            Ok(result)
        })?;
        assert!(reader.read(&mut [0]).is_err());
        let mut reader = RangeReader::open(|range: &str| Ok(response(&bytes, range)))?;
        reader.requests = MAX_REQUESTS;
        assert!(reader.read(&mut [0]).is_err());
        assert!(
            extract(
                Cursor::new(b"not a ZIP"),
                &identity(),
                Path::new("exact.json"),
                &Job::default()
            )
            .is_err()
        );
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(acquire(&identity(), Path::new("exact.json"), &job).is_err());
        Ok(())
    }
}
