//! Bounded, read-only Windows dump containers. Offsets are file-format facts.
//! References: Microsoft MINIDUMP_* definitions and DUMP_HEADER32/64 layouts.
use super::*;
use crate::image::Segment;
use serde::{Deserialize, Serialize};
use std::{fs::File, os::unix::fs::FileExt};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Metadata {
    pub architecture: Architecture,
    pub hibernation: Option<hiber::Info>,
    pub dtb: Option<u64>,
    pub module_list: Option<u64>,
    pub process_list: Option<u64>,
    pub dump_type: Option<u32>,
    pub build: Option<u32>,
    pub pid: Option<u32>,
    pub virtual_memory: bool,
    pub modules: Vec<Module>,
    pub threads: Vec<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Module {
    pub base: u64,
    pub size: u32,
    pub name: String,
}
pub struct Parsed {
    pub format: &'static str,
    pub segments: Vec<Segment>,
    pub metadata: Metadata,
}
struct Reader<'a> {
    file: &'a File,
    len: u64,
}
impl Reader<'_> {
    fn bytes(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        ensure!(
            size <= 64 * 1024 * 1024
                && offset
                    .checked_add(size as u64)
                    .is_some_and(|e| e <= self.len),
            "Windows 容器文件范围越界"
        );
        let mut b = vec![0; size];
        self.file.read_exact_at(&mut b, offset)?;
        Ok(b)
    }
    fn uint(&self, offset: u64, width: usize) -> Result<u64> {
        let b = self.bytes(offset, width)?;
        let mut out = [0; 8];
        out[..width].copy_from_slice(&b);
        Ok(u64::from_le_bytes(out))
    }
    fn segment(
        &self,
        segments: &mut Vec<Segment>,
        start: u64,
        length: u64,
        offset: u64,
    ) -> Result<()> {
        ensure!(
            length > 0 && offset.checked_add(length).is_some_and(|e| e <= self.len),
            "转储内存段截断"
        );
        let end = start.checked_add(length).context("转储地址溢出")?;
        segments.push(Segment {
            start,
            end,
            file_offset: offset,
        });
        Ok(())
    }
    fn string(&self, rva: u64) -> Result<String> {
        let length = self.uint(rva, 4)? as usize;
        ensure!(
            length <= 65536 && length.is_multiple_of(2),
            "minidump 字符串长度无效"
        );
        let b = self.bytes(add(rva, 4)?, length)?;
        Ok(String::from_utf16_lossy(
            &b.chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}
fn machine(value: u64) -> Result<Architecture> {
    match value {
        0x14c => Ok(Architecture::X86),
        0x8664 => Ok(Architecture::X64),
        0xaa64 => Ok(Architecture::Arm64),
        _ => bail!("未知转储机器类型 {value:#x}"),
    }
}
pub fn parse(file: &File, job: &Job) -> Result<Parsed> {
    job.check()?;
    let r = Reader {
        file,
        len: file.metadata()?.len(),
    };
    match r.bytes(0, 4)?.as_slice() {
        b"PAGE" => crash(&r, job),
        b"MDMP" => minidump(&r, job),
        _ => bail!("未知 Windows dump 容器"),
    }
}
fn finish(mut p: Parsed) -> Result<Parsed> {
    p.segments.sort_by_key(|s| s.start);
    ensure!(p.segments.len() <= MAX_OBJECTS, "转储内存段超限");
    ensure!(
        p.segments.windows(2).all(|s| s[0].end <= s[1].start),
        "转储内存段重叠"
    );
    Ok(p)
}
fn crash(r: &Reader<'_>, job: &Job) -> Result<Parsed> {
    let wide = match r.bytes(4, 4)?.as_slice() {
        b"DU64" => true,
        b"DUMP" => false,
        _ => bail!("crash dump ValidDump 无效"),
    };
    let (header, width, descriptor, type_offset, machine_offset) = if wide {
        (8192u64, 8usize, 136u64, 3992u64, 48u64)
    } else {
        (4096, 4, 100, 3976, 32)
    };
    ensure!(r.len >= header, "crash dump 头部截断");
    let arch = machine(r.uint(machine_offset, 4)?)?;
    ensure!(
        (arch == Architecture::X86) != wide,
        "crash dump 架构与头部冲突"
    );
    let kind = r.uint(type_offset, 4)? as u32;
    let metadata = Metadata {
        architecture: arch,
        dtb: Some(r.uint(16, width)?),
        module_list: Some(r.uint(if wide { 32 } else { 24 }, width)?),
        process_list: Some(r.uint(if wide { 40 } else { 28 }, width)?),
        dump_type: Some(kind),
        build: Some(r.uint(12, 4)? as u32),
        ..Default::default()
    };
    let mut p = Parsed {
        format: "Windows crash",
        segments: vec![],
        metadata,
    };
    match kind {
        1 => {
            let runs = r.uint(descriptor, 4)?;
            let start = descriptor + if wide { 16 } else { 8 };
            ensure!(
                runs > 0
                    && runs <= MAX_OBJECTS as u64
                    && start + runs * (width * 2) as u64 <= header,
                "crash dump run 表越界"
            );
            let mut offset = header;
            for i in 0..runs {
                job.check()?;
                let position = start + i * (width * 2) as u64;
                let base = r
                    .uint(position, width)?
                    .checked_mul(4096)
                    .context("crash PFN 溢出")?;
                let length = r
                    .uint(position + width as u64, width)?
                    .checked_mul(4096)
                    .context("crash 页数溢出")?;
                r.segment(&mut p.segments, base, length, offset)?;
                offset = add(offset, length)?;
            }
        }
        5 | 6 | 8 => {
            // SUMMARY_DUMP stores an absolute data offset and a physical-page bitmap.
            let signature = r.bytes(header, 8)?;
            ensure!(
                &signature[4..] == b"DUMP" && matches!(&signature[..4], b"SDMP" | b"FDMP"),
                "bitmap dump 标记无效"
            );
            let mut offset = r.uint(header + 32, 8)?;
            let pages = r.uint(header + 40, 8)?;
            let bits = r.uint(header + 48, 8)?;
            ensure!(
                bits > 0 && bits <= 128 * 1024 * 1024,
                "bitmap dump 页位图超限"
            );
            let bitmap_size = bits.div_ceil(8) as usize;
            ensure!(
                offset >= header + 56 + bitmap_size as u64 && offset.is_multiple_of(4096),
                "bitmap dump 数据偏移无效"
            );
            let bitmap = r.bytes(header + 56, bitmap_size)?;
            let mut count = 0;
            for bit in 0..bits {
                if bit.is_multiple_of(32768) {
                    job.check()?;
                }
                if bitmap[bit as usize / 8] & (1 << (bit % 8)) == 0 {
                    continue;
                }
                let base = bit * 4096;
                if let Some(last) = p.segments.last_mut()
                    && last.end == base
                    && last.file_offset + last.end - last.start == offset
                {
                    last.end += 4096;
                } else {
                    r.segment(&mut p.segments, base, 4096, offset)?;
                }
                offset = add(offset, 4096)?;
                count += 1;
            }
            ensure!(
                count == pages && offset <= r.len,
                "bitmap dump 页数不一致或截断"
            );
        }
        3 | 4 => {
            p.format = "Windows small crash";
        } // Metadata only; never pretend sparse pages are present.
        _ => bail!("尚未验证的 crash dump 类型 {kind}"),
    }
    finish(p)
}
fn minidump(r: &Reader<'_>, job: &Job) -> Result<Parsed> {
    ensure!(r.uint(4, 4)? & 0xffff == 0xa793, "minidump 版本无效");
    let count = r.uint(8, 4)?;
    let directory = r.uint(12, 4)?;
    ensure!(count <= 4096, "minidump stream 超限");
    r.bytes(directory, count as usize * 12)?;
    let mut p = Parsed {
        format: "Windows minidump",
        segments: vec![],
        metadata: Metadata {
            virtual_memory: true,
            ..Default::default()
        },
    };
    let mut streams = BTreeMap::new();
    for index in 0..count {
        job.check()?;
        let pos = directory + index * 12;
        let kind = r.uint(pos, 4)?;
        let size = r.uint(pos + 4, 4)?;
        let offset = r.uint(pos + 8, 4)?;
        ensure!(
            offset.checked_add(size).is_some_and(|end| end <= r.len),
            "minidump stream 截断"
        );
        ensure!(
            streams.insert(kind, (offset, size)).is_none(),
            "minidump stream 重复"
        );
    }
    if let Some(&(off, size)) = streams.get(&7) {
        ensure!(size >= 32, "minidump SystemInfo 截断");
        p.metadata.architecture = match r.uint(off, 2)? {
            0 => Architecture::X86,
            9 => Architecture::X64,
            12 => Architecture::Arm64,
            _ => bail!("未知 minidump CPU"),
        };
        p.metadata.build = Some(r.uint(off + 16, 4)? as u32);
    }
    if let Some(&(off, size)) = streams.get(&15) {
        ensure!(
            size >= 12 && r.uint(off, 4)? <= size,
            "minidump MiscInfo 截断"
        );
        if r.uint(off + 4, 4)? & 1 != 0 {
            p.metadata.pid = Some(r.uint(off + 8, 4)? as u32);
        }
    }
    if let Some(&(off, size)) = streams.get(&4) {
        ensure!(size >= 4, "minidump 模块表头截断");
        let modules = r.uint(off, 4)?;
        ensure!(
            modules <= MAX_OBJECTS as u64 && 4 + modules * 108 <= size,
            "minidump 模块表越界"
        );
        for i in 0..modules {
            job.check()?;
            let pos = off + 4 + i * 108;
            let base = r.uint(pos, 8)?;
            let size = r.uint(pos + 8, 4)? as u32;
            ensure!(
                base.checked_add(size as u64).is_some(),
                "minidump 模块范围溢出"
            );
            p.metadata.modules.push(Module {
                base,
                size,
                name: r.string(r.uint(pos + 20, 4)?)?,
            });
        }
    }
    for (&kind, &(off, size)) in &streams {
        if !matches!(kind, 5 | 9) || (kind == 5 && streams.contains_key(&9)) {
            continue;
        }
        let wide = kind == 9;
        ensure!(size >= if wide { 16 } else { 4 }, "minidump 内存表头截断");
        let count = r.uint(off, if wide { 8 } else { 4 })?;
        let header = if wide { 16 } else { 4 };
        ensure!(
            count <= MAX_OBJECTS as u64 && header + count * 16 <= size,
            "minidump 内存表越界"
        );
        let mut data = if wide { r.uint(off + 8, 8)? } else { 0 };
        for i in 0..count {
            job.check()?;
            let pos = off + header + i * 16;
            let base = r.uint(pos, 8)?;
            let length = r.uint(pos + 8, if wide { 8 } else { 4 })?;
            let file_offset = if wide { data } else { r.uint(pos + 12, 4)? };
            if length > 0 {
                r.segment(&mut p.segments, base, length, file_offset)?;
            }
            if wide {
                data = add(data, length)?;
            }
        }
    }
    if let Some(&(off, size)) = streams.get(&3) {
        ensure!(size >= 4, "minidump 线程表头截断");
        let threads = r.uint(off, 4)?;
        ensure!(
            threads <= MAX_OBJECTS as u64 && 4 + threads * 48 <= size,
            "minidump 线程表越界"
        );
        for i in 0..threads {
            job.check()?;
            let pos = off + 4 + i * 48;
            p.metadata.threads.push(r.uint(pos, 4)? as u32);
            let mut start = r.uint(pos + 24, 8)?;
            let length = r.uint(pos + 32, 4)?;
            let source = r.uint(pos + 36, 4)?;
            let original = start;
            let end = add(start, length)?;
            ensure!(
                source.checked_add(length).is_some_and(|end| end <= r.len),
                "minidump stack 截断"
            );
            p.segments.sort_by_key(|s| s.start);
            let mut gaps = Vec::new();
            for segment in &p.segments {
                if segment.end <= start || segment.start >= end {
                    continue;
                }
                if start < segment.start {
                    gaps.push((start, segment.start - start));
                }
                start = start.max(segment.end).min(end);
            }
            if start < end {
                gaps.push((start, end - start));
            }
            for (base, length) in gaps {
                r.segment(&mut p.segments, base, length, source + base - original)?;
            }
        }
    }
    finish(p)
}

pub(super) fn analyze(
    image: &Image,
    request: &Request<'_>,
    dump_options: Option<&DumpOptions>,
    options: &Options,
    job: &Job,
) -> Result<Results> {
    let meta = image.windows_container.as_ref().context("缺少容器元数据")?;
    ensure!(
        options.arch == Architecture::Auto
            || meta.architecture == Architecture::Auto
            || options.arch == meta.architecture,
        "显式架构与容器不一致"
    );
    ensure!(
        options.hive.is_none() && options.key.is_empty(),
        "此转储不包含注册表 hive"
    );
    let plugin = request.plugin;
    let mut result = Results {
        plugin: plugin.name().into(),
        columns: plugin
            .descriptor()
            .columns
            .iter()
            .map(|c| (*c).into())
            .collect(),
        rows: vec![],
        complete: true,
        diagnostics: vec![],
        banner: format!("Windows {}", image.format),
        symbol: String::new(),
        page_table: meta.dtb.unwrap_or(0),
        historical: false,
        system: "windows".into(),
        kernel_identity: serde_json::json!({"architecture":meta.architecture,"container":image.format,"scope":if meta.virtual_memory {"process"} else {"kernel metadata"},"metadata":meta,"capabilities":if meta.virtual_memory { vec!["windows.systeminfo","windows.dlllist","windows.pslist","windows.memdump","windows.procdump","windows.pedump"] } else { vec!["windows.systeminfo"] }}),
    };
    if let Some(hiber) = &meta.hibernation {
        result.complete = false;
        result
            .diagnostics
            .push("休眠文件仅包含保存页；容器目前仅有合成验证".into());
        result.diagnostics.extend(hiber.diagnostics.clone());
    }
    if plugin == Plugin::WinSysteminfo {
        for (key, value) in [
            ("Container", image.format.into()),
            ("Architecture", format!("{:?}", meta.architecture)),
            (
                "Build",
                meta.build.map(|n| n.to_string()).unwrap_or_default(),
            ),
            ("PID", meta.pid.map(|n| n.to_string()).unwrap_or_default()),
            ("CapturedThreads", meta.threads.len().to_string()),
            ("CapturedRanges", image.segments.len().to_string()),
            (
                "Scope",
                if meta.virtual_memory {
                    "process"
                } else {
                    "kernel metadata"
                }
                .into(),
            ),
        ] {
            result.rows.push(vec![key.into(), value]);
        }
        return Ok(result);
    }
    ensure!(
        meta.virtual_memory,
        "小型内核转储仅提供头部元数据；缺少插件所需内存"
    );
    let pid = meta.pid.context("minidump 未记录 PID，无法建立进程归属")?;
    ensure!(
        options.pid.is_none_or(|filter| filter == pid),
        "PID 与 minidump 不一致"
    );
    let name = meta
        .modules
        .first()
        .map(|m| m.name.rsplit(['\\', '/']).next().unwrap_or(&m.name))
        .unwrap_or("[unknown]");
    match plugin {
        Plugin::WinPslist => {
            result.rows.push(vec![
                pid.to_string(),
                String::new(),
                name.into(),
                String::new(),
                meta.threads.len().to_string(),
                String::new(),
                String::new(),
                String::new(),
            ]);
            Windows::issue(
                &mut result,
                "minidump",
                "进程范围，不含系统进程列表及 EPROCESS 字段",
            );
        }
        Plugin::WinDlllist => {
            ensure!(!meta.modules.is_empty(), "minidump 未提供模块列表");
            for module in &meta.modules {
                result.rows.push(vec![
                    pid.to_string(),
                    name.into(),
                    hex(module.base),
                    module.size.to_string(),
                    module.name.clone(),
                    "minidump".into(),
                ]);
            }
        }
        plugin if plugin.is_dump() => {
            let opts = dump_options.context("转储需要参数")?;
            opts.validate(plugin)?;
            ensure!(opts.pid == pid, "PID 与 minidump 不一致");
            crate::dump::directory(&opts.directory)?;
            let regions: Vec<_> = match plugin {
                Plugin::WinMemdump => vec![(
                    opts.start.context("缺少 start")?,
                    opts.end.context("缺少 end")?,
                )],
                Plugin::WinPedump => meta
                    .modules
                    .iter()
                    .map(|m| (m.base, m.base + m.size as u64))
                    .collect(),
                _ => image
                    .segments
                    .iter()
                    .filter_map(|s| {
                        let start = s.start.max(opts.start.unwrap_or(s.start));
                        let end = s.end.min(opts.end.unwrap_or(s.end));
                        (start < end).then_some((start, end))
                    })
                    .collect(),
            };
            let mut total = 0;
            for (start, end) in regions {
                job.check()?;
                let written = (|| -> Result<Vec<String>> {
                    let mut file = tempfile::NamedTempFile::new_in(&opts.directory)?;
                    let mut hash = sha2::Sha256::new();
                    let size = if plugin == Plugin::WinPedump {
                        super::dump::reconstruct_pe(
                            &mut |address, bytes| image.read(address, bytes),
                            start,
                            &mut file,
                            &mut hash,
                            job,
                        )?
                    } else {
                        ensure!(
                            end - start <= crate::dump::MAX_DUMP_BYTES,
                            "转储范围超过限制"
                        );
                        super::dump::write_reader(
                            &mut |address, bytes| image.read(address, bytes),
                            start,
                            end - start,
                            &mut file,
                            &mut hash,
                            job,
                        )?;
                        end - start
                    };
                    ensure!(
                        total + size <= crate::dump::MAX_DUMP_BYTES,
                        "转储累计超过限制"
                    );
                    job.check()?;
                    file.as_file().sync_all()?;
                    let digest = format!("{:x}", hash.finalize());
                    let target = opts.directory.join(format!(
                        "minidump-pid{pid}-{start:016x}-{}.{}",
                        &digest[..16],
                        if plugin == Plugin::WinPedump {
                            "exe"
                        } else {
                            "bin"
                        }
                    ));
                    file.persist(&target)?;
                    total += size;
                    Ok(vec![
                        pid.to_string(),
                        name.into(),
                        hex(start),
                        hex(end),
                        size.to_string(),
                        digest,
                        target.display().to_string(),
                    ])
                })();
                match written {
                    Ok(row) => result.rows.push(row),
                    Err(e) => Windows::issue(
                        &mut result,
                        format!("minidump range {start:#x}..{end:#x}"),
                        e,
                    ),
                }
            }
        }
        _ => bail!("此 minidump 未提供 {} 所需的内核/PEB 数据", plugin.name()),
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    fn full(raw: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 8192];
        b[..8].copy_from_slice(b"PAGEDU64");
        put(&mut b, 16, 0x1000);
        put(&mut b, 32, K + 0x700);
        put(&mut b, 40, K + 0x400);
        b[48..52].copy_from_slice(&0x8664u32.to_le_bytes());
        b[136..140].copy_from_slice(&1u32.to_le_bytes());
        put(&mut b, 152, 0);
        put(&mut b, 160, (raw.len() / 4096) as u64);
        b[3992..3996].copy_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(raw);
        b
    }
    #[test]
    fn full_crash_maps_physical_runs_and_bootstraps() {
        let (raw, isf) = fixture();
        let b = full(&raw);
        let img = image(&b);
        assert_eq!(img.format, "Windows crash");
        assert_eq!(
            img.windows_container.as_ref().unwrap().architecture,
            Architecture::X64
        );
        assert_eq!(img.u64(0x8380).unwrap(), K + 0x1000);
        assert_eq!(discover(&img, &isf, &Job::default()).unwrap(), (0x1000, K));
        let mut f = tempfile::tempfile().unwrap();
        use std::io::Write;
        f.write_all(&b[..b.len() - 1]).unwrap();
        assert!(Image::from_file(f, "short".into()).is_err());
    }
    #[test]
    fn bitmap_gaps_are_not_zero_filled() {
        let (raw, _) = fixture();
        let mut b = full(&[]);
        b[3992..3996].copy_from_slice(&5u32.to_le_bytes());
        b.resize(12288, 0);
        b[8192..8200].copy_from_slice(b"SDMPDUMP");
        put(&mut b, 8192 + 32, 12288);
        put(&mut b, 8192 + 40, 2);
        put(&mut b, 8192 + 48, 3);
        b[8192 + 56] = 5;
        b.extend_from_slice(&raw[..4096]);
        b.extend_from_slice(&raw[8192..12288]);
        let img = image(&b);
        assert_eq!(img.segments.len(), 2);
        assert!(img.u64(4096).is_err());
        assert_eq!(
            img.u64(8192).unwrap(),
            u64::from_le_bytes(raw[8192..8200].try_into().unwrap())
        );
        b[8192 + 40] = 3;
        let mut f = tempfile::tempfile().unwrap();
        use std::io::Write;
        f.write_all(&b).unwrap();
        assert!(Image::from_file(f, "bad count".into()).is_err());
    }
    fn mini() -> Vec<u8> {
        let mut b = vec![0; 8192];
        b[..4].copy_from_slice(b"MDMP");
        b[4..8].copy_from_slice(&0xa793u32.to_le_bytes());
        b[8..12].copy_from_slice(&3u32.to_le_bytes());
        b[12..16].copy_from_slice(&32u32.to_le_bytes());
        for (i, kind, size, off) in [(0, 7u32, 56u32, 128u32), (1, 15, 24, 192), (2, 9, 32, 224)] {
            let p = 32 + i * 12;
            b[p..p + 4].copy_from_slice(&kind.to_le_bytes());
            b[p + 4..p + 8].copy_from_slice(&size.to_le_bytes());
            b[p + 8..p + 12].copy_from_slice(&off.to_le_bytes());
        }
        b[128..130].copy_from_slice(&9u16.to_le_bytes());
        b[144..148].copy_from_slice(&19041u32.to_le_bytes());
        b[192..196].copy_from_slice(&24u32.to_le_bytes());
        b[196..200].copy_from_slice(&1u32.to_le_bytes());
        b[200..204].copy_from_slice(&42u32.to_le_bytes());
        put(&mut b, 224, 1);
        put(&mut b, 232, 4096);
        put(&mut b, 240, 0x123000);
        put(&mut b, 248, 4096);
        b[4096..].fill(0x5a);
        b
    }
    #[test]
    fn minidump_virtual_mapping_capabilities_and_atomic_range() {
        let b = mini();
        let img = image(&b);
        assert!(img.windows_container.as_ref().unwrap().virtual_memory);
        assert_eq!(img.u64(0x123000).unwrap(), 0x5a5a5a5a5a5a5a5a);
        assert!(img.u64(0).is_err());
        let out = tempfile::tempdir().unwrap();
        let req = Request {
            image: std::path::Path::new("fixture"),
            symbols: std::path::Path::new("missing"),
            choice: None,
            plugin: Plugin::WinMemdump,
            cache: out.path(),
            use_cache: false,
            network: false,
        };
        let opts = DumpOptions {
            pid: 42,
            directory: out.path().join("dump"),
            start: Some(0x123000),
            end: Some(0x124000),
        };
        let r = analyze(
            &img,
            &req,
            Some(&opts),
            &Options::default(),
            &Job::default(),
        )
        .unwrap();
        assert!(r.complete);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(std::fs::read(&r.rows[0][6]).unwrap(), vec![0x5a; 4096]);
        let wrong = DumpOptions { pid: 43, ..opts };
        assert!(
            analyze(
                &img,
                &req,
                Some(&wrong),
                &Options::default(),
                &Job::default()
            )
            .is_err()
        );
        let req = Request {
            plugin: Plugin::WinModules,
            ..req
        };
        assert!(analyze(&img, &req, None, &Options::default(), &Job::default()).is_err());
        let mut bad = b;
        put(&mut bad, 240, u64::MAX);
        let mut f = tempfile::tempfile().unwrap();
        use std::io::Write;
        f.write_all(&bad).unwrap();
        assert!(Image::from_file(f, "overflow".into()).is_err());
    }
}
