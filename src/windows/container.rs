//! Bounded, read-only Windows dump containers. Offsets are file-format facts.
//! References: Microsoft MINIDUMP_* definitions and DUMP_HEADER32/64 layouts.
use super::*;
use crate::image::Segment;
use serde::{Deserialize, Serialize};
use std::{fs::File, os::unix::fs::FileExt};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub kernel_virtual: bool,
    #[serde(default)]
    pub crash: Option<Crash>,
    #[serde(default)]
    pub contexts: Vec<ThreadContext>,
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Crash {
    pub code: u32,
    pub parameters: Vec<u64>,
    pub exception_address: Option<u64>,
    #[serde(default)]
    pub exception_code: Option<u32>,
    pub thread_id: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadContext {
    pub thread_id: Option<u32>,
    pub file_offset: u64,
    pub registers: BTreeMap<String, u64>,
}
mod context;
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
        crash: Some(Crash {
            code: r.uint(if wide { 56 } else { 40 }, 4)? as u32,
            parameters: (0..4)
                .map(|i| r.uint(if wide { 64 + i * 8 } else { 44 + i * 4 }, width))
                .collect::<Result<Vec<_>>>()?,
            ..Default::default()
        }),
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
            if kind == 4 && r.len > header {
                triage(r, &mut p, header, width, job)?;
            }
        } // Metadata only; never pretend sparse pages are present.
        _ => bail!("尚未验证的 crash dump 类型 {kind}"),
    }
    finish(p)
}
/// TRIAGE_DUMP32/64: file offsets are absolute; saved data blocks use virtual addresses.
fn triage(r: &Reader<'_>, p: &mut Parsed, header: u64, width: usize, job: &Job) -> Result<()> {
    let size = r.uint(header + 4, 4)?;
    ensure!(
        size >= header + 104 && size <= r.len,
        "triage SizeOfDump 无效"
    );
    let bounded = Reader {
        file: r.file,
        len: size,
    };
    let r = &bounded;
    r.bytes(header, if width == 8 { 128 } else { 104 })?;
    p.metadata.kernel_virtual = true;
    let context = r.uint(header + 12, 4)?;
    if context != 0 {
        let minimum = match p.metadata.architecture {
            Architecture::X86 => 204,
            Architecture::X64 => 256,
            Architecture::Arm64 => 272,
            _ => bail!("triage CPU 未知"),
        };
        p.metadata.contexts.push(context::parse(
            &r.bytes(context, minimum)?,
            p.metadata.architecture,
            None,
            context,
        )?);
    }
    let stack = r.uint(header + 40, 4)?;
    let stack_size = r.uint(header + 44, 4)?;
    let top = r.uint(header + 72, width)?;
    if stack_size != 0 {
        ensure!(top != 0, "triage 栈地址为空");
        r.segment(&mut p.segments, top, stack_size, stack)?;
    }
    let mut tail = header + 72 + width as u64 + 8 + width as u64;
    if width == 8 {
        let address = r.uint(tail, 8)?;
        let offset = r.uint(tail + 8, 4)?;
        let size = r.uint(tail + 12, 4)?;
        if size != 0 {
            r.segment(&mut p.segments, address, size, offset)?;
        }
        tail += 16;
    }
    let table = r.uint(tail + 8, 4)?;
    let count = r.uint(tail + 12, 4)?;
    ensure!(count <= MAX_OBJECTS as u64, "triage 数据块超限");
    let stride = width as u64 + 8;
    r.bytes(table, count as usize * stride as usize)?;
    for i in 0..count {
        job.check()?;
        let pos = table + i * stride;
        let address = r.uint(pos, width)?;
        let offset = r.uint(pos + width as u64, 4)?;
        let size = r.uint(pos + width as u64 + 4, 4)?;
        if size != 0 {
            r.segment(&mut p.segments, address, size, offset)?;
        }
    }
    let exception = r.uint(header + 16, 4)?;
    if exception != 0 {
        let address_offset = if width == 8 { 16 } else { 12 };
        let record_size = if width == 8 { 152 } else { 80 };
        r.bytes(exception, record_size)?;
        if let Some(crash) = &mut p.metadata.crash {
            crash.exception_code = Some(r.uint(exception, 4)? as u32);
            crash.exception_address = Some(r.uint(exception + address_offset, width)?);
        }
    }
    let drivers = r.uint(header + 48, 4)?;
    let driver_count = r.uint(header + 52, 4)?;
    let string_pool = r.uint(header + 56, 4)?;
    let string_size = r.uint(header + 60, 4)?;
    let entry_size = if width == 8 { 144 } else { 84 };
    ensure!(
        driver_count <= MAX_OBJECTS as u64,
        "triage driver count 超限"
    );
    r.bytes(drivers, driver_count as usize * entry_size)?;
    let pool_end = add(string_pool, string_size)?;
    ensure!(pool_end <= r.len, "triage 字符串池越界");
    for i in 0..driver_count {
        job.check()?;
        let entry = drivers + i * entry_size as u64;
        let name_offset = r.uint(entry, 4)?;
        ensure!(
            name_offset >= string_pool && add(name_offset, 4)? <= pool_end,
            "triage driver 名称不在字符串池内"
        );
        let chars = r.uint(name_offset, 4)?;
        ensure!(
            chars <= 32767 && add(name_offset, 4 + chars * 2 + 2)? <= pool_end,
            "triage driver 名称长度越界"
        );
        let bytes = r.bytes(name_offset + 4, chars as usize * 2)?;
        ensure!(
            r.uint(name_offset + 4 + chars * 2, 2)? == 0,
            "triage driver 名称未终止"
        );
        let name = String::from_utf16(
            &bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .context("triage driver 名称 UTF-16 无效")?;
        let base_offset = if width == 8 { 56 } else { 28 };
        let base = r.uint(entry + base_offset, width)?;
        let size = r.uint(entry + base_offset + 2 * width as u64, width)?;
        ensure!(
            size > 0 && size <= u32::MAX as u64 && base.checked_add(size).is_some(),
            "triage driver 范围无效"
        );
        p.metadata.modules.push(Module {
            base,
            size: size as u32,
            name,
        });
    }
    // Captures may save identical stack bytes twice at different file offsets.
    // Accept verified identical overlaps; reject conflicting bytes.
    p.segments.sort_by_key(|s| (s.start, s.end));
    let mut merged: Vec<Segment> = Vec::new();
    for mut segment in p.segments.drain(..) {
        if let Some(last) = merged.last_mut()
            && segment.start < last.end
        {
            if add(last.file_offset, segment.start - last.start)? == segment.file_offset {
                last.end = last.end.max(segment.end);
                continue;
            }
            let overlap = last.end.min(segment.end) - segment.start;
            let previous = add(last.file_offset, segment.start - last.start)?;
            let mut checked = 0;
            while checked < overlap {
                job.check()?;
                let size = (overlap - checked).min(65536) as usize;
                ensure!(
                    r.bytes(add(previous, checked)?, size)?
                        == r.bytes(add(segment.file_offset, checked)?, size)?,
                    "triage 虚拟映射冲突"
                );
                checked += size as u64;
            }
            if segment.end > last.end {
                segment.file_offset = add(segment.file_offset, last.end - segment.start)?;
                segment.start = last.end;
                merged.push(segment);
            }
        } else {
            merged.push(segment);
        }
    }
    p.segments = merged;
    Ok(())
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
        if kind == 0 {
            ensure!(size == 0, "UnusedStream 携带非空数据");
            continue;
        }
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
        ensure!(r.uint(off + 20, 4)? <= 2, "此 minidump 的平台不是 Windows");
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
            let tid = r.uint(pos, 4)? as u32;
            p.metadata.threads.push(tid);
            let context_size = r.uint(pos + 40, 4)? as usize;
            let context_offset = r.uint(pos + 44, 4)?;
            if context_size != 0 {
                p.metadata.contexts.push(context::parse(
                    &r.bytes(context_offset, context_size)?,
                    p.metadata.architecture,
                    Some(tid),
                    context_offset,
                )?);
            }
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
    if let Some(&(off, size)) = streams.get(&6) {
        ensure!(size >= 168, "minidump ExceptionStream 截断");
        let count = r.uint(off + 32, 4)?;
        ensure!(count <= 15, "异常参数超限");
        let tid = r.uint(off, 4)? as u32;
        p.metadata.crash = Some(Crash {
            code: r.uint(off + 8, 4)? as u32,
            parameters: (0..count)
                .map(|i| r.uint(off + 40 + i * 8, 8))
                .collect::<Result<Vec<_>>>()?,
            exception_address: Some(r.uint(off + 24, 8)?),
            exception_code: Some(r.uint(off + 8, 4)? as u32),
            thread_id: Some(tid),
        });
        let length = r.uint(off + 160, 4)? as usize;
        let offset = r.uint(off + 164, 4)?;
        if length != 0 {
            p.metadata.contexts.push(context::parse(
                &r.bytes(offset, length)?,
                p.metadata.architecture,
                Some(tid),
                offset,
            )?);
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
        kernel_identity: serde_json::json!({"architecture":meta.architecture,"container":image.format,"scope":if meta.kernel_virtual {"kernel virtual"} else if meta.virtual_memory {"process"} else {"kernel metadata"},"metadata":meta,"address_space":if meta.kernel_virtual {"kernel_virtual"} else if meta.virtual_memory {"process_virtual"} else {"physical"},"capabilities":if meta.kernel_virtual {vec!["windows.systeminfo","windows.crashinfo","windows.modules","windows.memdump"]} else if meta.virtual_memory { vec!["windows.systeminfo","windows.crashinfo","windows.dlllist","windows.pslist","windows.memdump","windows.procdump","windows.pedump"] } else { vec!["windows.systeminfo","windows.crashinfo"] }}),
    };
    if let Some(hiber) = &meta.hibernation {
        result.complete = false;
        result
            .diagnostics
            .push("休眠文件仅包含保存页；容器目前仅有合成验证".into());
        result.diagnostics.extend(hiber.diagnostics.clone());
    }
    if plugin == Plugin::WinCrashinfo {
        if let Some(crash) = &meta.crash {
            result
                .rows
                .push(vec!["Code".into(), format!("{:#x}", crash.code)]);
            for (i, value) in crash.parameters.iter().enumerate() {
                result
                    .rows
                    .push(vec![format!("Parameter{}", i + 1), hex(*value)]);
            }
            if let Some(code) = crash.exception_code {
                result
                    .rows
                    .push(vec!["ExceptionCode".into(), format!("{code:#x}")]);
            }
            if let Some(address) = crash.exception_address {
                result
                    .rows
                    .push(vec!["ExceptionAddress".into(), hex(address)]);
            }
        }
        for (i, context) in meta.contexts.iter().enumerate() {
            for (register, value) in &context.registers {
                result.rows.push(vec![
                    format!(
                        "Context{i}.Thread{}.{}",
                        context.thread_id.map(|n| n.to_string()).unwrap_or_default(),
                        register
                    ),
                    hex(*value),
                ]);
            }
        }
        result
            .rows
            .push(vec!["SavedRanges".into(), image.segments.len().to_string()]);
        Windows::issue(
            &mut result,
            "dump",
            "仅解析保存的控制/整数寄存器与内存范围；未解析 FP/SIMD/debug 寄存器或展开调用栈",
        );
        return Ok(result);
    }
    if meta.kernel_virtual && plugin == Plugin::WinModules {
        for module in &meta.modules {
            result.rows.push(vec![
                module
                    .name
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(&module.name)
                    .into(),
                hex(module.base),
                module.size.to_string(),
                module.name.clone(),
            ]);
        }
        Windows::issue(
            &mut result,
            "triage modules",
            "仅列出转储保存的驱动记录，非完整内核模块清单",
        );
        return Ok(result);
    }
    if meta.kernel_virtual && plugin == Plugin::WinMemdump {
        let opts = dump_options.context("范围转储需要参数")?;
        opts.validate(plugin)?;
        crate::dump::directory(&opts.directory)?;
        let start = opts.start.context("缺少 start")?;
        let end = opts.end.context("缺少 end")?;
        ensure!(
            end > start && end - start <= crate::dump::MAX_DUMP_BYTES,
            "范围超限"
        );
        let mut file = tempfile::NamedTempFile::new_in(&opts.directory)?;
        let mut hash = sha2::Sha256::new();
        super::dump::write_reader(
            &mut |address, bytes| image.read(address, bytes),
            start,
            end - start,
            &mut file,
            &mut hash,
            job,
        )?;
        job.check()?;
        file.as_file().sync_all()?;
        let digest = format!("{:x}", hash.finalize());
        let target = opts
            .directory
            .join(format!("kernel-range-{start:016x}-{}.bin", &digest[..16]));
        file.persist(&target)?;
        result.rows.push(vec![
            opts.pid.to_string(),
            "kernel".into(),
            hex(start),
            hex(end),
            (end - start).to_string(),
            digest,
            target.display().to_string(),
        ]);
        Windows::issue(&mut result, "small crash", "仅导出保存的内核虚拟内存");
        return Ok(result);
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
                if meta.kernel_virtual {
                    "kernel virtual"
                } else if meta.virtual_memory {
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
        "小型内核转储仅包含已保存内存与上下文；缺少此插件所需的完整内核"
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
    fn triage_virtual_blocks_and_contexts_preserve_holes_across_architectures() {
        for (arch, width, header, kind_offset) in [
            (Architecture::X86, 4usize, 4096usize, 3976usize),
            (Architecture::X64, 8, 8192, 3992),
            (Architecture::Arm64, 8, 8192, 3992),
        ] {
            let mut b = vec![0; header + 1024];
            b[..8].copy_from_slice(if width == 4 { b"PAGEDUMP" } else { b"PAGEDU64" });
            let machine_at = if width == 4 { 32 } else { 48 };
            b[machine_at..machine_at + 4].copy_from_slice(&(arch.machine() as u32).to_le_bytes());
            b[kind_offset..kind_offset + 4].copy_from_slice(&4u32.to_le_bytes());
            let size = b.len() as u32;
            b[header + 4..header + 8].copy_from_slice(&size.to_le_bytes());
            let tail = 72 + width + 8 + width + if width == 8 { 16 } else { 0 };
            b[header + tail + 8..header + tail + 12]
                .copy_from_slice(&((header + 160) as u32).to_le_bytes());
            b[header + tail + 12..header + tail + 16].copy_from_slice(&1u32.to_le_bytes());
            let address = if width == 4 {
                0x81234000u64
            } else {
                K + 0x1234000
            };
            b[header + 160..header + 160 + width].copy_from_slice(&address.to_le_bytes()[..width]);
            b[header + 160 + width..header + 164 + width]
                .copy_from_slice(&((header + 512) as u32).to_le_bytes());
            b[header + 164 + width..header + 168 + width].copy_from_slice(&16u32.to_le_bytes());
            b[header + 512..header + 528].fill(0x5a);
            b[header + 12..header + 16].copy_from_slice(&((header + 192) as u32).to_le_bytes());
            let (flags_at, flags, pc_at) = match arch {
                Architecture::X86 => (0, 0x10001u32, 184),
                Architecture::X64 => (48, 0x100001, 248),
                _ => (0, 0x400001, 264),
            };
            b[header + 192 + flags_at..header + 196 + flags_at]
                .copy_from_slice(&flags.to_le_bytes());
            b[header + 192 + pc_at..header + 192 + pc_at + width]
                .copy_from_slice(&address.to_le_bytes()[..width]);
            b[header + 48..header + 52].copy_from_slice(&((header + 560) as u32).to_le_bytes());
            b[header + 52..header + 56].copy_from_slice(&1u32.to_le_bytes());
            b[header + 56..header + 60].copy_from_slice(&((header + 900) as u32).to_le_bytes());
            b[header + 60..header + 64].copy_from_slice(&100u32.to_le_bytes());
            b[header + 560..header + 564].copy_from_slice(&((header + 900) as u32).to_le_bytes());
            let base_at = header + 560 + if width == 8 { 56 } else { 28 };
            b[base_at..base_at + width].copy_from_slice(&address.to_le_bytes()[..width]);
            b[base_at + 2 * width..base_at + 3 * width]
                .copy_from_slice(&4096u64.to_le_bytes()[..width]);
            b[header + 900..header + 904].copy_from_slice(&6u32.to_le_bytes());
            let name: Vec<u8> = "driver".encode_utf16().flat_map(u16::to_le_bytes).collect();
            b[header + 904..header + 904 + name.len()].copy_from_slice(&name);
            b[header + 16..header + 20].copy_from_slice(&((header + 720) as u32).to_le_bytes());
            b[header + 720..header + 724].copy_from_slice(&0xc0000005u32.to_le_bytes());
            let exception_at = header + 720 + if width == 8 { 16 } else { 12 };
            b[exception_at..exception_at + width].copy_from_slice(&address.to_le_bytes()[..width]);
            let img = image(&b);
            let meta = img.windows_container.as_ref().unwrap();
            assert!(meta.kernel_virtual);
            assert!(!meta.virtual_memory);
            assert_eq!(meta.contexts.len(), 1);
            assert_eq!(meta.modules[0].name, "driver");
            assert_eq!(
                meta.crash.as_ref().unwrap().exception_address,
                Some(address)
            );
            let mut saved = [0; 16];
            img.read(address, &mut saved).unwrap();
            assert_eq!(saved, [0x5a; 16]);
            assert!(img.read(address + 16, &mut [0]).is_err());
            assert!(img.read(0, &mut [0]).is_err());
            // Identical virtual mappings merge; separately stored copies require equal bytes.
            let stride = width + 8;
            b[header + tail + 12..header + tail + 16].copy_from_slice(&2u32.to_le_bytes());
            let second = header + 160 + stride;
            b[second..second + width].copy_from_slice(&(address + 8).to_le_bytes()[..width]);
            b[second + width..second + width + 4]
                .copy_from_slice(&((header + 520) as u32).to_le_bytes());
            b[second + width + 4..second + width + 8].copy_from_slice(&8u32.to_le_bytes());
            assert_eq!(image(&b).segments.len(), 1);
            // A separate copy of the same overlap is legitimate (real Server 2016 triage).
            b[header + 920..header + 928].fill(0x5a);
            b[second + width..second + width + 4]
                .copy_from_slice(&((header + 920) as u32).to_le_bytes());
            assert_eq!(image(&b).segments.len(), 1);
            // A new tail keeps its own file offset, while matching overlapping bytes.
            b[header + 928..header + 932].fill(0x6b);
            b[second + width + 4..second + width + 8].copy_from_slice(&12u32.to_le_bytes());
            let copies = image(&b);
            let mut tail_bytes = [0; 4];
            copies.read(address + 16, &mut tail_bytes).unwrap();
            assert_eq!(tail_bytes, [0x6b; 4]);
            b[second + width + 4..second + width + 8].copy_from_slice(&8u32.to_le_bytes());
            b[second + width..second + width + 4]
                .copy_from_slice(&((header + 521) as u32).to_le_bytes());
            let mut conflict = tempfile::tempfile().unwrap();
            use std::io::Write;
            conflict.write_all(&b).unwrap();
            assert!(Image::from_file(conflict, "conflict-triage".into()).is_err());
            b[second + width..second + width + 4]
                .copy_from_slice(&((header + 520) as u32).to_le_bytes());
            b[header + 164 + width..header + 168 + width].copy_from_slice(&0xffffu32.to_le_bytes());
            let mut f = tempfile::tempfile().unwrap();
            f.write_all(&b).unwrap();
            assert!(Image::from_file(f, "bad-triage".into()).is_err());
        }
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
