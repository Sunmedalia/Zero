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
        crate::bytes::le_uint(&self.bytes(offset, width)?).context("容器字段宽度无效")
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
        let length = usize::try_from(self.uint(rva, 4)?)?;
        ensure!(
            length <= 65536 && length.is_multiple_of(2),
            "minidump 字符串长度无效"
        );
        let b = self.bytes(add(rva, 4)?, length)?;
        Ok(crate::bytes::utf16_lossy(&b))
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
        p.segments.array_windows().all(|[a, b]| a.end <= b.start),
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
    let kind = u32::try_from(r.uint(type_offset, 4)?)?;
    let metadata = Metadata {
        architecture: arch,
        dtb: Some(r.uint(16, width)?),
        module_list: Some(r.uint(if wide { 32 } else { 24 }, width)?),
        process_list: Some(r.uint(if wide { 40 } else { 28 }, width)?),
        dump_type: Some(kind),
        build: Some(u32::try_from(r.uint(12, 4)?)?),
        crash: Some(Crash {
            code: u32::try_from(r.uint(if wide { 56 } else { 40 }, 4)?)?,
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
                matches!(signature.as_slice(), b"SDMPDUMP" | b"FDMPDUMP"),
                "bitmap dump 标记无效"
            );
            let mut offset = r.uint(header + 32, 8)?;
            let pages = r.uint(header + 40, 8)?;
            let bits = r.uint(header + 48, 8)?;
            ensure!(
                bits > 0 && bits <= 128 * 1024 * 1024,
                "bitmap dump 页位图超限"
            );
            let bitmap_size = usize::try_from(bits.div_ceil(8))?;
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
                if bitmap
                    .get(usize::try_from(bit)? / 8)
                    .is_none_or(|byte| byte & (1 << (bit % 8)) == 0)
                {
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
    r.bytes(table, usize::try_from(count)? * usize::try_from(stride)?)?;
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
            crash.exception_code = Some(u32::try_from(r.uint(exception, 4)?)?);
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
    r.bytes(drivers, usize::try_from(driver_count)? * entry_size)?;
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
        let bytes = r.bytes(name_offset + 4, usize::try_from(chars)? * 2)?;
        ensure!(
            r.uint(name_offset + 4 + chars * 2, 2)? == 0,
            "triage driver 名称未终止"
        );
        let name = String::from_utf16(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes(*b))
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
            size: u32::try_from(size)?,
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
    r.bytes(directory, usize::try_from(count)? * 12)?;
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
        p.metadata.build = Some(u32::try_from(r.uint(off + 16, 4)?)?);
        ensure!(r.uint(off + 20, 4)? <= 2, "此 minidump 的平台不是 Windows");
    }
    if let Some(&(off, size)) = streams.get(&15) {
        ensure!(
            size >= 12 && r.uint(off, 4)? <= size,
            "minidump MiscInfo 截断"
        );
        if r.uint(off + 4, 4)? & 1 != 0 {
            p.metadata.pid = Some(u32::try_from(r.uint(off + 8, 4)?)?);
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
            let size = u32::try_from(r.uint(pos + 8, 4)?)?;
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
            let tid = u32::try_from(r.uint(pos, 4)?)?;
            p.metadata.threads.push(tid);
            let context_size = usize::try_from(r.uint(pos + 40, 4)?)?;
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
        let tid = u32::try_from(r.uint(off, 4)?)?;
        p.metadata.crash = Some(Crash {
            code: u32::try_from(r.uint(off + 8, 4)?)?,
            parameters: (0..count)
                .map(|i| r.uint(off + 40 + i * 8, 8))
                .collect::<Result<Vec<_>>>()?,
            exception_address: Some(r.uint(off + 24, 8)?),
            exception_code: Some(u32::try_from(r.uint(off + 8, 4)?)?),
            thread_id: Some(tid),
        });
        let length = usize::try_from(r.uint(off + 160, 4)?)?;
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
        super::dump::publish_noclobber(file, &target)?;
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
        Plugin::WinVaddump | Plugin::WinModdump | Plugin::WinDumpfiles | Plugin::WinThrdscan => {
            bail!("此 minidump 未提供 {} 所需的内核数据", plugin.name())
        }
        plugin if plugin.is_dump() => {
            let opts = dump_options.context("转储需要参数")?;
            opts.validate(plugin)?;
            ensure!(opts.pid == pid, "PID 与 minidump 不一致");
            crate::dump::directory(&opts.directory)?;
            let pe_dump = matches!(plugin, Plugin::WinPedump | Plugin::WinDlldump);
            let regions: Vec<_> = match plugin {
                Plugin::WinMemdump => vec![(
                    opts.start.context("缺少 start")?,
                    opts.end.context("缺少 end")?,
                )],
                Plugin::WinPedump | Plugin::WinDlldump => meta
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
                    let size = if pe_dump {
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
                        if pe_dump { "exe" } else { "bin" }
                    ));
                    super::dump::publish_noclobber(file, &target)?;
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
mod tests;
