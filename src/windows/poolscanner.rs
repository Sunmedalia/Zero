//! Canonical pool scanner: every built-in kernel tag, scanned in the version's layer.
use super::*;
use memchr::memmem;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

const OPTIONAL_HEADERS: [&str; 9] = [
    "CREATOR_INFO",
    "NAME_INFO",
    "HANDLE_INFO",
    "QUOTA_INFO",
    "PROCESS_INFO",
    "AUDIT_INFO",
    "EXTENDED_INFO",
    "HANDLE_REVOCATION_INFO",
    "PADDING_INFO",
];

struct Constraint {
    tag: &'static [u8],
    type_name: &'static str,
    object_type: Option<&'static str>,
    minimum: u64,
    page: u8,
    skip_type: bool,
    extra: &'static [&'static str],
}

impl Constraint {
    const fn new(
        tag: &'static [u8],
        type_name: &'static str,
        object_type: Option<&'static str>,
        minimum: u64,
        page: u8,
        skip_type: bool,
        extra: &'static [&'static str],
    ) -> Self {
        Self {
            tag,
            type_name,
            object_type,
            minimum,
            page,
            skip_type,
            extra,
        }
    }
}

const CONSTRAINTS: &[Constraint] = &[
    Constraint::new(b"AtmT", "_RTL_ATOM_TABLE", None, 200, 7, false, &[]),
    Constraint::new(
        &[b'P', b'r', b'o', 0xe3],
        "_EPROCESS",
        Some("Process"),
        600,
        6,
        true,
        &[],
    ),
    Constraint::new(b"Proc", "_EPROCESS", Some("Process"), 600, 6, true, &[]),
    Constraint::new(
        &[b'T', b'h', b'r', 0xe5],
        "_ETHREAD",
        Some("Thread"),
        600,
        6,
        true,
        &[],
    ),
    Constraint::new(b"Thre", "_ETHREAD", Some("Thread"), 600, 6, false, &[]),
    Constraint::new(
        &[b'F', b'i', b'l', 0xe5],
        "_FILE_OBJECT",
        Some("File"),
        150,
        6,
        false,
        &[],
    ),
    Constraint::new(b"File", "_FILE_OBJECT", Some("File"), 150, 6, false, &[]),
    Constraint::new(
        &[b'M', b'u', b't', 0xe1],
        "_KMUTANT",
        Some("Mutant"),
        64,
        6,
        false,
        &[],
    ),
    Constraint::new(b"Muta", "_KMUTANT", Some("Mutant"), 64, 6, false, &[]),
    Constraint::new(
        &[b'D', b'r', b'i', 0xf6],
        "_DRIVER_OBJECT",
        Some("Driver"),
        248,
        6,
        false,
        &["_DRIVER_EXTENSION"],
    ),
    Constraint::new(
        b"Driv",
        "_DRIVER_OBJECT",
        Some("Driver"),
        248,
        6,
        false,
        &[],
    ),
    Constraint::new(b"MmLd", "_LDR_DATA_TABLE_ENTRY", None, 76, 6, false, &[]),
    Constraint::new(
        &[b'S', b'y', b'm', 0xe2],
        "_OBJECT_SYMBOLIC_LINK",
        Some("SymbolicLink"),
        72,
        5,
        false,
        &[],
    ),
    Constraint::new(
        b"Symb",
        "_OBJECT_SYMBOLIC_LINK",
        Some("SymbolicLink"),
        72,
        5,
        false,
        &[],
    ),
    Constraint::new(b"CM10", "_CMHIVE", None, 800, 5, true, &[]),
];

/// Merge the four-byte pool patterns in address order, consuming each match as
/// Python MultiStringScanner's regex does. Only one pending hit per pattern is
/// retained; a buffer with many tags cannot allocate a hit-sized side table.
struct PoolTagMatches<'data, 'tag> {
    data: &'data [u8],
    finders: Vec<memmem::Finder<'tag>>,
    pending: BinaryHeap<Reverse<(usize, usize)>>,
    consumed: usize,
}

impl<'data, 'tag> PoolTagMatches<'data, 'tag> {
    fn new(data: &'data [u8], tags: impl IntoIterator<Item = &'tag [u8]>) -> Result<Self> {
        let mut finders = Vec::new();
        let mut pending = BinaryHeap::new();
        let mut unique = HashSet::new();
        for (index, tag) in tags.into_iter().enumerate() {
            ensure!(tag.len() == 4, "pool 标签必须是四字节");
            ensure!(unique.insert(tag), "pool 标签约束重复");
            let finder = memmem::Finder::new(tag);
            if let Some(at) = finder.find(data) {
                pending.push(Reverse((at, index)));
            }
            finders.push(finder);
        }
        ensure!(!finders.is_empty(), "pool 标签约束为空");
        Ok(Self {
            data,
            finders,
            pending,
            consumed: 0,
        })
    }

    fn advance(&mut self, index: usize, from: usize) {
        if let Some(at) = self.finders[index].find(&self.data[from..]) {
            self.pending.push(Reverse((from + at, index)));
        }
    }
}

impl Iterator for PoolTagMatches<'_, '_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(Reverse((at, index))) = self.pending.pop() {
            if at < self.consumed {
                self.advance(index, self.consumed);
                continue;
            }
            self.consumed = at + 4;
            self.advance(index, self.consumed);
            return Some((index, at));
        }
        None
    }
}

const POOL_SCAN_CHUNK: u64 = 0x1000000;
const POOL_SCAN_OVERLAP: u64 = 0x1000;

/// Fixed DataLayer and TranslationLayer iterators use different final steps.
/// Preserve their exact overlap behavior instead of treating every large
/// mapping as one unbounded read or deduplicating repeated tail observations.
struct PoolScanChunks {
    ranges: std::vec::IntoIter<(u64, u64)>,
    current: Option<(u64, u64)>,
    translated: bool,
}

impl PoolScanChunks {
    fn new(ranges: Vec<(u64, u64)>, translated: bool) -> Self {
        Self {
            ranges: ranges.into_iter(),
            current: None,
            translated,
        }
    }
}

impl Iterator for PoolScanChunks {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (start, remaining) = self.current.take().or_else(|| self.ranges.next())?;
            if remaining == 0 {
                continue;
            }
            let length = remaining.min(POOL_SCAN_CHUNK + POOL_SCAN_OVERLAP);
            let advance = if self.translated {
                remaining.min(POOL_SCAN_CHUNK)
            } else if length > POOL_SCAN_CHUNK {
                length - POOL_SCAN_OVERLAP
            } else {
                length
            };
            if advance < remaining {
                self.current = Some((start + advance, remaining - advance));
            }
            return Some((start, length));
        }
    }
}

struct PoolHeaderRead<'a> {
    start: u64,
    data: &'a [u8],
    virtual_scan: bool,
    alignment: u64,
    vista: bool,
}

struct PoolCarve<'a> {
    block: u64,
    alignment: u64,
    type_size: u64,
    top_down: bool,
    optional: &'a [(bool, u64)],
    virtual_scan: bool,
}

struct PoolValidation {
    types: BTreeMap<u64, String>,
}

fn current_local_year() -> Result<i64> {
    #[cfg(unix)]
    {
        let now: libc::time_t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .try_into()?;
        let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
        // localtime_r initializes the supplied tm on success and retains no
        // pointer to it; this matches Python datetime.now()'s local calendar.
        let value = unsafe { libc::localtime_r(&now, local.as_mut_ptr()) };
        ensure!(!value.is_null(), "无法读取本地年份");
        Ok(i64::from(unsafe { local.assume_init() }.tm_year) + 1900)
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct LocalTime {
            year: u16,
            month: u16,
            weekday: u16,
            day: u16,
            hour: u16,
            minute: u16,
            second: u16,
            milliseconds: u16,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetLocalTime(value: *mut LocalTime);
        }
        let mut value = std::mem::MaybeUninit::<LocalTime>::uninit();
        // GetLocalTime writes all fields of the caller-owned SYSTEMTIME value.
        unsafe {
            GetLocalTime(value.as_mut_ptr());
        }
        Ok(i64::from(unsafe { value.assume_init() }.year))
    }
    #[cfg(not(any(unix, windows)))]
    bail!("当前平台无法读取本地年份")
}

impl Windows<'_> {
    pub(super) fn pool_scanner(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "PoolScanner 仅支持 Intel32/Intel64"
        );
        let mut result = self.result(Plugin::WinPoolScanner);
        if let Err(error) = self.pool_scanner_rows(&mut result, job) {
            job.check()?;
            Self::issue(&mut result, "PoolScanner", format!("{error:#}"));
        }
        Ok(result)
    }

    fn pool_scanner_rows(&self, result: &mut Results, job: &Job) -> Result<()> {
        let build = self.build_number()?;
        let virtual_scan = build >= 10240;
        let top_down = build >= 9200;
        let vista = build >= 6000;
        let alignment = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let (tag_offset, _) = self.pool_header_layout()?;
        let sizes = self.pool_type_sizes()?;
        let validation = PoolValidation {
            types: self.pool_reference_type_map()?,
        };
        let optional = if top_down {
            self.pool_optional_headers()?
        } else {
            Vec::new()
        };
        let layer = if virtual_scan {
            "layer_name"
        } else {
            "memory_layer"
        };
        let mut rows = 0usize;
        let mut text = 0usize;
        let mut diagnostics = 0usize;
        let translated = virtual_scan || self.vm.image.format != "RAW";
        for (start, length) in
            PoolScanChunks::new(self.pool_scan_ranges(virtual_scan, job)?, translated)
        {
            job.check()?;
            let mut data =
                vec![0u8; usize::try_from(length).context("pool 扫描范围超出地址空间")?];
            if self.pool_read(start, &mut data, virtual_scan).is_err() {
                self.pool_note(
                    result,
                    &mut diagnostics,
                    "pool range",
                    format!("{layer} {start:#x}+{length:#x} 不可读"),
                );
                continue;
            }
            for (index, tag) in PoolTagMatches::new(&data, CONSTRAINTS.iter().map(|c| c.tag))? {
                job.check()?;
                if tag as u64 >= POOL_SCAN_CHUNK {
                    break;
                }
                let constraint = &CONSTRAINTS[index];
                let Some(&type_size) = sizes.get(constraint.type_name) else {
                    continue;
                };
                let Some(address) = add(start, tag as u64)?.checked_sub(tag_offset as u64) else {
                    continue;
                };
                let Some(size) = self.pool_header_block(
                    constraint,
                    address,
                    PoolHeaderRead {
                        start,
                        data: &data,
                        virtual_scan,
                        alignment,
                        vista,
                    },
                )?
                else {
                    continue;
                };
                let bodies = self.pool_bodies(
                    constraint,
                    address,
                    PoolCarve {
                        block: size,
                        alignment,
                        type_size,
                        top_down,
                        optional: &optional,
                        virtual_scan,
                    },
                    job,
                )?;
                for body in bodies {
                    if !self.pool_object_valid(
                        constraint,
                        body,
                        virtual_scan,
                        &validation,
                        result,
                        &mut diagnostics,
                    )? {
                        continue;
                    }
                    let Some(name) = self.pool_scanner_name(constraint, body, virtual_scan)? else {
                        continue;
                    };
                    ensure!(rows < MAX_OBJECTS, "pool 结果数量超限");
                    let row = vec![
                        format!("symbol_table_name1!{}", constraint.type_name),
                        hex(address),
                        layer.into(),
                        name,
                    ];
                    text = text
                        .checked_add(row.iter().map(String::len).sum())
                        .context("pool 文本大小溢出")?;
                    ensure!(text <= 128 * 1024 * 1024, "pool 文本大小超限");
                    result.rows.push(row);
                    rows += 1;
                }
            }
        }
        if diagnostics > result.diagnostics.len() {
            Self::issue(
                result,
                "PoolScanner",
                format!(
                    "另有 {} 条诊断因上限未逐条保留",
                    diagnostics - result.diagnostics.len()
                ),
            );
        }
        result.kernel_identity["poolscanner"] = serde_json::json!({"source":"versioned kernel pool tags","layer":layer,"constraints":CONSTRAINTS.len(),"rows":rows,"diagnostics":diagnostics});
        Ok(())
    }

    fn pool_note(
        &self,
        result: &mut Results,
        diagnostics: &mut usize,
        context: &str,
        error: String,
    ) {
        if *diagnostics < 4096 {
            Self::issue(result, context, error);
        }
        *diagnostics += 1;
    }

    /// PoolHeaderScanner lazily reads only fields needed by the constraints.
    /// The matched tag may start at the scan buffer's first byte, and neither
    /// the header prefix nor its unused tail needs to be in that buffer.
    fn pool_header_block(
        &self,
        constraint: &Constraint,
        address: u64,
        scan: PoolHeaderRead<'_>,
    ) -> Result<Option<u64>> {
        let field = |name| -> Result<u64> {
            let layout = self.vm.isf.layout("_POOL_HEADER", name)?;
            let at = add(address, layout.offset)?;
            let length = usize::try_from(layout.size).context("pool 字段大小溢出")?;
            ensure!(matches!(length, 1 | 2 | 4 | 8), "pool 字段宽度无效");
            let mut bytes = [0; 8];
            if let Some(value) = at
                .checked_sub(scan.start)
                .and_then(|offset| usize::try_from(offset).ok())
                .and_then(|offset| offset.checked_add(length).map(|end| (offset, end)))
                .and_then(|(offset, end)| scan.data.get(offset..end))
            {
                bytes[..length].copy_from_slice(value);
            } else {
                self.pool_read(at, &mut bytes[..length], scan.virtual_scan)?;
            }
            json_number(self.vm.isf, u64::from_le_bytes(bytes), "_POOL_HEADER", name)
        };
        let Ok(block) = field("BlockSize") else {
            return Ok(None);
        };
        let Some(size) = block.checked_mul(scan.alignment) else {
            return Ok(None);
        };
        if size < constraint.minimum {
            return Ok(None);
        }
        if self.vm.isf.has_field("_POOL_HEADER", "PoolType") {
            let Ok(page) = field("PoolType") else {
                return Ok(None);
            };
            let paged = page > 0 && page % 2 == if scan.vista { 1 } else { 0 };
            let nonpaged = page > 0 && page % 2 == if scan.vista { 0 } else { 1 };
            let accepted = page == 0 && constraint.page & 4 != 0
                || paged && constraint.page & 1 != 0
                || nonpaged && constraint.page & 2 != 0;
            if !accepted {
                return Ok(None);
            }
        }
        Ok(Some(size))
    }

    fn pool_header_layout(&self) -> Result<(usize, u64)> {
        let size = self.vm.isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 pool header 大小")?;
        ensure!((8..=64).contains(&size), "pool header 大小无效");
        let tag = self.vm.isf.offset("_POOL_HEADER", "PoolTag")? as usize;
        ensure!(tag + 4 <= size as usize, "PoolTag 越界");
        let _ = self.vm.isf.layout("_POOL_HEADER", "BlockSize")?;
        Ok((tag, size))
    }

    fn pool_type_sizes(&self) -> Result<BTreeMap<&'static str, u64>> {
        let mut sizes = BTreeMap::new();
        for constraint in CONSTRAINTS {
            let size = self.vm.isf.data["user_types"][constraint.type_name]["size"]
                .as_u64()
                .context("缺少 pool 对象大小")?;
            ensure!((1..=65536).contains(&size), "pool 对象大小无效");
            sizes.insert(constraint.type_name, size);
        }
        Ok(sizes)
    }

    fn pool_optional_headers(&self) -> Result<Vec<(bool, u64)>> {
        let mut headers = Vec::new();
        for name in OPTIONAL_HEADERS {
            if let Some(size) =
                self.vm.isf.data["user_types"][format!("_OBJECT_HEADER_{name}")]["size"].as_u64()
            {
                ensure!(size <= 4096, "可选对象头大小无效");
                headers.push((name == "PADDING_INFO", size));
            }
        }
        let total = headers
            .iter()
            .try_fold(0u64, |total, (_, size)| total.checked_add(*size))
            .context("可选对象头溢出")?;
        ensure!((1..=4096).contains(&total), "缺少或无效可选对象头大小");
        Ok(headers)
    }

    fn pool_scan_ranges(&self, virtual_scan: bool, job: &Job) -> Result<Vec<(u64, u64)>> {
        if !virtual_scan {
            let maximum = self
                .vm
                .image
                .segments
                .last()
                .map(|s| s.end.saturating_sub(1))
                .unwrap_or(0);
            return self
                .vm
                .image
                .segments
                .iter()
                .map(|segment| {
                    Ok((
                        segment.start,
                        segment.end.min(maximum).saturating_sub(segment.start),
                    ))
                })
                .collect();
        }
        Ok(self
            .pool_virtual_ranges(job)?
            .into_iter()
            .map(|(start, size, _)| (start, size))
            .collect())
    }

    fn pool_virtual_ranges(&self, job: &Job) -> Result<Vec<(u64, u64, u64)>> {
        let geometry = self.vm.paging()?;
        let mut ranges = Vec::new();
        let mut current: Option<(u64, u64, u64)> = None;
        let flush = |ranges: &mut Vec<(u64, u64, u64)>, current: &mut Option<(u64, u64, u64)>| {
            if let Some((start, end, physical)) = current.take() {
                ranges.push((start, end - start, physical));
            }
        };
        self.walk_kernel_pages(self.vm.root, 0, 0, &geometry, &mut |va, physical, shift| {
            job.check()?;
            let va = va & self.driver_address_mask();
            // The reference's default section excludes maximum_address.
            // Clip and coalesce in the layer's native address domain. Extending
            // addresses first would split a contiguous range at the sign bit.
            let size =
                (1u64 << shift).min(self.driver_address_mask() - (va & self.driver_address_mask()));
            if size == 0 || !self.pool_captured_span(physical, size) {
                return Ok(());
            }
            let page = physical;
            match current {
                Some((start, end, previous))
                    if end == va && previous.checked_add(end - start) == Some(page) =>
                {
                    current = Some((start, va + size, previous))
                }
                _ => {
                    flush(&mut ranges, &mut current);
                    current = Some((va, va + size, page));
                }
            }
            Ok(())
        })?;
        flush(&mut ranges, &mut current);
        Ok(ranges
            .into_iter()
            .map(|(start, size, physical)| (self.pool_reference_pointer(start), size, physical))
            .collect())
    }

    fn pool_captured_span(&self, mut physical: u64, mut length: u64) -> bool {
        while length > 0 {
            let index = self
                .vm
                .image
                .segments
                .partition_point(|segment| segment.start <= physical);
            let Some(segment) = index
                .checked_sub(1)
                .and_then(|index| self.vm.image.segments.get(index))
            else {
                return false;
            };
            if physical >= segment.end {
                return false;
            }
            let take = length.min(segment.end - physical);
            length -= take;
            if length > 0 {
                let Some(next) = physical.checked_add(take) else {
                    return false;
                };
                physical = next;
            }
        }
        true
    }

    fn walk_kernel_pages(
        &self,
        table: u64,
        level: usize,
        prefix: u64,
        geometry: &Paging,
        visit: &mut dyn FnMut(u64, u64, u32) -> Result<()>,
    ) -> Result<()> {
        let shift = geometry.shifts()[level];
        let width = geometry.width();
        let entries = geometry.entries(level);
        // _get_valid_table always reads a full 4 KiB table, including the
        // four-entry PAE root; only indexing is restricted to those entries.
        let mut bytes = vec![0u8; 4096];
        if self.vm.image.read(table, &mut bytes).is_err() {
            return Ok(());
        }
        if bytes
            .chunks_exact(width)
            .all(|entry| entry == &bytes[..width])
            && bytes.iter().any(|byte| *byte != 0)
        {
            return Ok(());
        }
        for (index, entry_bytes) in bytes.chunks_exact(width).take(entries).enumerate() {
            let mut raw = [0u8; 8];
            raw[..width].copy_from_slice(entry_bytes);
            let entry = u64::from_le_bytes(raw);
            if entry & 1 == 0 && !(entry & (1 << 11) != 0 && entry & (1 << 10) == 0) {
                continue;
            }
            let large = geometry.block(entry, shift);
            let mask = geometry.mask();
            let frame = entry
                & mask
                & if large && geometry.arch != Architecture::Arm64 {
                    !(1 << 12) // large-page PAT bit is not part of the PFN
                } else {
                    u64::MAX
                };
            let relative = prefix | (index as u64) << shift;
            if large || shift == 12 {
                visit(self.pool_reference_pointer(relative), frame, shift)?;
            } else if level + 1 < geometry.shifts().len() {
                self.walk_kernel_pages(frame, level + 1, relative, geometry, visit)?;
            }
        }
        Ok(())
    }

    fn pool_bodies(
        &self,
        constraint: &Constraint,
        header: u64,
        carve: PoolCarve<'_>,
        job: &Job,
    ) -> Result<Vec<u64>> {
        let PoolCarve {
            block,
            alignment,
            type_size,
            top_down,
            optional,
            virtual_scan,
        } = carve;
        let pool_size = self.vm.isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 pool 大小")?;
        let start = add(header, pool_size)?;
        if constraint.object_type.is_none() {
            return Ok(vec![start]);
        }
        let body = self.vm.isf.offset("_OBJECT_HEADER", "Body")?;
        if !top_down {
            let mut size = type_size;
            for extra in constraint.extra {
                size = size
                    .checked_add(
                        self.vm.isf.data["user_types"][*extra]["size"]
                            .as_u64()
                            .context("缺少附加 pool 结构大小")?,
                    )
                    .context("pool 对象大小溢出")?;
            }
            let rounded =
                size.checked_add(alignment - 1).context("对齐溢出")? / alignment * alignment;
            return Ok(header
                .checked_add(block)
                .and_then(|end| end.checked_sub(rounded))
                .filter(|address| *address >= start)
                .into_iter()
                .collect());
        }
        let limit = optional
            .iter()
            .try_fold(0u64, |total, (_, size)| total.checked_add(*size))
            .context("可选对象头溢出")?
            .min(block);
        let info = self.vm.isf.offset("_OBJECT_HEADER", "InfoMask")? as usize;
        let pointer = self.vm.isf.offset("_OBJECT_HEADER", "PointerCount")? as usize;
        let pointer_size = self.vm.isf.size("_OBJECT_HEADER", "PointerCount")?;
        ensure!(matches!(pointer_size, 4 | 8), "PointerCount 宽度无效");
        let window_length = (limit as usize)
            .checked_add(info)
            .context("对象头扫描窗口溢出")?;
        let mut window = vec![0u8; window_length];
        self.pool_read_padded(start, &mut window, virtual_scan)?;
        let mut found = Vec::new();
        for delta in (0..limit).step_by(alignment as usize) {
            job.check()?;
            let count_at = delta as usize + pointer;
            let Some(slice) = window.get(count_at..count_at + pointer_size) else {
                continue;
            };
            let mut raw = [0u8; 8];
            raw[..pointer_size].copy_from_slice(slice);
            let count = u64::from_le_bytes(raw);
            let signed = if pointer_size == 8 {
                count as i64
            } else {
                count as u32 as i32 as i64
            };
            if !(0..0x1000000).contains(&signed) {
                continue;
            }
            let Some(&mask) = window.get(delta as usize + info) else {
                continue;
            };
            let mut selected = 0u64;
            let mut padding = None;
            for (bit, (padded, size)) in optional.iter().enumerate() {
                if u16::from(mask) & (1u16 << bit) != 0 {
                    selected = selected.saturating_add(*size);
                    if *padded {
                        padding = Some(*size);
                    }
                }
            }
            if let Some(padding_size) = padding {
                let Some(at) = (delta as usize).checked_sub(selected as usize) else {
                    continue;
                };
                let Some(encoded) = window.get(at..at + 4) else {
                    continue;
                };
                let encoded = u64::from(u32::from_le_bytes(encoded.try_into().unwrap()));
                // Pinned Python subtraction is signed: an encoded padding amount
                // below its structure size is retained. Preserve its exact chained
                // comparison instead of imposing a stricter unsigned range check.
                let extra = i128::from(encoded) - i128::from(padding_size);
                if i128::from(delta) - i128::from(selected) >= extra && extra > i128::from(delta) {
                    continue;
                }
            }
            found.push(add(add(start, delta)?, body)?);
        }
        Ok(found)
    }

    /// One executive pool tag, using the same layer and object-header recovery as PoolScanner.
    pub(super) fn scan_gui_pool(
        &self,
        tag: &'static [u8],
        type_size: u64,
        minimum: u64,
        job: &Job,
    ) -> Result<(bool, Vec<u64>, Vec<String>)> {
        let constraint = Constraint::new(
            tag,
            "tagWINDOWSTATION",
            Some("WindowStation"),
            minimum,
            3,
            true,
            &[],
        );
        self.scan_pool_objects(&[&constraint], type_size, job)
    }
    fn scan_pool_objects(
        &self,
        constraints: &[&Constraint],
        type_size: u64,
        job: &Job,
    ) -> Result<(bool, Vec<u64>, Vec<String>)> {
        let build = self.build_number()?;
        let virtual_scan = build >= 10240;
        let top_down = build >= 9200;
        let vista = build >= 6000;
        let alignment = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let (tag_offset, _) = self.pool_header_layout()?;
        let optional = if top_down {
            self.pool_optional_headers()?
        } else {
            Vec::new()
        };
        let mut bodies = Vec::new();
        let mut notes = Vec::new();
        let translated = virtual_scan || self.vm.image.format != "RAW";
        for (start, length) in
            PoolScanChunks::new(self.pool_scan_ranges(virtual_scan, job)?, translated)
        {
            job.check()?;
            let mut data =
                vec![0u8; usize::try_from(length).context("pool 扫描范围超出地址空间")?];
            if self.pool_read(start, &mut data, virtual_scan).is_err() {
                notes.push(format!("pool range {start:#x}+{length:#x} 不可读"));
                continue;
            }
            for (index, tag_at) in PoolTagMatches::new(&data, constraints.iter().map(|c| c.tag))? {
                job.check()?;
                if tag_at as u64 >= POOL_SCAN_CHUNK {
                    break;
                }
                let constraint = constraints[index];
                let Some(address) = add(start, tag_at as u64)?.checked_sub(tag_offset as u64)
                else {
                    continue;
                };
                let Some(size) = self.pool_header_block(
                    constraint,
                    address,
                    PoolHeaderRead {
                        start,
                        data: &data,
                        virtual_scan,
                        alignment,
                        vista,
                    },
                )?
                else {
                    continue;
                };
                let found = self.pool_bodies(
                    constraint,
                    address,
                    PoolCarve {
                        block: size,
                        alignment,
                        type_size,
                        top_down,
                        optional: &optional,
                        virtual_scan,
                    },
                    job,
                )?;
                for body in found {
                    if bodies.len() >= MAX_OBJECTS {
                        notes.push("池对象候选超限".into());
                        return Ok((virtual_scan, bodies, notes));
                    }
                    bodies.push(body);
                }
            }
        }
        Ok((virtual_scan, bodies, notes))
    }

    pub(super) fn reference_dispatch_drivers(
        &self,
        result: &mut Results,
        job: &Job,
    ) -> Result<Vec<(u64, u64)>> {
        let type_size = self.vm.isf.data["user_types"]["_DRIVER_OBJECT"]["size"]
            .as_u64()
            .context("缺少驱动对象大小")?;
        ensure!((16..=65536).contains(&type_size), "驱动对象大小无效");
        let types = self.pool_reference_type_map()?;
        let threshold = self.driver_kernel_start()?;
        let body_offset = self.vm.isf.offset("_OBJECT_HEADER", "Body")?;
        let mut out = Vec::new();
        let mut candidate_read_failures = 0usize;
        let constraints: Vec<_> = CONSTRAINTS
            .iter()
            .filter(|c| c.object_type == Some("Driver"))
            .collect();
        let (virtual_scan, bodies, notes) = self.scan_pool_objects(&constraints, type_size, job)?;
        for note in notes {
            Self::issue(result, "驱动池扫描", note);
        }
        for body in bodies {
            job.check()?;
            let valid = (|| -> Result<bool> {
                let header = body.checked_sub(body_offset).context("驱动对象头下溢")?;
                if self
                    .pool_reference_object_type(header, virtual_scan, &types)?
                    .as_deref()
                    != Some("Driver")
                {
                    return Ok(false);
                }
                self.reference_driver_start(body, virtual_scan, threshold)
            })();
            match valid {
                Ok(true) => {
                    ensure!(out.len() < MAX_OBJECTS, "驱动候选数量超限");
                    out.push((body, body));
                }
                Ok(false) => {}
                Err(_) => {
                    job.check()?;
                    // Invalid carved objects are expected during a tag
                    // scan; the reference rejects them without a row.
                    candidate_read_failures += 1;
                }
            }
        }
        result.kernel_identity["driver_pool"] = serde_json::json!({"source":"shared reference pool constraints and carving","offset_layer":if self.build_number()?>=10240 {"primary virtual"}else{"physical"},"driver_count":out.len(),"rejected_candidate_reads":candidate_read_failures,"driver_start":"8 readable bytes; zero or strictly above masked MmSystemRangeStart"});
        Ok(out)
    }
    fn reference_driver_start(
        &self,
        body: u64,
        virtual_scan: bool,
        threshold: u64,
    ) -> Result<bool> {
        let offset = self.vm.isf.offset("_DRIVER_OBJECT", "DriverStart")?;
        // DriverScan requires eight readable bytes even for an x86 pointer.
        let mut bytes = [0; 8];
        self.pool_read(add(body, offset)?, &mut bytes, virtual_scan)?;
        let raw = if self.vm.pointer_size() == 4 {
            u64::from(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
        } else {
            u64::from_le_bytes(bytes)
        };
        let start = raw & self.driver_address_mask();
        Ok(start == 0 || start > threshold)
    }
    pub(super) fn pool_read(&self, address: u64, out: &mut [u8], virtual_scan: bool) -> Result<()> {
        if virtual_scan {
            self.vm.read(address, out)
        } else {
            self.vm.image.read(address, out)
        }
    }

    fn pool_read_padded(
        &self,
        mut address: u64,
        mut out: &mut [u8],
        virtual_scan: bool,
    ) -> Result<()> {
        while !out.is_empty() {
            let length = out.len().min(4096 - (address & 4095) as usize);
            let (chunk, rest) = out.split_at_mut(length);
            if self.pool_read(address, chunk, virtual_scan).is_err() {
                // Preserve captured bytes even if a physical segment ends part
                // way through this page. Unreadable bytes alone become zero.
                for (offset, byte) in chunk.iter_mut().enumerate() {
                    let mut value = [0];
                    *byte = if self
                        .pool_read(add(address, offset as u64)?, &mut value, virtual_scan)
                        .is_ok()
                    {
                        value[0]
                    } else {
                        0
                    };
                }
            }
            address = add(address, length as u64)?;
            out = rest;
        }
        Ok(())
    }

    fn pool_value(
        &self,
        address: u64,
        structure: &str,
        field: &str,
        virtual_scan: bool,
    ) -> Result<u64> {
        if virtual_scan {
            self.number(address, structure, field)
        } else {
            self.physical_field(address, structure, field)
        }
    }

    fn pool_object_valid(
        &self,
        constraint: &Constraint,
        body: u64,
        virtual_scan: bool,
        validation: &PoolValidation,
        result: &mut Results,
        diagnostics: &mut usize,
    ) -> Result<bool> {
        let valid = (|| -> Result<bool> {
            if let Some(kind) = constraint.object_type
                && !constraint.skip_type
            {
                let header = body
                    .checked_sub(self.vm.isf.offset("_OBJECT_HEADER", "Body")?)
                    .context("对象头下溢")?;
                if self
                    .pool_reference_object_type(header, virtual_scan, &validation.types)?
                    .as_deref()
                    != Some(kind)
                {
                    return Ok(false);
                }
            }
            Ok(match constraint.type_name {
                "_EPROCESS" => self.pool_process_valid(body, virtual_scan, None)?,
                "_ETHREAD" => self.pool_thread_valid(body, virtual_scan, None)?,
                "_FILE_OBJECT" => {
                    let length =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Length", virtual_scan)?;
                    let buffer =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Buffer", virtual_scan)?;
                    length > 0 && self.address_readable(buffer)
                }
                _ => true,
            })
        })();
        match valid {
            Ok(valid) => Ok(valid),
            Err(error) => {
                self.pool_note(
                    result,
                    diagnostics,
                    "pool object",
                    format!("{body:#x}: {error:#}"),
                );
                Ok(false)
            }
        }
    }

    fn pool_reference_unicode(&self, descriptor: u64) -> Result<String> {
        let length = self.vm.uint(descriptor, 2)?;
        let buffer = self.pool_reference_pointer(self.vm.pointer(add(
            descriptor,
            self.vm.isf.offset("_UNICODE_STRING", "Buffer")?,
        )?)?);
        let mut bytes = vec![0; length as usize];
        self.vm.read(buffer, &mut bytes)?;
        Ok(windowstations::reference_unicode_name(&bytes))
    }

    fn pool_reference_type_map(&self) -> Result<BTreeMap<u64, String>> {
        let mut types = BTreeMap::new();
        if !self.vm.isf.has_field("_OBJECT_HEADER", "TypeIndex") {
            return Ok(types);
        }
        let table = self
            .symbol("ObTypeIndexTable")
            .or_else(|_| self.symbol("ObpObjectTypes"))?;
        if !self.address_readable(table) {
            return Ok(types);
        }
        // Handles.get_type_map reads 100 pointers and stops at the first null
        // after index zero. An unreadable name skips only that index; exported
        // type variables do not provide a fallback in this reference path.
        for index in 0..100 {
            let pointer = self.pool_reference_pointer(
                self.vm
                    .pointer(add(table, index * self.vm.pointer_size() as u64)?)?,
            );
            if index > 0 && pointer == 0 {
                break;
            }
            if let Ok(name) = self
                .field(pointer, "_OBJECT_TYPE", "Name")
                .and_then(|descriptor| self.pool_reference_unicode(descriptor))
            {
                types.insert(index, name);
            }
        }
        Ok(types)
    }

    fn pool_reference_object_type(
        &self,
        header: u64,
        virtual_scan: bool,
        types: &BTreeMap<u64, String>,
    ) -> Result<Option<String>> {
        if self.vm.isf.has_field("_OBJECT_HEADER", "TypeIndex") {
            let encoded = self.pool_value(header, "_OBJECT_HEADER", "TypeIndex", virtual_scan)?;
            let index = if let Ok(cookie_address) = self.symbol("ObHeaderCookie") {
                let cookie = self.vm.uint(cookie_address, 1)?;
                ((header >> 8) ^ cookie ^ encoded) & 0xff
            } else {
                encoded
            };
            return Ok(types.get(&index).cloned());
        }
        let pointer = self.pool_reference_pointer(self.pool_value(
            header,
            "_OBJECT_HEADER",
            "Type",
            virtual_scan,
        )?);
        let descriptor = self.field(pointer, "_OBJECT_TYPE", "Name")?;
        let length = self.vm.uint(descriptor, 2)?;
        if length == 0 || length > 128 {
            return Ok(None);
        }
        let name = self.pool_reference_unicode(descriptor)?;
        Ok((!name.is_empty() && name.chars().count() <= 128).then_some(name))
    }

    fn address_readable(&self, address: u64) -> bool {
        self.vm
            .translate(self.pool_reference_pointer(address))
            .is_ok_and(|physical| self.vm.image.read(physical, &mut [0]).is_ok())
    }

    fn pool_reference_pointer(&self, value: u64) -> u64 {
        if self.vm.pointer_size() == 4 {
            value & 0xffff_ffff
        } else {
            let value = value & 0xffff_ffff_ffff;
            if value & (1 << 47) != 0 {
                value | 0xffff_0000_0000_0000
            } else {
                value
            }
        }
    }

    fn pool_year(ticks: i64) -> Option<i64> {
        let seconds = ticks.div_euclid(10_000_000);
        if seconds == 0 {
            return None;
        }
        let stamp = crate::report::utc(seconds - 11_644_473_600);
        let year = stamp.split('-').next()?.parse().ok()?;
        (1..=9999).contains(&year).then_some(year)
    }

    fn pool_process_valid(
        &self,
        body: u64,
        virtual_scan: bool,
        current_year: Option<i64>,
    ) -> Result<bool> {
        let layout = self.vm.isf.layout("_EPROCESS", "ImageFileName")?;
        let mut bytes = vec![0u8; layout.size as usize];
        self.pool_read(add(body, layout.offset)?, &mut bytes, virtual_scan)?;
        let name = windowstations::reference_process_name(&bytes);
        if name.is_empty() {
            return Ok(false);
        }
        let pid = self.pool_typed_value(body, "_EPROCESS", "UniqueProcessId", virtual_scan)?;
        if pid == 0 || pid % 4 != 0 || pid > 0xffff_fffc {
            return Ok(false);
        }
        let system = name == "System" && pid == 4;
        if !system {
            let created = self.pool_value(body, "_EPROCESS", "CreateTime", virtual_scan)? as i64;
            let Some(year) = Self::pool_year(created) else {
                return Ok(false);
            };
            let current_year = current_year.map_or_else(current_local_year, Ok)?;
            if !(1998 < year && year < current_year + 10) {
                return Ok(false);
            }
            let exited = self.pool_value(body, "_EPROCESS", "ExitTime", virtual_scan)? as i64;
            if exited != 0
                && let Some(exit_year) = Self::pool_year(exited)
                && (!(1998 < exit_year && exit_year < current_year + 10)
                    || exited.div_euclid(10_000_000) < created.div_euclid(10_000_000))
            {
                return Ok(false);
            }
        }
        let dtb =
            self.pool_typed_value(body, "_EPROCESS", "Pcb.DirectoryTableBase", virtual_scan)?;
        if dtb == 0 || dtb & !0xfff == 0 {
            return Ok(false);
        }
        let flink =
            self.pool_typed_value(body, "_EPROCESS", "ThreadListHead.Flink", virtual_scan)?;
        let blink =
            self.pool_typed_value(body, "_EPROCESS", "ThreadListHead.Blink", virtual_scan)?;
        Ok(flink >= 0x8000_0000 && blink >= 0x8000_0000)
    }

    fn pool_thread_valid(
        &self,
        body: u64,
        virtual_scan: bool,
        current_year: Option<i64>,
    ) -> Result<bool> {
        let pid = self.pool_typed_value(body, "_ETHREAD", "Cid.UniqueProcess", virtual_scan)?;
        let tid = self.pool_typed_value(body, "_ETHREAD", "Cid.UniqueThread", virtual_scan)?;
        if pid % 4 != 0 || tid % 4 != 0 {
            return Ok(false);
        }
        if pid != 4 {
            let mut created = self.pool_value(body, "_ETHREAD", "CreateTime", virtual_scan)? as i64;
            if self.vm.isf.has_field("_ETHREAD", "ThreadsProcess") {
                created >>= 3;
            }
            let Some(year) = Self::pool_year(created) else {
                return Ok(false);
            };
            let current_year = current_year.map_or_else(current_local_year, Ok)?;
            if !(1998 < year && year < current_year + 10) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn pool_typed_value(
        &self,
        body: u64,
        ty: &str,
        field: &str,
        virtual_scan: bool,
    ) -> Result<u64> {
        let raw = self.pool_value(body, ty, field, virtual_scan)?;
        let kind = self.vm.isf.field(ty, field)?["type"]["kind"].as_str();
        // EPROCESS's array DTB is cast to a native pointer by the reference.
        if kind == Some("pointer") || (field == "Pcb.DirectoryTableBase" && kind == Some("array")) {
            Ok(self.pool_reference_pointer(raw))
        } else {
            Ok(raw)
        }
    }

    fn pool_scanner_name(
        &self,
        constraint: &Constraint,
        body: u64,
        virtual_scan: bool,
    ) -> Result<Option<String>> {
        match constraint.object_type {
            Some("Process") => {
                let layout = self.vm.isf.layout("_EPROCESS", "ImageFileName")?;
                let mut bytes = vec![0u8; layout.size as usize];
                self.pool_read(add(body, layout.offset)?, &mut bytes, virtual_scan)?;
                let end = bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len());
                Ok(Some(String::from_utf8_lossy(&bytes[..end]).into_owned()))
            }
            Some("File") => {
                // The reference generator skips a file whose name faults and
                // continues scanning. Propagating this read error truncates all
                // later pool observations, including unrelated object types.
                let name = (|| -> Result<String> {
                    let length =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Length", virtual_scan)?;
                    let buffer = self.pool_reference_pointer(self.pool_value(
                        body,
                        "_FILE_OBJECT",
                        "FileName.Buffer",
                        virtual_scan,
                    )?);
                    let mut bytes = vec![0u8; length as usize];
                    self.vm.read(buffer, &mut bytes)?;
                    Ok(windowstations::reference_unicode_name(&bytes))
                })();
                Ok(name.ok())
            }
            _ => Ok(Some(String::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn virtual_pool_ranges_match_actual_windows_intel_mapping() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-mappings.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let (_, mut isf) = fixture();
            let arch = case["arch"].as_str().unwrap();
            let width = case["width"].as_u64().unwrap() as usize;
            if arch != "x64" {
                isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
                isf.data["base_types"]["pointer"]["size"] = json!(4);
                if arch == "pae" {
                    isf.data["metadata"]["windows"]["paging"] = json!("pae");
                }
            }
            if arch == "x64" {
                // Real ISFs can expose the software flag as part of a 40-bit
                // transition PFN. The pinned Intel layer still uses raw 45-bit
                // physical extraction, independent of that field width.
                isf.data["user_types"]["_MMPTE_TRANSITION"] = json!({"size":8,"fields":{
                    "PageFrameNumber":{"offset":0,"type":{"kind":"bitfield","bit_position":12,
                        "bit_length":40,"type":{"kind":"base","name":"u64"}}}}});
            }
            let mut bytes = vec![0; case["length"].as_u64().unwrap() as usize];
            for write in case["writes"].as_array().unwrap() {
                let at = write[0].as_u64().unwrap() as usize;
                bytes[at..at + width]
                    .copy_from_slice(&write[1].as_u64().unwrap().to_le_bytes()[..width]);
            }
            if case["patterned"].as_bool().unwrap_or(false) {
                for page in (0x400000..bytes.len()).step_by(4096) {
                    bytes[page..page + 4096].fill(((page / 4096) % 251) as u8);
                }
            }
            for write in case["data_writes"].as_array().unwrap() {
                let at = write[0].as_u64().unwrap() as usize;
                let value = write[1].as_str().unwrap();
                for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                    bytes[at + index] =
                        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
                }
            }
            let mut snapshot = image(&bytes);
            snapshot.segments.clear();
            let mut start = 0;
            for hole in case["holes"].as_array().unwrap() {
                let end = hole[0].as_u64().unwrap();
                if start < end {
                    snapshot.segments.push(crate::image::Segment {
                        start,
                        end,
                        file_offset: start,
                    });
                }
                start = hole[1].as_u64().unwrap();
            }
            snapshot.segments.push(crate::image::Segment {
                start,
                end: bytes.len() as u64,
                file_offset: start,
            });
            let windows = Windows {
                vm: Memory::new(&snapshot, case["root"].as_u64().unwrap(), &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            for query in case["queries"].as_array().unwrap() {
                let address = query["address"].as_u64().unwrap();
                let translated = windows.vm.translate(address);
                match query["physical"].as_u64() {
                    Some(expected) => {
                        assert_eq!(translated.unwrap(), expected, "{} {query}", case["id"])
                    }
                    None => assert!(translated.is_err(), "{} {query}", case["id"]),
                }
                let mut byte = vec![0xff; query["length"].as_u64().unwrap_or(1) as usize];
                let read = windows.vm.read(address, &mut byte);
                if let Some(expected) = query["read_hex"].as_str() {
                    read.unwrap();
                    assert_eq!(
                        byte.iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                        expected,
                        "{} {query}",
                        case["id"]
                    );
                    let mut captured = vec![0xff; byte.len()];
                    windows.vm.read_captured(address, &mut captured).unwrap();
                    assert_eq!(captured, byte);
                } else {
                    assert!(read.is_err(), "{} {query}", case["id"]);
                    assert!(
                        windows.vm.read_captured(address, &mut byte).is_err(),
                        "{} {query}",
                        case["id"]
                    );
                }
            }
            let ranges = windows.pool_virtual_ranges(&Job::default()).unwrap();
            for &(at, length, physical) in &ranges {
                // For reserved PFN bits, the reference whole-range mapping
                // assumes linearity while direct translation ORs each start.
                // Both actual API observations are tested independently.
                if case["id"].as_str().unwrap().contains("reserved-bit") {
                    continue;
                }
                assert_eq!(
                    windows.vm.translate(at).unwrap(),
                    physical,
                    "{} at={at:#x}",
                    case["id"]
                );
                assert_eq!(
                    windows.vm.translate(at + length - 1).unwrap(),
                    physical + length - 1,
                    "{} tail",
                    case["id"]
                );
            }
            let masked: Vec<_> = ranges
                .into_iter()
                .map(|(at, size, physical)| [at & windows.driver_address_mask(), size, physical])
                .collect();
            assert_eq!(json!(masked), case["expected"], "{}", case["id"]);
            let job = Job::default();
            job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            // A valid mapping must reach the callback's cancellation check.
            if !masked.is_empty() {
                assert!(windows.pool_virtual_ranges(&job).is_err());
            }
        }
    }

    #[test]
    fn pool_chunk_plans_and_overlap_match_actual_layer_iterators() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-chunks.json"
        ))
        .unwrap();
        assert_eq!(vectors["chunk_size"], POOL_SCAN_CHUNK);
        assert_eq!(vectors["overlap"], POOL_SCAN_OVERLAP);
        for case in vectors["plans"].as_array().unwrap() {
            let ranges = case["ranges"]
                .as_array()
                .unwrap()
                .iter()
                .map(|range| (range[0].as_u64().unwrap(), range[1].as_u64().unwrap()))
                .collect();
            let chunks: Vec<_> = PoolScanChunks::new(ranges, case["translated"].as_bool().unwrap())
                .map(|(at, size)| [at, size])
                .collect();
            assert_eq!(json!(chunks), case["expected"], "{}", case["id"]);
        }
        for case in vectors["scans"].as_array().unwrap() {
            let length = case["length"].as_u64().unwrap();
            let mut bytes = vec![0; length as usize];
            for at in case["tags"].as_array().unwrap() {
                let at = at.as_u64().unwrap() as usize;
                bytes[at..at + 4].copy_from_slice(b"Driv");
            }
            let mut found = Vec::new();
            let mut chunks = Vec::new();
            for (start, length) in
                PoolScanChunks::new(vec![(0, length)], case["translated"].as_bool().unwrap())
            {
                chunks.push(vec![[start, length]]);
                if case["fault_chunks"].as_array().unwrap().iter().any(|bad| {
                    let bad = bad.as_u64().unwrap() * POOL_SCAN_CHUNK;
                    start <= bad && bad < start + length
                }) {
                    continue;
                }
                let data = &bytes[start as usize..(start + length) as usize];
                for (_, at) in PoolTagMatches::new(data, [b"Driv".as_slice()]).unwrap() {
                    if at as u64 >= POOL_SCAN_CHUNK {
                        break;
                    }
                    found.push(start + at as u64);
                }
            }
            assert_eq!(json!(chunks), case["chunks"], "{}", case["id"]);
            assert_eq!(json!(found), case["expected"], "{}", case["id"]);
        }
    }

    #[test]
    fn shared_carver_handles_chunk_crossings_and_reference_raw_tail_repeats() {
        for (length, tag, copies) in [
            (
                POOL_SCAN_CHUNK + POOL_SCAN_OVERLAP + 16,
                POOL_SCAN_CHUNK - 2,
                1,
            ),
            (POOL_SCAN_CHUNK + 100, POOL_SCAN_CHUNK - 20, 2),
        ] {
            let (mut bytes, isf, base, _) =
                super::super::driver_irp::tests::driver_fixture(false, false, false);
            bytes.resize(length as usize, 0);
            let header = tag as usize - 4;
            bytes[header..header + 2].copy_from_slice(&32u16.to_le_bytes());
            bytes[header + 2..header + 4].copy_from_slice(&2u16.to_le_bytes());
            bytes[tag as usize..tag as usize + 4].copy_from_slice(b"Wind");
            let snapshot = image(&bytes);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let constraint = Constraint::new(b"Wind", "station", None, 0x90, 3, true, &[]);
            let (_, bodies, notes) = windows
                .scan_pool_objects(&[&constraint], 32, &Job::default())
                .unwrap();
            assert_eq!(bodies, vec![header as u64 + 16; copies]);
            assert!(notes.is_empty(), "{notes:?}");
        }
        let (mut bytes, isf, base, _) =
            super::super::driver_irp::tests::driver_fixture(false, false, false);
        bytes.extend_from_slice(b"Wind");
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let ranges = windows.pool_scan_ranges(false, &Job::default()).unwrap();
        assert_eq!(ranges, [(0, bytes.len() as u64 - 1)]);
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-chunks.json"
        ))
        .unwrap();
        let length = vectors["default_section"]["length"].as_u64().unwrap() as usize;
        let data = b"....Driv";
        let found: Vec<_> = PoolTagMatches::new(&data[..length], [b"Driv".as_slice()])
            .unwrap()
            .map(|(_, at)| at)
            .collect();
        assert_eq!(json!(found), vectors["default_section"]["expected"]);
    }

    #[test]
    fn pool_header_constraints_read_only_required_fields_across_scan_slices() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-boundaries.json"
        ))
        .unwrap();
        for x86 in [false, true] {
            for virtual_scan in [false, true] {
                for case in vectors["cases"].as_array().unwrap() {
                    let (mut bytes, mut isf, base, _) =
                        super::super::driver_irp::tests::driver_fixture(x86, virtual_scan, false);
                    let physical = 0x18000;
                    let address = if virtual_scan {
                        base + 0x10000
                    } else {
                        physical as u64
                    };
                    let payload: Vec<_> = case["payload_hex"]
                        .as_str()
                        .unwrap()
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect();
                    bytes[physical..physical + payload.len()].copy_from_slice(&payload);
                    let mut snapshot = image(&bytes);
                    let mut missing: Vec<_> = case["missing"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|at| physical as u64 + at.as_u64().unwrap() - 0x1000)
                        .collect();
                    missing.sort_unstable();
                    // Backing-byte holes are real Image segments, so fallback
                    // cannot accidentally read them from the scan buffer.
                    let mut begin = 0;
                    snapshot.segments.clear();
                    for at in missing {
                        if at > begin {
                            snapshot.segments.push(crate::image::Segment {
                                start: begin,
                                end: at,
                                file_offset: begin,
                            });
                        }
                        begin = at + 1;
                    }
                    snapshot.segments.push(crate::image::Segment {
                        start: begin,
                        end: bytes.len() as u64,
                        file_offset: begin,
                    });
                    // Both pointer widths use the fixed vector's explicit
                    // alignment; these isolate header reads, not carving.
                    isf.data["user_types"]["_POOL_HEADER"]["size"] = json!(16);
                    let windows = Windows {
                        vm: Memory::new(&snapshot, 0x1000, &isf, None),
                        base,
                        pdb: PdbIdentity::from_isf(&isf).unwrap(),
                    };
                    let constraint = Constraint::new(b"Wind", "station", None, 0x90, 3, true, &[]);
                    let local = case["scan_start"].as_u64().unwrap() as usize - 0x1000;
                    let length = case["scan_length"].as_u64().unwrap() as usize;
                    let matched = windows
                        .pool_header_block(
                            &constraint,
                            address,
                            PoolHeaderRead {
                                start: address + local as u64,
                                data: &payload[local..local + length],
                                virtual_scan,
                                alignment: 16,
                                vista: case["vista"].as_bool().unwrap(),
                            },
                        )
                        .unwrap();
                    assert_eq!(
                        matched.is_some(),
                        !case["expected"].as_array().unwrap().is_empty(),
                        "{} x86={x86} virtual={virtual_scan}",
                        case["id"]
                    );
                    if let Some(size) = matched {
                        assert_eq!(size, 512);
                    }
                }
            }
        }
    }

    #[test]
    fn carved_pool_tag_at_segment_start_does_not_require_unused_header_tail() {
        let (mut bytes, isf, base, _) =
            super::super::driver_irp::tests::driver_fixture(false, false, false);
        bytes[0xb000..0xb008].fill(0); // Remove unrelated driver tag.
        bytes[0x18000..0x18002].copy_from_slice(&32u16.to_le_bytes());
        bytes[0x18002..0x18004].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x18004..0x18008].copy_from_slice(b"Wind");
        let mut snapshot = image(&bytes);
        snapshot.segments = vec![
            crate::image::Segment {
                start: 0,
                end: 0x18004,
                file_offset: 0,
            },
            crate::image::Segment {
                start: 0x18004,
                end: 0x18008,
                file_offset: 0x18004,
            },
            crate::image::Segment {
                start: 0x18010,
                end: bytes.len() as u64,
                file_offset: 0x18010,
            },
        ];
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let constraint = Constraint::new(b"Wind", "station", None, 0x90, 3, true, &[]);
        let (_, bodies, notes) = windows
            .scan_pool_objects(&[&constraint], 32, &Job::default())
            .unwrap();
        assert_eq!(bodies, [0x18010]);
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn merged_pool_tags_match_actual_reference_order_and_non_overlap() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-order.json"
        ))
        .unwrap();
        let decode = |text: &str| -> Vec<u8> {
            text.as_bytes()
                .chunks_exact(2)
                .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
                .collect()
        };
        for case in vectors["cases"].as_array().unwrap() {
            let data = decode(case["data_hex"].as_str().unwrap());
            let tags: Vec<_> = case["tags_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tag| decode(tag.as_str().unwrap()))
                .collect();
            let matches: Vec<_> = PoolTagMatches::new(&data, tags.iter().map(Vec::as_slice))
                .unwrap()
                .map(|(index, at)| [at, index])
                .collect();
            assert_eq!(
                serde_json::json!(matches),
                case["expected_matches"],
                "{}",
                case["id"]
            );
            let headers: Vec<_> = matches
                .iter()
                .filter(|entry| {
                    !case["rejected_indices"]
                        .as_array()
                        .unwrap()
                        .contains(&serde_json::json!(entry[1]))
                })
                .map(|entry| [0x1000 + entry[0] - 4, entry[1]])
                .collect();
            assert_eq!(
                serde_json::json!(headers),
                case["expected_headers"],
                "{}",
                case["id"]
            );
        }
        assert!(PoolTagMatches::new(b"Driv", [b"Driv".as_slice(), b"Driv".as_slice()]).is_err());
        assert!(PoolTagMatches::new(b"", std::iter::empty()).is_err());
    }

    #[test]
    fn driverscan_requires_eight_captured_bytes_and_a_strict_start_boundary() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/driver-scan.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let width = case["width"].as_u64().unwrap();
            let (mut bytes, isf, base, _) =
                super::super::driver_irp::tests::driver_fixture(width == 4, false, false);
            let available = case["available_bytes"].as_u64().unwrap() as usize;
            let descriptor = 0x3f000;
            put(&mut bytes, descriptor, case["raw"].as_u64().unwrap());
            bytes.truncate(descriptor + available);
            let snapshot = image(&bytes);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let found = windows
                .reference_driver_start(
                    (descriptor - 16) as u64,
                    false,
                    case["threshold"].as_u64().unwrap(),
                )
                .unwrap_or(false);
            assert_eq!(found, case["expected"].as_bool().unwrap(), "{}", case["id"]);
        }
    }

    #[test]
    fn process_and_thread_validity_match_pinned_calendar_name_and_pointer_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-validity.json"
        ))
        .unwrap();
        for case in vectors["process"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            isf.data["user_types"]["_EPROCESS"]["fields"]["ThreadListHead"] =
                json!({"offset":128,"type":{"kind":"struct","name":"_LIST_ENTRY"}});
            if !case["pid_pointer"].as_bool().unwrap() {
                isf.data["user_types"]["_EPROCESS"]["fields"]["UniqueProcessId"]["type"] =
                    json!({"kind":"base","name":"u64"});
            }
            if case["dtb_array"].as_bool().unwrap() {
                isf.data["user_types"]["_KPROCESS"]["fields"]["DirectoryTableBase"]["type"] =
                    json!({"kind":"array","count":8});
            }
            bytes[0xc000..0xc100].fill(0);
            let name: Vec<_> = case["name_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect();
            bytes[0xc030..0xc030 + name.len()].copy_from_slice(&name);
            for (offset, key) in [(32, "pid"), (112, "dtb"), (128, "flink"), (136, "blink")] {
                put(&mut bytes, 0xc000 + offset, case[key].as_u64().unwrap());
            }
            for (offset, key) in [(88, "created"), (96, "exited")] {
                put(
                    &mut bytes,
                    0xc000 + offset,
                    case[key].as_i64().unwrap() as u64,
                );
            }
            let snapshot = image(&bytes);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert_eq!(
                windows
                    .pool_process_valid(0xc000, false, Some(case["year"].as_i64().unwrap()))
                    .unwrap(),
                case["expected"].as_bool().unwrap(),
                "{}",
                case["id"]
            );
        }
        for case in vectors["thread"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
            isf.data["user_types"]["_ETHREAD"] = json!({"size":64,"fields":{"Cid":{"offset":0,"type":{"kind":"struct","name":"_CLIENT_ID"}},"CreateTime":{"offset":16,"type":{"kind":"base","name":"u64"}}}});
            isf.data["user_types"]["_CLIENT_ID"] =
                json!({"size":16,"fields":{"UniqueProcess":pointer(0),"UniqueThread":pointer(8)}});
            if case["legacy"].as_bool().unwrap() {
                isf.data["user_types"]["_ETHREAD"]["fields"]["ThreadsProcess"] = pointer(24);
            }
            bytes[0xc000..0xc040].fill(0);
            put(&mut bytes, 0xc000, case["pid"].as_u64().unwrap());
            put(&mut bytes, 0xc008, case["tid"].as_u64().unwrap());
            put(&mut bytes, 0xc010, case["created"].as_i64().unwrap() as u64);
            let snapshot = image(&bytes);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert_eq!(
                windows
                    .pool_thread_valid(0xc000, false, Some(case["year"].as_i64().unwrap()))
                    .unwrap(),
                case["expected"].as_bool().unwrap(),
                "{}",
                case["id"]
            );
        }
    }

    #[test]
    fn recursive_kernel_page_aliases_match_fixed_intel_mapping() {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x1000, 0x2003);
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-types.json"
        ))
        .unwrap();
        let alias = windows
            .pool_reference_pointer(vectors["recursive_mapping"]["address"].as_u64().unwrap());
        let expected_physical = vectors["recursive_mapping"]["mappings"][0][2]
            .as_u64()
            .unwrap();
        let mut found = None;
        let mut user = None;
        windows
            .walk_kernel_pages(
                windows.vm.root,
                0,
                0,
                &windows.vm.paging().unwrap(),
                &mut |va, physical, shift| {
                    if alias >= va && alias < va + (1 << shift) {
                        found = Some(physical + alias - va);
                    }
                    if va == 0 {
                        user = Some(physical);
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(found, Some(expected_physical));
        assert_eq!(user, vectors["user_mapping"]["mappings"][0][2].as_u64());
    }

    #[test]
    fn pool_pointer_values_match_reference_native_layer_mask() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-types.json"
        ))
        .unwrap();
        for case in vectors["pointer_cases"].as_array().unwrap() {
            let (bytes, mut isf) = fixture();
            let width = case["width"].as_u64().unwrap();
            if width == 4 {
                isf.data["base_types"]["pointer"]["size"] = json!(4);
                isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
            }
            let snapshot = image(&bytes);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let value = windows.pool_reference_pointer(case["raw"].as_u64().unwrap());
            let mask = if width == 4 {
                0xffff_ffff
            } else {
                0xffff_ffff_ffff
            };
            assert_eq!(value & mask, case["expected"].as_u64().unwrap());
            assert!(windows.vm.paging().unwrap().canonical(value));
        }
    }

    #[test]
    fn top_down_missing_window_tail_matches_pinned_padded_carving() {
        let (bytes, mut isf) = fixture();
        isf.data["base_types"]["u8"] = json!({"size":1});
        isf.data["user_types"]["_POOL_HEADER"] = json!({"size":16,"fields":{}});
        isf.data["user_types"]["_OBJECT_HEADER"] = json!({"size":56,"fields":{"Body":{"offset":48,"type":{"kind":"base","name":"u64"}},"InfoMask":{"offset":26,"type":{"kind":"base","name":"u8"}},"PointerCount":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
        let mut truncated = bytes[..0x2000].to_vec();
        truncated[0x1fc0..].fill(0);
        let snapshot = image(&truncated);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let constraint = Constraint::new(
            b"Wind",
            "tagWINDOWSTATION",
            Some("WindowStation"),
            0,
            3,
            true,
            &[],
        );
        let bodies = windows
            .pool_bodies(
                &constraint,
                0x1fc0,
                PoolCarve {
                    block: 128,
                    alignment: 16,
                    type_size: 152,
                    top_down: true,
                    optional: &[(false, 32), (true, 4)],
                    virtual_scan: false,
                },
                &Job::default(),
            )
            .unwrap();
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/gui-pool-padding.json"
        ))
        .unwrap();
        assert_eq!(
            serde_json::json!(bodies),
            vectors["missing_tail"]["expected_bodies"]
        );
        // A successful prefix is retained; padding replaces only absent bytes.
        truncated[0x1ffe..].copy_from_slice(&[0x41, 0x42]);
        let snapshot = image(&truncated);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut read = [0xff; 4];
        windows.pool_read_padded(0x1ffe, &mut read, false).unwrap();
        assert_eq!(read, [0x41, 0x42, 0, 0]);
    }

    #[test]
    fn pool_type_map_matches_pinned_sentinel_limit_and_missing_names() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-types.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            isf.data["user_types"]["_OBJECT_HEADER"] = json!({"size":56,"fields":{"TypeIndex":{"offset":24,"type":{"kind":"base","name":"u16"}}}});
            isf.data["user_types"]["_OBJECT_TYPE"] = json!({"size":16,"fields":{"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
            isf.data["symbols"]["ObTypeIndexTable"] = json!({"address":0x500});
            bytes[0x8500..0x8500 + 102 * 8].fill(0);
            for (index, entry) in case["entries"].as_array().unwrap().iter().enumerate() {
                let Some(name) = entry.as_str() else { continue };
                let descriptor = 0x12000 + index * 32;
                let buffer = 0x16000 + index * 32;
                put(
                    &mut bytes,
                    0x8500 + index * 8,
                    K + (descriptor - 0x8000) as u64,
                );
                let encoded: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                bytes[descriptor..descriptor + 2]
                    .copy_from_slice(&(encoded.len() as u16).to_le_bytes());
                put(
                    &mut bytes,
                    descriptor + 8,
                    if name == "!unreadable" {
                        K + 0x30000
                    } else {
                        K + (buffer - 0x8000) as u64
                    },
                );
                bytes[buffer..buffer + encoded.len()].copy_from_slice(&encoded);
            }
            if !case["table_valid"].as_bool().unwrap() {
                isf.data["symbols"]["ObTypeIndexTable"] = json!({"address":0x30000});
            }
            let snapshot = image(&bytes);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert_eq!(
                serde_json::json!(windows.pool_reference_type_map().unwrap()),
                case["expected"],
                "{}",
                case["id"]
            );
        }
    }

    #[test]
    fn nonexecutive_hives_keep_raw_observations_without_signature_validation() {
        let (bytes, mut isf) = fixture();
        isf.data["user_types"]["_POOL_HEADER"] = json!({"size":16,"fields":{}});
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let constraint = CONSTRAINTS.iter().find(|c| c.tag == b"CM10").unwrap();
        let bodies = windows
            .pool_bodies(
                constraint,
                0x1000,
                PoolCarve {
                    block: 800,
                    alignment: 16,
                    type_size: 816,
                    top_down: true,
                    optional: &[],
                    virtual_scan: false,
                },
                &Job::default(),
            )
            .unwrap();
        let reference: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-types.json"
        ))
        .unwrap();
        assert_eq!(serde_json::json!(bodies), reference["nonexecutive_bodies"]);
        let mut result = windows.result(Plugin::WinPoolScanner);
        let mut diagnostics = 0;
        for body in bodies {
            assert!(
                windows
                    .pool_object_valid(
                        constraint,
                        body,
                        false,
                        &PoolValidation {
                            types: BTreeMap::new(),
                        },
                        &mut result,
                        &mut diagnostics
                    )
                    .unwrap()
            );
        }
        assert_eq!(diagnostics, 0);
    }

    #[test]
    fn missing_file_name_tail_skips_only_that_file() {
        let (mut bytes, mut isf) = fixture();
        isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":160,"fields":{"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
        put(&mut bytes, 0x1000, 0x2003); // The native kernel DTB also maps user addresses.
        put(&mut bytes, 0x4000 + 2 * 8, 0); // Missing second name page.
        bytes[0xc000..0xc002].copy_from_slice(&4u16.to_le_bytes());
        put(&mut bytes, 0xc008, K + 0x1ffe);
        bytes[0x9ffe..0xa000].copy_from_slice(&[b'x', 0]);
        bytes[0xc100..0xc102].copy_from_slice(&4u16.to_le_bytes());
        put(&mut bytes, 0xc108, 0xd100000000006000);
        bytes[0xe000..0xe004].copy_from_slice(&[b'o', 0, b'k', 0]);
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let file = CONSTRAINTS.iter().find(|c| c.tag == b"File").unwrap();
        assert!(windows.address_readable(K + 0x1ffe));
        assert!(windows.address_readable(0xd100000000006000));
        assert_eq!(
            windows.pool_scanner_name(file, 0xc000, false).unwrap(),
            None
        );
        let names: Vec<_> = [0xc000, 0xc100]
            .into_iter()
            .filter_map(|at| windows.pool_scanner_name(file, at, false).unwrap())
            .collect();
        let reference: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-headers.json"
        ))
        .unwrap();
        assert_eq!(
            serde_json::json!(names),
            reference["file_name_fault"]["expected_names"]
        );
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/gui-stations.json"
        ))
        .unwrap();
        for case in vectors["strings"].as_array().unwrap() {
            let data: Vec<_> = case["hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|word| u8::from_str_radix(std::str::from_utf8(word).unwrap(), 16).unwrap())
                .collect();
            let mut named = bytes.clone();
            named[0xc100..0xc102].copy_from_slice(&(data.len() as u16).to_le_bytes());
            named[0xe000..0xe000 + data.len()].copy_from_slice(&data);
            let snapshot = image(&named);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert_eq!(
                serde_json::json!(windows.pool_scanner_name(file, 0xc100, false).unwrap()),
                case["expected"],
                "{case}"
            );
        }
    }

    #[test]
    fn gui_tag_matches_keep_the_exact_unaligned_header_address() {
        let (mut bytes, mut isf) = fixture();
        let field =
            |offset, name| serde_json::json!({"offset":offset,"type":{"kind":"base","name":name}});
        for (name, size) in [("u16", 2), ("u8", 1), ("u32", 4)] {
            isf.data["base_types"][name] = serde_json::json!({"size":size});
        }
        isf.data["user_types"]["_POOL_HEADER"] = serde_json::json!({"size":16,"fields":{"BlockSize":field(0,"u16"),"PoolType":field(2,"u16"),"PoolTag":field(4,"u32")}});
        isf.data["user_types"]["_QUAD"] = serde_json::json!({"size":8,"fields":{}});
        isf.data["user_types"]["_OBJECT_HEADER"] = serde_json::json!({"size":56,"fields":{"Body":{"offset":48,"type":{"kind":"struct","name":"_QUAD"}},"InfoMask":field(26,"u8"),"PointerCount":field(0,"u64")}});
        isf.data["user_types"]["_OBJECT_HEADER_NAME_INFO"] =
            serde_json::json!({"size":32,"fields":{}});
        put(&mut bytes, 0x8200, 15063);
        let at = 0xc003;
        bytes[at..at + 64].fill(0);
        bytes[at..at + 2].copy_from_slice(&16u16.to_le_bytes());
        bytes[at + 2..at + 4].copy_from_slice(&1u16.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(b"Wind");
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let (virtual_scan, bodies, _) = w
            .scan_gui_pool(b"Wind", 152, 0x90, &Job::default())
            .unwrap();
        assert!(virtual_scan);
        assert!(bodies.contains(&(K + 0x4003 + 16 + 48)), "{bodies:x?}");
        assert!(
            !bodies.contains(&(K + 0x4000 + 16 + 48)),
            "must not carve at a different header: {bodies:x?}"
        );
    }
    #[test]
    fn top_down_padding_matches_pinned_signed_subtraction_and_comparison() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/gui-pool-padding.json"
        ))
        .unwrap();
        for c in vectors["cases"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            isf.data["base_types"]["u8"] = serde_json::json!({"size":1});
            isf.data["user_types"]["_POOL_HEADER"] = serde_json::json!({"size":16,"fields":{}});
            isf.data["user_types"]["_QUAD"] = serde_json::json!({"size":8,"fields":{}});
            isf.data["user_types"]["_OBJECT_HEADER"] = serde_json::json!({"size":56,"fields":{"Body":{"offset":48,"type":{"kind":"struct","name":"_QUAD"}},"InfoMask":{"offset":26,"type":{"kind":"base","name":"u8"}},"PointerCount":{"offset":0,"type":{"kind":"base","name":"u64"}}}});
            bytes[0xc000..0xc080].fill(0);
            bytes[0xc01c..0xc020]
                .copy_from_slice(&(c["encoded_padding"].as_u64().unwrap() as u32).to_le_bytes());
            bytes[0xc03a] = 2;
            let img = image(&bytes);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let constraint = Constraint::new(
                b"Wind",
                "tagWINDOWSTATION",
                Some("WindowStation"),
                0,
                3,
                true,
                &[],
            );
            let found = w
                .pool_bodies(
                    &constraint,
                    K + 0x4000,
                    PoolCarve {
                        block: 128,
                        alignment: 16,
                        type_size: 152,
                        top_down: true,
                        optional: &[(false, 32), (true, 4)],
                        virtual_scan: true,
                    },
                    &Job::default(),
                )
                .unwrap();
            let relative: Vec<_> = found.into_iter().map(|at| at - (K + 0x4000)).collect();
            assert_eq!(serde_json::json!(relative), c["expected_bodies"]);
        }
    }
    #[test]
    fn physical_pool_scan_keeps_valid_process_and_reports_unreadable_ranges() {
        let (mut bytes, mut isf) = fixture();
        let field = |offset, name| json!({"offset":offset,"type":{"kind":"base","name":name}});
        for (name, size) in [("u32", 4), ("u16", 2), ("u8", 1)] {
            isf.data["base_types"][name] = json!({"size":size});
        }
        isf.data["symbols"]["NtBuildNumber"] = json!({"address":0x200});
        put(&mut bytes, 0x8200, 3790);
        for (name, size, fields) in [
            (
                "_POOL_HEADER",
                16,
                json!({"BlockSize":field(0,"u16"),"PoolType":field(2,"u16"),"PoolTag":field(4,"u32")}),
            ),
            (
                "_OBJECT_HEADER",
                16,
                json!({"Body":{"offset":8,"type":{"kind":"struct","name":"_QUAD"}}}),
            ),
            (
                "_RTL_ATOM_TABLE",
                208,
                json!({"NumberOfBuckets":field(0,"u32")}),
            ),
            (
                "_EPROCESS",
                640,
                json!({"UniqueProcessId":field(32,"u64"),"ImageFileName":{"offset":48,"type":{"kind":"array","count":16}},"CreateTime":field(88,"u64"),"ExitTime":field(96,"u64"),"Pcb":{"offset":112,"type":{"kind":"struct","name":"_KPROCESS"}},"ThreadListHead":{"offset":128,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}),
            ),
            (
                "_ETHREAD",
                640,
                json!({"Cid":{"offset":0,"type":{"kind":"struct","name":"_CLIENT_ID"}},"CreateTime":field(32,"u64")}),
            ),
            (
                "_CLIENT_ID",
                16,
                json!({"UniqueProcess":field(0,"u64"),"UniqueThread":field(8,"u64")}),
            ),
            (
                "_FILE_OBJECT",
                160,
                json!({"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}),
            ),
            ("_KMUTANT", 64, json!({"Header":field(0,"u64")})),
            ("_DRIVER_OBJECT", 256, json!({"DriverStart":field(0,"u64")})),
            (
                "_DRIVER_EXTENSION",
                16,
                json!({"DriverObject":field(0,"u64")}),
            ),
            (
                "_LDR_DATA_TABLE_ENTRY",
                80,
                json!({"DllBase":field(0,"u64")}),
            ),
            (
                "_OBJECT_SYMBOLIC_LINK",
                80,
                json!({"CreationTime":field(0,"u64")}),
            ),
            (
                "_CMHIVE",
                816,
                json!({"Hive":{"offset":0,"type":{"kind":"struct","name":"_HHIVE"}}}),
            ),
            ("_HHIVE", 8, json!({"Signature":field(0,"u32")})),
            ("_QUAD", 8, json!({})),
        ] {
            isf.data["user_types"][name] = json!({"size":size,"fields":fields});
        }
        bytes[0xc000..0xc002].copy_from_slice(&41u16.to_le_bytes());
        bytes[0xc002..0xc004].copy_from_slice(&1u16.to_le_bytes());
        bytes[0xc004..0xc008].copy_from_slice(&[b'P', b'r', b'o', 0xe3]);
        bytes[0xc000 + 16 + 32..0xc000 + 16 + 40].copy_from_slice(&4u64.to_le_bytes());
        bytes[0xc000 + 16 + 48..0xc000 + 16 + 54].copy_from_slice(b"System");
        bytes[0xc000 + 16 + 112..0xc000 + 16 + 120].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[0xc000 + 16 + 128..0xc000 + 16 + 136].copy_from_slice(&(K + 0x1000).to_le_bytes());
        bytes[0xc000 + 16 + 136..0xc000 + 16 + 144].copy_from_slice(&(K + 0x1000).to_le_bytes());
        let image = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let result = windows.pool_scanner(&Job::default()).unwrap();
        assert_eq!(result.rows.len(), 1, "{:#?}", result);
        assert_eq!(result.rows[0][0], "symbol_table_name1!_EPROCESS");
        assert_eq!(result.rows[0][2], "memory_layer");
        assert_eq!(result.rows[0][3], "System");
        assert!(result.columns == ["Tag", "Offset", "Layer", "Name"]);
        assert!(result.complete);
        // A later atom tag must not jump ahead of the earlier process merely
        // because its constraint appears first in the builtin list.
        let mut mixed = bytes.clone();
        mixed[0xc400..0xc402].copy_from_slice(&13u16.to_le_bytes());
        mixed[0xc404..0xc408].copy_from_slice(b"AtmT");
        let snapshot = super::super::tests::image(&mixed);
        let native = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let ordered = native.pool_scanner(&Job::default()).unwrap();
        assert_eq!(
            ordered
                .rows
                .iter()
                .map(|row| row[0].as_str())
                .collect::<Vec<_>>(),
            [
                "symbol_table_name1!_EPROCESS",
                "symbol_table_name1!_RTL_ATOM_TABLE"
            ]
        );

        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/pool-headers.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let offset = case["header_offset"].as_u64().unwrap() as usize;
            let mut shifted = bytes.clone();
            shifted[0xc000..0xc400].fill(0);
            let expected_type = if case["tag_hex"] == "50726fe3" {
                shifted[0xc000 + offset..0xc300 + offset].copy_from_slice(&bytes[0xc000..0xc300]);
                "symbol_table_name1!_EPROCESS"
            } else {
                shifted[0xc000 + offset..0xc002 + offset].copy_from_slice(&13u16.to_le_bytes());
                shifted[0xc004 + offset..0xc008 + offset].copy_from_slice(b"AtmT");
                "symbol_table_name1!_RTL_ATOM_TABLE"
            };
            let snapshot = super::super::tests::image(&shifted);
            let native = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            }
            .pool_scanner(&Job::default())
            .unwrap();
            let expected: Vec<_> = case["expected_headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|at| hex(0xc000 + at.as_u64().unwrap()))
                .collect();
            assert_eq!(
                native.rows.iter().map(|r| r[1].clone()).collect::<Vec<_>>(),
                expected,
                "{case}"
            );
            assert!(native.rows.iter().all(|r| r[0] == expected_type));
        }
    }
}
