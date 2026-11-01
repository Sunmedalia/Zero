//! Canonical pool scanner: every built-in kernel tag, scanned in the version's layer.
use super::*;
use crate::bytes::le_u32;
use memchr::memmem;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

mod tables;
mod validation;
use tables::*;

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
        let tag = usize::try_from(self.vm.isf.offset("_POOL_HEADER", "PoolTag")?)?;
        ensure!(tag + 4 <= usize::try_from(size)?, "PoolTag 越界");
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
        let info = usize::try_from(self.vm.isf.offset("_OBJECT_HEADER", "InfoMask")?)?;
        let pointer = usize::try_from(self.vm.isf.offset("_OBJECT_HEADER", "PointerCount")?)?;
        let pointer_size = self.vm.isf.size("_OBJECT_HEADER", "PointerCount")?;
        ensure!(matches!(pointer_size, 4 | 8), "PointerCount 宽度无效");
        let window_length = usize::try_from(limit)?
            .checked_add(info)
            .context("对象头扫描窗口溢出")?;
        let mut window = vec![0u8; window_length];
        self.pool_read_padded(start, &mut window, virtual_scan)?;
        let mut found = Vec::new();
        for delta in (0..limit).step_by(usize::try_from(alignment)?) {
            job.check()?;
            let count_at = usize::try_from(delta)? + pointer;
            let Some(slice) = window.get(count_at..count_at + pointer_size) else {
                continue;
            };
            let mut raw = [0u8; 8];
            raw[..pointer_size].copy_from_slice(slice);
            let count = u64::from_le_bytes(raw);
            let signed = if pointer_size == 8 {
                count as i64
            } else {
                i64::from(crate::bytes::low_u32(count) as i32)
            };
            if !(0..0x1000000).contains(&signed) {
                continue;
            }
            let Some(&mask) = window.get(usize::try_from(delta)? + info) else {
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
                let Some(at) = usize::try_from(delta)?.checked_sub(usize::try_from(selected)?)
                else {
                    continue;
                };
                let Some(encoded) = le_u32(&window, at).map(u64::from) else {
                    continue;
                };
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
}

#[cfg(test)]
mod tests;
