//! Canonical pool scanner: every built-in kernel tag, scanned in the version's layer.
use super::*;
use memchr::memmem;
use objects::physical_number;
use std::collections::BTreeMap;

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

struct PoolCarve<'a> {
    block: u64,
    alignment: u64,
    type_size: u64,
    top_down: bool,
    optional: &'a [(bool, u64)],
    virtual_scan: bool,
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
        let (tag_offset, header_size) = self.pool_header_layout()?;
        let sizes = self.pool_type_sizes()?;
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
        for (start, length) in self.pool_scan_ranges(virtual_scan, job)? {
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
            let position = start;
            {
                for constraint in CONSTRAINTS {
                    let Some(&type_size) = sizes.get(constraint.type_name) else {
                        continue;
                    };
                    let finder = memmem::Finder::new(constraint.tag);
                    let mut from = 0;
                    while let Some(at) = finder.find(&data[from..]) {
                        job.check()?;
                        let tag = from + at;
                        from = tag + 1;
                        let Some(mut local) = tag.checked_sub(tag_offset) else {
                            continue;
                        };
                        // Executive pool headers are aligned, but non-executive
                        // records follow the reference scan and keep every tag hit.
                        if constraint.object_type.is_some() {
                            local -= local % alignment as usize;
                        }
                        if !local.is_multiple_of(alignment as usize)
                            || local + header_size as usize > data.len()
                        {
                            continue;
                        }
                        let bytes = &data[local..local + header_size as usize];
                        let Ok(block) =
                            physical_number(self.vm.isf, bytes, "_POOL_HEADER", "BlockSize")
                        else {
                            continue;
                        };
                        let Some(size) = block.checked_mul(alignment) else {
                            continue;
                        };
                        if size < constraint.minimum {
                            continue;
                        }
                        if self.vm.isf.has_field("_POOL_HEADER", "PoolType") {
                            let Ok(page) =
                                physical_number(self.vm.isf, bytes, "_POOL_HEADER", "PoolType")
                            else {
                                continue;
                            };
                            let paged = page > 0 && page % 2 == if vista { 1 } else { 0 };
                            let nonpaged = page > 0 && page % 2 == if vista { 0 } else { 1 };
                            let accepted = page == 0 && constraint.page & 4 != 0
                                || paged && constraint.page & 1 != 0
                                || nonpaged && constraint.page & 2 != 0;
                            if !accepted {
                                continue;
                            }
                        }
                        let address = position + local as u64;
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
                                result,
                                &mut diagnostics,
                            )? {
                                continue;
                            }
                            let Some(name) =
                                self.pool_scanner_name(constraint, body, virtual_scan)?
                            else {
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
            return self
                .vm
                .image
                .segments
                .iter()
                .map(|segment| {
                    Ok((
                        segment.start,
                        segment
                            .end
                            .checked_sub(segment.start)
                            .context("物理区段下溢")?,
                    ))
                })
                .collect();
        }
        let geometry = self.vm.paging()?;
        let mut ranges = Vec::new();
        let mut current: Option<(u64, u64, u64)> = None;
        let flush = |ranges: &mut Vec<(u64, u64)>, current: &mut Option<(u64, u64, u64)>| {
            if let Some((start, end, _)) = current.take() {
                ranges.push((start, end - start));
            }
        };
        self.walk_kernel_pages(self.vm.root, 0, 0, &geometry, &mut |va, physical, shift| {
            job.check()?;
            let size = 1u64 << shift;
            let page = physical & !(size - 1);
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
        Ok(ranges)
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
        let mut bytes = vec![0u8; entries * width];
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
        for (index, entry_bytes) in bytes.chunks_exact(width).enumerate() {
            if level == 0 && index < entries / 2 {
                continue;
            }
            let mut raw = [0u8; 8];
            raw[..width].copy_from_slice(entry_bytes);
            let entry = u64::from_le_bytes(raw);
            if entry & 1 == 0 && !(entry & (1 << 11) != 0 && entry & (1 << 10) == 0) {
                continue;
            }
            let frame = if entry & 1 == 0 {
                self.vm.transition_frame(entry, *geometry)?
            } else if geometry.block(entry, shift) && shift > 12 {
                entry & geometry.mask() & !((1u64 << shift) - 1) & !0x1000
            } else {
                entry & geometry.mask()
            };
            let relative = prefix | (index as u64) << shift;
            if geometry.block(entry, shift) || shift == 12 {
                visit(geometry.extend(relative), frame, shift)?;
            } else if level + 1 < geometry.shifts().len()
                && !(geometry.arch == Architecture::X64 && level == 0 && frame == table)
            {
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
            .checked_add(info.max(pointer))
            .and_then(|value| value.checked_add(pointer_size))
            .context("对象头扫描窗口溢出")?;
        let mut window = vec![0u8; window_length];
        if self.pool_read(start, &mut window, virtual_scan).is_err() {
            return Ok(Vec::new());
        }
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
        let build = self.build_number()?;
        let virtual_scan = build >= 10240;
        let top_down = build >= 9200;
        let vista = build >= 6000;
        let alignment = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let (tag_offset, header_size) = self.pool_header_layout()?;
        let optional = if top_down {
            self.pool_optional_headers()?
        } else {
            Vec::new()
        };
        let constraint = Constraint::new(
            tag,
            "tagWINDOWSTATION",
            Some("WindowStation"),
            minimum,
            3,
            true,
            &[],
        );
        let mut bodies = Vec::new();
        let mut notes = Vec::new();
        for (start, length) in self.pool_scan_ranges(virtual_scan, job)? {
            job.check()?;
            let mut data =
                vec![0u8; usize::try_from(length).context("pool 扫描范围超出地址空间")?];
            if self.pool_read(start, &mut data, virtual_scan).is_err() {
                notes.push(format!("pool range {start:#x}+{length:#x} 不可读"));
                continue;
            }
            let finder = memmem::Finder::new(constraint.tag);
            let mut from = 0;
            while let Some(at) = finder.find(&data[from..]) {
                job.check()?;
                let tag_at = from + at;
                from = tag_at + 1;
                let Some(local) = tag_at.checked_sub(tag_offset) else {
                    continue;
                };
                // The fixed scanner reads the header exactly before the matched tag.
                // Rounding this address down associates the tag with unrelated bytes.
                if local + header_size as usize > data.len() {
                    continue;
                }
                let bytes = &data[local..local + header_size as usize];
                let Ok(block) = physical_number(self.vm.isf, bytes, "_POOL_HEADER", "BlockSize")
                else {
                    continue;
                };
                let Some(size) = block.checked_mul(alignment) else {
                    continue;
                };
                if size < constraint.minimum {
                    continue;
                }
                if self.vm.isf.has_field("_POOL_HEADER", "PoolType") {
                    let Ok(page) = physical_number(self.vm.isf, bytes, "_POOL_HEADER", "PoolType")
                    else {
                        continue;
                    };
                    let paged = page > 0 && page % 2 == if vista { 1 } else { 0 };
                    let nonpaged = page > 0 && page % 2 == if vista { 0 } else { 1 };
                    let accepted = page == 0 && constraint.page & 4 != 0
                        || paged && constraint.page & 1 != 0
                        || nonpaged && constraint.page & 2 != 0;
                    if !accepted {
                        continue;
                    }
                }
                let address = start + local as u64;
                let found = self.pool_bodies(
                    &constraint,
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
                        notes.push("窗口站池候选超限".into());
                        return Ok((virtual_scan, bodies, notes));
                    }
                    bodies.push(body);
                }
            }
        }
        Ok((virtual_scan, bodies, notes))
    }

    pub(super) fn pool_read(&self, address: u64, out: &mut [u8], virtual_scan: bool) -> Result<()> {
        if virtual_scan {
            self.vm.read(address, out)
        } else {
            self.vm.image.read(address, out)
        }
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
                let found = if virtual_scan {
                    self.object_type(header, &self.object_header_layout())?
                } else {
                    self.physical_object_type(header)?
                };
                if found != kind {
                    return Ok(false);
                }
            }
            Ok(match constraint.type_name {
                "_EPROCESS" => self.pool_process_valid(body, virtual_scan)?,
                "_ETHREAD" => self.pool_thread_valid(body, virtual_scan)?,
                "_FILE_OBJECT" => {
                    let length =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Length", virtual_scan)?;
                    let buffer =
                        self.pool_value(body, "_FILE_OBJECT", "FileName.Buffer", virtual_scan)?;
                    length > 0 && self.address_readable(buffer)
                }
                "_CMHIVE" => {
                    self.pool_value(body, "_CMHIVE", "Hive.Signature", virtual_scan)? == 0xBEE0BEE0
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

    fn address_readable(&self, address: u64) -> bool {
        self.vm.kernel(address) && self.vm.translate(address).is_ok()
    }

    fn pool_year(ticks: u64) -> Option<i64> {
        let seconds = ticks.checked_div(10_000_000)?.checked_sub(11_644_473_600)?;
        Some(1970 + seconds as i64 / 31_557_600)
    }

    fn pool_process_valid(&self, body: u64, virtual_scan: bool) -> Result<bool> {
        let layout = self.vm.isf.layout("_EPROCESS", "ImageFileName")?;
        let mut bytes = vec![0u8; layout.size as usize];
        self.pool_read(add(body, layout.offset)?, &mut bytes, virtual_scan)?;
        if bytes.first().is_none_or(|byte| *byte == 0) {
            return Ok(false);
        }
        let pid = self.pool_value(body, "_EPROCESS", "UniqueProcessId", virtual_scan)?;
        if pid == 0 || pid % 4 != 0 || pid > 0xffff_fffc {
            return Ok(false);
        }
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        let system = bytes[..end] == *b"System" && pid == 4;
        if !system {
            let created = self.pool_value(body, "_EPROCESS", "CreateTime", virtual_scan)?;
            let Some(year) = Self::pool_year(created) else {
                return Ok(false);
            };
            if !(1998 < year && year < 2036) {
                return Ok(false);
            }
            let exited = self.pool_value(body, "_EPROCESS", "ExitTime", virtual_scan)?;
            if exited != 0
                && let Some(exit_year) = Self::pool_year(exited)
                && (!(1998 < exit_year && exit_year < 2036) || exited < created)
            {
                return Ok(false);
            }
        }
        let dtb = self.pool_value(body, "_EPROCESS", "Pcb.DirectoryTableBase", virtual_scan)?
            & self.vm.root_mask();
        if dtb == 0 || dtb & !0xfff == 0 {
            return Ok(false);
        }
        let flink = self.pool_value(body, "_EPROCESS", "ThreadListHead.Flink", virtual_scan)?;
        let blink = self.pool_value(body, "_EPROCESS", "ThreadListHead.Blink", virtual_scan)?;
        Ok(flink >= 0x8000_0000 && blink >= 0x8000_0000)
    }

    fn pool_thread_valid(&self, body: u64, virtual_scan: bool) -> Result<bool> {
        let pid = self.pool_value(body, "_ETHREAD", "Cid.UniqueProcess", virtual_scan)?;
        let tid = self.pool_value(body, "_ETHREAD", "Cid.UniqueThread", virtual_scan)?;
        if pid % 4 != 0 || tid % 4 != 0 {
            return Ok(false);
        }
        if pid != 4 {
            let mut created = self.pool_value(body, "_ETHREAD", "CreateTime", virtual_scan)?;
            if self.vm.isf.has_field("_ETHREAD", "ThreadsProcess") {
                created >>= 3;
            }
            let Some(year) = Self::pool_year(created) else {
                return Ok(false);
            };
            if !(1998 < year && year < 2036) {
                return Ok(false);
            }
        }
        Ok(true)
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
                let length =
                    self.pool_value(body, "_FILE_OBJECT", "FileName.Length", virtual_scan)?;
                let buffer =
                    self.pool_value(body, "_FILE_OBJECT", "FileName.Buffer", virtual_scan)?;
                let mut bytes = vec![0u8; length as usize];
                self.vm.read(buffer, &mut bytes)?;
                let units = bytes
                    .chunks_exact(2)
                    .map(|word| u16::from_le_bytes([word[0], word[1]]))
                    .collect::<Vec<_>>();
                let end = units
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(units.len());
                Ok(Some(String::from_utf16_lossy(&units[..end])))
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
    }
}
