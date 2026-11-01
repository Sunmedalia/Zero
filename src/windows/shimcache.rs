//! windows.shimcachemem.ShimcacheMem: the in-memory ahcache/ntoskrnl LRU list.
use super::*;
use crate::bytes::Checked as _;

struct ShimLayout {
    /// 8.1+ looks in ahcache.sys; earlier builds look in the NT kernel.
    ahcache: bool,
    /// Windows 8 x64 uses the first handle; every later x64 build uses the second.
    second_handle: bool,
    avl_size: u64,
    allocate: u64,
    compare: u64,
    free: u64,
    path: u64,
    detail: Option<u64>,
    last_modified: u64,
    insert_flags: Option<u64>,
    blob_size: Option<u64>,
    blob_buffer: Option<u64>,
    file_size: Option<u64>,
    last_update: Option<u64>,
}

impl ShimLayout {
    fn x64(version: [u16; 4]) -> Result<Self> {
        let (major, minor, build) = (version[0], version[1], version[2]);
        let _ = build;
        if major >= 10 {
            return Ok(Self {
                ahcache: true,
                second_handle: true,
                avl_size: 104,
                allocate: 80,
                compare: 72,
                free: 88,
                path: 24,
                detail: Some(40),
                last_modified: 8,
                insert_flags: None,
                blob_size: Some(16),
                blob_buffer: Some(24),
                file_size: None,
                last_update: None,
            });
        }
        if major == 6 && minor >= 2 {
            return Ok(Self {
                ahcache: minor >= 3,
                second_handle: minor >= 3,
                avl_size: 104,
                allocate: 80,
                compare: 72,
                free: 88,
                path: 24,
                detail: Some(56),
                last_modified: 0,
                insert_flags: Some(8),
                blob_size: None,
                blob_buffer: None,
                file_size: None,
                last_update: None,
            });
        }
        if major == 6 && minor == 1 {
            return Ok(Self {
                ahcache: false,
                second_handle: false,
                avl_size: 104,
                allocate: 80,
                compare: 72,
                free: 88,
                path: 16,
                detail: None,
                last_modified: 32,
                insert_flags: None,
                blob_size: None,
                blob_buffer: None,
                file_size: None,
                last_update: None,
            });
        }
        if major == 6 {
            return Ok(Self {
                ahcache: false,
                second_handle: false,
                avl_size: 104,
                allocate: 80,
                compare: 72,
                free: 88,
                path: 16,
                detail: None,
                last_modified: 32,
                insert_flags: Some(40),
                blob_size: None,
                blob_buffer: None,
                file_size: None,
                last_update: None,
            });
        }
        bail!("该 Windows 版本没有已发布的 x64 shimcache 布局")
    }
}

impl Windows<'_> {
    pub(super) fn shimcache_memory(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinShimcacheMem);
        let arch = Architecture::from_isf(self.vm.isf)?;
        ensure!(
            arch == Architecture::X64,
            "shimcachemem 目前只实现已发布的 x64 布局"
        );
        let layout = ShimLayout::x64(self.declared_kernel_version()?)?;
        let names: &[&str] = if layout.ahcache {
            &["ahcache.sys"]
        } else {
            &[
                "ntoskrnl.exe",
                "ntkrnlmp.exe",
                "ntkrnlpa.exe",
                "ntkrpamp.exe",
                "ntkrnlmp.exe",
            ]
        };
        let Some((base, _)) = self.named_module(names, job)? else {
            Self::issue(&mut r, "module", "没有找到 shimcache 所在模块");
            return Ok(r);
        };
        let Some((data, data_size)) = self.pe_section(base, ".data")? else {
            bail!("模块缺少 .data 节");
        };
        let Some((page, page_size)) = self.pe_section(base, "PAGE")? else {
            bail!("模块缺少 PAGE 节");
        };
        let page_end = add(page, page_size)?;
        let mut offset = data;
        let end = add(data, data_size)?;
        let head = if layout.ahcache {
            let mut heads = Vec::new();
            while offset + 8 <= end && heads.len() < 2 {
                job.check()?;
                if let Some(found) = self.shim_head(offset, &layout, page, page_end, true) {
                    heads.push(found);
                }
                offset += 8;
            }
            let index = if layout.second_handle { 1 } else { 0 };
            heads.get(index).copied()
        } else {
            let mut found = None;
            while offset + 16 <= end {
                job.check()?;
                if let Ok(candidate) = self.shim_probe(offset, &layout, page, page_end) {
                    found = Some(candidate);
                    break;
                }
                offset += 8;
            }
            found
        };
        let Some(head) = head else {
            Self::issue(&mut r, hex(base), "没有找到有效的 shimcache 链表");
            return Ok(r);
        };
        let mut current = self.vm.pointer(head).unwrap_or(0);
        let mut guard = HashSet::new();
        let mut order = 0u64;
        while self.vm.kernel(current) && current != head && guard.insert(current) && order < 4096 {
            job.check()?;
            if let Some(row) = self.shim_entry(current, &layout, order) {
                r.rows.push(row);
                order += 1;
            }
            current = self.vm.pointer(current).unwrap_or(0);
        }
        Ok(r)
    }

    fn named_module(&self, names: &[&str], job: &Job) -> Result<Option<(u64, u64)>> {
        let module_type = self.module_type()?;
        let (modules, _) = self.list_partial(
            self.symbol("PsLoadedModuleList")?,
            self.vm.isf.offset(module_type, "InLoadOrderLinks")?,
            job,
        )?;
        for module in modules {
            let name = self
                .vm
                .unicode(self.field(module, module_type, "BaseDllName")?)
                .unwrap_or_default();
            let kernel = name.to_ascii_lowercase().starts_with("ntkr");
            if names.iter().any(|wanted| name.eq_ignore_ascii_case(wanted)) || kernel {
                return Ok(Some((
                    self.number(module, module_type, "DllBase")?,
                    self.number(module, module_type, "SizeOfImage")?,
                )));
            }
        }
        Ok(None)
    }

    fn pe_section(&self, base: u64, wanted: &str) -> Result<Option<(u64, u64)>> {
        let mut header = [0; 4096];
        self.vm.read(base, &mut header)?;
        let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
        ensure!(header.at(pe..pe + 4)? == b"PE\0\0", "PE 签名无效");
        let optional = pe + 24;
        let magic = u16::from_le_bytes(header.at(optional..optional + 2)?.try_into()?);
        let data_directories = if magic == 0x20b { 112 } else { 96 };
        let section_offset = optional + data_directories + 16;
        // NumberOfRvaAndSizes is immediately before the section table only after SizeOfOptionalHeader.
        let size_optional = u16::from_le_bytes(header.at(pe + 20..pe + 22)?.try_into()?) as usize;
        let sections = pe + 24 + size_optional;
        let count = u16::from_le_bytes(header.at(pe + 6..pe + 8)?.try_into()?) as usize;
        ensure!(count <= 96, "PE 节数量无效");
        let _ = section_offset;
        for index in 0..count {
            let at = sections + index * 40;
            let record = header.get(at..at + 40).context("PE 节表超出已读头部")?;
            let name_end = record.at(..8)?.iter().position(|b| *b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(record.at(..name_end)?);
            if !name.eq_ignore_ascii_case(wanted) {
                continue;
            }
            let virtual_size = u32::from_le_bytes(record.at(8..12)?.try_into()?) as u64;
            let virtual_address = u32::from_le_bytes(record.at(12..16)?.try_into()?) as u64;
            return Ok(Some((add(base, virtual_address)?, virtual_size)));
        }
        Ok(None)
    }

    fn shim_probe(
        &self,
        offset: u64,
        layout: &ShimLayout,
        page: u64,
        page_end: u64,
    ) -> std::result::Result<u64, usize> {
        let Ok(slot) = add(offset, 8) else {
            return Err(0);
        };
        let Ok(table) = self.vm.pointer(slot) else {
            return Err(0);
        };
        if !self.vm.kernel(table) {
            return Err(1);
        }
        let Ok(parent) = self.vm.pointer(table) else {
            return Err(2);
        };
        if parent != table {
            return Err(2);
        }
        let in_page = |value: u64| value >= page && value < page_end;
        let Ok(allocate_at) = add(table, layout.allocate) else {
            return Err(3);
        };
        let Ok(compare_at) = add(table, layout.compare) else {
            return Err(3);
        };
        let Ok(free_at) = add(table, layout.free) else {
            return Err(3);
        };
        let (Ok(allocate), Ok(compare), Ok(free)) = (
            self.vm.pointer(allocate_at),
            self.vm.pointer(compare_at),
            self.vm.pointer(free_at),
        ) else {
            return Err(3);
        };
        if !in_page(allocate)
            || !in_page(compare)
            || allocate == compare
            || allocate == free
            || compare == free
        {
            return Err(3);
        }
        let Ok(head) = add(table, layout.avl_size) else {
            return Err(4);
        };
        let Ok(flink) = self.vm.pointer(head) else {
            return Err(4);
        };
        let Ok(blink_at) = add(head, 8) else {
            return Err(4);
        };
        let Ok(blink) = self.vm.pointer(blink_at) else {
            return Err(4);
        };
        if flink == 0 || !self.vm.kernel(flink) || !self.vm.kernel(blink) || flink == blink {
            return Err(4);
        }
        Ok(head)
    }

    fn shim_head(
        &self,
        offset: u64,
        layout: &ShimLayout,
        page: u64,
        page_end: u64,
        indirect: bool,
    ) -> Option<u64> {
        // Windows 8.1+ stores pointers to handles. Older builds store the handle inline.
        let slot = if indirect {
            let handle = self.vm.pointer(offset).ok()?;
            if !self.vm.kernel(handle) {
                return None;
            }
            handle
        } else {
            offset
        };
        let table = self.vm.pointer(add(slot, 8).ok()?).ok()?;
        if !self.vm.kernel(table) {
            return None;
        }
        let parent = self.vm.pointer(table).ok()?;
        if parent != table {
            return None;
        }
        let in_page = |value: u64| value >= page && value < page_end;
        let allocate = self.vm.pointer(add(table, layout.allocate).ok()?).ok()?;
        let compare = self.vm.pointer(add(table, layout.compare).ok()?).ok()?;
        let free = self.vm.pointer(add(table, layout.free).ok()?).ok()?;
        if !in_page(allocate)
            || !in_page(compare)
            || allocate == compare
            || allocate == free
            || compare == free
        {
            return None;
        }
        let head = add(table, layout.avl_size).ok()?;
        let flink = self.vm.pointer(head).ok()?;
        let blink = self.vm.pointer(add(head, 8).ok()?).ok()?;
        if flink == 0 || !self.vm.kernel(flink) || !self.vm.kernel(blink) || flink == blink {
            return None;
        }
        let back = self.vm.pointer(add(flink, 8).ok()?).unwrap_or(0);
        if back != head {
            return None;
        }
        Some(head)
    }

    fn shim_entry(&self, address: u64, layout: &ShimLayout, order: u64) -> Option<Vec<String>> {
        let path = self.shim_path(add(address, layout.path).ok()?)?;
        if path.is_empty() || path.chars().any(char::is_control) {
            return None;
        }
        let detail = layout
            .detail
            .and_then(|offset| self.vm.pointer(add(address, offset).ok()?).ok())
            .filter(|value| self.vm.kernel(*value));
        let time_at = if layout.detail.is_some() {
            detail.and_then(|base| add(base, layout.last_modified).ok())
        } else {
            add(address, layout.last_modified).ok()
        };
        let modified = time_at
            .and_then(|at| self.vm.uint(at, 8).ok())
            .filter(|ticks| *ticks != 0)
            .map(crate::windows::timeline::filetime_utc)
            .unwrap_or_default();
        let exec = if let Some(offset) = layout.insert_flags {
            let at = detail
                .map(|base| add(base, offset))
                .unwrap_or_else(|| add(address, offset));
            match at.and_then(|at| self.vm.uint(at, 4)) {
                Ok(flags) => {
                    if flags & 2 == 2 {
                        "True"
                    } else {
                        "False"
                    }
                }
                Err(_) => "-",
            }
        } else if let (Some(size_off), Some(buffer_off), Some(base)) =
            (layout.blob_size, layout.blob_buffer, detail)
        {
            let size = self.vm.uint(add(base, size_off).ok()?, 4).ok()?;
            let buffer = self.vm.uint(add(base, buffer_off).ok()?, 8).ok()?;
            if size == 4 && self.vm.kernel(buffer) {
                match self.vm.uint(buffer, 4) {
                    Ok(flag) => {
                        if flag != 0 {
                            "True"
                        } else {
                            "False"
                        }
                    }
                    Err(_) => "-",
                }
            } else {
                "-"
            }
        } else {
            "N/A"
        };
        let file_size = if let Some(offset) = layout.file_size {
            self.vm
                .uint(add(address, offset).ok()?, 8)
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|_| "-".into())
        } else {
            "N/A".into()
        };
        let updated = if let Some(offset) = layout.last_update {
            self.vm
                .uint(add(address, offset).ok()?, 8)
                .ok()
                .filter(|ticks| *ticks != 0)
                .map(crate::windows::timeline::filetime_utc)
                .unwrap_or_default()
        } else {
            "N/A".into()
        };
        Some(vec![
            order.to_string(),
            modified,
            updated,
            exec.into(),
            file_size,
            path,
        ])
    }

    fn shim_path(&self, address: u64) -> Option<String> {
        let length = usize::try_from(self.vm.uint(address, 2).ok()?).ok()?;
        let buffer = self.vm.pointer(add(address, 8).ok()?).ok()?;
        if length == 0 || length > 1024 || !length.is_multiple_of(2) || !self.vm.kernel(buffer) {
            return None;
        }
        let mut bytes = vec![0; length];
        self.vm.read(buffer, &mut bytes).ok()?;
        Some(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}
