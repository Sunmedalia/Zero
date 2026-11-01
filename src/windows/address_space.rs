//! Windows virtual address translation over a read-only image.
use super::*;

/// Independent Windows translation; software PTEs never change Linux semantics.
pub struct Memory<'a> {
    pub image: &'a Image,
    pub root: u64,
    pub isf: &'a Isf,
    pub sources: Option<&'a paging::Sources>,
    /// Paging geometry is fixed for this ISF. Callers mutate ISF layouts only before the first translation.
    pub(super) paging: std::sync::OnceLock<Paging>,
    /// Virtual 4 KiB page → physical 4 KiB page and mapping shift. The image is read-only.
    pub(super) pages: std::sync::Mutex<crate::resources::Lru<u64, (u64, u32)>>,
    /// Immutable captured Intel tables: cache both valid and rejected pages.
    pub(super) tables: std::sync::Mutex<crate::resources::Lru<u64, bool>>,
}
impl<'a> Memory<'a> {
    pub(crate) fn new(
        image: &'a Image,
        root: u64,
        isf: &'a Isf,
        sources: Option<&'a paging::Sources>,
    ) -> Self {
        Self {
            image,
            root,
            isf,
            sources,
            paging: std::sync::OnceLock::new(),
            tables: std::sync::Mutex::new(crate::resources::Lru::new(
                image.limits.page_cache_entries.min(1025),
            )),
            pages: std::sync::Mutex::new(crate::resources::Lru::new(
                image.limits.page_cache_entries,
            )),
        }
    }
    pub(super) fn paging(&self) -> Result<Paging> {
        if let Some(paging) = self.paging.get() {
            return Ok(*paging);
        }
        let paging = Paging::new(self.isf)?;
        Ok(*self.paging.get_or_init(|| paging))
    }
    pub(super) fn pointer_size(&self) -> usize {
        // A Memory is built from an ISF already validated by Paging::new; translation
        // reports any failure, so this default never reaches a successful read.
        self.paging().map_or(8, |paging| paging.arch.pointer_size())
    }
    pub(super) fn pointer(&self, address: u64) -> Result<u64> {
        self.uint(address, self.pointer_size())
    }
    pub(super) fn kernel(&self, address: u64) -> bool {
        self.paging()
            .is_ok_and(|paging| paging.arch.kernel(address))
    }
    pub(super) fn root_mask(&self) -> u64 {
        self.paging().map_or(u64::MAX, |paging| paging.root_mask())
    }
    pub fn translate(&self, va: u64) -> Result<u64> {
        self.translate_span(va).map(|(physical, _)| physical)
    }
    pub(super) fn translate_span(&self, va: u64) -> Result<(u64, u64)> {
        let va = self.paging()?.translation_address(va);
        let page = va & !4095;
        let cached = self
            .pages
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&page)
            .copied();
        let (physical, shift) = if let Some((base, shift)) = cached {
            (base | (va & 4095), shift)
        } else {
            let (physical, shift) = self.translate_walk(va)?;
            self.pages
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(page, (physical & !4095, shift), 1);
            (physical, shift)
        };
        Ok((physical, (1u64 << shift) - (va & ((1u64 << shift) - 1))))
    }
    pub(super) fn captured_table_entry(
        &self,
        geometry: Paging,
        table: u64,
        index: usize,
    ) -> Result<u64> {
        if geometry.arch == Architecture::Arm64 {
            return geometry.entry(self.image, table, index);
        }
        let cached = self
            .tables
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&table)
            .copied();
        let valid = match cached {
            Some(valid) => valid,
            None => {
                let mut bytes = [0; 4096];
                let valid = self.image.read(table, &mut bytes).is_ok()
                    && !bytes
                        .chunks_exact(geometry.width())
                        .all(|entry| entry == &bytes[..geometry.width()]);
                self.tables
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(table, valid, 1);
                valid
            }
        };
        ensure!(valid, "Windows 页表不可读或全页重复 @ {table:#x}");
        geometry.entry(self.image, table, index)
    }
    pub(super) fn translate_walk(&self, va: u64) -> Result<(u64, u32)> {
        let geometry = self.paging()?;
        ensure!(geometry.canonical(va), "Windows 非 canonical 地址");
        let mut table = self.root & geometry.root_mask();
        for (level, &shift) in geometry.shifts().iter().enumerate() {
            let index = usize::try_from((va >> shift) & (geometry.entries(level) as u64 - 1))?;
            let mut entry = self.captured_table_entry(geometry, table, index)?;
            if entry & 1 == 0 {
                if entry & (1 << 11) != 0 && entry & (1 << 10) == 0 {
                    if geometry.arch == Architecture::Arm64 {
                        entry = self.transition_frame(entry, geometry)? | 3;
                    }
                } else {
                    bail!("Windows 缺页 VA {va:#x} level {shift} PTE {entry:#x}");
                }
            }
            if geometry.block(entry, shift) {
                let mask = (1u64 << shift) - 1;
                // Large-page bit 12 is PAT, not part of the physical address.
                let physical = if geometry.arch == Architecture::Arm64 {
                    entry & geometry.mask()
                } else {
                    entry & geometry.mask() & !(1 << 12)
                };
                let physical = if geometry.arch == Architecture::Arm64 {
                    physical & !mask
                } else {
                    physical
                };
                return Ok((physical | (va & mask), shift));
            }
            if geometry.arch == Architecture::Arm64 {
                ensure!(entry & 3 == 3, "无效 ARM64 table/page descriptor");
            }
            table = entry & geometry.mask();
        }
        Ok((table | (va & 4095), 12))
    }
    /// Conservative skip hint for a zero page-table entry in this read-only image.
    /// Nonzero software/prototype/pagefile PTEs, missing tables and captured-page
    /// holes produce no hint and still pass through the normal recovery reader.
    pub(super) fn absent_end(&self, va: u64, limit: u64) -> Option<u64> {
        let geometry = self.paging().ok()?;
        if geometry.arch == Architecture::Arm64 && !geometry.canonical(va) {
            return None;
        }
        let mut table = self.root & geometry.root_mask();
        for (level, &shift) in geometry.shifts().iter().enumerate() {
            let index =
                usize::try_from((va >> shift) & (geometry.entries(level) as u64 - 1)).ok()?;
            let mut entry = self.captured_table_entry(geometry, table, index).ok()?;
            if entry == 0 {
                return Some((va | ((1u64 << shift) - 1)).checked_add(1)?.min(limit));
            }
            if entry & 1 == 0 {
                if entry & (1 << 11) != 0 && entry & (1 << 10) == 0 {
                    if geometry.arch == Architecture::Arm64 {
                        entry = self.transition_frame(entry, geometry).ok()? | 3;
                    }
                } else {
                    return None;
                }
            }
            if geometry.block(entry, shift) {
                return None;
            }
            if geometry.arch == Architecture::Arm64 && entry & 3 != 3 {
                return None;
            }
            table = entry & geometry.mask();
        }
        None
    }
    /// Read directly translated capture pages. Matches the reference Intel layer:
    /// valid/transition PTEs are allowed; prototype/pagefile reconstruction is separate.
    pub(super) fn read_captured(&self, mut va: u64, mut out: &mut [u8]) -> Result<()> {
        if !out.is_empty() {
            va.checked_add(out.len() as u64 - 1)
                .context("Windows 读取越界")?;
        }
        while !out.is_empty() {
            let (physical, available) = self.translate_span(va)?;
            let n = usize::try_from(available.min(out.len() as u64))?;
            self.image.read(physical, out.at_mut(..n)?)?;
            out = out.at_mut(n..)?;
            if !out.is_empty() {
                va = add(va, n as u64)?;
            }
        }
        Ok(())
    }
    pub fn read(&self, mut va: u64, mut out: &mut [u8]) -> Result<()> {
        if !out.is_empty() {
            va.checked_add(out.len() as u64 - 1)
                .context("Windows 读取越界")?;
        }
        while !out.is_empty() {
            let _depth = paging::ReadDepth::enter(self.image, self.root, va)?;
            let translated = self.translate_span(va);
            let available = translated
                .as_ref()
                .map(|(_, span)| *span)
                .unwrap_or(4096 - (va & 4095));
            let n = usize::try_from(available.min(out.len() as u64))?;
            match translated {
                Ok((physical, _)) => self.image.read(physical, out.at_mut(..n)?)?,
                Err(original) => match self.prototype(va) {
                    Ok(physical) => self.image.read(physical, out.at_mut(..n)?)?,
                    Err(proto) => self
                        .pagefile_read(va, out.at_mut(..n)?)
                        .with_context(|| format!("{original:#}; {proto:#}"))?,
                },
            }
            out = out.at_mut(n..)?;
            if !out.is_empty() {
                va = add(va, n as u64)?;
            }
        }
        Ok(())
    }
    pub(in crate::windows) fn transition_frame(&self, entry: u64, geometry: Paging) -> Result<u64> {
        if geometry.arch != Architecture::Arm64 {
            // Windows Intel layers extract PFNs from the raw PTE's fixed
            // physical domain; ISF transition fields may include software flags.
            return Ok(entry & geometry.mask());
        }
        if self
            .isf
            .field("_MMPTE_TRANSITION", "PageFrameNumber")
            .is_ok()
        {
            let pfn = json_number(self.isf, entry, "_MMPTE_TRANSITION", "PageFrameNumber")?;
            ensure!(pfn <= geometry.mask() >> 12, "transition PFN 越界");
            Ok(pfn << 12)
        } else {
            ensure!(
                geometry.arch != Architecture::Arm64,
                "ARM64 transition PTE 缺少精确 PFN 类型"
            );
            Ok(entry & geometry.mask())
        }
    }
    pub(super) fn prototype_address(&self, entry: u64) -> Result<u64> {
        let geometry = self.paging()?;
        ensure!(
            entry & (1 << 10) != 0 && entry & 1 == 0,
            "不是 prototype PTE"
        );
        let prototype = if geometry.arch == Architecture::X86 && !geometry.pae {
            let low = json_number(self.isf, entry, "_MMPTE_PROTOTYPE", "ProtoAddressLow")?;
            let high = json_number(self.isf, entry, "_MMPTE_PROTOTYPE", "ProtoAddressHigh")?;
            ensure!(low < 256 && high < (1 << 21), "x86 prototype 地址字段越界");
            0x80000000 | (high << 10) | (low << 2)
        } else {
            let value = json_number(self.isf, entry, "_MMPTE_PROTOTYPE", "ProtoAddress")?;
            if geometry.arch == Architecture::X86 {
                ensure!(value <= u32::MAX as u64, "PAE prototype 地址越界");
                value
            } else {
                ((value << 16) as i64 >> 16) as u64
            }
        };
        ensure!(
            self.kernel(prototype) && prototype.is_multiple_of(geometry.width() as u64),
            "prototype PTE 指针无效"
        );
        Ok(prototype)
    }
    pub(super) fn prototype_page(&self, entry: u64, va: u64) -> Result<u64> {
        let geometry = self.paging()?;
        let prototype = self.prototype_address(entry)?;
        let pte = self.uint(prototype, geometry.width())?;
        let frame = if pte & 1 != 0 {
            if geometry.arch == Architecture::Arm64 {
                ensure!(pte & 3 == 3, "无效 ARM64 prototype 页 descriptor");
            }
            pte & geometry.mask()
        } else {
            ensure!(
                pte & (1 << 11) != 0 && pte & (1 << 10) == 0,
                "prototype 页面不驻留"
            );
            self.transition_frame(pte, geometry)?
        };
        Ok(frame | (va & 4095))
    }
    pub(super) fn prototype(&self, va: u64) -> Result<u64> {
        let geometry = self.paging()?;
        let va = geometry.translation_address(va);
        ensure!(geometry.canonical(va), "Windows 非 canonical 地址");
        let mut table = self.root & geometry.root_mask();
        for (level, &shift) in geometry.shifts().iter().enumerate() {
            let index = usize::try_from((va >> shift) & (geometry.entries(level) as u64 - 1))?;
            let entry = self.captured_table_entry(geometry, table, index)?;
            if entry & 1 != 0 {
                table = entry & geometry.mask();
                continue;
            }
            if entry & (1 << 11) != 0 && entry & (1 << 10) == 0 {
                table = self.transition_frame(entry, geometry)?;
                continue;
            }
            ensure!(shift == 12, "prototype 所在页表不驻留");
            return self.prototype_page(entry, va);
        }
        bail!("未找到 prototype PTE")
    }
    pub fn uint(&self, va: u64, size: usize) -> Result<u64> {
        ensure!(
            matches!(size, 1 | 2 | 4 | 8),
            "无效 Windows 数值宽度 {size}"
        );
        let mut b = [0; 8];
        self.read(va, b.at_mut(..size)?)?;
        Ok(u64::from_le_bytes(b))
    }
    pub(super) fn number(&self, base: u64, structure: &str, field: &str) -> Result<u64> {
        let layout = self.isf.layout(structure, field)?;
        let size = usize::try_from(layout.size).context("ISF 字段过大")?;
        let n = self.uint(add(base, layout.offset)?, size)?;
        json_number(self.isf, n, structure, field)
    }
    pub(super) fn unicode(&self, address: u64) -> Result<String> {
        let len = self.number(address, "_UNICODE_STRING", "Length")?;
        let max = self.number(address, "_UNICODE_STRING", "MaximumLength")?;
        ensure!(
            len % 2 == 0 && len <= max && len <= 65534,
            "无效 UNICODE_STRING 长度"
        );
        let mut bytes = vec![0; usize::try_from(len)?];
        if len > 0 {
            self.read(
                self.number(address, "_UNICODE_STRING", "Buffer")?,
                &mut bytes,
            )?;
        }
        Ok(String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}
