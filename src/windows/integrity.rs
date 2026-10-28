//! Kernel tables and carved module entries: the native system service table
//! and `MmLd` pool allocations cross-checked against PsLoadedModuleList.
use super::*;
use drivers::module_at;
use objects::physical_number;

/// Ceiling on KiServiceLimit; real tables hold a few hundred services.
const SERVICE_LIMIT: u64 = 4096;
const IMAGE_LIMIT: u64 = 1024 * 1024 * 1024;

impl Windows<'_> {
    /// Sorted kernel symbols as virtual addresses, for naming code pointers.
    fn kernel_symbols(&self) -> Result<Vec<(u64, String)>> {
        let mut symbols = Vec::new();
        for (name, value) in self.vm.isf.data["symbols"]
            .as_object()
            .context("ISF symbols 缺失")?
        {
            if value["address"].as_u64().is_some()
                && let Ok(address) = self.symbol(name)
            {
                symbols.push((address, name.clone()));
            }
        }
        symbols.sort_unstable();
        Ok(symbols)
    }
    /// windows.ssdt: every KiServiceTable entry, its target, owner and symbol.
    pub(super) fn ssdt(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinSsdt);
        let table = self
            .symbol("KiServiceTable")
            .context("不支持: 缺少 KiServiceTable")?;
        let limit = self.vm.uint(
            self.symbol("KiServiceLimit")
                .context("不支持: 缺少 KiServiceLimit")?,
            4,
        )?;
        ensure!(
            (1..=SERVICE_LIMIT).contains(&limit),
            "KiServiceLimit 无效: {limit}"
        );
        let modules = self.modules(Plugin::WinModules, job)?;
        r.complete = modules.complete;
        r.diagnostics = modules.diagnostics.clone();
        let symbols = self.kernel_symbols()?;
        let x64 = self.vm.pointer_size() == 8;
        for index in 0..limit {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let entry = self.vm.uint(add(table, index * 4)?, 4)?;
                // x64 stores signed offsets from the table, shifted past four
                // argument-count bits; x86 stores absolute addresses.
                let target = if x64 {
                    let offset = i64::from(entry as u32 as i32) >> 4;
                    table.wrapping_add_signed(offset)
                } else {
                    entry
                };
                let owner = module_at(&modules, target);
                let at = symbols.partition_point(|(address, _)| *address <= target);
                let symbol = match at.checked_sub(1).map(|i| &symbols[i]) {
                    Some((address, name)) if *address == target => name.clone(),
                    Some((address, name)) if target - address < 0x10_0000 => {
                        format!("{name}+{:#x}", target - address)
                    }
                    _ => "[unknown]".into(),
                };
                let kernel = modules.rows.first().map(|m| m[0].as_str());
                let reason = if owner.is_empty() {
                    "OutsideLoadedModules"
                } else if Some(owner.as_str()) == kernel {
                    "Kernel"
                } else {
                    "ModuleTarget; inspect hook"
                };
                Ok(vec![
                    index.to_string(),
                    hex(target),
                    if owner.is_empty() {
                        "[unknown]".into()
                    } else {
                        owner
                    },
                    symbol,
                    reason.into(),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => Self::issue(&mut r, format!("KiServiceTable[{index}]"), format!("{e:#}")),
            }
        }
        r.kernel_identity["coverage"] = serde_json::json!(
            "native KiServiceTable only; the win32k shadow table needs a GUI session space"
        );
        Ok(r)
    }
    /// windows.modscan: `MmLd` pool allocations that parse as loader entries.
    pub(super) fn modscan(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinModscan);
        let ty = self.module_type()?;
        let isf = self.vm.isf;
        let size = isf.data["user_types"][ty]["size"]
            .as_u64()
            .context("缺少模块条目大小")?;
        ensure!((32..=4096).contains(&size), "模块条目大小无效");
        let listed = self.modules(Plugin::WinModules, job)?;
        if !listed.complete {
            r.complete = false;
            r.diagnostics.extend(listed.diagnostics.clone());
        }
        let bases: HashSet<String> = listed.rows.iter().map(|m| m[1].clone()).collect();
        let align = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let mut seen = HashSet::new();
        for (start, length) in self.pool_blocks(&[b"MmLd"], size, job)? {
            job.check()?;
            let mut block = vec![0; length as usize];
            if self.vm.image.read(start, &mut block).is_err() {
                continue;
            }
            for delta in (0..=length - size).step_by(align) {
                let entry = &block[delta as usize..(delta + size) as usize];
                let Ok((base, image, name, path)) = self.carved_module(entry, ty) else {
                    continue;
                };
                if !seen.insert((base, name.to_ascii_lowercase())) {
                    break;
                }
                r.rows.push(vec![
                    hex(add(start, delta)?),
                    name,
                    hex(base),
                    image.to_string(),
                    path,
                    bases.contains(&hex(base)).to_string(),
                ]);
                break;
            }
        }
        r.kernel_identity["coverage"] = serde_json::json!(
            "MmLd pool allocations; freed entries can remain and paged-out names are skipped"
        );
        Ok(r)
    }
    /// One physical candidate, accepted only with a kernel image range and
    /// readable names that look like a loaded image.
    fn carved_module(&self, entry: &[u8], ty: &str) -> Result<(u64, u64, String, String)> {
        let isf = self.vm.isf;
        let base = physical_number(isf, entry, ty, "DllBase")?;
        let image = physical_number(isf, entry, ty, "SizeOfImage")?;
        ensure!(
            self.vm.kernel(base) && base.is_multiple_of(4096) && image > 0 && image <= IMAGE_LIMIT,
            "模块范围无效"
        );
        let name = self.unicode_in(entry, ty, "BaseDllName")?;
        let lower = name.to_ascii_lowercase();
        ensure!(
            [".sys", ".dll", ".exe"].iter().any(|s| lower.ends_with(s))
                && !name.chars().any(char::is_control),
            "模块名称无效"
        );
        let path = self
            .unicode_in(entry, ty, "FullDllName")
            .unwrap_or_default();
        Ok((base, image, name, path))
    }
    /// Read a UNICODE_STRING embedded in physical bytes; its buffer is virtual.
    fn unicode_in(&self, bytes: &[u8], ty: &str, field: &str) -> Result<String> {
        let isf = self.vm.isf;
        let offset = isf.offset(ty, field)? as usize;
        let string = bytes.get(offset..).context("UNICODE_STRING 截断")?;
        let length = physical_number(isf, string, "_UNICODE_STRING", "Length")?;
        let maximum = physical_number(isf, string, "_UNICODE_STRING", "MaximumLength")?;
        let buffer = physical_number(isf, string, "_UNICODE_STRING", "Buffer")?;
        ensure!(
            length > 0 && length % 2 == 0 && length <= maximum && length <= 1024,
            "UNICODE_STRING 长度无效"
        );
        ensure!(self.vm.kernel(buffer), "UNICODE_STRING 缓冲区无效");
        let mut b = vec![0; length as usize];
        self.vm.read(buffer, &mut b)?;
        String::from_utf16(
            &b.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
        .context("UNICODE_STRING 非法 UTF-16")
    }
}

/// Ceilings for the big-page table and device chains.
const BIG_PAGE_LIMIT: u64 = 16 * 1024 * 1024;
const DEVICE_LIMIT: usize = 4096;
const ATTACH_LIMIT: usize = 64;

impl Windows<'_> {
    /// windows.bigpools: allocated entries of PoolBigPageTable.
    pub(super) fn bigpools(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinBigpools);
        let ty = "_POOL_TRACKER_BIG_PAGES";
        let table = self.vm.pointer(
            self.symbol("PoolBigPageTable")
                .context("不支持: 缺少 PoolBigPageTable")?,
        )?;
        let count = self.vm.pointer(
            self.symbol("PoolBigPageTableSize")
                .context("不支持: 缺少 PoolBigPageTableSize")?,
        )?;
        ensure!(
            self.vm.kernel(table) && count > 0 && count <= BIG_PAGE_LIMIT,
            "PoolBigPageTable 无效"
        );
        let size = self.vm.isf.data["user_types"][ty]["size"]
            .as_u64()
            .context("不支持: 缺少 _POOL_TRACKER_BIG_PAGES")?;
        ensure!((8..=64).contains(&size), "大页池表项大小无效");
        let bytes_field = if self.vm.isf.field(ty, "NumberOfBytes").is_ok() {
            "NumberOfBytes"
        } else {
            "Size"
        };
        let pool_type = self.vm.isf.field(ty, "PoolType").is_ok();
        // Read the table a page-run at a time; it can hold a million entries.
        let per_chunk = (64 * 1024 / size).max(1);
        let mut index = 0;
        while index < count {
            job.check()?;
            let n = per_chunk.min(count - index);
            let mut chunk = vec![0; (n * size) as usize];
            let start = add(table, index * size)?;
            if let Err(e) = self.vm.read(start, &mut chunk) {
                Self::issue(
                    &mut r,
                    format!("PoolBigPageTable[{index}..{}]", index + n),
                    format!("{e:#}"),
                );
                index += n;
                continue;
            }
            for entry in chunk.chunks_exact(size as usize) {
                let isf = self.vm.isf;
                let va = objects::physical_number(isf, entry, ty, "Va")?;
                // The low bit marks a free entry.
                if va == 0 || va & 1 != 0 {
                    continue;
                }
                let key = objects::physical_number(isf, entry, ty, "Key")? as u32;
                let tag: String = key
                    .to_le_bytes()
                    .iter()
                    .map(|b| {
                        let b = b & 0x7f;
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                r.rows.push(vec![
                    hex(va),
                    tag,
                    if pool_type {
                        format!(
                            "{:#x}",
                            objects::physical_number(isf, entry, ty, "PoolType")?
                        )
                    } else {
                        String::new()
                    },
                    objects::physical_number(isf, entry, ty, bytes_field)?.to_string(),
                ]);
            }
            index += n;
        }
        Ok(r)
    }
    /// windows.devicetree: each scanned driver's devices and attached stacks.
    pub(super) fn devicetree(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinDevicetree);
        let drivers = self.drivers(Plugin::WinDriverscan, job)?;
        r.complete = drivers.complete;
        r.diagnostics = drivers.diagnostics.clone();
        for driver in drivers.rows {
            job.check()?;
            let address = u64::from_str_radix(driver[0].trim_start_matches("0x"), 16)?;
            if let Err(e) = self.driver_devices(address, &driver[1], &mut r, job) {
                job.check()?;
                Self::issue(&mut r, format!("driver {}", driver[1]), format!("{e:#}"));
            }
        }
        Ok(r)
    }
    /// Object-manager name of a device; unnamed devices are common.
    fn device_name(&self, device: u64) -> String {
        let Ok(body) = self.vm.isf.offset("_OBJECT_HEADER", "Body") else {
            return String::new();
        };
        device
            .checked_sub(body)
            .and_then(|header| self.object_name(header, &self.object_header_layout()).ok())
            .unwrap_or_default()
    }
    /// One driver's DeviceObject/NextDevice list and each AttachedDevice stack.
    fn driver_devices(&self, driver: u64, name: &str, r: &mut Results, job: &Job) -> Result<()> {
        let mut device = self.number(driver, "_DRIVER_OBJECT", "DeviceObject")?;
        let mut seen = HashSet::new();
        while device != 0 {
            job.check()?;
            ensure!(self.vm.kernel(device), "无效 DeviceObject {device:#x}");
            ensure!(
                seen.insert(device) && seen.len() <= DEVICE_LIMIT,
                "设备链表循环或超限"
            );
            r.rows.push(vec![
                hex(driver),
                name.into(),
                "DEV".into(),
                hex(device),
                self.device_name(device),
                format!(
                    "{:#x}",
                    self.number(device, "_DEVICE_OBJECT", "DeviceType")?
                ),
            ]);
            let mut attached = self.number(device, "_DEVICE_OBJECT", "AttachedDevice")?;
            let mut depth = 0;
            while attached != 0 {
                ensure!(
                    self.vm.kernel(attached),
                    "无效 AttachedDevice {attached:#x}"
                );
                depth += 1;
                ensure!(depth <= ATTACH_LIMIT, "附加设备链超过 {ATTACH_LIMIT} 层");
                let owner = self.number(attached, "_DEVICE_OBJECT", "DriverObject")?;
                let owner_name = self
                    .field(owner, "_DRIVER_OBJECT", "DriverName")
                    .and_then(|field| self.vm.unicode(field))
                    .unwrap_or_default();
                r.rows.push(vec![
                    hex(owner),
                    owner_name,
                    format!("ATT{depth}"),
                    hex(attached),
                    self.device_name(attached),
                    format!(
                        "{:#x}",
                        self.number(attached, "_DEVICE_OBJECT", "DeviceType")?
                    ),
                ]);
                attached = self.number(attached, "_DEVICE_OBJECT", "AttachedDevice")?;
            }
            device = self.number(device, "_DEVICE_OBJECT", "NextDevice")?;
        }
        Ok(())
    }
}

/// Per-list ceiling for the timer walk.
const TIMER_LIMIT: usize = 65536;

/// KiDecodeTimerDpc (Windows 8+ x64):
/// `wait_always ^ bswap(timer ^ rotl(wait_never ^ encoded, wait_never as u8))`.
pub(super) fn decode_timer_dpc(encoded: u64, timer: u64, wait_never: u64, wait_always: u64) -> u64 {
    let rotated = (wait_never ^ encoded).rotate_left((wait_never & 0xff) as u32);
    wait_always ^ (timer ^ rotated).swap_bytes()
}

impl Windows<'_> {
    /// windows.timers: kernel timers of every processor and their DPC routines.
    pub(super) fn timers(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinTimers);
        let isf = self.vm.isf;
        let processors = self.processor_roots(&mut r, job)?;
        let encoded = self.vm.pointer_size() == 8 && self.symbol("KiWaitNever").is_ok();
        let (never, always) = if encoded {
            (
                self.vm.uint(self.symbol("KiWaitNever")?, 8)?,
                self.vm.uint(self.symbol("KiWaitAlways")?, 8)?,
            )
        } else {
            (0, 0)
        };
        let modules = self.modules(Plugin::WinModules, job)?;
        if !modules.complete {
            r.complete = false;
            r.diagnostics.extend(modules.diagnostics.clone());
        }
        let table =
            isf.offset("_KPRCB", "TimerTable")? + isf.offset("_KTIMER_TABLE", "TimerEntries")?;
        // Windows 11 nests two 256-entry tables; flatten any nesting.
        let mut ty = &isf.field("_KTIMER_TABLE", "TimerEntries")?["type"];
        let mut count = 1u64;
        while ty["kind"] == "array" {
            count *= ty["count"].as_u64().context("TimerEntries 维度缺失")?;
            ty = &ty["subtype"];
        }
        ensure!(count <= 4096, "TimerEntries 数量无效");
        let entry_size = isf.data["user_types"]["_KTIMER_TABLE_ENTRY"]["size"]
            .as_u64()
            .context("缺少 _KTIMER_TABLE_ENTRY 大小")?;
        let list = isf.offset("_KTIMER_TABLE_ENTRY", "Entry")?;
        let link = isf.offset("_KTIMER", "TimerListEntry")?;
        for (cpu, prcb) in processors {
            job.check()?;
            for index in 0..count {
                let head = add(add(prcb, table)?, index * entry_size + list)?;
                let (timers, diagnostics) = match self.list_partial(head, link, job) {
                    Ok(walk) => walk,
                    Err(e) => {
                        Self::issue(
                            &mut r,
                            format!("CPU {cpu} timer list {index}"),
                            format!("{e:#}"),
                        );
                        continue;
                    }
                };
                for diagnostic in diagnostics.into_iter().take(1) {
                    Self::issue(&mut r, format!("CPU {cpu} timer list {index}"), diagnostic);
                }
                for timer in timers.into_iter().take(TIMER_LIMIT) {
                    let read = (|| -> Result<Vec<String>> {
                        let raw = self.number(timer, "_KTIMER", "Dpc")?;
                        let dpc = if raw == 0 {
                            0
                        } else if encoded {
                            let decoded = decode_timer_dpc(raw, timer, never, always);
                            if self.vm.kernel(decoded) {
                                decoded
                            } else {
                                raw
                            }
                        } else {
                            raw
                        };
                        let routine = if dpc != 0 && self.vm.kernel(dpc) {
                            self.number(dpc, "_KDPC", "DeferredRoutine")?
                        } else {
                            0
                        };
                        let owner = module_at(&modules, routine);
                        Ok(vec![
                            cpu.to_string(),
                            hex(timer),
                            self.number(timer, "_KTIMER", "DueTime")?.to_string(),
                            self.number(timer, "_KTIMER", "Period")?.to_string(),
                            hex(dpc),
                            hex(routine),
                            if routine == 0 {
                                String::new()
                            } else if owner.is_empty() {
                                "[unknown]".into()
                            } else {
                                owner
                            },
                        ])
                    })();
                    match read {
                        Ok(row) => r.rows.push(row),
                        Err(e) => {
                            Self::issue(&mut r, format!("timer {timer:#x}"), format!("{e:#}"))
                        }
                    }
                }
            }
        }
        Ok(r)
    }
}

/// Page counts of one address space, by leaf PTE state.
#[derive(Debug, Default, PartialEq)]
pub(super) struct PageStatistics {
    pub valid: u64,
    pub large: u64,
    pub transition: u64,
    pub software: u64,
    pub empty: u64,
    pub missing_tables: u64,
    pub shared_tables: u64,
}

impl Windows<'_> {
    /// windows.statistics: leaf page states of the kernel address space.
    pub(super) fn statistics(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinStatistics);
        let geometry = self.vm.paging()?;
        let mut stats = PageStatistics::default();
        let top = geometry.entries(0);
        // The kernel owns the upper half of the root table except on ARM64,
        // whose kernel root covers kernel space alone.
        let first = if geometry.arch == Architecture::Arm64 {
            0
        } else {
            top / 2
        };
        let mut stack = vec![(0usize, self.vm.root & geometry.root_mask(), first, top)];
        // Tables can be referenced from several parents; count each once.
        let mut visited = HashSet::new();
        while let Some((level, table, from, to)) = stack.pop() {
            job.check()?;
            if !visited.insert((level, table)) {
                stats.shared_tables += 1;
                continue;
            }
            ensure!(visited.len() <= MAX_OBJECTS, "页表数量超过上限");
            let shift = geometry.shifts()[level];
            let leaf = level + 1 == geometry.shifts().len();
            for index in from..to {
                let entry = match geometry.entry(self.vm.image, table, index) {
                    Ok(entry) => entry,
                    Err(_) => {
                        stats.missing_tables += 1;
                        break;
                    }
                };
                if entry & 1 == 0 {
                    if entry == 0 {
                        if leaf {
                            stats.empty += 1;
                        }
                    } else if leaf {
                        if entry & (1 << 11) != 0 && entry & (1 << 10) == 0 {
                            stats.transition += 1;
                        } else {
                            stats.software += 1;
                        }
                    } else {
                        stats.missing_tables += 1;
                    }
                    continue;
                }
                if level == 0 && entry & geometry.mask() == table {
                    // The page-table self-map: walking it would recount tables.
                    continue;
                }
                if leaf {
                    stats.valid += 1;
                } else if geometry.block(entry, shift) {
                    stats.large += 1;
                } else {
                    stack.push((
                        level + 1,
                        entry & geometry.mask(),
                        0,
                        geometry.entries(level + 1),
                    ));
                }
            }
        }
        r.rows = vec![
            vec!["ValidPages4K".into(), stats.valid.to_string()],
            vec!["ValidLargePages".into(), stats.large.to_string()],
            vec!["TransitionPages".into(), stats.transition.to_string()],
            vec!["SoftwarePTEs".into(), stats.software.to_string()],
            vec!["EmptyPTEs".into(), stats.empty.to_string()],
            vec![
                "UnreadableOrNonPresentTables".into(),
                stats.missing_tables.to_string(),
            ],
            vec![
                "SharedTableReferences".into(),
                stats.shared_tables.to_string(),
            ],
        ];
        r.kernel_identity["coverage"] = serde_json::json!(
            "kernel half of the validated kernel page tables; software PTEs include paged-out, demand-zero and prototype entries"
        );
        Ok(r)
    }
}

impl Windows<'_> {
    /// windows.virtmap: kernel virtual address regions by system VA type.
    pub(super) fn virtmap(&self) -> Result<Results> {
        let mut r = self.result(Plugin::WinVirtmap);
        let isf = self.vm.isf;
        let symbol = self
            .symbol("MiVisibleState")
            .context("不支持: 缺少 MiVisibleState（Windows 10 之前的布局）")?;
        // Public symbols carry no type; MiVisibleState is a pointer variable
        // unless the ISF explicitly types it as the structure itself.
        let state = if isf.data["symbols"]["MiVisibleState"]["type"]["kind"] == "struct" {
            symbol
        } else {
            self.vm.pointer(symbol)?
        };
        ensure!(self.vm.kernel(state), "MiVisibleState 无效");
        let count = isf.field("_MI_VISIBLE_STATE", "SystemVaRegions")?["type"]["count"]
            .as_u64()
            .context("SystemVaRegions 长度缺失")?;
        ensure!(count <= 64, "SystemVaRegions 长度无效");
        let size = isf.data["user_types"]["_MI_SYSTEM_VA_ASSIGNMENT"]["size"]
            .as_u64()
            .context("缺少 _MI_SYSTEM_VA_ASSIGNMENT 大小")?;
        let regions = self.field(state, "_MI_VISIBLE_STATE", "SystemVaRegions")?;
        // SystemVaRegions is indexed by _MI_ASSIGNED_REGION_TYPES, whose
        // order differs between builds; older layouts reuse the VA type.
        let names_enum = if isf.data["enums"]["_MI_ASSIGNED_REGION_TYPES"].is_object() {
            "_MI_ASSIGNED_REGION_TYPES"
        } else {
            "_MI_SYSTEM_VA_TYPE"
        };
        let names: BTreeMap<u64, String> = isf.data["enums"][names_enum]["constants"]
            .as_object()
            .map(|constants| {
                constants
                    .iter()
                    .filter_map(|(name, value)| Some((value.as_u64()?, name.clone())))
                    .collect()
            })
            .unwrap_or_default();
        for index in 0..count {
            let entry = add(regions, index * size)?;
            let read = (|| -> Result<Option<Vec<String>>> {
                let base = self.number(entry, "_MI_SYSTEM_VA_ASSIGNMENT", "BaseAddress")?;
                let length = self.number(entry, "_MI_SYSTEM_VA_ASSIGNMENT", "NumberOfBytes")?;
                if base == 0 || length == 0 {
                    return Ok(None);
                }
                ensure!(self.vm.kernel(base), "区域起始地址不是内核地址 {base:#x}");
                Ok(Some(vec![
                    names
                        .get(&index)
                        .cloned()
                        .unwrap_or_else(|| format!("Type{index}")),
                    hex(base),
                    hex(base.checked_add(length).context("区域结束地址溢出")?),
                    length.to_string(),
                ]))
            })();
            match read {
                Ok(Some(row)) => r.rows.push(row),
                Ok(None) => {}
                Err(e) => Self::issue(
                    &mut r,
                    format!("SystemVaRegions[{index}]"),
                    format!("{e:#}"),
                ),
            }
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    fn field(offset: u64, ty: &str) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"base","name":ty}})
    }
    /// One listed module "ntoskrnl.exe" covering K..K+0x10000, and a pool
    /// header type for carving.
    fn prepare() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["base_types"]["u8"] = json!({"size":1});
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":112,"fields":{
            "InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},
            "DllBase":field(48,"pointer"),
            "SizeOfImage":field(64,"u32"),
            "BaseDllName":{"offset":72,"type":{"kind":"struct","name":"_UNICODE_STRING"}},
            "FullDllName":{"offset":88,"type":{"kind":"struct","name":"_UNICODE_STRING"}},
        }});
        isf.data["user_types"]["_POOL_HEADER"] =
            json!({"size":16,"fields":{"BlockSize":field(2,"u8"),"PoolTag":field(4,"u32")}});
        put(&mut b, 0x8700, K + 0x7000);
        put(&mut b, 0x8708, K + 0x7000);
        module(&mut b, 0xf000, K, 0x10000);
        put(&mut b, 0xf000, K + 0x700);
        put(&mut b, 0xf008, K + 0x700);
        let name: Vec<u8> = "ntoskrnl.exe"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xf100..0xf100 + name.len()].copy_from_slice(&name);
        (b, isf)
    }
    fn module(b: &mut [u8], at: usize, base: u64, size: u32) {
        put(b, at + 48, base);
        b[at + 64..at + 68].copy_from_slice(&size.to_le_bytes());
        for string in [72, 88] {
            b[at + string..at + string + 2].copy_from_slice(&24u16.to_le_bytes());
            b[at + string + 2..at + string + 4].copy_from_slice(&26u16.to_le_bytes());
            put(b, at + string + 8, K + 0x7100);
        }
    }
    fn engine<'a>(img: &'a Image, isf: &'a Isf) -> Windows<'a> {
        Windows {
            vm: Memory::new(img, 0x1000, isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(isf).unwrap(),
        }
    }
    #[test]
    fn ssdt_decodes_x64_relative_entries_and_attributes_owners() {
        let (mut b, mut isf) = prepare();
        isf.data["symbols"]["KiServiceTable"] = json!({"address":0x6000});
        isf.data["symbols"]["KiServiceLimit"] = json!({"address":0x6100});
        isf.data["symbols"]["NtClose"] = json!({"address":0x6200});
        b[0xe100..0xe104].copy_from_slice(&3u32.to_le_bytes());
        for (index, offset) in [(0usize, 0x200i32), (1, -0x7000), (2, 0x208)] {
            let entry = (offset << 4) | 2;
            b[0xe000 + index * 4..0xe004 + index * 4].copy_from_slice(&entry.to_le_bytes());
        }
        let img = image(&b);
        let r = engine(&img, &isf).ssdt(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows[0],
            ["0", &hex(K + 0x6200), "ntoskrnl.exe", "NtClose", "Kernel"].map(String::from)
        );
        assert_eq!(r.rows[1][1], hex(K - 0x1000));
        assert_eq!(
            &r.rows[1][2..],
            ["[unknown]", "[unknown]", "OutsideLoadedModules"]
        );
        assert_eq!(r.rows[2][3], "NtClose+0x8");
        // A missing limit symbol is an explicit unsupported table.
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("KiServiceLimit");
        let e = engine(&img, &isf).ssdt(&Job::default()).unwrap_err();
        assert!(format!("{e:#}").contains("不支持"));
    }
    #[test]
    fn bigpools_skip_free_entries_and_decode_tags() {
        let (mut b, mut isf) = prepare();
        isf.data["symbols"]["PoolBigPageTable"] = json!({"address":0x6000});
        isf.data["symbols"]["PoolBigPageTableSize"] = json!({"address":0x6008});
        isf.data["user_types"]["_POOL_TRACKER_BIG_PAGES"] = json!({"size":24,"fields":{
            "Va":field(0,"pointer"),"Key":field(8,"u32"),"PoolType":field(12,"u32"),"NumberOfBytes":field(16,"u64"),
        }});
        put(&mut b, 0xe000, K + 0x6100);
        put(&mut b, 0xe008, 3);
        for (index, va, tag, bytes) in [
            (0usize, K + 0x20000, b"Ntfx", 0x2000u64),
            (1, K + 0x30001, b"Free", 0x1000), // low bit: free
            (2, 0, b"None", 0),
        ] {
            let at = 0xe100 + index * 24;
            put(&mut b, at, va);
            b[at + 8..at + 12].copy_from_slice(tag);
            b[at + 12..at + 16].copy_from_slice(&1u32.to_le_bytes());
            put(&mut b, at + 16, bytes);
        }
        let img = image(&b);
        let r = engine(&img, &isf).bigpools(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [[hex(K + 0x20000), "Ntfx".into(), "0x1".into(), "8192".into()].to_vec()]
        );
    }
    #[test]
    fn devicetree_walks_devices_attachments_and_rejects_loops() {
        let (mut b, mut isf) = prepare();
        isf.data["user_types"]["_DRIVER_OBJECT"] = json!({"size":64,"fields":{
            "DeviceObject":field(8,"pointer"),
            "DriverName":{"offset":16,"type":{"kind":"struct","name":"_UNICODE_STRING"}},
        }});
        isf.data["user_types"]["_DEVICE_OBJECT"] = json!({"size":64,"fields":{
            "DriverObject":field(8,"pointer"),"NextDevice":field(16,"pointer"),
            "AttachedDevice":field(24,"pointer"),"DeviceType":field(32,"u32"),
        }});
        // Driver K+0x3000 owns devices K+0x3100 -> K+0x3200; a filter
        // driver K+0x3400 attaches K+0x3300 above the first device.
        put(&mut b, 0xb008, K + 0x3100);
        put(&mut b, 0xb110, K + 0x3200);
        put(&mut b, 0xb118, K + 0x3300);
        b[0xb120..0xb124].copy_from_slice(&0x22u32.to_le_bytes());
        put(&mut b, 0xb308, K + 0x3400);
        b[0xb410..0xb412].copy_from_slice(&24u16.to_le_bytes());
        b[0xb412..0xb414].copy_from_slice(&24u16.to_le_bytes());
        put(&mut b, 0xb418, K + 0x7100);
        let img = image(&b);
        let w = engine(&img, &isf);
        let mut r = w.result(Plugin::WinDevicetree);
        w.driver_devices(K + 0x3000, "\\Driver\\disk", &mut r, &Job::default())
            .unwrap();
        let shape: Vec<_> = r
            .rows
            .iter()
            .map(|row| (row[0].clone(), row[2].clone(), row[3].clone()))
            .collect();
        assert_eq!(
            shape,
            [
                (hex(K + 0x3000), "DEV".into(), hex(K + 0x3100)),
                (hex(K + 0x3400), "ATT1".into(), hex(K + 0x3300)),
                (hex(K + 0x3000), "DEV".into(), hex(K + 0x3200)),
            ]
        );
        assert_eq!(r.rows[0][5], "0x22");
        assert_eq!(r.rows[1][1], "ntoskrnl.exe");
        // A NextDevice loop stops the walk with an error, keeping earlier rows.
        put(&mut b, 0xb210, K + 0x3100);
        let img = image(&b);
        let w = engine(&img, &isf);
        let mut r = w.result(Plugin::WinDevicetree);
        let e = w
            .driver_devices(K + 0x3000, "disk", &mut r, &Job::default())
            .unwrap_err();
        assert!(format!("{e:#}").contains("循环"));
        assert_eq!(r.rows.len(), 3);
    }
    #[test]
    fn timer_dpc_decoding_inverts_the_kernel_encoding() {
        let (never, always, timer, dpc) = (
            0x1234_5678_9abc_de0fu64,
            0x0fed_cba9_8765_4321u64,
            K + 0x3000,
            K + 0x4000,
        );
        // KiEncodeTimerDpc is the inverse of the decode rule.
        let encoded =
            ((dpc ^ always).swap_bytes() ^ timer).rotate_right((never & 0xff) as u32) ^ never;
        assert_eq!(decode_timer_dpc(encoded, timer, never, always), dpc);
    }
    #[test]
    fn statistics_count_kernel_leaf_states() {
        let (b, isf) = prepare();
        let img = image(&b);
        let r = engine(&img, &isf).statistics(&Job::default()).unwrap();
        let get = |key: &str| {
            r.rows.iter().find(|row| row[0] == key).unwrap()[1]
                .parse::<u64>()
                .unwrap()
        };
        // The fixture maps 32 kernel pages through one page table.
        assert_eq!(get("ValidPages4K"), 32);
        assert_eq!(get("EmptyPTEs"), 512 - 32);
        assert_eq!(get("ValidLargePages"), 0);
    }
    #[test]
    fn virtmap_names_regions_by_va_type() {
        let (mut b, mut isf) = prepare();
        isf.data["symbols"]["MiVisibleState"] = json!({"address":0x6000,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_MI_VISIBLE_STATE"] = json!({"size":64,"fields":{
            "SystemVaRegions":{"offset":16,"type":{"kind":"array","count":3,"subtype":{"kind":"struct","name":"_MI_SYSTEM_VA_ASSIGNMENT"}}},
        }});
        isf.data["user_types"]["_MI_SYSTEM_VA_ASSIGNMENT"] = json!({"size":16,"fields":{"BaseAddress":field(0,"pointer"),"NumberOfBytes":field(8,"u64")}});
        isf.data["enums"]["_MI_SYSTEM_VA_TYPE"] = json!({"size":4,"base":"int","constants":{"MiVaUnused":0,"MiVaSessionSpace":1,"MiVaProcessSpace":2}});
        // The assigned-region enum, when present, names the slots instead.
        isf.data["enums"]["_MI_ASSIGNED_REGION_TYPES"] = json!({"size":4,"base":"int","constants":{"AssignedRegionNonPagedPool":0,"AssignedRegionPagedPool":1,"AssignedRegionSystemCache":2}});
        put(&mut b, 0xe000, K + 0x6100);
        put(&mut b, 0xe100 + 16 + 16, 0xffff_f680_0000_0000);
        put(&mut b, 0xe100 + 16 + 24, 0x80_0000_0000);
        let img = image(&b);
        let r = engine(&img, &isf).virtmap().unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(
            r.rows,
            [[
                "AssignedRegionPagedPool".into(),
                hex(0xffff_f680_0000_0000),
                hex(0xffff_f700_0000_0000),
                0x80_0000_0000u64.to_string()
            ]
            .to_vec()]
        );
    }
    #[test]
    fn modscan_carves_unlisted_loader_entries_and_marks_listed_ones() {
        let (mut b, isf) = prepare();
        // Hidden entry: valid image range and name, absent from the list.
        let header = 0x10000;
        b[header + 2] = 8; // 128-byte block: 16-byte header + 112-byte entry.
        b[header + 4..header + 8].copy_from_slice(b"MmLd");
        module(&mut b, header + 16, K + 0x20000, 0x2000);
        // Listed entry also carved: same base as the list.
        let listed = 0x10100;
        b[listed + 2] = 8;
        b[listed + 4..listed + 8].copy_from_slice(b"MmLd");
        module(&mut b, listed + 16, K, 0x10000);
        // Decoy: unaligned image base.
        let decoy = 0x10200;
        b[decoy + 2] = 8;
        b[decoy + 4..decoy + 8].copy_from_slice(b"MmLd");
        module(&mut b, decoy + 16, K + 0x123, 0x2000);
        let img = image(&b);
        let r = engine(&img, &isf).modscan(&Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        let rows: Vec<_> = r
            .rows
            .iter()
            .map(|row| (row[2].clone(), row[5].clone()))
            .collect();
        assert_eq!(
            rows,
            [(hex(K + 0x20000), "false".into()), (hex(K), "true".into())]
        );
        assert_eq!(r.rows[0][0], hex(0x10010));
        assert_eq!(r.rows[0][1], "ntoskrnl.exe");
    }
}
