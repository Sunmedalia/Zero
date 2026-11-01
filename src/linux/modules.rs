//! Shared module allocation ranges, carving and independent module views.
use super::*;
use crate::bytes::JsonKey as _;

/// Ceiling for the module carving range and for the bytes read from it.
const CARVE_SPAN: u64 = 2 * 1024 * 1024 * 1024;
const CARVE_BUDGET: u64 = 256 * 1024 * 1024;
const PAGE: u64 = 4096;
/// x86_64 MODULES_VADDR / MODULES_END, used when the ISF has no mod_tree.
const X86_MODULES: (u64, u64) = (0xffff_ffff_a000_0000, 0xffff_ffff_ff00_0000);

struct ModuleRegions {
    ranges: Vec<(u64, u64)>,
    span_only: bool,
    allocator_bounds: bool,
}

impl Linux<'_> {
    /// Virtual ranges that hold module allocations, and whether they are only
    /// the span of the listed modules (a weaker bound).
    fn module_regions(&self, listed: &[u64]) -> Result<ModuleRegions> {
        if let Ok(tree) = self.isf.address("mod_tree") {
            let mut regions = Vec::new();
            for (min, max) in [("addr_min", "addr_max"), ("data_addr_min", "data_addr_max")] {
                if self.isf.field("mod_tree_root", min).is_ok() {
                    let start = self.number(tree, "mod_tree_root", min)?;
                    let end = self.number(tree, "mod_tree_root", max)?;
                    if start != 0 && start < end && start != u64::MAX {
                        regions.push((start, end));
                    }
                }
            }
            if !regions.is_empty() {
                return Ok(ModuleRegions {
                    ranges: regions,
                    span_only: false,
                    allocator_bounds: true,
                });
            }
        }
        if let Ok(min) = self.isf.address("module_addr_min") {
            let width = self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .context("模块分配边界指针宽度缺失")?;
            ensure!(matches!(width, 4 | 8), "模块分配边界指针宽度无效");
            let start = self.vm.uint(min, usize::try_from(width)?)?;
            let end = self.vm.uint(
                self.isf.address("module_addr_max")?,
                usize::try_from(width)?,
            )?;
            ensure!(start < end && start != u64::MAX, "module_addr_min/max 无效");
            return Ok(ModuleRegions {
                ranges: vec![(start, end)],
                span_only: false,
                allocator_bounds: true,
            });
        }
        if !self.arm64() {
            return Ok(ModuleRegions {
                ranges: vec![X86_MODULES],
                span_only: false,
                allocator_bounds: false,
            });
        }
        let mut start = u64::MAX;
        let mut end = 0;
        for &module in listed {
            let (text, text_end) = self.module_range(module)?;
            start = start.min(module).min(text);
            end = end.max(add(module, PAGE)?).max(text_end);
        }
        ensure!(start < end, "没有可用的模块内存范围");
        Ok(ModuleRegions {
            ranges: vec![(start, end)],
            span_only: true,
            allocator_bounds: false,
        })
    }
    /// hidden_modules: carve `struct module` from module memory by its
    /// `mkobj.mod` back-reference and report those absent from `modules`.
    pub(super) fn hidden_modules(&self, r: &mut Results, job: &Job) -> Result<()> {
        let listed = self.listed_modules(job)?;
        let known = listed.iter().copied().collect();
        for module in self.scan_module_objects(&listed, &known, false, r, job)? {
            if let Some(row) = self.carved_module(module, self.isf.size("module", "name")?) {
                r.rows.push(row);
            }
        }
        Ok(())
    }
    /// Carve independently of the list; callers choose whether to exclude known objects.
    pub(super) fn scan_module_objects(
        &self,
        listed: &[u64],
        known: &HashSet<u64>,
        strict: bool,
        r: &mut Results,
        job: &Job,
    ) -> Result<Vec<u64>> {
        self.require(&[
            ("module", "list"),
            ("module", "name"),
            ("module", "state"),
            ("module", "mkobj"),
            ("module_kobject", "mod"),
        ])?;
        let back = add(
            self.isf.offset("module", "mkobj")?,
            self.isf.offset("module_kobject", "mod")?,
        )?;
        let width = self.isf.size("module_kobject", "mod")?;
        ensure!(matches!(width, 4 | 8), "module.mkobj.mod 宽度无效");
        let alignment = self.isf.data.key("base_types")["pointer"]
            .key("size")
            .as_u64()
            .context("模块扫描指针宽度缺失")?;
        ensure!(matches!(alignment, 4 | 8), "模块扫描指针宽度无效");
        let step = if known.iter().any(|address| address % alignment != 0) {
            1
        } else {
            usize::try_from(alignment)?
        };
        ensure!(
            back <= PAGE - width as u64,
            "module.mkobj 偏移超过一页，无法雕刻"
        );
        let name_size = self.isf.size("module", "name")?;
        let ModuleRegions {
            ranges: regions,
            span_only,
            allocator_bounds: bounds_proven,
        } = self.module_regions(listed)?;
        if strict && !bounds_proven && !span_only {
            partial(
                r,
                "模块扫描范围",
                anyhow::anyhow!("缺少分配器边界；仅扫描 x86_64 模块地址区域，视图覆盖未验证"),
            );
        }
        if span_only {
            partial(
                r,
                "模块内存范围",
                anyhow::anyhow!(
                    "ISF 缺少 mod_tree；只扫描已列出模块的地址跨度，跨度外的隐藏模块无法发现"
                ),
            );
        }
        let mut budget = CARVE_BUDGET;
        let mut validation_budget = CARVE_BUDGET;
        let mut candidates = 0usize;
        let mut missing_pages = 0u64;
        let mut first_missing = String::new();
        if strict {
            self.module_size_layout()?;
        }
        let mut found = Vec::new();
        'scan: for (start, end) in regions {
            let lower = start;
            let start = start & !(PAGE - 1);
            ensure!(end - start <= CARVE_SPAN, "模块内存范围超过 2 GiB 上限");
            // Two-page window: a candidate in the previous page may keep its
            // back-reference in the current one.
            let mut window = vec![0u8; 2 * usize::try_from(PAGE)?];
            let mut previous_mapped = false;
            let mut page = start;
            let flush = add(end, PAGE - 1)? & !(PAGE - 1);
            while page <= flush {
                job.check()?;
                window.copy_within(usize::try_from(PAGE)?.., 0);
                let current = window.at_mut(usize::try_from(PAGE)?..)?;
                let mapped = if page >= end {
                    false
                } else {
                    match self.vm.read(page, current) {
                        Ok(()) => true,
                        Err(error) => {
                            // Non-present PTEs are ordinary gaps between allocations.
                            // Missing captured physical pages / page tables are coverage loss.
                            if strict
                                && !error.to_string().starts_with("缺页 VA ")
                                && !error.to_string().starts_with("ARM64 缺页 VA ")
                            {
                                missing_pages += 1;
                                if first_missing.is_empty() {
                                    first_missing = format!("{page:#x}: {error:#}");
                                }
                            }
                            false
                        }
                    }
                };
                if !mapped {
                    current.fill(0);
                } else {
                    if budget < PAGE {
                        partial(
                            r,
                            "module scanner",
                            anyhow::anyhow!("模块内存读取达到 256 MiB 上限"),
                        );
                        break 'scan;
                    }
                    budget -= PAGE;
                }
                if previous_mapped {
                    let base = page - PAGE;
                    let first = if base < lower {
                        lower - base
                    } else {
                        (step as u64 - (base - lower) % step as u64) % step as u64
                    };
                    for offset in (first..PAGE).step_by(step) {
                        let candidate = base + offset;
                        let at = usize::try_from(offset + back)?;
                        let mut raw = [0u8; 8];
                        raw.at_mut(..width)?
                            .copy_from_slice(window.at(at..at + width)?);
                        let pointer = u64::from_le_bytes(raw);
                        if candidate < lower
                            || candidate >= end
                            || pointer != candidate
                            || known.contains(&candidate)
                        {
                            continue;
                        }
                        candidates += 1;
                        if candidates > LIMIT {
                            partial(
                                r,
                                "module scanner",
                                anyhow::anyhow!("模块候选超过 100 万项上限"),
                            );
                            break 'scan;
                        }
                        if self.carved_module(candidate, name_size).is_some() {
                            if strict {
                                match self.valid_module_allocation(
                                    candidate,
                                    job,
                                    &mut validation_budget,
                                ) {
                                    Ok(true) => {}
                                    Ok(false) => continue,
                                    Err(error) => {
                                        job.check()?;
                                        partial(r, "module scanner", error);
                                        break 'scan;
                                    }
                                }
                            }
                            found.push(candidate);
                        }
                    }
                }
                previous_mapped = mapped;
                page = add(page, PAGE)?;
                if (page - start).is_multiple_of(64 * 1024 * 1024) {
                    job.report(format!(
                        "hidden_modules: 已扫描 {} MiB",
                        (page - start) >> 20
                    ));
                }
            }
        }
        if missing_pages > 0 {
            partial(
                r,
                "模块扫描覆盖",
                anyhow::anyhow!("{missing_pages} 个页面无法读取；首处 {first_missing}"),
            );
        }
        job.report(format!("module scan: {} 个模块对象", found.len()));
        found.sort_unstable();
        found.dedup();
        Ok(found)
    }
    /// Validate one carved candidate; anything implausible is not a module.
    fn carved_module(&self, module: u64, name_size: usize) -> Option<Vec<String>> {
        let state = self.number(module, "module", "state").ok()?;
        if state > 3 {
            return None;
        }
        let name = self
            .vm
            .string(
                self.field_address(module, "module", "name").ok()?,
                name_size,
            )
            .ok()?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return None;
        }
        let (start, end) = self.module_range(module).ok()?;
        if start == 0 || start >= end {
            return None;
        }
        let state = match state {
            0 => "LIVE",
            1 => "COMING",
            2 => "GOING",
            _ => "UNFORMED",
        };
        Some(vec![
            name,
            hex(module),
            hex(start),
            hex(end),
            state.into(),
            "NotInModuleList; carved by mkobj back-reference".into(),
        ])
    }
    pub(super) fn listed_modules(&self, job: &Job) -> Result<Vec<u64>> {
        self.list_objects(
            self.isf
                .address("modules")
                .context("不支持: 缺少 modules")?,
            self.isf.offset("module", "list")?,
            job,
        )
    }
    pub(super) fn sysfs_modules(&self, r: &mut Results, job: &Job) -> Result<Vec<u64>> {
        let kset = self.vm.uint(
            self.isf
                .address("module_kset")
                .context("不支持: 缺少 module_kset")?,
            8,
        )?;
        let objects = self.list_objects(
            self.field_address(kset, "kset", "list")?,
            self.isf.offset("kobject", "entry")?,
            job,
        )?;
        let mut modules = Vec::new();
        for kobj in objects {
            job.check()?;
            let read = (|| -> Result<()> {
                let name = self.kernel_text(self.number(kobj, "kobject", "name")?, 128)?;
                let holder = kobj
                    .checked_sub(self.isf.offset("module_kobject", "kobj")?)
                    .context("module kobject 下溢")?;
                let module = self.number(holder, "module_kobject", "mod")?;
                if module == 0 {
                    return Ok(());
                }
                ensure!(
                    self.field_address(module, "module", "mkobj")? == holder,
                    "模块 kobject 反向引用不一致"
                );
                ensure!(
                    self.kernel_text(self.field_address(module, "module", "name")?, 128)? == name,
                    "模块名称不一致"
                );
                modules.push(module);
                Ok(())
            })();
            if let Err(e) = read {
                partial(r, format!("module kobject {kobj:#x}"), e);
            }
        }
        modules.sort_unstable();
        modules.dedup();
        Ok(modules)
    }
}

/// Only per-module flags participate in the older static table. Keep ordering,
/// including the reference's pre-4.10 P/G same-bit behavior for plain output.
const MODULE_TAINTS: &[(u8, char, &str)] = &[
    (0, 'P', "PROPRIETARY_MODULE"),
    (0, 'G', ""),
    (10, 'C', "CRAP"),
    (12, 'O', "OOT_MODULE"),
    (13, 'E', "UNSIGNED_MODULE"),
    (15, 'K', "LIVEPATCH"),
    (16, 'X', "AUX"),
    (17, 'T', "RANDSTRUCT"),
    (18, 'N', "TEST"),
];
fn taint_description(c: char) -> Option<&'static str> {
    match c {
        'G' => Some(""),
        'P' => Some("PROPRIETARY_MODULE"),
        'F' => Some("FORCED_MODULE"),
        'S' => Some("CPU_OUT_OF_SPEC"),
        'R' => Some("FORCED_RMMOD"),
        'M' => Some("MACHINE_CHECK"),
        'B' => Some("BAD_PAGE"),
        'U' => Some("USER"),
        'D' => Some("DIE"),
        'A' => Some("OVERRIDDEN_ACPI_TABLE"),
        'W' => Some("WARN"),
        'C' => Some("CRAP"),
        'I' => Some("FIRMWARE_WORKAROUND"),
        'O' => Some("OOT_MODULE"),
        'E' => Some("UNSIGNED_MODULE"),
        'L' => Some("SOFTLOCKUP"),
        'K' => Some("LIVEPATCH"),
        'X' => Some("AUX"),
        'T' => Some("RANDSTRUCT"),
        'N' => Some("TEST"),
        _ => None,
    }
}
impl Linux<'_> {
    pub(super) fn module_taints(&self, module: u64, plain: bool) -> Result<String> {
        let value = self.number(module, "module", "taints")?;
        let mut chars = String::new();
        if let Ok(flags) = self.isf.address("taint_flags") {
            let count = self.isf.data.key("symbols")["taint_flags"].key("type")["count"]
                .as_u64()
                .context("taint_flags 长度缺失")?;
            ensure!((1..=64).contains(&count), "taint_flags 长度无效");
            let size = self.isf.data.key("user_types")["taint_flag"]
                .key("size")
                .as_u64()
                .context("taint_flag size 缺失")?;
            ensure!((1..=4096).contains(&size), "taint_flag size 无效");
            for bit in 0..count {
                let flag = add(flags, bit * size)?;
                if self.number(flag, "taint_flag", "module")? == 0 {
                    continue;
                }
                let code = self.number(
                    flag,
                    "taint_flag",
                    if value & (1 << bit) != 0 {
                        "c_true"
                    } else {
                        "c_false"
                    },
                )?;
                if let Some(c) = u32::try_from(code).ok().and_then(char::from_u32)
                    && c != ' '
                {
                    chars.push(c);
                }
            }
        } else {
            for &(bit, c, _) in MODULE_TAINTS {
                if value & (1 << bit) != 0 {
                    chars.push(c);
                }
            }
        }
        if plain {
            return Ok(chars);
        }
        Ok(chars
            .chars()
            .filter_map(|c| match taint_description(c) {
                Some("") => None,
                Some(desc) => Some(desc.to_owned()),
                None => Some(format!("<UNKNOWN_TAINT_CHAR_{c}>")),
            })
            .collect::<Vec<_>>()
            .join(","))
    }
    /// Missing views remain unknown. A captured module is never made absent just
    /// because another gatherer failed, and each gatherer runs independently.
    pub(super) fn modxview(&self, plain: bool, job: &Job) -> Result<Results> {
        let mut result = self.result(Plugin::Modxview);
        let mut views: BTreeMap<u64, [bool; 3]> = BTreeMap::new();
        let mut complete = [true; 3];
        let listed = match self.listed_modules(job) {
            Ok(listed) => listed,
            Err(error) => {
                job.check()?;
                complete[0] = false;
                partial(&mut result, "module procfs", error);
                Vec::new()
            }
        };
        for &module in &listed {
            views.entry(module).or_default()[0] = true;
        }
        let before = result.diagnostics.len();
        match self.sysfs_modules(&mut result, job) {
            Ok(modules) => {
                for module in modules {
                    views.entry(module).or_default()[1] = true;
                }
            }
            Err(error) => {
                job.check()?;
                partial(&mut result, "module sysfs", error);
            }
        }
        complete[1] = result.diagnostics.len() == before;
        let before = result.diagnostics.len();
        match self.scan_module_objects(&listed, &HashSet::new(), true, &mut result, job) {
            Ok(modules) => {
                for module in modules {
                    views.entry(module).or_default()[2] = true;
                }
            }
            Err(error) => {
                job.check()?;
                partial(&mut result, "module scanner", error);
            }
        }
        complete[2] = result.diagnostics.len() == before;
        for (module, sources) in views {
            job.check()?;
            let name = match self.module_name(module, job) {
                Ok(name) => name,
                Err(error) => {
                    partial(&mut result, format!("module {module:#x} name"), error);
                    String::new()
                }
            };
            let taints = match self.module_taints(module, plain) {
                Ok(taints) => taints,
                Err(error) => {
                    partial(&mut result, format!("module {module:#x} taints"), error);
                    String::new()
                }
            };
            let mut row = vec![name, hex(module)];
            for i in 0..3 {
                row.push(if *sources.at(i)? || *complete.at(i)? {
                    sources.at(i)?.to_string()
                } else {
                    String::new()
                });
            }
            row.push(taints);
            result.rows.push(row);
        }
        Ok(result)
    }
}

impl Linux<'_> {
    pub(super) fn module_code_size(&self, module: u64) -> Result<u64> {
        if self.isf.has_field("module", "mem") {
            let count = self.isf.field("module", "mem")?["type"]
                .key("count")
                .as_u64()
                .context("module.mem count 缺失")?;
            let stride = self.isf.data.key("user_types")["module_memory"]
                .key("size")
                .as_u64()
                .context("module_memory size 缺失")?;
            ensure!(
                (1..=32).contains(&count) && (1..=4096).contains(&stride),
                "module.mem 布局无效"
            );
            let mem = self.field_address(module, "module", "mem")?;
            let mut total = 0;
            for name in [
                "MOD_INIT_TEXT",
                "MOD_INIT_DATA",
                "MOD_INIT_RODATA",
                "MOD_TEXT",
                "MOD_DATA",
                "MOD_RODATA",
                "MOD_RO_AFTER_INIT",
            ] {
                let index = self.isf.data.key("enums")["mod_mem_type"].key("constants")[name]
                    .as_u64()
                    .with_context(|| format!("{name} enum 缺失"))?;
                ensure!(index < count, "module.mem enum 越界");
                total = add(
                    total,
                    self.number(add(mem, index * stride)?, "module_memory", "size")?,
                )?;
            }
            return Ok(total);
        }
        let size = |layout: &str, legacy: &str| -> Result<u64> {
            if self.isf.has_field("module", layout) {
                self.number(
                    self.field_address(module, "module", layout)?,
                    "module_layout",
                    "size",
                )
            } else {
                self.number(module, "module", legacy)
            }
        };
        add(
            size("init_layout", "init_size")?,
            size("core_layout", "core_size")?,
        )
    }

    fn module_size_layout(&self) -> Result<()> {
        if self.isf.has_field("module", "mem") {
            self.require(&[("module_memory", "size")])?;
            for name in [
                "MOD_TEXT",
                "MOD_DATA",
                "MOD_RODATA",
                "MOD_RO_AFTER_INIT",
                "MOD_INIT_TEXT",
                "MOD_INIT_DATA",
                "MOD_INIT_RODATA",
            ] {
                ensure!(
                    self.isf.data.key("enums")["mod_mem_type"].key("constants")[name].is_u64(),
                    "缺少 {name} enum"
                );
            }
        } else if self.isf.has_field("module", "core_layout") {
            self.require(&[
                ("module", "core_layout.size"),
                ("module", "core_layout.text_size"),
                ("module", "init_layout.size"),
            ])?;
        } else {
            self.require(&[
                ("module", "core_size"),
                ("module", "core_text_size"),
                ("module", "init_size"),
            ])?;
        }
        Ok(())
    }
    fn module_sizes(&self, module: u64) -> Result<(u64, u64, u64)> {
        if self.isf.has_field("module", "mem") {
            let count = self.isf.field("module", "mem")?["type"]
                .key("count")
                .as_u64()
                .context("module.mem count 缺失")?;
            let size = self.isf.data.key("user_types")["module_memory"]
                .key("size")
                .as_u64()
                .context("module_memory size 缺失")?;
            ensure!(
                count <= 32 && (1..=4096).contains(&size),
                "module.mem 布局无效"
            );
            let mem = self.field_address(module, "module", "mem")?;
            let read = |name: &str| -> Result<u64> {
                let index = self.isf.data.key("enums")["mod_mem_type"].key("constants")[name]
                    .as_u64()
                    .context("module enum 缺失")?;
                ensure!(index < count, "module.mem enum 越界");
                self.number(add(mem, index * size)?, "module_memory", "size")
            };
            let text = read("MOD_TEXT")?;
            let core = add(
                add(add(text, read("MOD_DATA")?)?, read("MOD_RODATA")?)?,
                read("MOD_RO_AFTER_INIT")?,
            )?;
            let init = add(
                add(read("MOD_INIT_TEXT")?, read("MOD_INIT_DATA")?)?,
                read("MOD_INIT_RODATA")?,
            )?;
            Ok((text, core, init))
        } else if self.isf.has_field("module", "core_layout") {
            Ok((
                self.number(module, "module", "core_layout.text_size")?,
                self.number(module, "module", "core_layout.size")?,
                self.number(module, "module", "init_layout.size")?,
            ))
        } else {
            Ok((
                self.number(module, "module", "core_text_size")?,
                self.number(module, "module", "core_size")?,
                self.number(module, "module", "init_size")?,
            ))
        }
    }
    fn valid_module_allocation(&self, module: u64, job: &Job, budget: &mut u64) -> Result<bool> {
        let size = self.isf.data.key("user_types")["module"]
            .key("size")
            .as_u64()
            .context("module size 缺失")?;
        ensure!((1..=REGION_LIMIT).contains(&size), "module size 无效");
        ensure!(*budget >= size, "模块对象验证读取达到 256 MiB 上限");
        *budget -= size;
        let validate = (|| -> Result<bool> {
            let mut chunk = [0; 4096];
            let mut offset = 0;
            while offset < size {
                job.check()?;
                let count = (size - offset).min(4096) as usize;
                self.vm.read(add(module, offset)?, chunk.at_mut(..count)?)?;
                offset += count as u64;
            }
            let (text, core, init) = self.module_sizes(module)?;
            Ok((1..=20_000_000).contains(&text)
                && (1..=20_000_000).contains(&core)
                && add(core, init)? >= 4096)
        })();
        job.check()?;
        Ok(validate.unwrap_or(false))
    }
}

impl Linux<'_> {
    pub(super) fn module_extraction_bounds(&self) -> Result<(Vec<(u64, u64)>, bool)> {
        let regions = self.module_regions(&[])?;
        Ok((regions.ranges, regions.allocator_bounds))
    }
}

#[cfg(test)]
mod tests;
