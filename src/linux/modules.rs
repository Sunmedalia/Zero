//! Shared module allocation ranges, carving and independent module views.
use super::*;

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
            let start = self.vm.uint(min, 8)?;
            let end = self.vm.uint(self.isf.address("module_addr_max")?, 8)?;
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
        ensure!(back <= PAGE - 8, "module.mkobj 偏移超过一页，无法雕刻");
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
            let mut window = vec![0u8; 2 * PAGE as usize];
            let mut previous_mapped = false;
            let mut page = start;
            let flush = add(end, PAGE - 1)? & !(PAGE - 1);
            while page <= flush {
                job.check()?;
                window.copy_within((PAGE as usize).., 0);
                let current = &mut window[(PAGE as usize)..];
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
                    for offset in (0..PAGE).step_by(8) {
                        let at = (offset + back) as usize;
                        let pointer = u64::from_le_bytes(window[at..at + 8].try_into()?);
                        let candidate = base + offset;
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
    fn module_taints(&self, module: u64, plain: bool) -> Result<String> {
        let value = self.number(module, "module", "taints")?;
        let mut chars = String::new();
        if let Ok(flags) = self.isf.address("taint_flags") {
            let count = self.isf.data["symbols"]["taint_flags"]["type"]["count"]
                .as_u64()
                .context("taint_flags 长度缺失")?;
            ensure!((1..=64).contains(&count), "taint_flags 长度无效");
            let size = self.isf.data["user_types"]["taint_flag"]["size"]
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
            let name = match self.string(module, "module", "name") {
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
                row.push(if sources[i] || complete[i] {
                    sources[i].to_string()
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
                    self.isf.data["enums"]["mod_mem_type"]["constants"][name].is_u64(),
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
            let count = self.isf.field("module", "mem")?["type"]["count"]
                .as_u64()
                .context("module.mem count 缺失")?;
            let size = self.isf.data["user_types"]["module_memory"]["size"]
                .as_u64()
                .context("module_memory size 缺失")?;
            ensure!(
                count <= 32 && (1..=4096).contains(&size),
                "module.mem 布局无效"
            );
            let mem = self.field_address(module, "module", "mem")?;
            let read = |name: &str| -> Result<u64> {
                let index = self.isf.data["enums"]["mod_mem_type"]["constants"][name]
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
        let size = self.isf.data["user_types"]["module"]["size"]
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
                self.vm.read(add(module, offset)?, &mut chunk[..count])?;
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
mod tests {
    use super::*;
    use serde_json::json;
    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, Isf) {
        let (mut bytes, mut isf) = super::super::tests::fixture();
        let u64_field = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["module"] = json!({"size":144,"fields":{
            "list":{"offset":0,"type":{"kind":"struct","name":"list_head"}},
            "name":{"offset":16,"type":{"kind":"array","count":32,"subtype":{"kind":"base","name":"char"}}},
            "state":u64_field(48),
            "mkobj":{"offset":56,"type":{"kind":"struct","name":"module_kobject"}},
            "module_core":u64_field(96), "core_size":u64_field(104),
            "taints":u64_field(112), "core_text_size":u64_field(120), "init_size":u64_field(128)
        }});
        isf.data["user_types"]["module_kobject"] = json!({"size":40,"fields":{
            "kobj":{"offset":0,"type":{"kind":"struct","name":"kobject"}},
            "mod":u64_field(32)
        }});
        isf.data["user_types"]["kobject"] = json!({"size":24,"fields":{
            "entry":{"offset":0,"type":{"kind":"struct","name":"list_head"}}, "name":u64_field(16)
        }});
        isf.data["user_types"]["kset"] = json!({"size":16,"fields":{"list":{"offset":0,"type":{"kind":"struct","name":"list_head"}}}});
        for (name, address) in [
            ("modules", 0x31000),
            ("module_kset", 0x30000),
            ("module_addr_min", 0x30010),
            ("module_addr_max", 0x30018),
        ] {
            isf.data["symbols"][name] = json!({"address":address});
        }
        for (at, value) in [
            (0x31000, 0x34100),
            (0x31008, 0x34100),
            (0x34100, 0x31000),
            (0x34108, 0x31000),
            (0x30000, 0x30200),
            (0x30010, 0x34000),
            (0x30018, 0x37000),
            (0x30200, 0x34138),
            (0x30208, 0x36138),
            (0x34138, 0x36138),
            (0x34140, 0x30200),
            (0x36138, 0x30200),
            (0x36140, 0x34138),
        ] {
            put(&mut bytes, at, value);
        }
        for (module, name, string) in [
            (0x34100, b"listed".as_slice(), 0x38000),
            (0x35100, b"hidden".as_slice(), 0x38020),
            (0x36100, b"sysfs".as_slice(), 0x38040),
        ] {
            bytes[module + 16..module + 16 + name.len()].copy_from_slice(name);
            bytes[string..string + name.len()].copy_from_slice(name);
            put(&mut bytes, module + 72, string as u64);
            put(&mut bytes, module + 88, module as u64);
            put(&mut bytes, module + 96, 0x18000);
            put(&mut bytes, module + 104, 4096);
            put(&mut bytes, module + 120, 2048);
        }
        (bytes, isf)
    }
    #[test]
    fn independent_module_views_and_taints() {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x35100 + 112, 1 | (1 << 12));
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        let result = linux.modxview(false, &Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 3);
        assert_eq!(&result.rows[0][2..5], ["true", "true", "true"]);
        assert_eq!(&result.rows[1][2..5], ["false", "false", "true"]);
        assert_eq!(&result.rows[2][2..5], ["false", "true", "true"]);
        assert_eq!(result.rows[1][5], "PROPRIETARY_MODULE,OOT_MODULE");
        assert_eq!(
            linux.modxview(true, &Job::default()).unwrap().rows[1][5],
            "PGO"
        );
    }
    #[test]
    fn unreadable_view_is_unknown_and_other_views_survive() {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x31000, u64::MAX);
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        let result = linux.modxview(false, &Job::default()).unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 3);
        assert!(result.rows.iter().all(|r| r[2].is_empty()));
        assert_eq!(&result.rows[0][3..5], ["true", "true"]);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(linux.modxview(false, &job).is_err());
    }
    #[test]
    fn scan_rejects_freed_allocations_and_does_not_infer_presence() {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x34100 + 120, 0); // self-reference alone is insufficient
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .modxview(false, &Job::default())
            .unwrap();
        assert!(result.complete);
        assert_eq!(&result.rows[0][2..5], ["true", "true", "false"]);
    }
    #[test]
    fn missing_scan_layout_keeps_known_objects_with_unknown_scan_status() {
        let (bytes, mut isf) = fixture();
        isf.data["user_types"]["module"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("core_text_size");
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .modxview(false, &Job::default())
            .unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 2);
        assert!(result.rows.iter().all(|r| r[4].is_empty()));
    }
    #[test]
    fn modern_split_module_memory_sizes_drive_independent_validation() {
        let (mut bytes, mut isf) = fixture();
        let fields = isf.data["user_types"]["module"]["fields"]
            .as_object_mut()
            .unwrap();
        for field in ["module_core", "core_size", "core_text_size", "init_size"] {
            fields.remove(field);
        }
        fields.insert("mem".into(),json!({"offset":160,"type":{"kind":"array","count":7,"subtype":{"kind":"struct","name":"module_memory"}}}));
        isf.data["user_types"]["module"]["size"] = json!(272);
        isf.data["user_types"]["module_memory"] = json!({"size":16,"fields":{
            "base":{"offset":0,"type":{"kind":"pointer"}},
            "size":{"offset":8,"type":{"kind":"base","name":"u64"}}
        }});
        isf.data["enums"]["mod_mem_type"]["constants"] = json!({"MOD_TEXT":0,"MOD_DATA":1,"MOD_RODATA":2,"MOD_RO_AFTER_INIT":3,"MOD_INIT_TEXT":4,"MOD_INIT_DATA":5,"MOD_INIT_RODATA":6});
        for module in [0x34100, 0x35100, 0x36100] {
            put(&mut bytes, module + 160, 0x18000);
            put(&mut bytes, module + 168, 2048);
            put(&mut bytes, module + 184, 2048);
        }
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        assert_eq!(linux.module_sizes(0x34100).unwrap(), (2048, 4096, 0));
        let result = linux.modxview(false, &Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 3);
        assert!(result.rows.iter().all(|row| row[4] == "true"));
    }
    #[test]
    fn object_validation_has_an_independent_read_budget() {
        let (bytes, isf) = fixture();
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        let mut budget = 0;
        assert!(
            linux
                .valid_module_allocation(0x34100, &Job::default(), &mut budget)
                .unwrap_err()
                .to_string()
                .contains("上限")
        );
        assert_eq!(budget, 0);
    }
    #[test]
    fn unaligned_allocation_end_flushes_last_scan_page() {
        let (mut bytes, isf) = fixture();
        put(&mut bytes, 0x30018, 0x35101);
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .modxview(false, &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 3);
        assert_eq!(result.rows[1][0], "hidden");
        assert_eq!(result.rows[1][4], "true");
        assert_eq!(result.rows[2][4], "false");
    }
    #[test]
    fn missing_captured_scan_pages_are_coverage_diagnostics() {
        let (mut bytes, isf) = fixture();
        // PTE is present, but the corresponding physical page is absent from the capture.
        put(&mut bytes, 0x30018, 0x41000);
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .modxview(false, &Job::default())
            .unwrap();
        assert_eq!(result.rows.len(), 3);
        assert!(!result.complete);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.contains("模块扫描覆盖"))
        );
    }
    #[test]
    fn runtime_taint_definitions_override_static_flags_and_preserve_unknowns() {
        let (mut bytes, mut isf) = fixture();
        isf.data["symbols"]["taint_flags"] =
            json!({"address":0x39000,"type":{"kind":"array","count":2}});
        isf.data["user_types"]["taint_flag"] = json!({"size":3,"fields":{
            "c_true":{"offset":0,"type":{"kind":"base","name":"char"}},
            "c_false":{"offset":1,"type":{"kind":"base","name":"char"}},
            "module":{"offset":2,"type":{"kind":"base","name":"char"}}
        }});
        bytes[0x39000..0x39006].copy_from_slice(&[b'P', b'G', 1, b'Z', b' ', 1]);
        put(&mut bytes, 0x34100 + 112, 2);
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        assert_eq!(linux.module_taints(0x34100, true).unwrap(), "GZ");
        assert_eq!(
            linux.module_taints(0x34100, false).unwrap(),
            "<UNKNOWN_TAINT_CHAR_Z>"
        );
    }
}
