//! Native Windows x64 memory analysis. Offsets come from exact ISF types.
use crate::{
    Job,
    analysis::Options,
    dump::DumpOptions,
    image::Image,
    linux::{Outcome, Plugin, Request},
    report::hex,
    store::{self, Results},
    symbols::Isf,
    windows_symbols::{self, PdbIdentity},
};
use anyhow::{Context, Result, bail, ensure};
use sha2::Digest;
use std::collections::{BTreeMap, HashSet};

pub mod arch;
pub use arch::Architecture;
use arch::Paging;
mod artifacts;
mod codec;
mod compatibility;
mod compressed;
pub mod container;
mod drivers;
mod dump;
pub mod hiber;
mod legacy_network;
mod memory;
mod network;
mod network_layout;
mod objects;
pub mod paging;
mod pool;
mod process;
mod registry;
mod user_artifacts;
mod user_layout;
mod wow64;
const MAX_OBJECTS: usize = 1_000_000;
const PHYSICAL_MASK: u64 = 0x000f_ffff_ffff_f000;
fn add(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).context("Windows 对象地址溢出")
}
fn kernel(pointer: u64) -> bool {
    pointer >= 0xffff_8000_0000_0000 && pointer != u64::MAX
}
fn filetime(value: u64) -> String {
    if value == 0 {
        String::new()
    } else {
        value.to_string()
    }
}

/// Independent Windows translation; software PTEs never change Linux semantics.
pub struct Memory<'a> {
    pub image: &'a Image,
    pub root: u64,
    pub isf: &'a Isf,
    pub sources: Option<&'a paging::Sources>,
    /// Paging geometry is fixed for this ISF. Callers mutate ISF layouts only before the first translation.
    paging: std::sync::OnceLock<Paging>,
    /// Virtual 4 KiB page → physical 4 KiB page. The image is read-only.
    pages: std::sync::Mutex<std::collections::HashMap<u64, u64>>,
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
            pages: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn paging(&self) -> Result<Paging> {
        if let Some(paging) = self.paging.get() {
            return Ok(*paging);
        }
        let paging = Paging::new(self.isf)?;
        Ok(*self.paging.get_or_init(|| paging))
    }
    fn pointer_size(&self) -> usize {
        self.paging()
            .expect("validated Windows ISF")
            .arch
            .pointer_size()
    }
    fn pointer(&self, address: u64) -> Result<u64> {
        self.uint(address, self.pointer_size())
    }
    fn kernel(&self, address: u64) -> bool {
        self.paging()
            .is_ok_and(|paging| paging.arch.kernel(address))
    }
    fn root_mask(&self) -> u64 {
        self.paging().expect("validated Windows ISF").root_mask()
    }
    pub fn translate(&self, va: u64) -> Result<u64> {
        let page = va & !4095;
        if let Some(base) = self
            .pages
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&page)
            .copied()
        {
            return Ok(base | (va & 4095));
        }
        let pa = self.translate_walk(va)?;
        self.pages
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(page, pa & !4095);
        Ok(pa)
    }
    fn translate_walk(&self, va: u64) -> Result<u64> {
        let geometry = self.paging()?;
        ensure!(geometry.canonical(va), "Windows 非 canonical 地址");
        let mut table = self.root & geometry.root_mask();
        for (level, &shift) in geometry.shifts().iter().enumerate() {
            let index = ((va >> shift) & (geometry.entries(level) as u64 - 1)) as usize;
            let mut entry = geometry.entry(self.image, table, index)?;
            if entry & 1 == 0 {
                if entry & (1 << 11) != 0 && entry & (1 << 10) == 0 {
                    entry = self.transition_frame(entry, geometry)?
                        | if geometry.arch == Architecture::Arm64 {
                            3
                        } else {
                            1
                        };
                } else {
                    bail!("Windows 缺页 VA {va:#x} level {shift} PTE {entry:#x}");
                }
            }
            if geometry.block(entry, shift) {
                let mask = (1u64 << shift) - 1;
                return Ok((entry & geometry.mask() & !mask) | (va & mask));
            }
            if geometry.arch == Architecture::Arm64 {
                ensure!(entry & 3 == 3, "无效 ARM64 table/page descriptor");
            }
            table = entry & geometry.mask();
        }
        Ok(table | (va & 4095))
    }
    pub fn read(&self, mut va: u64, mut out: &mut [u8]) -> Result<()> {
        va.checked_add(out.len() as u64)
            .context("Windows 读取越界")?;
        while !out.is_empty() {
            let _depth = paging::ReadDepth::enter(self.image, self.root, va)?;
            let n = out.len().min(4096 - (va & 4095) as usize);
            match self.translate(va) {
                Ok(physical) => self.image.read(physical, &mut out[..n])?,
                Err(original) => match self.prototype(va) {
                    Ok(physical) => self.image.read(physical, &mut out[..n])?,
                    Err(proto) => self
                        .pagefile_read(va, &mut out[..n])
                        .with_context(|| format!("{original:#}; {proto:#}"))?,
                },
            }
            va += n as u64;
            out = &mut out[n..];
        }
        Ok(())
    }
    fn transition_frame(&self, entry: u64, geometry: Paging) -> Result<u64> {
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
    fn prototype_address(&self, entry: u64) -> Result<u64> {
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
    fn prototype_page(&self, entry: u64, va: u64) -> Result<u64> {
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
    fn prototype(&self, va: u64) -> Result<u64> {
        let geometry = self.paging()?;
        ensure!(geometry.canonical(va), "Windows 非 canonical 地址");
        let mut table = self.root & geometry.root_mask();
        for (level, &shift) in geometry.shifts().iter().enumerate() {
            let index = ((va >> shift) & (geometry.entries(level) as u64 - 1)) as usize;
            let entry = geometry.entry(self.image, table, index)?;
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
        self.read(va, &mut b[..size])?;
        Ok(u64::from_le_bytes(b))
    }
    fn number(&self, base: u64, structure: &str, field: &str) -> Result<u64> {
        let layout = self.isf.layout(structure, field)?;
        let size = usize::try_from(layout.size).context("ISF 字段过大")?;
        let n = self.uint(add(base, layout.offset)?, size)?;
        json_number(self.isf, n, structure, field)
    }
    fn unicode(&self, address: u64) -> Result<String> {
        let len = self.number(address, "_UNICODE_STRING", "Length")?;
        let max = self.number(address, "_UNICODE_STRING", "MaximumLength")?;
        ensure!(
            len % 2 == 0 && len <= max && len <= 65534,
            "无效 UNICODE_STRING 长度"
        );
        let mut bytes = vec![0; len as usize];
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
fn json_number(isf: &Isf, n: u64, structure: &str, field: &str) -> Result<u64> {
    // The memoized layout answers the common case; fall back to the raw field
    // so a field that fails outer bounds checks still decodes as before.
    let bits = match isf.layout(structure, field) {
        Ok(layout) => layout.bits,
        Err(_) => {
            let ty = &isf.field(structure, field)?["type"];
            (ty["kind"] == "bitfield")
                .then(|| (ty["bit_position"].as_u64(), ty["bit_length"].as_u64()))
        }
    };
    if let Some((pos, len)) = bits {
        let pos = pos.context("缺少位域位置")?;
        let len = len.context("缺少位域长度")?;
        ensure!(len > 0 && pos + len <= 64, "无效 Windows 位域");
        Ok((n >> pos) & (u64::MAX >> (64 - len)))
    } else {
        Ok(n)
    }
}

pub struct Windows<'a> {
    pub vm: Memory<'a>,
    pub base: u64,
    pub pdb: PdbIdentity,
}
#[derive(Clone, Debug)]
pub struct Process {
    pub address: u64,
    pub physical: bool,
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
    pub dtb: u64,
    pub threads: u64,
    pub handles: Option<u64>,
    pub created: u64,
    pub exited: u64,
}
impl Process {
    fn row(&self) -> Vec<String> {
        vec![
            self.pid.to_string(),
            self.ppid.to_string(),
            self.name.clone(),
            if self.physical {
                format!("physical:{:#x}", self.address)
            } else {
                hex(self.address)
            },
            self.threads.to_string(),
            self.handles.map(|h| h.to_string()).unwrap_or_default(),
            filetime(self.created),
            filetime(self.exited),
        ]
    }
}
impl Windows<'_> {
    fn number(&self, b: u64, t: &str, f: &str) -> Result<u64> {
        self.vm.number(b, t, f)
    }
    fn field(&self, b: u64, t: &str, f: &str) -> Result<u64> {
        add(b, self.vm.isf.offset(t, f)?)
    }
    fn symbol(&self, name: &str) -> Result<u64> {
        add(self.base, self.vm.isf.raw_address(name)?)
    }
    fn result(&self, p: Plugin) -> Results {
        Results {
            plugin: p.name().into(),
            columns: p.descriptor().columns.iter().map(|s| (*s).into()).collect(),
            rows: vec![],
            complete: true,
            diagnostics: vec![],
            banner: format!(
                "Windows {:?} {}",
                Architecture::from_isf(self.vm.isf).unwrap(),
                self.pdb.key()
            ),
            symbol: self.vm.isf.label.clone(),
            page_table: self.vm.root,
            historical: false,
            system: "windows".into(),
            kernel_identity: serde_json::json!({"version":self.version_identity(),"pdb":self.pdb,"architecture":Architecture::from_isf(self.vm.isf).unwrap(),"container":self.vm.image.format,"kernel_base":self.base,"time_format":"FILETIME"}),
        }
    }
    fn list_partial(&self, head: u64, offset: u64, job: &Job) -> Result<(Vec<u64>, Vec<String>)> {
        ensure!(self.vm.kernel(head), "Windows 链表头非内核地址");
        let mut nodes = Vec::new();
        let mut diagnostics = Vec::new();
        let mut all = HashSet::new();
        for direction in [0, self.vm.pointer_size() as u64] {
            let mut previous = head;
            let mut current = self.vm.pointer(add(head, direction)?)?;
            let mut seen = HashSet::new();
            while current != head {
                job.check()?;
                let read = (|| -> Result<u64> {
                    ensure!(
                        self.vm.kernel(current) && current % self.vm.pointer_size() as u64 == 0,
                        "无效链表地址 {current:#x}"
                    );
                    ensure!(
                        seen.insert(current) && seen.len() <= MAX_OBJECTS,
                        "Windows 链表循环或超限 {current:#x}"
                    );
                    let opposite = self
                        .vm
                        .pointer(add(current, self.vm.pointer_size() as u64 - direction)?)?;
                    if opposite != previous {
                        diagnostics.push(format!("Windows 链表不一致 @ {current:#x} direction {direction}: expected {previous:#x}, found {opposite:#x}"));
                    }
                    let object = current.checked_sub(offset).context("链表成员地址下溢")?;
                    if all.insert(object) {
                        nodes.push(object);
                    }
                    self.vm.pointer(add(current, direction)?)
                })();
                match read {
                    Ok(next) => {
                        previous = current;
                        current = next
                    }
                    Err(e) => {
                        diagnostics.push(format!("链表 @ {head:#x} direction {direction}: {e:#}"));
                        break;
                    }
                }
            }
            if current == head
                && self
                    .vm
                    .pointer(add(head, self.vm.pointer_size() as u64 - direction)?)?
                    != previous
            {
                diagnostics.push(format!(
                    "Windows 链表末尾未闭合 @ {head:#x} direction {direction}"
                ));
            }
        }
        Ok((nodes, diagnostics))
    }
    fn process(&self, address: u64) -> Result<Process> {
        let len = self.vm.isf.size("_EPROCESS", "ImageFileName")?;
        ensure!(len <= 256, "进程名称过长");
        let mut b = vec![0; len];
        self.vm
            .read(self.field(address, "_EPROCESS", "ImageFileName")?, &mut b)?;
        let end = b.iter().position(|b| *b == 0).unwrap_or(b.len());
        let name = String::from_utf8_lossy(&b[..end]).into_owned();
        let pid = self.number(address, "_EPROCESS", "UniqueProcessId")?;
        ensure!(
            pid <= u32::MAX as u64 && !name.is_empty() && !name.chars().any(char::is_control),
            "无效 EPROCESS"
        );
        let dtb =
            self.number(address, "_EPROCESS", "Pcb.DirectoryTableBase")? & self.vm.root_mask();
        Ok(Process {
            address,
            physical: false,
            pid,
            ppid: self.number(address, "_EPROCESS", "InheritedFromUniqueProcessId")?,
            name,
            dtb,
            threads: self.number(address, "_EPROCESS", "ActiveThreads")?,
            handles: self
                .number(address, "_EPROCESS", "ObjectTable")
                .ok()
                .filter(|p| *p != 0)
                .and_then(|p| self.number(p, "_HANDLE_TABLE", "HandleCount").ok()),
            created: self.number(address, "_EPROCESS", "CreateTime")?,
            exited: self.number(address, "_EPROCESS", "ExitTime")?,
        })
    }
    fn processes_partial(&self, job: &Job) -> Result<(Vec<Process>, Vec<String>)> {
        let (nodes, mut diagnostics) = self.list_partial(
            self.symbol("PsActiveProcessHead")?,
            self.vm.isf.offset("_EPROCESS", "ActiveProcessLinks")?,
            job,
        )?;
        let mut out = Vec::new();
        for address in nodes {
            job.check()?;
            match self.process(address) {
                Ok(p) => out.push(p),
                Err(e) => diagnostics.push(format!("EPROCESS {address:#x}: {e:#}")),
            }
        }
        Ok((out, diagnostics))
    }
    fn process_memory(&self, p: &Process) -> Result<Memory<'_>> {
        ensure!(!p.physical, "扫描进程没有已验证虚拟地址");
        let user = self
            .number(p.address, "_EPROCESS", "Pcb.UserDirectoryTableBase")
            .unwrap_or(0)
            & self.vm.root_mask();
        ensure!(p.dtb != 0 || user != 0, "进程没有地址空间");
        Ok(Memory::new(
            self.vm.image,
            if p.dtb != 0 { p.dtb } else { user },
            self.vm.isf,
            self.vm.sources,
        ))
    }
    fn issue(r: &mut Results, context: impl std::fmt::Display, error: impl std::fmt::Display) {
        r.complete = false;
        r.diagnostics.push(format!("{context}: {error}"));
    }
    pub fn run(&self, p: Plugin, options: &Options, job: &Job) -> Result<Results> {
        job.check()?;
        let mut result = self.result(p);
        if p == Plugin::WinSysteminfo {
            result.rows = vec![
                vec!["OS".into(), "Windows".into()],
                vec![
                    "Architecture".into(),
                    format!("{:?}", Architecture::from_isf(self.vm.isf)?),
                ],
                vec!["PDB".into(), self.pdb.key()],
                vec!["KernelBase".into(), hex(self.base)],
                vec!["DTB".into(), hex(self.vm.root)],
                vec!["ImageSHA256".into(), self.vm.image.digest.clone()],
                vec!["ISFSHA256".into(), self.vm.isf.digest.clone()],
                vec![
                    "Validation".into(),
                    "PE/PDB/System/DTB/list entry validated".into(),
                ],
            ];
            if let Ok(address) = self.symbol("NtBuildNumber") {
                result.rows.push(vec![
                    "Build".into(),
                    (self.vm.uint(address, 4)? & 0xffff).to_string(),
                ]);
            }
            for key in ["product", "major", "minor", "product_type", "evidence"] {
                if let Some(value) = result.kernel_identity["version"].get(key) {
                    result.rows.push(vec![key.into(), value.to_string()]);
                }
            }
            return Ok(result);
        }
        if matches!(p, Plugin::WinCallbacks | Plugin::WinUnloadedmodules) {
            return self.kernel_artifacts(p, job);
        }
        if matches!(p, Plugin::WinFilescan | Plugin::WinMutantscan) {
            return self.pool_artifacts(p, job);
        }
        if matches!(p, Plugin::WinConnscan | Plugin::WinSockscan) {
            return self.legacy_network(p, job);
        }
        if matches!(p, Plugin::WinDriverscan | Plugin::WinDrivercheck) {
            return self.drivers(p, job);
        }
        if matches!(
            p,
            Plugin::WinSvcscan | Plugin::WinCmdscan | Plugin::WinConsoles
        ) {
            return self.user_artifacts(p, options, job);
        }
        if p == Plugin::WinModules {
            return self.modules(p, job);
        }
        if p == Plugin::WinHivelist {
            return self.registry(p, options, job);
        }
        if matches!(p, Plugin::WinPrintkey | Plugin::WinAutoruns) {
            let (processes, diagnostics) = self.processes_partial(job)?;
            let owners: Vec<_> = processes
                .iter()
                .filter(|process| {
                    process.name == "Registry" && process.ppid == 4 && process.exited == 0
                })
                .collect();
            ensure!(owners.len() <= 1, "Registry 进程归属歧义");
            let registry_vm = owners
                .first()
                .map(|process| self.process_memory(process))
                .transpose()?;
            let registry = Windows {
                vm: registry_vm.unwrap_or(Memory::new(
                    self.vm.image,
                    self.vm.root,
                    self.vm.isf,
                    self.vm.sources,
                )),
                base: self.base,
                pdb: self.pdb.clone(),
            };
            let mut result = if p == Plugin::WinAutoruns {
                registry.autoruns(options, job)?
            } else {
                registry.registry(p, options, job)?
            };
            if !diagnostics.is_empty() {
                result.complete = false;
                result.diagnostics.extend(diagnostics);
            }
            if let Some(owner) = owners.first() {
                result.kernel_identity["registry_process"] = serde_json::json!({"pid":owner.pid,"address":owner.address,"dtb":registry.vm.root,"kernel_dtb":self.vm.root});
            }
            return Ok(result);
        }
        if p == Plugin::WinNetscan {
            return self.netscan(job, None);
        }
        if matches!(p, Plugin::WinPsscan | Plugin::WinPsxview) {
            return self.scan_processes(p, options, job);
        }
        let (processes, diagnostics) = self.processes_partial(job)?;
        result.complete = diagnostics.is_empty();
        result.diagnostics = diagnostics;
        let thread_modules = if p == Plugin::WinThreads {
            Some(self.modules(Plugin::WinModules, job)?)
        } else {
            None
        };
        if let Some(modules) = &thread_modules
            && !modules.complete
        {
            result.complete = false;
            result.diagnostics.extend(modules.diagnostics.clone());
        }
        for process in processes
            .into_iter()
            .filter(|p| options.pid.is_none_or(|pid| p.pid == u64::from(pid)))
        {
            job.check()?;
            let read = match p {
                Plugin::WinPslist | Plugin::WinPstree => {
                    result.rows.push(process.row());
                    Ok(())
                }
                Plugin::WinCmdline => self.cmdline(&process, &mut result),
                Plugin::WinGetsids => self.sids(&process, &mut result, job),
                Plugin::WinEnvars => self.environments(&process, &mut result, job),
                Plugin::WinThreads => self.thread_rows(
                    &process,
                    &mut result,
                    thread_modules.as_ref().expect("thread modules"),
                    job,
                ),
                Plugin::WinDlllist => self.dlllist(&process, &mut result, job),
                Plugin::WinVadinfo | Plugin::WinMalfind => {
                    self.vad_result(&process, p, &mut result, job)
                }
                Plugin::WinHandles => self.handles(&process, &mut result, job),
                _ => bail!("不支持的 Windows 插件 {}", p.name()),
            };
            if let Err(e) = read {
                job.check()?;
                Self::issue(
                    &mut result,
                    format!("PID {} @ {:#x}", process.pid, process.address),
                    format!("{e:#}"),
                );
            }
        }
        Ok(result)
    }
    fn module_type(&self) -> Result<&'static str> {
        for name in ["_KLDR_DATA_TABLE_ENTRY", "_LDR_DATA_TABLE_ENTRY"] {
            if self.vm.isf.offset(name, "InLoadOrderLinks").is_ok() {
                return Ok(name);
            }
        }
        bail!("缺少内核模块条目类型")
    }
    fn modules(&self, p: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(p);
        let module_type = self.module_type()?;
        let (modules, diagnostics) = self.list_partial(
            self.symbol("PsLoadedModuleList")?,
            self.vm.isf.offset(module_type, "InLoadOrderLinks")?,
            job,
        )?;
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        for address in modules {
            let read = (|| -> Result<Vec<String>> {
                Ok(vec![
                    self.vm
                        .unicode(self.field(address, module_type, "BaseDllName")?)?,
                    hex(self.number(address, module_type, "DllBase")?),
                    self.number(address, module_type, "SizeOfImage")?
                        .to_string(),
                    self.vm
                        .unicode(self.field(address, module_type, "FullDllName")?)?,
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => Self::issue(&mut r, hex(address), e),
            }
        }
        Ok(r)
    }
}

pub fn analyze(
    image: &Image,
    request: &Request<'_>,
    dump: Option<&DumpOptions>,
    options: &Options,
    job: &Job,
) -> Result<Outcome> {
    if image.windows_container.as_ref().is_some_and(|m| {
        m.virtual_memory
            || m.kernel_virtual
            || image.segments.is_empty()
            || request.plugin == Plugin::WinCrashinfo
    }) {
        ensure!(
            options.pagefiles.is_empty() && options.swapfile.is_none(),
            "此容器没有可验证的内核分页索引，不接受分页附件"
        );
        return container::analyze(image, request, dump, options, job).map(Outcome::Ready);
    }
    if request.plugin.is_dump() {
        dump.context("Windows 转储需要 PID 和输出目录")?
            .validate(request.plugin)?;
    } else {
        ensure!(dump.is_none(), "分析插件不接受转储参数");
    }
    ensure!(
        request.plugin == Plugin::WinPrintkey
            || (request.plugin == Plugin::WinAutoruns && options.key.is_empty())
            || (options.hive.is_none() && options.key.is_empty()),
        "hive/key 仅用于 windows.printkey"
    );
    if request.plugin == Plugin::WinPrintkey {
        ensure!(options.hive.is_some(), "windows.printkey 需要 --hive 地址");
    }
    ensure!(
        options.pid.is_none() || request.plugin.descriptor().columns.contains(&"PID"),
        "此插件不支持 PID 筛选"
    );
    let symbols =
        windows_symbols::resolve(request.symbols, image, request.cache, request.network, job)?;
    let isf = if let Some(choice) = request.choice {
        symbols
            .iter()
            .find(|s| s.label == choice)
            .context("所选 Windows 符号不在精确匹配候选中")?
    } else {
        if symbols.len() > 1 {
            return Ok(Outcome::Choose(
                symbols.iter().map(|s| s.label.clone()).collect(),
            ));
        }
        &symbols[0]
    };
    let arch = Architecture::from_isf(isf)?;
    ensure!(
        options.arch == Architecture::Auto || options.arch == arch,
        "显式架构与符号不一致"
    );
    if let Some(hiber) = &image.hibernation {
        ensure!(
            arch.pointer_size() == hiber.info.pointer_size,
            "休眠容器与符号指针宽度不一致"
        );
    }
    let (root, base) = discover(image, isf, job)?;
    let mut sources = paging::Sources::open(options, job)?;
    let mut engine = Windows {
        vm: Memory::new(image, root, isf, None),
        base,
        pdb: PdbIdentity::from_isf(isf)?,
    };
    sources.configure_kernel(&engine)?;
    engine.vm.sources = Some(&sources);
    let key = store::key(
        &image.digest,
        &isf.digest,
        &format!(
            "{}:{:?}:{:?}:{}:{}",
            request.plugin.name(),
            options.pid,
            options.hive,
            sources.cache_identity(),
            format_args!(
                "{}:{:x}",
                options.key,
                sha2::Sha256::digest(network::LAYOUTS.as_bytes())
            )
        ),
    );
    if request.use_cache
        && !request.plugin.is_dump()
        && let Some(r) = store::load(request.cache, &key)
    {
        sources.validate()?;
        return Ok(Outcome::Ready(r));
    }
    let mut result = if let Some(dump) = dump {
        engine.run_dump(request.plugin, dump, job)?
    } else if request.plugin == Plugin::WinNetscan {
        engine.netscan(job, Some((request.cache, request.network)))?
    } else {
        engine.run(request.plugin, options, job)?
    };
    if let Some(pid) = options.pid
        && let Some(index) = result.columns.iter().position(|c| c == "PID")
    {
        result.rows.retain(|row| row[index] == pid.to_string());
    }
    sources.validate()?;
    result.kernel_identity["paging_sources"] = sources.manifest()?;
    let compressed = sources.compressed_evidence()?;
    if !compressed.as_array().is_none_or(Vec::is_empty) {
        Windows::issue(
            &mut result,
            "压缩 store",
            "此恢复路径经合成测试验证，尚未完成真实镜像对照",
        );
    }
    result.kernel_identity["compressed_pages"] = compressed;
    if let Some(hiber) = image.hibernation.as_ref() {
        result.kernel_identity["hibernation"] = serde_json::to_value(&hiber.info)?;
        Windows::issue(
            &mut result,
            "休眠文件",
            if hiber.info.hiberboot == Some(true) {
                "Fast Startup 保存内核会话，用户会话页面可能缺失；此容器路径目前仅有合成验证"
            } else {
                "仅包含休眠文件保存的物理页；此容器路径目前仅有合成验证"
            },
        );
        result.diagnostics.extend(hiber.info.diagnostics.clone());
    }
    job.check()?;
    if request.use_cache && !request.plugin.is_dump() {
        store::save(request.cache, &key, &result, job)?;
    }
    Ok(Outcome::Ready(result))
}

/// Discover self-referencing x64 roots and validate a mapped kernel against its PDB.
pub fn discover(image: &Image, isf: &Isf, job: &Job) -> Result<(u64, u64)> {
    job.check()?;
    let identity = PdbIdentity::from_isf(isf)?;
    let signatures: Vec<_> = image
        .windows_candidates(job)?
        .iter()
        .filter(|c| c.pdb == identity)
        .map(|c| c.offset)
        .collect();
    ensure!(!signatures.is_empty(), "ISF 与镜像 PDB 不匹配");
    if let Some(value) = image
        .windows_roots
        .lock()
        .map_err(|_| anyhow::anyhow!("Windows 准备缓存锁损坏"))?
        .get(&isf.digest)
    {
        return Ok(*value);
    }
    let geometry = Paging::new(isf)?;
    let mut headers = HashSet::new();
    let minimum = isf.raw_address("PsInitialSystemProcess")?;
    let mut roots = image
        .windows_container
        .as_ref()
        .and_then(|m| m.dtb)
        .into_iter()
        .collect::<Vec<_>>();
    let mut block = vec![0; 4 * 1024 * 1024];
    for segment in &image.segments {
        let mut start = segment.start.next_multiple_of(4096);
        while start < segment.end {
            job.check()?;
            let n = ((segment.end - start) as usize).min(block.len());
            image.read(start, &mut block[..n])?;
            for (i, page) in block[..n].chunks_exact(4096).enumerate() {
                let pa = start + i as u64 * 4096;
                if pe_header(page)
                    .is_ok_and(|(size, debug)| u64::from(size) > minimum && debug != 0)
                {
                    headers.insert(pa);
                }
                if geometry.arch == Architecture::X64
                    && page.chunks_exact(8).skip(256).any(|b| {
                        let e = u64::from_le_bytes(b.try_into().unwrap());
                        e & 1 != 0 && e & PHYSICAL_MASK == pa
                    })
                {
                    roots.push(pa);
                }
            }
            start += n as u64;
            job.report(format!(
                "Windows DTB 候选扫描 @ {start:#x} · {} 候选",
                roots.len()
            ));
        }
    }

    // A physical System EPROCESS gives a root candidate on every architecture.
    // Candidates still require mapped PE identity, PID, DTB and list validation.
    let name_offset = isf.offset("_EPROCESS", "ImageFileName")?;
    for hit in image.scan(b"System\0", job)? {
        job.check()?;
        let Some(address) = hit.checked_sub(name_offset) else {
            continue;
        };
        let read = |field: &str| -> Result<u64> {
            let mut b = [0; 8];
            image.read(
                add(address, isf.offset("_EPROCESS", field)?)?,
                &mut b[..isf.size("_EPROCESS", field)?],
            )?;
            Ok(u64::from_le_bytes(b))
        };
        if read("UniqueProcessId").is_ok_and(|pid| pid == 4)
            && let Ok(root) = read("Pcb.DirectoryTableBase")
            && root & geometry.root_mask() != 0
        {
            roots.push(root & geometry.root_mask());
        }
    }
    roots.sort_unstable();
    roots.dedup();

    ensure!(!headers.is_empty(), "找不到 Windows 内核 PE 头");
    job.report(format!(
        "Windows {} 个 PE 头，{} 个 DTB 候选",
        headers.len(),
        roots.len()
    ));
    for root in roots {
        job.check()?;
        let mut bases = Vec::new();
        let mut visited = HashSet::new();
        let mut budget = MAX_OBJECTS;
        find_mappings(
            image,
            root,
            geometry,
            0,
            0,
            &headers,
            &mut bases,
            &mut visited,
            &mut budget,
            job,
        )?;
        for base in bases {
            let vm = Memory::new(image, root, isf, None);
            let test = (|| -> Result<()> {
                let mut header = [0; 4096];
                vm.read(base, &mut header)?;
                let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
                pe_header(&header)?;
                ensure!(
                    u16::from_le_bytes(header[pe + 4..pe + 6].try_into()?)
                        == geometry.arch.machine(),
                    "内核 PE 与符号指针架构冲突"
                );
                ensure!(
                    network::pe_identity(&vm, base)? == identity,
                    "内核 PE 身份不匹配"
                );
                let engine = Windows {
                    vm,
                    base,
                    pdb: identity.clone(),
                };
                let system = engine
                    .vm
                    .pointer(engine.symbol("PsInitialSystemProcess")?)?;
                let process = engine.process(system)?;
                ensure!(
                    process.pid == 4 && process.name == "System" && process.dtb != 0,
                    "System 进程验证失败"
                );
                let head = engine.symbol("PsActiveProcessHead")?;
                let link = engine.field(system, "_EPROCESS", "ActiveProcessLinks")?;
                ensure!(
                    engine.vm.pointer(head)? == link
                        && engine
                            .vm
                            .pointer(add(link, engine.vm.pointer_size() as u64)?)?
                            == head,
                    "System 链表入口验证失败"
                );
                let next = engine.vm.pointer(link)?;
                ensure!(
                    engine.vm.kernel(next)
                        && engine
                            .vm
                            .pointer(add(next, engine.vm.pointer_size() as u64)?)?
                            == link,
                    "System 相邻链表验证失败"
                );
                let system_vm = Memory::new(image, process.dtb, isf, None);
                ensure!(system_vm.uint(base, 2)? == 0x5a4d, "System DTB 未映射内核");
                Ok(())
            })();
            if test.is_ok() {
                job.report(format!("Windows 内核已验证 DTB {root:#x} Base {base:#x}"));
                let vm = Memory::new(image, root, isf, None);
                let system = vm.pointer(add(base, isf.raw_address("PsInitialSystemProcess")?)?)?;
                let root = vm.number(system, "_EPROCESS", "Pcb.DirectoryTableBase")?
                    & geometry.root_mask();
                image
                    .windows_roots
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Windows 准备缓存锁损坏"))?
                    .insert(isf.digest.clone(), (root, base));
                return Ok((root, base));
            } else if let Err(e) = test {
                job.report(format!(
                    "Windows 内核候选拒绝 DTB {root:#x} Base {base:#x}: {e:#}"
                ));
            }
        }
    }
    bail!("无法验证 Windows 内核/DTB/PDB/进程链表")
}
#[allow(clippy::too_many_arguments)]
fn find_mappings(
    image: &Image,
    table: u64,
    geometry: Paging,
    level: usize,
    prefix: u64,
    headers: &HashSet<u64>,
    out: &mut Vec<u64>,
    seen: &mut HashSet<(u64, u32)>,
    budget: &mut usize,
    job: &Job,
) -> Result<()> {
    job.check()?;
    let shift = geometry.shifts()[level];
    if !seen.insert((table, shift)) {
        return Ok(());
    }
    ensure!(*budget > 0, "Windows 页表搜索超限");
    *budget -= 1;
    let mut bytes = vec![0; geometry.entries(level) * geometry.width()];
    if image.read(table, &mut bytes).is_err() {
        return Ok(());
    }
    for (i, chunk) in bytes.chunks_exact(geometry.width()).enumerate() {
        if level == 0 && i < geometry.entries(level) / 2 {
            continue;
        }
        let mut raw = [0; 8];
        raw[..geometry.width()].copy_from_slice(chunk);
        let e = u64::from_le_bytes(raw);
        if e & 1 == 0 {
            continue;
        }
        let va = prefix | ((i as u64) << shift);
        let pa = e & geometry.mask();
        if shift == 12 || geometry.block(e, shift) {
            let mask = (1u64 << shift) - 1;
            let pa = pa & !mask;
            for &h in headers {
                if h >= pa && h - pa <= mask {
                    out.push(geometry.extend(va | (h - pa)));
                }
            }
        } else if level + 1 < geometry.shifts().len() {
            find_mappings(
                image,
                pa,
                geometry,
                level + 1,
                va,
                headers,
                out,
                seen,
                budget,
                job,
            )?;
        }
    }
    Ok(())
}
pub(crate) fn pe_header(b: &[u8]) -> Result<(u32, u32)> {
    ensure!(b.len() >= 64 && &b[..2] == b"MZ", "非 PE");
    let pe = u32::from_le_bytes(b[60..64].try_into()?) as usize;
    ensure!(
        pe >= 64 && pe + 24 + 168 <= b.len() && &b[pe..pe + 4] == b"PE\0\0",
        "PE 头越界"
    );
    let machine = u16::from_le_bytes(b[pe + 4..pe + 6].try_into()?);
    let magic = u16::from_le_bytes(b[pe + 24..pe + 26].try_into()?);
    ensure!(
        matches!((machine, magic), (0x14c, 0x10b) | (0x8664 | 0xaa64, 0x20b)),
        "未知 PE 机器类型/optional header"
    );
    let directories = if magic == 0x10b { 96 } else { 112 };
    let size = u32::from_le_bytes(b[pe + 80..pe + 84].try_into()?);
    let debug =
        u32::from_le_bytes(b[pe + 24 + directories + 48..pe + 24 + directories + 52].try_into()?);
    ensure!(
        (4096..=256 * 1024 * 1024).contains(&size),
        "PE SizeOfImage 无效"
    );
    Ok((size, debug))
}

#[cfg(test)]
mod tests;
