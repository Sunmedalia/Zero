//! The Linux engine: ISF-driven field readers and plugin routing.
use super::*;
pub struct Linux<'a> {
    pub vm: VirtualMemory<'a>,
    pub isf: &'a Isf,
}
/// One entry of the validated tasks list, as pslist reports it.
pub(crate) struct Task {
    pub pid: String,
    pub name: String,
    pub address: u64,
}
impl Linux<'_> {
    /// Walk the tasks list through pslist and hand back its entries plus an empty
    /// result for `plugin` that inherits pslist's completeness and diagnostics.
    pub(crate) fn tasks(&self, plugin: Plugin, job: &Job) -> Result<(Results, Vec<Task>)> {
        if plugin.name().starts_with("linux.") {
            return self.tasks_from_rows(plugin, self.reference_process_rows(plugin, job)?);
        }
        self.tasks_from_rows(plugin, self.run(Plugin::Pslist, job)?)
    }
    pub(super) fn task_identities(
        &self,
        plugin: Plugin,
        job: &Job,
    ) -> Result<(Results, Vec<Task>)> {
        self.tasks_from_rows(plugin, self.reference_process_rows(plugin, job)?)
    }
    #[cfg(test)]
    pub(super) fn adapter_tasks(&self, plugin: Plugin, job: &Job) -> Result<(Results, Vec<Task>)> {
        self.tasks_from_rows(plugin, self.process_identities(plugin, job)?)
    }
    fn tasks_from_rows(&self, plugin: Plugin, mut result: Results) -> Result<(Results, Vec<Task>)> {
        let tasks = std::mem::take(&mut result.rows)
            .into_iter()
            .map(|row| {
                Ok(Task {
                    address: u64::from_str_radix(&row[4][2..], 16)?,
                    pid: row[0].clone(),
                    name: row[3].clone(),
                })
            })
            .collect::<Result<_>>()?;
        result.plugin = plugin.name().into();
        result.columns = plugin
            .descriptor()
            .columns
            .iter()
            .map(|s| (*s).into())
            .collect();
        Ok((result, tasks))
    }
    /// Match task.get_parent_pid: use the parent's TGID only when the whole
    /// pointed-to task object is readable; otherwise report zero.
    pub(super) fn task_parent_tgid(&self, task: u64) -> Result<u64> {
        let parent = self.number(task, "task_struct", "real_parent")?;
        let size = self.isf.data["user_types"]["task_struct"]["size"]
            .as_u64()
            .context("task_struct 缺少大小")?;
        ensure!(size <= 1024 * 1024, "task_struct 超过读取上限");
        if parent != 0 && self.vm.read(parent, &mut vec![0; size as usize]).is_ok() {
            self.number(parent, "task_struct", "tgid")
        } else {
            Ok(0)
        }
    }
    pub(crate) fn field_address(&self, base: u64, structure: &str, field: &str) -> Result<u64> {
        base.checked_add(self.isf.offset(structure, field)?)
            .context("对象地址溢出")
    }
    pub(crate) fn number(&self, base: u64, structure: &str, field: &str) -> Result<u64> {
        if structure == "vfsmount"
            && self.modern_mount()
            && self.isf.field(structure, field).is_err()
        {
            let offset = self.isf.offset("mount", "mnt")?;
            let mount = base.checked_sub(offset).context("mount 地址下溢")?;
            let value = self.number(mount, "mount", field)?;
            return if field == "mnt_parent" {
                value.checked_add(offset).context("mount 地址溢出")
            } else {
                Ok(value)
            };
        }
        let layout = self.isf.layout(structure, field)?;
        let size = usize::try_from(layout.size).context("ISF 字段过大")?;
        let address = base.checked_add(layout.offset).context("对象地址溢出")?;
        let value = self.vm.uint(address, size)?;
        if let Some((position, length)) = layout.bits {
            let position = position.context("ISF bit position 无效")?;
            let length = length.context("ISF bit length 无效")?;
            ensure!(
                length > 0
                    && position
                        .checked_add(length)
                        .is_some_and(|end| end <= (size * 8) as u64),
                "ISF 位域越界"
            );
            Ok((value >> position) & (u64::MAX >> (64 - length)))
        } else {
            Ok(value)
        }
    }
    /// Empty result carrying this kernel's identity and validation warnings.
    pub(crate) fn result(&self, plugin: Plugin) -> Results {
        let diagnostics = self.isf.validation_diagnostics.read().unwrap().clone();
        Results {
            plugin: plugin.name().into(),
            columns: plugin
                .descriptor()
                .columns
                .iter()
                .map(|s| (*s).into())
                .collect(),
            rows: vec![],
            complete: diagnostics.is_empty(),
            diagnostics,
            banner: String::from_utf8_lossy(&self.isf.banner[..self.isf.banner.len() - 1])
                .trim_end()
                .into(),
            symbol: self.isf.label.clone(),
            page_table: self.vm.root,
            historical: false,
            system: "linux".into(),
            kernel_identity: if self.isf.validation_diagnostics.read().unwrap().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!({"system": "linux", "validation": {
                    "partial": true, "diagnostics": self.isf.validation_diagnostics.read().unwrap().clone()
                }})
            },
        }
    }
    /// Fail before traversal when the ISF lacks a field the plugin reads.
    /// Modern kernels moved `vfsmount` members into the enclosing `mount`.
    pub(crate) fn require(&self, fields: &[(&str, &str)]) -> Result<()> {
        for (s, f) in fields {
            if *s == "vfsmount" && self.modern_mount() && self.isf.field(s, f).is_err() {
                self.isf
                    .size("mount", f)
                    .with_context(|| format!("不支持: 缺少 mount.{f}"))?;
                continue;
            }
            self.isf
                .size(s, f)
                .with_context(|| format!("不支持: 缺少或无效字段 {s}.{f}"))?;
        }
        Ok(())
    }
    pub(super) fn string(&self, base: u64, structure: &str, field: &str) -> Result<String> {
        self.vm.string(
            self.field_address(base, structure, field)?,
            self.isf.size(structure, field)?,
        )
    }
    /// Route every plugin; non-Linux plugins are rejected instead of reaching a family
    /// dispatcher that does not handle them.
    pub fn run(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        use Plugin::*;
        match plugin {
            Pslist | Pstree | Lsmod => self.kernel_list(plugin, job),
            VmaRegExScan => anyhow::bail!("此插件需要 --pattern 字节正则及扫描参数"),
            Fbdev => self.fbdev(None, job),
            PsCallStack => self.ps_callstack(&Default::default(), job),
            LinuxSockscan => self.sockscan(job),
            LinuxPsscan => self.psscan(job),
            Kallsyms => self.kallsyms(Default::default(), job),
            Modxview => self.modxview(false, job),
            ProcessSpoofing => self.process_spoofing(job),
            LinuxPslist => self.process_details(job),
            LinuxBoottime => self.namespace_boottimes(job),
            LinuxCapabilities => self.capabilities(&Default::default(), job),
            LinuxEnvars => self.envars(&Default::default(), job),
            LinuxPsaux => self.psaux(&Default::default(), job),
            Banners => banner_result(self.vm.image, job),
            Psaux | Envars | Maps | Lsof | Sockstat | Netscan => self.task_objects(plugin, job),
            Pwd | Pscred | CheckCreds | Threads | Mountinfo => self.task_context(plugin, job),
            Psstate | Capabilities | Fdsummary => self.task_state(plugin, job),
            Elfs | LibraryList | Malfind | Bash => self.vma_scan(plugin, job),
            Iomem | Ioports | Ptrace | KeyboardNotifiers => self.kernel_relations(plugin, job),
            Dmesg => self.dmesg(job),
            Systeminfo => self.systeminfo(),
            Psxview => self.psxview_result(job),
            CheckExec => self.check_exec(job),
            CheckModules => {
                let mut r = self.result(plugin);
                self.check_modules(&mut r, job)?;
                Ok(r)
            }
            CheckSyscall => {
                let mut r = self.result(plugin);
                self.check_syscall(&mut r, job)?;
                Ok(r)
            }
            CheckIdt => {
                let mut r = self.result(plugin);
                self.check_idt(&mut r, job)?;
                Ok(r)
            }
            TtyCheck => {
                let mut r = self.result(plugin);
                self.tty_check(&mut r, job)?;
                Ok(r)
            }
            Pidhashtable => {
                let mut r = self.result(plugin);
                self.pidhashtable(&mut r, job)?;
                Ok(r)
            }
            Vmcoreinfo => {
                let mut r = self.result(plugin);
                self.vmcoreinfo(&mut r)?;
                Ok(r)
            }
            IpAddr => {
                let mut r = self.result(plugin);
                self.ip_addr(&mut r, job)?;
                Ok(r)
            }
            IpLink => {
                let mut r = self.result(plugin);
                self.ip_link(&mut r, job)?;
                Ok(r)
            }
            CheckAfinfo => {
                let mut r = self.result(plugin);
                self.check_afinfo(&mut r, job)?;
                Ok(r)
            }
            Kthreads => self.kthreads(job),
            Vmayarascan => bail!("vmayarascan 需要 --pattern"),
            Netfilter => {
                let mut r = self.result(plugin);
                self.netfilter(&mut r, job)?;
                Ok(r)
            }
            Tracepoints => {
                let mut r = self.result(plugin);
                self.tracepoints(&mut r, job)?;
                Ok(r)
            }
            Ftrace => {
                let mut r = self.result(plugin);
                self.ftrace(&mut r, job)?;
                Ok(r)
            }
            PerfEvents => self.perf_events(job),
            Ebpf => {
                let mut r = self.result(plugin);
                self.ebpf(&mut r, job)?;
                Ok(r)
            }
            Boottime => {
                let mut r = self.result(plugin);
                self.boottime(&mut r)?;
                Ok(r)
            }
            Pagecache => {
                let mut r = self.result(plugin);
                self.pagecache(&mut r, job)?;
                Ok(r)
            }
            HiddenModules => {
                let mut r = self.result(plugin);
                self.hidden_modules(&mut r, job)?;
                Ok(r)
            }
            WinTruecryptPassphrase
            | WinSkeletonKeyCheck
            | WinStrings
            | WinDirectSystemCalls
            | WinIndirectSystemCalls => Err(unrouted(plugin)),
            WinUnhookedSystemCalls => Err(unrouted(plugin)),
            ModuleExtract | Procdump | Memdump | Elfdump | WinLdrmodules | WinHollowprocesses
            | WinSuspiciousThreads | WinCallbacks | WinUnloadedmodules | WinFilescan
            | WinMutantscan | WinGetsids | WinConnscan | WinSockscan | WinConsoles | WinCmdscan
            | WinDrivercheck | WinDriverscan | WinSvcscan | WinCrashinfo | WinAutoruns
            | WinEnvars | WinThreads | WinSysteminfo | WinPslist | WinPstree | WinCmdline
            | WinModules | WinDlllist | WinVadinfo | WinHandles | WinMalfind | WinNetscan
            | WinNetstat | WinShimcacheMem | WinHivelist | WinPrintkey | WinPsscan | WinPsxview
            | WinProcdump | WinMemdump | WinPedump | WinSsdt | WinModscan | WinPrivileges
            | WinSessions | WinUserassist | WinBigpools | WinSymlinkscan | WinDevicetree
            | WinGetservicesids | WinIat | WinVerinfo | WinMftscan | WinOrphanThreads
            | WinEtwpatch | WinScheduledTasks | WinScheduledTasksV4 | WinDebugRegisters
            | WinSuspendedThreads | WinPESymbols | WinAmcacheV4 | WinAmcache | WinCertificates
            | WinProcessghosting | WinJoblinks | WinTimeliner | WinUserAssistV4 | WinMemmap
            | WinSvcScanV4 | WinSvcDiff | WinSvcList | WinGetCellRoutine | WinPebMasquerade
            | WinHiveScan | WinDriverModule | WinDriverIrp | WinKpcrs | WinMbrscan | WinTimers
            | WinStatistics | WinShimcache | WinVirtmap | WinVadWalk | WinVadRegExScan
            | WinVadyarascan | WinVaddump | WinDlldump | WinModdump | WinHashdump | WinLsadump
            | WinCachedump | WinDumpfiles | WinThrdscan | WinPoolScanner | WinWindowStations
            | WinDesktops | WinDeskScan | WinWindows => Err(unrouted(plugin)),
        }
    }
    /// Export the modules recovered by the forward list walk, preserving partial diagnostics.
    pub(super) fn lsmod_with_dump(
        &self,
        options: &crate::dump::DumpOptions,
        job: &Job,
    ) -> Result<Results> {
        let mut result = self.kernel_list(Plugin::Lsmod, job)?;
        for index in 0..result.rows.len() {
            job.check()?;
            let address = result.rows[index][0].clone();
            let object = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;
            let extraction = crate::dump::DumpOptions {
                pid: 0,
                start: Some(if self.arm64() {
                    object
                } else {
                    object & ((1u64 << 48) - 1)
                }),
                end: None,
                directory: options.directory.clone(),
            };
            let mut output = "-".to_owned();
            let mut output_type = "NotAvailableValue";
            match self.extract_module(&extraction, job) {
                Ok(extracted) => {
                    if let Some(row) = extracted.rows.first() {
                        output = row[2].clone();
                        output_type = "file";
                    }
                    if !extracted.complete {
                        result.complete = false;
                    }
                    result.diagnostics.extend(extracted.diagnostics);
                    result.kernel_identity["module_exports"][format!("{object:#x}")] =
                        extracted.kernel_identity;
                }
                Err(error) => {
                    job.check()?;
                    partial(&mut result, format!("module {object:#x} export"), error);
                }
            }
            result.rows[index][5] = output;
            result.kernel_identity["module_file_output_types"][format!("{object:#x}")] =
                output_type.into();
        }
        Ok(result)
    }

    fn kernel_list(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        if plugin != Plugin::Lsmod {
            return self.process_list(plugin, job);
        }
        let structure = "module";
        let offset = self.isf.offset(structure, "list")?;
        let head = self.isf.address("modules")?;
        let next = self.isf.offset("list_head", "next")?;
        let mut result = self.result(plugin);
        let traversal = (|| -> Result<()> {
            let mut node = self.vm.uint(add(head, next)?, 8)?;
            let mut visited = HashSet::new();
            while node != head {
                job.check()?;
                ensure!(visited.insert(node), "链表循环未回到表头 @ {node:#x}");
                ensure!(visited.len() <= 1_000_000, "链表超过安全上限");
                ensure!(node != 0, "模块链表遇到空 next");
                let object = node.checked_sub(offset).context("对象地址下溢")?;
                let row = (|| -> Result<Vec<String>> {
                    Ok({
                        let (base, size) = if self.isf.field("module", "mem").is_ok() {
                            let mem = self.field_address(object, "module", "mem")?;
                            let n = self.isf.field("module", "mem")?["type"]["count"]
                                .as_u64()
                                .context("module.mem count")?;
                            ensure!((1..=32).contains(&n), "module.mem count 无效");
                            let size = self.isf.data["user_types"]["module_memory"]["size"]
                                .as_u64()
                                .context("module_memory size")?;
                            let text =
                                self.isf.data["enums"]["mod_mem_type"]["constants"]["MOD_TEXT"]
                                    .as_u64()
                                    .context("MOD_TEXT enum 缺失")?;
                            ensure!(text < n, "MOD_TEXT enum 越界");
                            let mut total = 0u64;
                            for kind in ["MOD_TEXT", "MOD_DATA", "MOD_RODATA", "MOD_RO_AFTER_INIT"]
                            {
                                let i = self.isf.data["enums"]["mod_mem_type"]["constants"][kind]
                                    .as_u64()
                                    .with_context(|| format!("{kind} enum 缺失"))?;
                                ensure!(i < n, "module memory enum 越界");
                                total = total
                                    .checked_add(self.number(
                                        add(mem, i * size)?,
                                        "module_memory",
                                        "size",
                                    )?)
                                    .context("模块大小溢出")?;
                            }
                            (
                                self.number(add(mem, text * size)?, "module_memory", "base")?,
                                total,
                            )
                        } else if self.isf.field("module", "core_layout").is_ok() {
                            let layout = self.field_address(object, "module", "core_layout")?;
                            (
                                self.number(layout, "module_layout", "base")?,
                                self.number(layout, "module_layout", "size")?,
                            )
                        } else {
                            (
                                self.number(object, structure, "module_core")?,
                                self.number(object, structure, "core_size")?,
                            )
                        };
                        ensure!(base != 0 && size > 0, "模块基址或大小无效 @ {object:#x}");
                        vec![
                            self.string(object, structure, "name")?,
                            format!("{base:#018x}"),
                            size.to_string(),
                        ]
                    })
                })();
                match row {
                    Ok(row) => {
                        let name = row[0].clone();
                        result.kernel_identity["module_ranges"][format!("{object:#x}")] =
                            serde_json::json!({"base":row[1],"core_size":row[2]});
                        let mut code_size = "N/A".to_owned();
                        let mut arguments = "N/A".to_owned();
                        let code_size_layout = if self.isf.has_field("module", "mem") {
                            ["MOD_INIT_TEXT", "MOD_INIT_DATA", "MOD_INIT_RODATA"]
                                .iter()
                                .all(|name| {
                                    self.isf.data["enums"]["mod_mem_type"]["constants"][name]
                                        .is_u64()
                                })
                        } else {
                            self.isf.has_field("module", "init_layout")
                                || self.isf.has_field("module", "init_size")
                        };
                        if code_size_layout {
                            match self.module_code_size(object) {
                                Ok(size) => {
                                    code_size = size.to_string();
                                    result.kernel_identity["module_code_sizes"]
                                        [format!("{object:#x}")] = size.into()
                                }
                                Err(error) => partial(
                                    &mut result,
                                    format!("module {object:#x} code size"),
                                    error,
                                ),
                            }
                        } else {
                            result.kernel_identity["module_code_size_unsupported"] = true.into();
                            partial(
                                &mut result,
                                format!("module {object:#x} code size"),
                                anyhow::anyhow!("缺少 init 大小布局"),
                            );
                        }
                        match self.module_load_arguments(object, job) {
                            Ok(value) => {
                                arguments = value.clone();
                                result.kernel_identity["module_load_arguments"]
                                    [format!("{object:#x}")] = value.into();
                            }
                            Err(error) => {
                                job.check()?;
                                partial(
                                    &mut result,
                                    format!("module {object:#x} parameters"),
                                    error,
                                );
                            }
                        }
                        let taints = match self.module_taints(object, false) {
                            Ok(value) => value,
                            Err(error) => {
                                partial(&mut result, format!("module {object:#x} taints"), error);
                                "N/A".into()
                            }
                        };
                        result.kernel_identity["module_file_output_types"]
                            [format!("{object:#x}")] = "NotApplicableValue".into();
                        result.rows.push(vec![
                            hex(object),
                            name,
                            code_size,
                            taints,
                            arguments,
                            "N/A".into(),
                        ]);
                    }
                    Err(error) => {
                        job.check()?;
                        result.complete = false;
                        result
                            .diagnostics
                            .push(format!("对象 {object:#018x}: {error:#}"));
                    }
                }
                node = self.vm.uint(add(node, next)?, 8)?;
                job.report(format!("{}: {} 条", plugin.name(), result.rows.len()));
            }
            Ok(())
        })();
        if let Err(error) = traversal {
            job.check()?;
            result.complete = false;
            result.diagnostics.push(format!("部分结果: {error:#}"));
        }
        Ok(result)
    }
}
/// A family dispatcher was handed a plugin the router never sends it.
pub(super) fn unrouted(plugin: Plugin) -> anyhow::Error {
    anyhow::anyhow!("{} 不是此 Linux 分析入口支持的插件", plugin.name())
}
