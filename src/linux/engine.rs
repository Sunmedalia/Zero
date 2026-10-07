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
        let mut result = self.run(Plugin::Pslist, job)?;
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
    /// Empty, complete result carrying this kernel's identity.
    pub(crate) fn result(&self, plugin: Plugin) -> Results {
        Results {
            plugin: plugin.name().into(),
            columns: plugin
                .descriptor()
                .columns
                .iter()
                .map(|s| (*s).into())
                .collect(),
            rows: vec![],
            complete: true,
            diagnostics: vec![],
            banner: String::from_utf8_lossy(&self.isf.banner[..self.isf.banner.len() - 1])
                .trim_end()
                .into(),
            symbol: self.isf.label.clone(),
            page_table: self.vm.root,
            historical: false,
            system: "linux".into(),
            kernel_identity: serde_json::Value::Null,
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
            Banners => banner_result(self.vm.image, job),
            Psaux | Envars | Maps | Lsof | Sockstat => self.task_objects(plugin, job),
            Pwd | Pscred | CheckCreds | Threads | Mountinfo => self.task_context(plugin, job),
            Psstate | Capabilities | Fdsummary => self.task_state(plugin, job),
            Elfs | Malfind | Bash | History => self.vma_scan(plugin, job),
            Iomem | Ioports | Ptrace | KeyboardNotifiers => self.kernel_relations(plugin, job),
            Dmesg => self.dmesg(job),
            Systeminfo => self.systeminfo(),
            Psxview => self.psxview_result(job),
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
            Procdump | Memdump | Elfdump | WinCallbacks | WinUnloadedmodules | WinFilescan
            | WinMutantscan | WinGetsids | WinConnscan | WinSockscan | WinConsoles | WinCmdscan
            | WinDrivercheck | WinDriverscan | WinSvcscan | WinCrashinfo | WinAutoruns
            | WinEnvars | WinThreads | WinSysteminfo | WinPslist | WinPstree | WinCmdline
            | WinModules | WinDlllist | WinVadinfo | WinHandles | WinMalfind | WinNetscan
            | WinHivelist | WinPrintkey | WinPsscan | WinPsxview | WinProcdump | WinMemdump
            | WinPedump => Err(unrouted(plugin)),
        }
    }
    /// pslist / pstree over `init_task.tasks`, lsmod over `modules`, with full
    /// next/prev consistency checks.
    fn kernel_list(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let process = plugin != Plugin::Lsmod;
        let structure = if process { "task_struct" } else { "module" };
        let member = if process { "tasks" } else { "list" };
        let offset = self.isf.offset(structure, member)?;
        let head = if process {
            self.field_address(self.isf.address("init_task")?, structure, member)?
        } else {
            self.isf.address("modules")?
        };
        let next = self.isf.offset("list_head", "next")?;
        let prev = self.isf.offset("list_head", "prev")?;
        let mut result = self.result(plugin);
        let traversal = (|| -> Result<()> {
            let mut node = self.vm.uint(add(head, next)?, 8)?;
            let mut previous = head;
            let mut visited = HashSet::new();
            let mut pids = HashSet::new();
            while node != head {
                job.check()?;
                ensure!(visited.insert(node), "链表循环未回到表头 @ {node:#x}");
                ensure!(visited.len() <= 1_000_000, "链表超过安全上限");
                ensure!(
                    self.vm.uint(add(node, prev)?, 8)? == previous,
                    "链表 prev 不一致 @ {node:#x}"
                );
                let successor = self.vm.uint(add(node, next)?, 8)?;
                ensure!(
                    self.vm.uint(add(successor, prev)?, 8)? == node,
                    "链表 next/prev 不一致 @ {node:#x}"
                );
                let object = node.checked_sub(offset).context("对象地址下溢")?;
                let row = (|| -> Result<Vec<String>> {
                    Ok(if process {
                        let pid = self.number(object, structure, "pid")?;
                        let tgid = self.number(object, structure, "tgid")?;
                        ensure!(
                            pid > 0
                                && pid <= i32::MAX as u64
                                && tgid > 0
                                && tgid <= i32::MAX as u64,
                            "非法 PID/TGID @ {object:#x}"
                        );
                        ensure!(pids.insert(pid), "重复 PID {pid}");
                        let parent = self.number(object, structure, "real_parent")?;
                        let ppid = self.number(parent, structure, "pid")?;
                        ensure!(ppid <= i32::MAX as u64, "非法 PPID @ {object:#x}");
                        vec![
                            pid.to_string(),
                            tgid.to_string(),
                            ppid.to_string(),
                            self.string(object, structure, "comm")?,
                            format!("{object:#018x}"),
                        ]
                    } else {
                        let (base, size) = if self.isf.field("module", "module_core").is_ok() {
                            (
                                self.number(object, structure, "module_core")?,
                                self.number(object, structure, "core_size")?,
                            )
                        } else if self.isf.field("module", "mem").is_ok() {
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
                        } else {
                            let layout = self.field_address(object, "module", "core_layout")?;
                            (
                                self.number(layout, "module_layout", "base")?,
                                self.number(layout, "module_layout", "size")?,
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
                    Ok(row) => result.rows.push(row),
                    Err(error) => {
                        job.check()?;
                        result.complete = false;
                        result
                            .diagnostics
                            .push(format!("对象 {object:#018x}: {error:#}"));
                    }
                }
                previous = node;
                node = successor;
                job.report(format!("{}: {} 条", plugin.name(), result.rows.len()));
            }
            ensure!(
                self.vm.uint(add(head, prev)?, 8)? == previous,
                "链表表头 prev 不一致"
            );
            Ok(())
        })();
        if let Err(error) = traversal {
            job.check()?;
            result.complete = false;
            result.diagnostics.push(format!("部分结果: {error:#}"));
        }
        if process && result.complete {
            let pids: HashSet<_> = result.rows.iter().map(|r| r[0].as_str()).collect();
            let orphans: Vec<_> = result
                .rows
                .iter()
                .filter(|r| r[2] != "0" && !pids.contains(r[2].as_str()))
                .map(|r| r[0].clone())
                .collect();
            if !orphans.is_empty() {
                result.diagnostics.push(format!(
                    "父进程不在 tasks 链表（可能为线程或已退出）: {}",
                    orphans.join(",")
                ));
            }
        }
        Ok(result)
    }
}
/// A family dispatcher was handed a plugin the router never sends it.
pub(super) fn unrouted(plugin: Plugin) -> anyhow::Error {
    anyhow::anyhow!("{} 不是此 Linux 分析入口支持的插件", plugin.name())
}
