use super::*;
#[derive(Clone, Debug)]
/// Symbol-derived layout facts for resolving a VAD's backing file.
pub(super) struct VadLayout {
    pub(super) direct_control: bool,
    fast_ref: bool,
    mask: u64,
}
pub(super) struct Vad {
    pub address: u64,
    pub start: u64,
    pub end: u64,
    pub protection: u64,
    pub private: bool,
    pub path: String,
}
pub(super) struct VadNode {
    pub address: u64,
    pub parent: Option<u64>,
    pub left: Option<u64>,
    pub right: Option<u64>,
    pub start: u64,
    pub end: u64, // exclusive internally; VadWalk renders the inclusive last byte
    pub tag: String,
}
#[derive(Default, serde::Serialize)]
pub(super) struct VadWalkCoverage {
    pub visited: usize,
    pub yielded: usize,
    pub stopped: bool,
}
struct VadTree<'a> {
    root: u64,
    offset: u64,
    node_type: &'a str,
    children: [&'static str; 2],
}
impl Windows<'_> {
    /// The native PEB, or `None` when `EPROCESS.Peb` was read and is zero.
    ///
    /// Minimal processes (Registry, MemCompression, Secure System) never have a
    /// user-mode PEB, and a process in teardown has released it; that is a read
    /// fact about the process, not a missing page, so it is not a diagnostic.
    pub(super) fn peb(&self, p: &Process) -> Result<Option<u64>> {
        let peb = self.number(p.address, "_EPROCESS", "Peb")?;
        Ok((peb != 0).then_some(peb))
    }
    pub(super) fn cmdline(&self, p: &Process, r: &mut Results) -> Result<()> {
        if p.pid <= 4 {
            return Ok(());
        }
        let native = (|| -> Result<Option<String>> {
            let vm = self.process_memory(p)?;
            let Some(peb) = self.peb(p)? else {
                return Ok(None);
            };
            let params = vm.number(peb, "_PEB", "ProcessParameters")?;
            vm.unicode(add(
                params,
                self.vm
                    .isf
                    .offset("_RTL_USER_PROCESS_PARAMETERS", "CommandLine")?,
            )?)
            .map(Some)
        })();
        match native {
            Ok(Some(command)) => r.rows.push(vec![
                p.pid.to_string(),
                p.name.clone(),
                command,
                "native".into(),
            ]),
            Ok(None) => {}
            Err(e) => Self::issue(r, format!("PID {} native command", p.pid), e),
        }
        match self.wow64_peb(p) {
            Ok(Some(peb)) => match self.wow64_command(p, peb) {
                Ok(command) => r.rows.push(vec![
                    p.pid.to_string(),
                    p.name.clone(),
                    command,
                    "wow64".into(),
                ]),
                Err(e) => Self::issue(r, format!("PID {} WOW64 command", p.pid), e),
            },
            Ok(None) => {}
            Err(e) => Self::issue(r, format!("PID {} WOW64 PEB", p.pid), e),
        }
        Ok(())
    }
    pub(super) fn dlls(
        &self,
        p: &Process,
        job: &Job,
        result: &mut Results,
    ) -> Result<Vec<(u64, u64, String, String)>> {
        self.dlls_partial(p, job, Some(result))
    }
    pub(super) fn dlls_partial(
        &self,
        p: &Process,
        job: &Job,
        result: Option<&mut Results>,
    ) -> Result<Vec<(u64, u64, String, String)>> {
        let mut scratch = self.result(Plugin::WinDlllist);
        let r = result.unwrap_or(&mut scratch);
        let mut out = match self.native_dlls_partial(p, job, Some(r)) {
            Ok(out) => out,
            Err(e) => {
                Self::issue(r, format!("PID {} native DLL", p.pid), e);
                Vec::new()
            }
        };
        match self.wow64_peb(p) {
            Ok(Some(peb)) => match self.wow64_dlls(p, peb, job, r) {
                Ok(dlls) => out.extend(dlls),
                Err(e) => Self::issue(r, format!("PID {} WOW64 DLL", p.pid), e),
            },
            Ok(None) => {}
            Err(e) => Self::issue(r, format!("PID {} WOW64 PEB", p.pid), e),
        }
        Ok(out)
    }
    fn native_dlls_partial(
        &self,
        p: &Process,
        job: &Job,
        mut result: Option<&mut Results>,
    ) -> Result<Vec<(u64, u64, String, String)>> {
        if p.pid <= 4 {
            return Ok(Vec::new());
        }
        let vm = self.process_memory(p)?;
        let Some(peb) = self.peb(p)? else {
            return Ok(Vec::new());
        };
        let ldr = vm.number(peb, "_PEB", "Ldr")?;
        let head = add(
            ldr,
            self.vm
                .isf
                .offset("_PEB_LDR_DATA", "InLoadOrderModuleList")?,
        )?;
        let offset = self
            .vm
            .isf
            .offset("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")?;
        let mut previous = head;
        let mut node = vm.pointer(head)?;
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        while node != head {
            job.check()?;
            let step = (|| -> Result<()> {
                ensure!(
                    seen.insert(node) && seen.len() <= MAX_OBJECTS,
                    "DLL 链表循环或超限"
                );
                ensure!(
                    vm.pointer(add(node, vm.pointer_size() as u64)?)? == previous,
                    "DLL 双向链表损坏"
                );
                let address = node.checked_sub(offset).context("DLL 地址下溢")?;
                out.push((
                    vm.number(address, "_LDR_DATA_TABLE_ENTRY", "DllBase")?,
                    vm.number(address, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage")?,
                    vm.unicode(add(
                        address,
                        self.vm.isf.offset("_LDR_DATA_TABLE_ENTRY", "FullDllName")?,
                    )?)?,
                    "native".into(),
                ));
                previous = node;
                node = vm.pointer(node)?;
                Ok(())
            })();
            if let Err(e) = step {
                match result.as_deref_mut() {
                    Some(r) => {
                        Self::issue(r, format!("PID {} DLL {node:#x}", p.pid), e);
                        return Ok(out);
                    }
                    None => return Err(e),
                }
            }
        }
        if vm.pointer(add(head, vm.pointer_size() as u64)?)? != previous {
            match result {
                Some(r) => Self::issue(r, format!("PID {} DLL", p.pid), "DLL 链表未闭合"),
                None => bail!("DLL 链表未闭合"),
            }
        }
        Ok(out)
    }
    pub(super) fn dlllist(&self, p: &Process, r: &mut Results, job: &Job) -> Result<()> {
        for (base, size, path, view) in self.dlls_partial(p, job, Some(r))? {
            r.rows.push(vec![
                p.pid.to_string(),
                p.name.clone(),
                hex(base),
                size.to_string(),
                path,
                view,
            ]);
        }
        Ok(())
    }
    /// windows.vadyarascan: every VAD of one process searched for `pattern`.
    pub(super) fn vad_pattern_scan(
        &self,
        p: &Process,
        pattern: &crate::pattern::Pattern,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let vm = self.process_memory(p)?;
        let mut budget = 256 * 1024 * 1024u64;
        let mut unreadable = 0u64;
        // Keep the readable part of a damaged VAD tree, as vadinfo does.
        for v in self.vads_partial(p, job, Some(r))? {
            job.check()?;
            let remaining = 100_000usize.saturating_sub(r.rows.len());
            ensure!(remaining > 0, "命中数达到 100000 上限");
            if v.end.saturating_sub(v.start) > crate::pattern::REGION_LIMIT {
                Self::issue(
                    r,
                    format!("PID {} VAD {:#x}", p.pid, v.start),
                    "区域超过 1 GiB，未扫描",
                );
                continue;
            }
            let scan = crate::pattern::scan_region(
                pattern,
                v.start,
                v.end,
                &mut budget,
                remaining,
                |at, out| {
                    job.check()?;
                    vm.read(at, out)
                },
            )?;
            unreadable += scan.unreadable;
            for (address, bytes) in scan.hits {
                r.rows.push(vec![
                    p.pid.to_string(),
                    p.name.clone(),
                    hex(address),
                    hex(v.start),
                    protection(v.protection),
                    v.path.clone(),
                    crate::pattern::context(&bytes),
                ]);
            }
        }
        // Unscanned pages mean an absent match proves nothing.
        if unreadable > 0 {
            Self::issue(
                r,
                format!("PID {}", p.pid),
                format!("{unreadable} 个页不可读，未扫描"),
            );
        }
        Ok(())
    }
    fn vad_tree(&self, p: &Process) -> Result<VadTree<'_>> {
        let isf = self.vm.isf;
        let root_addr = self.field(p.address, "_EPROCESS", "VadRoot")?;
        let root_field = isf.field("_EPROCESS", "VadRoot")?;
        let root = if root_field["type"]["kind"] == "pointer" {
            self.vm.pointer(root_addr)?
        } else {
            let ty = root_field["type"]["name"]
                .as_str()
                .unwrap_or("_RTL_AVL_TREE");
            let field = if isf.has_field(ty, "Root") {
                "Root"
            } else {
                "BalancedRoot.RightChild"
            };
            self.number(root_addr, ty, field)?
        };
        let (offset, node_type) = if let Ok(field) = isf.field("_MMVAD_SHORT", "VadNode") {
            (
                isf.offset("_MMVAD_SHORT", "VadNode")?,
                field["type"]["name"]
                    .as_str()
                    .context("VAD node 缺少类型")?,
            )
        } else {
            (0, "_MMVAD_SHORT")
        };
        let children = if isf.has_field(node_type, "Left") {
            ["Left", "Right"]
        } else {
            ["LeftChild", "RightChild"]
        };
        Ok(VadTree {
            root,
            offset,
            node_type,
            children,
        })
    }
    /// The shared tag/range walk used by scanners and link inspection. Unrelated
    /// file/protection fields never prevent a readable VAD from being visited.
    pub(super) fn walk_tagged_vads(
        &self,
        p: &Process,
        r: &mut Results,
        job: &Job,
        mut visit: impl FnMut(VadNode, &mut Results) -> Result<bool>,
    ) -> Result<VadWalkCoverage> {
        let tree = self.vad_tree(p)?;
        let parent = [("ParentValue", !3), ("u1.Parent", !3), ("Parent", u64::MAX)]
            .into_iter()
            .find(|(f, _)| self.vm.isf.has_field(tree.node_type, f));
        let high = self.vm.isf.has_field("_MMVAD_SHORT", "StartingVpnHigh");
        let mut stack = vec![(tree.root, 0usize)];
        let mut seen = HashSet::new();
        let mut coverage = VadWalkCoverage::default();
        while let Some((node, depth)) = stack.pop() {
            job.check()?;
            if node == 0 {
                continue;
            }
            coverage.visited += 1;
            let read = (|| -> Result<Option<VadNode>> {
                ensure!(
                    self.vm.kernel(node)
                        && seen.insert(node)
                        && seen.len() <= MAX_OBJECTS
                        && depth <= 100,
                    "VAD 节点地址/循环/深度/数量无效"
                );
                let address = node.checked_sub(tree.offset).context("VAD 地址下溢")?;
                let mut tag = [0; 4];
                let tag_address = address
                    .checked_sub(if self.vm.pointer_size() == 8 { 12 } else { 4 })
                    .context("VAD tag 地址下溢")?;
                let tag_read = self.vm.read(tag_address, &mut tag);
                let recognized = tag_read.is_ok()
                    && tag.starts_with(b"Vad")
                    && std::str::from_utf8(&tag).is_ok();
                ensure!(recognized || depth == 0, "VAD pool tag 无法验证");
                let mut links = [None, None];
                // Right first on the stack gives the reference's left-first traversal.
                for index in [1, 0] {
                    let field = tree.children[index];
                    match self.number(node, tree.node_type, field) {
                        Ok(child) => {
                            links[index] = Some(child);
                            if child == 0 {
                                continue;
                            }
                            if let Some((parent, mask)) = parent {
                                match self.number(child, tree.node_type, parent) {
                                    Ok(value) if value & mask == node => (),
                                    value => Self::issue(
                                        r,
                                        format!("PID {} VAD {node:#x} {field}", p.pid),
                                        format!(
                                            "父指针不可读或不一致；继续验证带 tag 的子节点: {value:?}"
                                        ),
                                    ),
                                }
                            }
                            stack.push((child, depth + 1));
                        }
                        Err(error) => {
                            Self::issue(r, format!("PID {} VAD {node:#x} {field}", p.pid), error)
                        }
                    }
                }
                if !recognized {
                    Self::issue(
                        r,
                        format!("PID {} VAD root {node:#x}", p.pid),
                        "根节点无有效 tag，仅遍历其子节点",
                    );
                    return Ok(None);
                }
                let mut start = self.number(address, "_MMVAD_SHORT", "StartingVpn")?;
                let mut end = self.number(address, "_MMVAD_SHORT", "EndingVpn")?;
                if high {
                    start |= self.number(address, "_MMVAD_SHORT", "StartingVpnHigh")? << 32;
                    end |= self.number(address, "_MMVAD_SHORT", "EndingVpnHigh")? << 32;
                }
                let start = start.checked_mul(4096).context("VAD 地址溢出")?;
                let end = end
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(4096))
                    .context("VAD 地址溢出")?;
                ensure!(start < end && end <= 0x0000_8000_0000_0000, "VAD 范围无效");
                let parent = parent.and_then(|(field, mask)| {
                    self.number(node, tree.node_type, field)
                        .ok()
                        .map(|n| n & mask)
                });
                Ok(Some(VadNode {
                    address,
                    parent,
                    left: links[0],
                    right: links[1],
                    start,
                    end,
                    tag: String::from_utf8_lossy(&tag).into_owned(),
                }))
            })();
            match read {
                Ok(Some(node)) => {
                    coverage.yielded += 1;
                    if !visit(node, r)? {
                        coverage.stopped = true;
                        break;
                    }
                }
                Ok(None) => (),
                Err(error) => {
                    job.check()?;
                    Self::issue(r, format!("PID {} VAD {node:#x}", p.pid), error);
                }
            }
            if seen.len() >= MAX_OBJECTS {
                Self::issue(r, format!("PID {} VAD", p.pid), "节点数量达到上限");
                coverage.stopped = true;
                break;
            }
        }
        Ok(coverage)
    }
    pub(super) fn vad_scan_ranges(
        &self,
        p: &Process,
        r: &mut Results,
        job: &Job,
    ) -> Result<Vec<(u64, u64)>> {
        let mut ranges = Vec::new();
        self.walk_tagged_vads(p, r, job, |node, _| {
            ranges.push((node.start, node.end));
            Ok(true)
        })?;
        Ok(ranges)
    }
    pub(super) fn vad_walk(&self, options: &Options, job: &Job) -> Result<Results> {
        ensure!(options.pids.len() <= 4096, "PID 列表超过 4096 项");
        let pids: std::collections::BTreeSet<u64> = options
            .pids
            .iter()
            .copied()
            .chain(options.pid)
            .map(u64::from)
            .collect();
        let mut result = self.result(Plugin::WinVadWalk);
        let (processes, diagnostics) = self.processes_partial(job)?;
        result.complete &= diagnostics.is_empty();
        result.diagnostics.extend(diagnostics);
        let mut text_bytes = 0usize;
        let mut stopped = false;
        let mut reports = Vec::new();
        for process in processes
            .into_iter()
            .filter(|p| pids.is_empty() || pids.contains(&p.pid))
        {
            job.check()?;
            let mut missing_parents = 0;
            let read = self.walk_tagged_vads(&process, &mut result, job, |node, r| {
                let pointer = |value: Option<u64>| value.map(hex).unwrap_or_else(|| "N/A".into());
                if node.parent.is_none() {
                    missing_parents += 1;
                }
                let row = vec![
                    process.pid.to_string(),
                    process.name.clone(),
                    hex(node.address),
                    pointer(node.parent),
                    pointer(node.left),
                    pointer(node.right),
                    hex(node.start),
                    hex(node.end - 1),
                    node.tag,
                ];
                let size = row.iter().map(String::len).sum::<usize>();
                if r.rows.len() >= MAX_OBJECTS || text_bytes + size > 128 * 1024 * 1024 {
                    stopped = true;
                    return Ok(false);
                }
                text_bytes += size;
                r.rows.push(row);
                Ok(true)
            });
            match read {
                Ok(coverage)=>reports.push(serde_json::json!({"pid":process.pid,"coverage":coverage,"unavailable_parent_fields":missing_parents})),
                Err(error)=>{job.check()?;Self::issue(&mut result,format!("PID {} VAD",process.pid),error);}
            }
            if missing_parents > 0 {
                Self::issue(
                    &mut result,
                    format!("PID {} VAD", process.pid),
                    format!("{missing_parents} 个父字段不可读或布局缺失；保留范围与其他链接"),
                );
            }
            if reports.len() >= 65536 {
                stopped = true;
            }
            if stopped {
                Self::issue(
                    &mut result,
                    "VAD 输出",
                    "行数/文本/覆盖记录达到上限，保留已读取前缀",
                );
                break;
            }
        }
        result.kernel_identity["vad_walk"] = serde_json::json!({"pids":pids,"end_is_inclusive":true,"tag_validation":true,"max_depth":100,"max_nodes_per_process":MAX_OBJECTS,"max_output_rows":MAX_OBJECTS,"max_text_bytes":128*1024*1024,"stopped":stopped,"processes":reports});
        Ok(result)
    }
    pub(super) fn vads(&self, p: &Process, job: &Job) -> Result<Vec<Vad>> {
        self.vads_partial(p, job, None)
    }
    pub(super) fn vads_partial(
        &self,
        p: &Process,
        job: &Job,
        mut result: Option<&mut Results>,
    ) -> Result<Vec<Vad>> {
        let isf = self.vm.isf;
        let tree = self.vad_tree(p)?;
        let (root, offset, node_type, children) =
            (tree.root, tree.offset, tree.node_type, tree.children);
        // Layout probes are properties of the symbol file, not of the node, so
        // they are resolved once instead of once per VAD.
        let parent_field = ["ParentValue", "u1.Parent"]
            .into_iter()
            .find(|field| isf.has_field(node_type, field));
        let high_vpn = isf.has_field("_MMVAD_SHORT", "StartingVpnHigh");
        let path_layout = self.vad_layout();
        let mut stack = vec![root];
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        while let Some(node) = stack.pop() {
            job.check()?;
            if node == 0 {
                continue;
            }
            let parsed = (|| -> Result<Vad> {
                ensure!(
                    self.vm.kernel(node) && seen.insert(node) && seen.len() <= MAX_OBJECTS,
                    "VAD 节点无效/循环/超限"
                );
                for f in children {
                    match self.number(node, node_type, f) {
                        Ok(child) => {
                            let valid = (|| -> Result<()> {
                                if child != 0
                                    && let Some(parent) = parent_field
                                {
                                    ensure!(
                                        self.number(child, node_type, parent)? & !3 == node,
                                        "VAD 子节点父指针不一致"
                                    );
                                }
                                Ok(())
                            })();
                            match valid {
                                Ok(()) => stack.push(child),
                                Err(e) => match result.as_deref_mut() {
                                    Some(r) => Self::issue(
                                        r,
                                        format!("PID {} VAD {node:#x} {f}", p.pid),
                                        e,
                                    ),
                                    None => return Err(e),
                                },
                            }
                        }
                        Err(e) => match result.as_deref_mut() {
                            Some(r) => {
                                Self::issue(r, format!("PID {} VAD {node:#x} {f}", p.pid), e)
                            }
                            None => return Err(e),
                        },
                    }
                }
                let address = node.checked_sub(offset).context("VAD 地址下溢")?;
                let mut start = self.number(address, "_MMVAD_SHORT", "StartingVpn")?;
                let mut end = self.number(address, "_MMVAD_SHORT", "EndingVpn")?;
                if high_vpn {
                    start |= self.number(address, "_MMVAD_SHORT", "StartingVpnHigh")? << 32;
                    end |= self.number(address, "_MMVAD_SHORT", "EndingVpnHigh")? << 32;
                }
                let start = start.checked_mul(4096).context("VAD 地址溢出")?;
                let end = end
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(4096))
                    .context("VAD 地址溢出")?;
                ensure!(start < end && end <= 0x0000_8000_0000_0000, "VAD 范围无效");
                let flags = self.field(address, "_MMVAD_SHORT", "u")?;
                let protection = self.number(flags, "_MMVAD_FLAGS", "Protection")?;
                let private = self.number(flags, "_MMVAD_FLAGS", "PrivateMemory")? != 0;
                let path = if private {
                    String::new()
                } else {
                    match self.vad_path(address, &path_layout) {
                        Ok(mut path) => {
                            if let Some(end) = path.find('\0') {
                                match result.as_deref_mut() {
                                    Some(r) => Self::issue(
                                        r,
                                        format!("PID {} VAD {node:#x} file", p.pid),
                                        "VAD 文件名含 NUL，已截断损坏尾部",
                                    ),
                                    None => bail!("VAD 文件名含 NUL"),
                                }
                                path.truncate(end);
                            }
                            path
                        }
                        Err(e) => match result.as_deref_mut() {
                            Some(r) => {
                                Self::issue(r, format!("PID {} VAD {node:#x} file", p.pid), e);
                                String::new()
                            }
                            None => return Err(e),
                        },
                    }
                };
                Ok(Vad {
                    address,
                    start,
                    end,
                    protection,
                    private,
                    path,
                })
            })();
            match parsed {
                Ok(vad) => out.push(vad),
                Err(e) => match result.as_deref_mut() {
                    Some(r) => Self::issue(r, format!("PID {} VAD {node:#x}", p.pid), e),
                    None => return Err(e),
                },
            }
            if seen.len() >= MAX_OBJECTS {
                break;
            }
        }
        out.sort_by_key(|v| v.start);
        if !out.windows(2).all(|v| v[0].end <= v[1].start) {
            match result {
                Some(r) => Self::issue(r, format!("PID {} VAD", p.pid), "VAD 范围重叠"),
                None => bail!("VAD 范围重叠"),
            }
        }
        Ok(out)
    }
    /// How the VAD and control-area layouts describe their file, resolved once
    /// per plugin run rather than once per VAD.
    ///
    /// These are properties of the symbol file; probing them per VAD costs a
    /// full ISF resolution each time.
    pub(super) fn vad_layout(&self) -> VadLayout {
        let direct_control = self.vm.isf.has_field("_MMVAD", "ControlArea");
        let fast_ref = self
            .vm
            .isf
            .field("_CONTROL_AREA", "FilePointer")
            .map(|field| field["type"]["kind"] != "pointer")
            .unwrap_or(false);
        VadLayout {
            direct_control,
            fast_ref,
            mask: if self.vm.pointer_size() == 4 { !7 } else { !15 },
        }
    }
    fn vad_path(&self, address: u64, layout: &VadLayout) -> Result<String> {
        let control = if layout.direct_control {
            self.number(address, "_MMVAD", "ControlArea")?
        } else {
            let subsection = self.number(address, "_MMVAD", "Subsection")?;
            if subsection == 0 {
                return Ok(String::new());
            }
            self.number(subsection, "_SUBSECTION", "ControlArea")?
        };
        if control == 0 {
            return Ok(String::new());
        }
        ensure!(self.vm.kernel(control), "无效 VAD ControlArea");
        let file_ref = self.field(control, "_CONTROL_AREA", "FilePointer")?;
        let file = if layout.fast_ref {
            self.number(file_ref, "_EX_FAST_REF", "Object")? & layout.mask
        } else {
            self.vm.pointer(file_ref)?
        };
        if file == 0 {
            return Ok(String::new());
        }
        ensure!(self.vm.kernel(file), "无效 VAD 文件指针");
        self.vm
            .unicode(self.field(file, "_FILE_OBJECT", "FileName")?)
    }
    pub(super) fn vad_result(
        &self,
        p: &Process,
        plugin: Plugin,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let vm = self.process_memory(p)?;
        // Every row repeats the same PID and name, and protection only has 32
        // possible spellings; build them once instead of per row.
        let pid = p.pid.to_string();
        let mut protections: std::collections::HashMap<u64, String> =
            std::collections::HashMap::new();
        for v in self.vads_partial(p, job, Some(r))? {
            job.check()?;
            let protection = protections
                .entry(v.protection)
                .or_insert_with(|| protection(v.protection))
                .clone();
            if plugin == Plugin::WinVadinfo {
                r.rows.push(vec![
                    pid.clone(),
                    p.name.clone(),
                    hex(v.start),
                    hex(v.end),
                    protection,
                    v.private.to_string(),
                    v.path,
                    hex(v.address),
                ]);
                continue;
            }
            let executable = matches!(v.protection & 7, 2 | 3 | 6 | 7);
            let writable = matches!(v.protection & 7, 4..=7);
            if !executable || (!writable && !v.private) {
                continue;
            }
            let mut preview = [0; 32];
            match vm.read(v.start, &mut preview) {
                Ok(()) => r.rows.push(vec![
                    pid.clone(),
                    p.name.clone(),
                    hex(v.start),
                    hex(v.end),
                    protection,
                    if writable {
                        "Writable executable region"
                    } else {
                        "Private executable region"
                    }
                    .into(),
                    preview
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                ]),
                Err(e) => Self::issue(r, format!("PID {} VAD {:#x}", p.pid, v.start), e),
            }
        }
        Ok(())
    }
}
pub(super) fn protection(value: u64) -> String {
    let base = [
        "PAGE_NOACCESS",
        "PAGE_READONLY",
        "PAGE_EXECUTE",
        "PAGE_EXECUTE_READ",
        "PAGE_READWRITE",
        "PAGE_WRITECOPY",
        "PAGE_EXECUTE_READWRITE",
        "PAGE_EXECUTE_WRITECOPY",
    ][(value & 7) as usize];
    let modifier = if value & 7 == 0 {
        ""
    } else {
        match value & 24 {
            8 => "|PAGE_NOCACHE",
            16 => "|PAGE_GUARD",
            24 => "|PAGE_WRITECOMBINE",
            _ => "",
        }
    };
    format!("{base}{modifier}")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn vad_ranges_protection_and_cycles() {
        let (mut b, mut isf) = fixture();
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"] =
            json!({"offset":128,"type":{"kind":"struct","name":"_RTL_AVL_TREE"}});
        isf.data["user_types"]["_RTL_AVL_TREE"] = json!({"size":8,"fields":{"Root":pointer(0)}});
        isf.data["user_types"]["_RTL_BALANCED_NODE"] =
            json!({"size":24,"fields":{"Left":pointer(0),"Right":pointer(8)}});
        isf.data["user_types"]["_MMVAD_SHORT"] = json!({"size":64,"fields":{"VadNode":{"offset":0,"type":{"kind":"struct","name":"_RTL_BALANCED_NODE"}},"StartingVpn":number(24),"EndingVpn":number(32),"u":{"offset":40,"type":{"kind":"struct","name":"_MMVAD_FLAGS"}}}});
        isf.data["user_types"]["_MMVAD_FLAGS"] = json!({"size":8,"fields":{"Protection":{"offset":0,"type":{"kind":"bitfield","bit_position":0,"bit_length":5,"type":{"kind":"base","name":"u64"}}},"PrivateMemory":{"offset":0,"type":{"kind":"bitfield","bit_position":5,"bit_length":1,"type":{"kind":"base","name":"u64"}}}}});
        put(&mut b, 0xa080, K + 0x3000);
        put(&mut b, 0xb018, 1);
        put(&mut b, 0xb020, 3);
        put(&mut b, 0xb028, 6 | 32);
        let good = image(&b);
        let engine = Windows {
            vm: Memory::new(&good, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let process = engine.process(K + 0x2000).unwrap();
        let vads = engine.vads(&process, &Job::default()).unwrap();
        assert_eq!((vads[0].start, vads[0].end), (4096, 16384));
        assert!(vads[0].private);
        assert_eq!(protection(vads[0].protection), "PAGE_EXECUTE_READWRITE");
        let mut legacy_isf = Isf::parse(
            &serde_json::to_vec(&isf.data).unwrap(),
            "legacy-vad-fixture".into(),
        )
        .unwrap();
        legacy_isf.data["user_types"]["_EPROCESS"]["fields"]["VadRoot"]["type"]["name"] =
            json!("_MM_AVL_TABLE");
        legacy_isf.data["user_types"]["_MM_AVL_TABLE"] = json!({"size":24,"fields":{"BalancedRoot":{"offset":0,"type":{"kind":"struct","name":"_MMADDRESS_NODE"}}}});
        legacy_isf.data["user_types"]["_MMADDRESS_NODE"] =
            json!({"size":24,"fields":{"LeftChild":pointer(0),"RightChild":pointer(8)}});
        let fields = legacy_isf.data["user_types"]["_MMVAD_SHORT"]["fields"]
            .as_object_mut()
            .unwrap();
        fields.remove("VadNode");
        fields.insert("LeftChild".into(), pointer(0));
        fields.insert("RightChild".into(), pointer(8));
        let mut legacy_bytes = b.clone();
        put(&mut legacy_bytes, 0xa080, 0);
        put(&mut legacy_bytes, 0xa088, K + 0x3000);
        let legacy = image(&legacy_bytes);
        let engine = Windows {
            vm: Memory::new(&legacy, 0x1000, &legacy_isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&legacy_isf).unwrap(),
        };
        let legacy_vads = engine.vads(&process, &Job::default()).unwrap();
        assert_eq!((legacy_vads[0].start, legacy_vads[0].end), (4096, 16384));
        // NT6 AVL parent lives in a tagged union rather than ParentValue.
        let mut parent_isf = Isf::parse(
            &serde_json::to_vec(&isf.data).unwrap(),
            "parent-vad-fixture".into(),
        )
        .unwrap();
        parent_isf.data["user_types"]["_RTL_BALANCED_NODE"]["fields"]["u1"] =
            json!({"offset":16,"type":{"kind":"union","name":"_VAD_PARENT"}});
        parent_isf.data["user_types"]["_VAD_PARENT"] =
            json!({"size":8,"fields":{"Parent":pointer(0)}});
        let mut branch = b.clone();
        put(&mut branch, 0xb008, K + 0x4000);
        branch[0xc000..0xc040].fill(0);
        put(&mut branch, 0xc010, (K + 0x3000) | 3);
        put(&mut branch, 0xc018, 5);
        put(&mut branch, 0xc020, 6);
        put(&mut branch, 0xc028, 4 | 32);
        for (parent, count) in [(K + 0x3000, 2), (K + 0x5000, 1)] {
            put(&mut branch, 0xc010, parent | 3);
            let img = image(&branch);
            let engine = Windows {
                vm: Memory::new(&img, 0x1000, &parent_isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&parent_isf).unwrap(),
            };
            let mut result = engine.result(Plugin::WinVadinfo);
            let nodes = engine
                .vads_partial(&process, &Job::default(), Some(&mut result))
                .unwrap();
            assert_eq!(nodes.len(), count);
            assert_eq!(result.complete, count == 2);
        }
        put(&mut b, 0xb000, K + 0x3000);
        let cycle = image(&b);
        let engine = Windows {
            vm: Memory::new(&cycle, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(engine.vads(&process, &Job::default()).is_err());
    }
}

#[cfg(test)]
mod control_area_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn legacy_direct_control_area_and_modern_fast_ref_paths() {
        for modern in [false, true] {
            let (mut b, mut isf) = fixture();
            let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
            isf.data["user_types"]["_MMVAD"] = json!({"size":8,"fields":{}});
            isf.data["user_types"]["_CONTROL_AREA"] = json!({"size":8,"fields":{}});
            isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":16,"fields":{"FileName":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
            let file = if modern {
                isf.data["user_types"]["_MMVAD"]["fields"]["Subsection"] = ptr(0);
                isf.data["user_types"]["_SUBSECTION"] =
                    json!({"size":8,"fields":{"ControlArea":ptr(0)}});
                isf.data["user_types"]["_EX_FAST_REF"] =
                    json!({"size":8,"fields":{"Object":ptr(0)}});
                isf.data["user_types"]["_CONTROL_AREA"]["fields"]["FilePointer"] =
                    json!({"offset":0,"type":{"kind":"struct","name":"_EX_FAST_REF"}});
                put(&mut b, 0xb000, K + 0x4000);
                put(&mut b, 0xc000, K + 0x5000);
                put(&mut b, 0xd000, K + 0x600f);
                0xe000
            } else {
                isf.data["user_types"]["_MMVAD"]["fields"]["ControlArea"] = ptr(0);
                isf.data["user_types"]["_CONTROL_AREA"]["fields"]["FilePointer"] = ptr(0);
                put(&mut b, 0xb000, K + 0x4000);
                put(&mut b, 0xc000, K + 0x5000);
                0xd000
            };
            b[file..file + 4].copy_from_slice(&[8, 0, 8, 0]);
            put(&mut b, file + 8, K + 0x7000);
            b[0xf000..0xf008].copy_from_slice(&[b't', 0, b'e', 0, b's', 0, b't', 0]);
            let img = image(&b);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: K,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert_eq!(w.vad_path(K + 0x3000, &w.vad_layout()).unwrap(), "test");
        }
    }
}
