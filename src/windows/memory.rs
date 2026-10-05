use super::*;
#[derive(Clone, Debug)]
pub(super) struct Vad {
    pub address: u64,
    pub start: u64,
    pub end: u64,
    pub protection: u64,
    pub private: bool,
    pub path: String,
}
impl Windows<'_> {
    pub(super) fn cmdline(&self, p: &Process, r: &mut Results) -> Result<()> {
        if p.pid <= 4 {
            return Ok(());
        }
        self.native_process(p)?;
        let vm = self.process_memory(p)?;
        let peb = self.number(p.address, "_EPROCESS", "Peb")?;
        ensure!(peb != 0, "PEB 不存在");
        let params = vm.number(peb, "_PEB", "ProcessParameters")?;
        let command = vm.unicode(add(
            params,
            self.vm
                .isf
                .offset("_RTL_USER_PROCESS_PARAMETERS", "CommandLine")?,
        )?)?;
        r.rows
            .push(vec![p.pid.to_string(), p.name.clone(), command]);
        Ok(())
    }
    pub(super) fn native_process(&self, p: &Process) -> Result<()> {
        if self.vm.isf.field("_EPROCESS", "WoW64Process").is_ok() {
            ensure!(
                self.number(p.address, "_EPROCESS", "WoW64Process")? == 0,
                "WOW64 PEB/DLL/命令行未支持"
            );
        }
        Ok(())
    }
    pub(super) fn dlls(&self, p: &Process, job: &Job) -> Result<Vec<(u64, u64, String)>> {
        self.dlls_partial(p, job, None)
    }
    fn dlls_partial(
        &self,
        p: &Process,
        job: &Job,
        mut result: Option<&mut Results>,
    ) -> Result<Vec<(u64, u64, String)>> {
        if p.pid <= 4 {
            return Ok(Vec::new());
        }
        self.native_process(p)?;
        let vm = self.process_memory(p)?;
        let peb = self.number(p.address, "_EPROCESS", "Peb")?;
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
        let mut node = vm.uint(head, 8)?;
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        while node != head {
            job.check()?;
            let step = (|| -> Result<()> {
                ensure!(
                    seen.insert(node) && seen.len() <= MAX_OBJECTS,
                    "DLL 链表循环或超限"
                );
                ensure!(vm.uint(add(node, 8)?, 8)? == previous, "DLL 双向链表损坏");
                let address = node.checked_sub(offset).context("DLL 地址下溢")?;
                out.push((
                    vm.number(address, "_LDR_DATA_TABLE_ENTRY", "DllBase")?,
                    vm.number(address, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage")?,
                    vm.unicode(add(
                        address,
                        self.vm.isf.offset("_LDR_DATA_TABLE_ENTRY", "FullDllName")?,
                    )?)?,
                ));
                previous = node;
                node = vm.uint(node, 8)?;
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
        if vm.uint(add(head, 8)?, 8)? != previous {
            match result {
                Some(r) => Self::issue(r, format!("PID {} DLL", p.pid), "DLL 链表未闭合"),
                None => bail!("DLL 链表未闭合"),
            }
        }
        Ok(out)
    }
    pub(super) fn dlllist(&self, p: &Process, r: &mut Results, job: &Job) -> Result<()> {
        for (base, size, path) in self.dlls_partial(p, job, Some(r))? {
            r.rows.push(vec![
                p.pid.to_string(),
                p.name.clone(),
                hex(base),
                size.to_string(),
                path,
            ]);
        }
        Ok(())
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
        let root_addr = self.field(p.address, "_EPROCESS", "VadRoot")?;
        let root = self.number(root_addr, "_RTL_AVL_TREE", "Root")?;
        let offset = isf.offset("_MMVAD_SHORT", "VadNode")?;
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
                    kernel(node) && seen.insert(node) && seen.len() <= MAX_OBJECTS,
                    "VAD 节点无效/循环/超限"
                );
                for f in ["Left", "Right"] {
                    match self.number(node, "_RTL_BALANCED_NODE", f) {
                        Ok(child) => {
                            let valid = (|| -> Result<()> {
                                if child != 0
                                    && isf.field("_RTL_BALANCED_NODE", "ParentValue").is_ok()
                                {
                                    ensure!(
                                        self.number(child, "_RTL_BALANCED_NODE", "ParentValue")?
                                            & !3
                                            == node,
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
                if isf.field("_MMVAD_SHORT", "StartingVpnHigh").is_ok() {
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
                    match self.vad_path(address) {
                        Ok(path) => path,
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
    fn vad_path(&self, address: u64) -> Result<String> {
        let subsection = self.number(address, "_MMVAD", "Subsection")?;
        if subsection == 0 {
            return Ok(String::new());
        }
        let control = self.number(subsection, "_SUBSECTION", "ControlArea")?;
        if control == 0 {
            return Ok(String::new());
        }
        let file_ref = self.field(control, "_CONTROL_AREA", "FilePointer")?;
        let pointer = self.number(file_ref, "_EX_FAST_REF", "Object")?;
        // ISF Object is a pointer member, whereas Value includes low refcount bits.
        let file = pointer & !15;
        if file == 0 {
            return Ok(String::new());
        }
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
        for v in self.vads_partial(p, job, Some(r))? {
            job.check()?;
            let protection = protection(v.protection);
            if plugin == Plugin::WinVadinfo {
                r.rows.push(vec![
                    p.pid.to_string(),
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
                    p.pid.to_string(),
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
            vm: Memory {
                image: &good,
                root: 0x1000,
                isf: &isf,
            },
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let process = engine.process(K + 0x2000).unwrap();
        let vads = engine.vads(&process, &Job::default()).unwrap();
        assert_eq!((vads[0].start, vads[0].end), (4096, 16384));
        assert!(vads[0].private);
        assert_eq!(protection(vads[0].protection), "PAGE_EXECUTE_READWRITE");
        put(&mut b, 0xb000, K + 0x3000);
        let cycle = image(&b);
        let engine = Windows {
            vm: Memory {
                image: &cycle,
                root: 0x1000,
                isf: &isf,
            },
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(engine.vads(&process, &Job::default()).is_err());
    }
}
