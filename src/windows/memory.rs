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
        let native = (|| -> Result<String> {
            let vm = self.process_memory(p)?;
            let peb = self.number(p.address, "_EPROCESS", "Peb")?;
            ensure!(peb != 0, "PEB 不存在");
            let params = vm.number(peb, "_PEB", "ProcessParameters")?;
            vm.unicode(add(
                params,
                self.vm
                    .isf
                    .offset("_RTL_USER_PROCESS_PARAMETERS", "CommandLine")?,
            )?)
        })();
        match native {
            Ok(command) => r.rows.push(vec![
                p.pid.to_string(),
                p.name.clone(),
                command,
                "native".into(),
            ]),
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
    fn dlls_partial(
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
        let root_field = isf.field("_EPROCESS", "VadRoot")?;
        let root = if root_field["type"]["kind"] == "pointer" {
            self.vm.pointer(root_addr)?
        } else {
            let ty = root_field["type"]["name"]
                .as_str()
                .unwrap_or("_RTL_AVL_TREE");
            let field = if isf.field(ty, "Root").is_ok() {
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
        let children = if isf.field(node_type, "Left").is_ok() {
            ["Left", "Right"]
        } else {
            ["LeftChild", "RightChild"]
        };
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
                                if child != 0 {
                                    let parent = ["ParentValue", "u1.Parent"]
                                        .into_iter()
                                        .find(|field| isf.field(node_type, field).is_ok());
                                    if let Some(parent) = parent {
                                        ensure!(
                                            self.number(child, node_type, parent)? & !3 == node,
                                            "VAD 子节点父指针不一致"
                                        );
                                    }
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
    fn vad_path(&self, address: u64) -> Result<String> {
        let control = if self.vm.isf.field("_MMVAD", "ControlArea").is_ok() {
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
        let field = self.vm.isf.field("_CONTROL_AREA", "FilePointer")?;
        let file = if field["type"]["kind"] == "pointer" {
            self.vm.pointer(file_ref)?
        } else {
            self.number(file_ref, "_EX_FAST_REF", "Object")?
                & if self.vm.pointer_size() == 4 { !7 } else { !15 }
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
            assert_eq!(w.vad_path(K + 0x3000).unwrap(), "test");
        }
    }
}
