//! Bounded callbacks, unloaded driver records and token SIDs.
//! Declaration facts: Volatility 3 v2.28 callbacks/unloadedmodules ISFs.
use super::drivers::module_at;
use super::*;
fn account(sid: &str) -> &'static str {
    match sid {
        "S-1-0-0" => "Nobody",
        "S-1-1-0" => "Everyone",
        "S-1-2-0" => "Local",
        "S-1-5-2" => "Network",
        "S-1-5-4" => "Interactive",
        "S-1-5-6" => "Service",
        "S-1-5-7" => "Anonymous",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-18" => "Local System",
        "S-1-5-19" => "Local Service",
        "S-1-5-20" => "Network Service",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-546" => "Guests",
        "S-1-16-4096" => "Low Integrity",
        "S-1-16-8192" => "Medium Integrity",
        "S-1-16-12288" => "High Integrity",
        "S-1-16-16384" => "System Integrity",
        _ => "",
    }
}
fn sid_string(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len() >= 8 && bytes[0] == 1 && bytes[1] <= 15,
        "无效 SID 头"
    );
    let count = usize::from(bytes[1]);
    ensure!(bytes.len() == 8 + count * 4, "SID 长度无效");
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    let mut sid = format!("S-1-{authority}");
    for n in bytes[8..].chunks_exact(4) {
        sid.push_str(&format!("-{}", u32::from_le_bytes(n.try_into()?)));
    }
    Ok(sid)
}
impl Windows<'_> {
    pub(super) fn sids(&self, p: &Process, r: &mut Results, job: &Job) -> Result<()> {
        let fast = self.field(p.address, "_EPROCESS", "Token")?;
        let token = if self.vm.isf.field("_EX_FAST_REF", "Object").is_ok() {
            self.number(fast, "_EX_FAST_REF", "Object")?
        } else {
            self.vm.pointer(fast)?
        } & !(self.vm.pointer_size() as u64 * 2 - 1);
        ensure!(self.vm.kernel(token), "无效进程 Token 指针");
        let count = self.number(token, "_TOKEN", "UserAndGroupCount")?;
        ensure!((1..=65535).contains(&count), "Token SID 数量无效");
        let groups = self.number(token, "_TOKEN", "UserAndGroups")?;
        ensure!(self.vm.kernel(groups), "无效 Token SID 数组");
        let size = self.vm.isf.data["user_types"]["_SID_AND_ATTRIBUTES"]["size"]
            .as_u64()
            .context("缺少 SID_AND_ATTRIBUTES 大小")?;
        ensure!(
            (self.vm.pointer_size() as u64 + 4..=64).contains(&size),
            "SID_AND_ATTRIBUTES 大小无效"
        );
        for index in 0..count {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let entry = add(groups, index.checked_mul(size).context("SID 索引溢出")?)?;
                let sid = self.number(entry, "_SID_AND_ATTRIBUTES", "Sid")?;
                ensure!(self.vm.kernel(sid), "无效 SID 指针");
                let mut header = [0; 8];
                self.vm.read(sid, &mut header)?;
                ensure!(header[0] == 1 && header[1] <= 15, "SID revision/count 无效");
                let mut bytes = vec![0; 8 + usize::from(header[1]) * 4];
                self.vm.read(sid, &mut bytes)?;
                let text = sid_string(&bytes)?;
                Ok(vec![
                    p.pid.to_string(),
                    p.name.clone(),
                    text.clone(),
                    format!(
                        "{:#x}",
                        self.number(entry, "_SID_AND_ATTRIBUTES", "Attributes")?
                    ),
                    account(&text).into(),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => Self::issue(r, format!("PID {} SID[{index}]", p.pid), format!("{e:#}")),
            }
        }
        Ok(())
    }
    pub(super) fn kernel_artifacts(&self, p: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(p);
        if p == Plugin::WinUnloadedmodules {
            let read = self.unloaded(&mut r, job);
            if let Err(e) = read {
                job.check()?;
                Self::issue(&mut r, "unloadedmodules", format!("{e:#}"));
            }
            return Ok(r);
        }
        let modules = match self.modules(Plugin::WinModules, job) {
            Ok(modules) => modules,
            Err(e) => {
                job.check()?;
                Self::issue(&mut r, "callback module attribution", format!("{e:#}"));
                self.result(Plugin::WinModules)
            }
        };
        if !modules.complete {
            r.complete = false;
            r.diagnostics.extend(modules.diagnostics.clone());
        }
        for (symbol, extended) in [
            ("PspCreateProcessNotifyRoutine", true),
            ("PspCreateThreadNotifyRoutine", true),
            ("PspLoadImageNotifyRoutine", false),
        ] {
            let read = (|| -> Result<()> {
                let base = self.symbol(symbol)?;
                let count = self.vm.isf.data["symbols"][symbol]["type"]["count"]
                    .as_u64()
                    .filter(|n| (1..=128).contains(n));
                let count = match count {
                    Some(n) => n,
                    None => {
                        ensure!(self.declared_build(), "未知构建没有声明的回调数组长度");
                        let build = self.build_number()?;
                        Self::issue(
                            &mut r,
                            symbol,
                            "数组长度采用声明布局，尚未完成此 PDB 身份验收",
                        );
                        if (extended && build >= 6000) || (!extended && build >= 9600) {
                            64
                        } else {
                            8
                        }
                    }
                };
                self.callback_vector(symbol, base, count, &modules, &mut r, job)
            })();
            if let Err(e) = read {
                job.check()?;
                Self::issue(&mut r, symbol, format!("{e:#}"));
            }
        }
        let read = (|| -> Result<()> {
            if self.vm.isf.raw_address("CmpCallBackVector").is_ok() {
                let n = self.vm.uint(self.symbol("CmpCallBackCount")?, 4)?;
                ensure!(n <= 128, "注册表回调数量超限");
                return self.callback_vector(
                    "CmRegisterCallback",
                    self.symbol("CmpCallBackVector")?,
                    n,
                    &modules,
                    &mut r,
                    job,
                );
            }
            let head = self.symbol("CallbackListHead")?;
            let exact = self.vm.isf.field("_CM_CALLBACK_ENTRY", "Function").is_ok();
            let declaration: serde_json::Value =
                serde_json::from_str(include_str!("callback_layouts.json"))?;
            let arch = Architecture::from_isf(self.vm.isf)?;
            let layout = &declaration[if arch == Architecture::X86 {
                "x86"
            } else {
                "x64"
            }];
            if !exact {
                ensure!(
                    self.declared_build()
                        && self.build_number()? >= 6000
                        && arch != Architecture::Arm64,
                    "缺少精确注册表回调类型或声明布局"
                );
                Self::issue(
                    &mut r,
                    "registry callback layout",
                    format!("声明布局尚未验证此 PDB 身份: {}", layout["source"]),
                );
            }
            let offset = |name| -> Result<u64> {
                if exact {
                    self.vm.isf.offset("_CM_CALLBACK_ENTRY", name)
                } else {
                    layout["registry"][name]
                        .as_u64()
                        .context("缺少注册表回调字段")
                }
            };
            let (nodes, diags) = self.list_partial(head, offset("Link")?, job)?;
            if !diags.is_empty() {
                r.complete = false;
                r.diagnostics.extend(diags);
            }
            for node in nodes {
                job.check()?;
                let read = (|| -> Result<()> {
                    let function = self.vm.pointer(add(node, offset("Function")?)?)?;
                    ensure!(self.vm.kernel(function), "无效注册表回调地址");
                    let altitude = match self.vm.unicode(add(node, offset("Altitude")?)?) {
                        Ok(v) => v,
                        Err(e) => {
                            Self::issue(&mut r, format!("registry altitude {node:#x}"), e);
                            String::new()
                        }
                    };
                    r.rows.push(vec![
                        "CmRegisterCallbackEx".into(),
                        hex(node),
                        hex(function),
                        module_at(&modules, function),
                        format!("Altitude: {altitude}"),
                    ]);
                    Ok(())
                })();
                if let Err(e) = read {
                    Self::issue(
                        &mut r,
                        format!("registry callback {node:#x}"),
                        format!("{e:#}"),
                    );
                }
            }
            Ok(())
        })();
        if let Err(e) = read {
            job.check()?;
            Self::issue(&mut r, "registry callbacks", format!("{e:#}"));
        }
        Ok(r)
    }
    fn callback_vector(
        &self,
        kind: &str,
        base: u64,
        count: u64,
        modules: &Results,
        r: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let pointer = self.vm.pointer_size() as u64;
        let exact = self
            .vm
            .isf
            .field("_EX_CALLBACK_ROUTINE_BLOCK", "Function")
            .is_ok();
        if !exact {
            ensure!(self.declared_build(), "缺少精确回调类型且构建未知");
            Self::issue(r, kind, "回调字段采用带来源的 x86/x64 声明布局");
        }
        ensure!(
            Architecture::from_isf(self.vm.isf)? != Architecture::Arm64 || exact,
            "ARM64 回调需要精确类型"
        );
        for index in 0..count {
            job.check()?;
            let read = (|| -> Result<()> {
                let fast = self.vm.pointer(add(base, index * pointer)?)?;
                let object = fast & !(pointer * 2 - 1);
                if object == 0 {
                    return Ok(());
                }
                ensure!(self.vm.kernel(object), "无效回调块地址");
                let function = if exact {
                    self.number(object, "_EX_CALLBACK_ROUTINE_BLOCK", "Function")?
                } else {
                    self.vm.pointer(add(object, pointer)?)?
                };
                ensure!(self.vm.kernel(function), "无效回调函数地址");
                r.rows.push(vec![
                    kind.into(),
                    hex(object),
                    hex(function),
                    module_at(modules, function),
                    format!("slot={index}"),
                ]);
                Ok(())
            })();
            if let Err(e) = read {
                Self::issue(r, format!("{kind}[{index}]"), format!("{e:#}"));
            }
        }
        Ok(())
    }
    fn unloaded(&self, r: &mut Results, job: &Job) -> Result<()> {
        let base = self.vm.pointer(self.symbol("MmUnloadedDrivers")?)?;
        // MmLastUnloadedDriver is ULONG, including x64. Never consume adjacent bytes.
        let count = self.vm.uint(self.symbol("MmLastUnloadedDriver")?, 4)?;
        ensure!(count <= 1024, "已卸载驱动数组数量超限");
        if count == 0 {
            return Ok(());
        }
        ensure!(self.vm.kernel(base), "无效已卸载驱动数组");
        let exact = self.vm.isf.data["user_types"]["_UNLOADED_DRIVER"].is_object();
        let pointer = self.vm.pointer_size() as u64;
        let stride = if exact {
            self.vm.isf.data["user_types"]["_UNLOADED_DRIVER"]["size"]
                .as_u64()
                .context("缺少卸载记录大小")?
        } else {
            ensure!(
                self.declared_build()
                    && Architecture::from_isf(self.vm.isf)? != Architecture::Arm64,
                "未知构建/架构需要精确卸载驱动类型"
            );
            Self::issue(
                r,
                "unloadedmodules layout",
                "使用 Volatility 3 v2.28 x86/x64 声明布局，尚未验证此 PDB 身份",
            );
            if pointer == 4 { 24 } else { 40 }
        };
        ensure!((24..=256).contains(&stride), "卸载记录大小无效");
        for index in 0..count {
            job.check()?;
            let read = (|| -> Result<()> {
                let node = add(base, index * stride)?;
                let offsets = if pointer == 4 {
                    [0, 8, 12, 16]
                } else {
                    [0, 16, 24, 32]
                };
                let field = |name, offset| -> Result<u64> {
                    if exact {
                        self.field(node, "_UNLOADED_DRIVER", name)
                    } else {
                        add(node, offset)
                    }
                };
                let start = self.vm.pointer(field("StartAddress", offsets[1])?)?;
                let end = self.vm.pointer(field("EndAddress", offsets[2])?)?;
                ensure!(
                    self.vm.kernel(start) && self.vm.kernel(end) && end > start,
                    "卸载驱动地址范围无效"
                );
                let name = self.vm.unicode(field("Name", offsets[0])?)?;
                let time = self.vm.uint(field("CurrentTime", offsets[3])?, 8)?;
                ensure!(
                    time > 0 && time <= 2650467743999999999,
                    "卸载驱动 FILETIME 无效"
                );
                r.rows
                    .push(vec![name, hex(start), hex(end), filetime(time)]);
                Ok(())
            })();
            if let Err(e) = read {
                Self::issue(r, format!("unloaded[{index}]"), format!("{e:#}"));
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sid_authority_uses_all_six_bytes_and_checks_length() {
        assert_eq!(
            sid_string(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]).unwrap(),
            "S-1-5-18"
        );
        assert_eq!(
            sid_string(&[1, 0, 1, 2, 3, 4, 5, 6]).unwrap(),
            "S-1-1108152157446"
        );
        assert!(sid_string(&[1, 16, 0, 0, 0, 0, 0, 5]).is_err());
        assert!(sid_string(&[2, 0, 0, 0, 0, 0, 0, 5]).is_err());
        assert!(sid_string(&[1, 1, 0, 0, 0, 0, 0, 5]).is_err());
        assert_eq!(account("S-1-5-18"), "Local System");
        assert_eq!(account("S-1-5-21-123"), "");
    }
}

#[cfg(test)]
mod object_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    fn field(offset: u64, ty: &str) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"base","name":ty}})
    }
    fn prepare(x86: bool) -> (Vec<u8>, Isf, u64) {
        let (mut b, mut isf) = fixture();
        let k = if x86 { 0x80000000 } else { K };
        let width = if x86 { 4 } else { 8 };
        isf.data["base_types"]["u32"] = json!({"size":4});
        isf.data["base_types"]["u8"] = json!({"size":1});
        if x86 {
            isf.data["base_types"]["pointer"]["size"] = json!(4);
            isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
            b[0x1000..0x3000].fill(0);
            b[0x1000 + 512 * 4..0x1000 + 513 * 4].copy_from_slice(&0x2003u32.to_le_bytes());
            for i in 0..32 {
                b[0x2000 + i * 4..0x2000 + i * 4 + 4]
                    .copy_from_slice(&(0x8003 + i as u32 * 4096).to_le_bytes());
            }
            isf.data["user_types"]["_UNICODE_STRING"]["fields"]["Buffer"]["offset"] = json!(4);
        }
        isf.data["user_types"]["_EPROCESS"]["fields"]["Token"] = field(128, "pointer");
        isf.data["user_types"]["_TOKEN"] = json!({"size":32,"fields":{"UserAndGroupCount":field(0,"u32"),"UserAndGroups":field(8,"pointer")}});
        isf.data["user_types"]["_SID_AND_ATTRIBUTES"] = json!({"size":width*2,"fields":{"Sid":field(0,"pointer"),"Attributes":field(width,"u32")}});
        isf.data["symbols"]["PspCreateProcessNotifyRoutine"] =
            json!({"address":0x3000,"type":{"kind":"array","count":2}});
        isf.data["user_types"]["_EX_CALLBACK_ROUTINE_BLOCK"] =
            json!({"size":width*3,"fields":{"Function":field(width,"pointer")}});
        isf.data["symbols"]["MmUnloadedDrivers"] = json!({"address":0x3100});
        isf.data["symbols"]["MmLastUnloadedDriver"] = json!({"address":0x3108});
        isf.data["user_types"]["_UNLOADED_DRIVER"] = json!({"size":40,"fields":{"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}},"StartAddress":field(16,"pointer"),"EndAddress":field(24,"pointer"),"CurrentTime":field(32,"u64")}});
        (b, isf, k)
    }
    #[test]
    fn token_sids_and_callback_fast_refs_work_at_both_pointer_widths() {
        for x86 in [false, true] {
            let (mut b, isf, k) = prepare(x86);
            let width = if x86 { 4 } else { 8 };
            put(&mut b, 0x9080, k + 0x4000 + 7);
            put(&mut b, 0xc000, 2);
            put(&mut b, 0xc008, k + 0x5000);
            put(&mut b, 0xd000, k + 0x6000);
            b[0xd000 + width..0xd000 + width + 4].copy_from_slice(&4u32.to_le_bytes());
            put(&mut b, 0xd000 + width * 2, k + 0x6100);
            b[0xe000..0xe00c].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
            b[0xe100] = 2;
            put(&mut b, 0xb000, k + 0x7007);
            put(&mut b, 0xf000 + width, k + 0x9000);
            let img = image(&b);
            let w = Windows {
                vm: Memory {
                    image: &img,
                    root: 0x1000,
                    isf: &isf,
                    sources: None,
                },
                base: k,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let p = Process {
                address: k + 0x1000,
                physical: false,
                pid: 4,
                ppid: 0,
                name: "System".into(),
                dtb: 0x1000,
                threads: 0,
                handles: None,
                created: 0,
                exited: 0,
            };
            let mut r = w.result(Plugin::WinGetsids);
            w.sids(&p, &mut r, &Job::default()).unwrap();
            assert_eq!(r.rows.len(), 1);
            assert_eq!(r.rows[0][2], "S-1-5-18");
            assert_eq!(r.rows[0][4], "Local System");
            assert!(!r.complete);
            let r = w
                .kernel_artifacts(Plugin::WinCallbacks, &Job::default())
                .unwrap();
            assert_eq!(r.rows.len(), 1);
            assert_eq!(r.rows[0][2], hex(k + 0x9000));
            assert!(!r.complete);
        }
    }
    #[test]
    fn unloaded_records_preserve_valid_rows_and_do_not_read_ulong_neighbors() {
        let (mut b, isf, k) = prepare(false);
        put(&mut b, 0xb100, k + 0x4000);
        put(&mut b, 0xb108, 0xdeadbeef00000002);
        put(&mut b, 0xc010, k + 0x9000);
        put(&mut b, 0xc018, k + 0xa000);
        put(&mut b, 0xc020, 130000000000000000);
        b[0xc000..0xc002].copy_from_slice(&6u16.to_le_bytes());
        b[0xc002..0xc004].copy_from_slice(&6u16.to_le_bytes());
        put(&mut b, 0xc008, k + 0x6000);
        b[0xe000..0xe006].copy_from_slice(&[b'a', 0, b'.', 0, b's', 0]);
        let img = image(&b);
        let w = Windows {
            vm: Memory {
                image: &img,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
            base: k,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = w
            .kernel_artifacts(Plugin::WinUnloadedmodules, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][0], "a.s");
        assert!(!r.complete);
    }
}
