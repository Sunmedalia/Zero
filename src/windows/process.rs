//! Process artifacts read using exact kernel types and the 32-bit NT user ABI.
use super::*;
const ENVIRONMENT_LIMIT: usize = 1024 * 1024;

impl Windows<'_> {
    pub(super) fn environments(&self, p: &Process, r: &mut Results, job: &Job) -> Result<()> {
        if p.pid <= 4 {
            return Ok(());
        }
        let vm = self.process_memory(p)?;
        let native = (|| -> Result<u64> {
            let peb = self.number(p.address, "_EPROCESS", "Peb")?;
            ensure!(peb != 0, "PEB 不存在");
            let params = vm.number(peb, "_PEB", "ProcessParameters")?;
            ensure!(params != 0, "ProcessParameters 不存在");
            vm.number(params, "_RTL_USER_PROCESS_PARAMETERS", "Environment")
        })();
        let mut views = vec![("native", native)];
        match self.wow64_peb(p) {
            Ok(Some(peb)) => views.push((
                "wow64",
                (|| -> Result<u64> {
                    let params = vm.uint(add(peb, 16)?, 4)?;
                    ensure!(params != 0, "WOW64 ProcessParameters 不存在");
                    vm.uint(add(params, 0x48)?, 4)
                })(),
            )),
            Ok(None) => {}
            Err(e) => Self::issue(r, format!("PID {} WOW64 PEB", p.pid), e),
        }
        for (view, address) in views {
            let read = (|| -> Result<()> {
                let address = address?;
                if address == 0 {
                    return Ok(());
                }
                ensure!(
                    !vm.kernel(address) && address.is_multiple_of(2),
                    "环境块不是对齐用户地址"
                );
                let mut entry = Vec::new();
                let mut previous_zero = false;
                for offset in (0..ENVIRONMENT_LIMIT).step_by(2) {
                    if offset.is_multiple_of(4096) {
                        job.check()?;
                    }
                    let unit = vm.uint(add(address, offset as u64)?, 2)? as u16;
                    if unit == 0 {
                        if previous_zero {
                            return Ok(());
                        }
                        if !entry.is_empty() {
                            let text =
                                String::from_utf16(&entry).context("环境变量 UTF-16 无效")?;
                            let (name, value) = split_environment(&text)?;
                            r.rows.push(vec![
                                p.pid.to_string(),
                                p.name.clone(),
                                view.into(),
                                name.into(),
                                value.into(),
                            ]);
                            entry.clear();
                        }
                        previous_zero = true;
                    } else {
                        previous_zero = false;
                        entry.push(unit);
                    }
                }
                bail!("环境块未终止或超过 1 MiB")
            })();
            if let Err(e) = read {
                job.check()?;
                Self::issue(
                    r,
                    format!("PID {} {view} environment", p.pid),
                    format!("{e:#}"),
                );
            }
        }
        Ok(())
    }
    pub(super) fn thread_rows(
        &self,
        p: &Process,
        r: &mut Results,
        modules: &Results,
        job: &Job,
    ) -> Result<()> {
        let (threads, diagnostics) = self.list_partial(
            self.field(p.address, "_EPROCESS", "ThreadListHead")?,
            self.vm.isf.offset("_ETHREAD", "ThreadListEntry")?,
            job,
        )?;
        for diagnostic in diagnostics {
            Self::issue(r, format!("PID {} threads", p.pid), diagnostic);
        }
        for thread in threads {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let pid = self.number(thread, "_ETHREAD", "Cid.UniqueProcess")?;
                ensure!(pid == p.pid, "线程归属 PID 不一致");
                let tid = self.number(thread, "_ETHREAD", "Cid.UniqueThread")?;
                let mut row = vec![
                    p.pid.to_string(),
                    p.name.clone(),
                    tid.to_string(),
                    hex(thread),
                ];
                for field in ["Tcb.State", "StartAddress", "CreateTime", "ExitTime"] {
                    if field == "ExitTime"
                        && self.vm.isf.field("_ETHREAD", "Terminated").is_ok()
                        && self.number(thread, "_ETHREAD", "Terminated")? == 0
                    {
                        row.push(String::new());
                        continue;
                    }
                    let value = self.number(thread, "_ETHREAD", field).map(|value| {
                        if field == "CreateTime"
                            && self.vm.isf.field("_ETHREAD", "ThreadsProcess").is_ok()
                        {
                            value >> 3
                        } else {
                            value
                        }
                    });
                    match value {
                        Ok(value)
                            if field.ends_with("Time")
                                && value != 0
                                && !(116_444_736_000_000_000..190_000_000_000_000_000)
                                    .contains(&value) =>
                        {
                            Self::issue(
                                r,
                                format!("thread {thread:#x} {field}"),
                                "FILETIME 超出已支持范围",
                            );
                            row.push(String::new());
                        }
                        Ok(value) => row.push(if field == "StartAddress" {
                            hex(value)
                        } else if field.ends_with("Time") {
                            filetime(value)
                        } else {
                            value.to_string()
                        }),
                        Err(e) => {
                            Self::issue(r, format!("thread {thread:#x} {field}"), e);
                            row.push(String::new());
                        }
                    }
                }
                let start = u64::from_str_radix(row[5].trim_start_matches("0x"), 16).unwrap_or(0);
                let module = modules
                    .rows
                    .iter()
                    .find(|m| {
                        let base =
                            u64::from_str_radix(m[1].trim_start_matches("0x"), 16).unwrap_or(0);
                        let size = m[2].parse::<u64>().unwrap_or(0);
                        start != 0
                            && start >= base
                            && base.checked_add(size).is_some_and(|end| start < end)
                    })
                    .map(|m| m[3].clone())
                    .unwrap_or_default();
                row.insert(6, module);
                Ok(row)
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => Self::issue(r, format!("PID {} thread {thread:#x}", p.pid), e),
            }
        }
        Ok(())
    }
}
fn split_environment(text: &str) -> Result<(&str, &str)> {
    let start = usize::from(text.starts_with('='));
    let split = text[start..]
        .find('=')
        .map(|n| n + start)
        .context("环境变量缺少等号")?;
    ensure!(split > 0, "环境变量名为空");
    Ok((&text[..split], &text[split + 1..]))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn environment_preserves_drive_entries_and_embedded_equals() {
        assert_eq!(
            split_environment("=C:=C:\\work").unwrap(),
            ("=C:", "C:\\work")
        );
        assert_eq!(split_environment("A=b=c").unwrap(), ("A", "b=c"));
        assert!(split_environment("=broken").is_err());
        assert!(split_environment("broken").is_err());
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn native_environment_crosses_pages_and_preserves_partial_rows() {
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["_PEB"] =
            json!({"size":8,"fields":{"ProcessParameters":{"offset":0,"type":{"kind":"pointer"}}}});
        isf.data["user_types"]["_RTL_USER_PROCESS_PARAMETERS"] =
            json!({"size":8,"fields":{"Environment":{"offset":0,"type":{"kind":"pointer"}}}});
        // Low user mapping and a block starting four bytes before a page boundary.
        put(&mut b, 0x1000, 0x2003);
        put(&mut b, 0xa068, 0x3000);
        put(&mut b, 0xb000, 0x4000);
        put(&mut b, 0xc000, 0x5ffc);
        let bytes: Vec<u8> = "A=one\0=C:=C:\\x\0B=two=three\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xdffc..0xdffc + bytes.len()].copy_from_slice(&bytes);
        let img = image(&b);
        let engine = Windows {
            vm: Memory {
                image: &img,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .run(
                Plugin::WinEnvars,
                &Options {
                    pid: Some(8),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 3);
        assert_eq!(&r.rows[1][3..], ["=C:", "C:\\x"]);
        // Missing following page retains the first complete entry and diagnoses truncation.
        let bytes: Vec<u8> = "A=one\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        put(&mut b, 0xc000, 0x5000);
        b[0xd000..0xd000 + bytes.len()].copy_from_slice(&bytes);
        b[0xd000 + bytes.len()..0xe000].fill(0x41);
        put(&mut b, 0x4030, 0);
        let img = image(&b);
        let engine = Windows {
            vm: Memory {
                image: &img,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .run(
                Plugin::WinEnvars,
                &Options {
                    pid: Some(8),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(!r.complete);
        assert_eq!(r.rows.len(), 1);
        assert!(!r.diagnostics.is_empty());
    }
    #[test]
    fn threads_validate_ownership_and_keep_readable_entries() {
        let (mut b, mut isf) = fixture();
        let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_EPROCESS"]["fields"]["ThreadListHead"] =
            json!({"offset":144,"type":{"kind":"struct","name":"_LIST_ENTRY"}});
        isf.data["user_types"]["_ETHREAD"] = json!({"size":72,"fields":{"ThreadListEntry":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},"Cid":{"offset":16,"type":{"kind":"struct","name":"_CLIENT_ID"}},"Tcb":{"offset":32,"type":{"kind":"struct","name":"_KTHREAD"}},"StartAddress":ptr(40),"CreateTime":ptr(48),"ExitTime":ptr(56)}});
        isf.data["user_types"]["_CLIENT_ID"] =
            json!({"size":16,"fields":{"UniqueProcess":ptr(0),"UniqueThread":ptr(8)}});
        isf.data["user_types"]["_KTHREAD"] = json!({"size":8,"fields":{"State":ptr(0)}});
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":16,"fields":{"InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}});
        put(&mut b, 0xa090, K + 0x3000);
        put(&mut b, 0xa098, K + 0x3000);
        put(&mut b, 0xb000, K + 0x2090);
        put(&mut b, 0xb008, K + 0x2090);
        put(&mut b, 0xb010, 8);
        put(&mut b, 0xb018, 9);
        put(&mut b, 0xb020, 2);
        put(&mut b, 0xb028, K + 0x6000);
        let img = image(&b);
        let engine = Windows {
            vm: Memory {
                image: &img,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .run(
                Plugin::WinThreads,
                &Options {
                    pid: Some(8),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows[0][2], "9");
        assert_eq!(r.rows[0].len(), 9);
        // NT5 ETHREAD uses low creation-time flag bits, identified by ThreadsProcess.
        isf.data["user_types"]["_ETHREAD"]["size"] = json!(80);
        isf.data["user_types"]["_ETHREAD"]["fields"]["ThreadsProcess"] =
            json!({"offset":72,"type":{"kind":"pointer"}});
        let offset = isf.offset("_ETHREAD", "CreateTime").unwrap() as usize;
        put(&mut b, 0xb000 + offset, (130000000000000000 << 3) | 3);
        let img = image(&b);
        let engine = Windows {
            vm: Memory {
                image: &img,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .run(
                Plugin::WinThreads,
                &Options {
                    pid: Some(8),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(r.rows[0][7], "130000000000000000");
        put(&mut b, 0xb010, 4);
        let img = image(&b);
        let engine = Windows {
            vm: Memory {
                image: &img,
                root: 0x1000,
                isf: &isf,
                sources: None,
            },
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .run(
                Plugin::WinThreads,
                &Options {
                    pid: Some(8),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(!r.complete);
        assert!(r.rows.is_empty());
    }
}
