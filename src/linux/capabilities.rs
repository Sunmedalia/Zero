//! Decode capability sets from real credentials; display identity from task credentials.
use super::*;
use crate::analysis::Options;

const NAMES: [&str; 41] = [
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

fn decode(value: u64, last: i64) -> String {
    let full = if last < 0 {
        0
    } else if last >= 63 {
        u64::MAX
    } else {
        (1u64 << (last + 1)) - 1
    };
    let value = value & full;
    if value == 0 {
        String::new()
    } else if last < 64 && value == full {
        "all".into()
    } else {
        NAMES
            .iter()
            .enumerate()
            .filter_map(|(bit, name)| (value & (1u64 << bit) != 0).then_some(*name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Linux<'_> {
    fn capabilities_last(&self) -> Result<i64> {
        if self.isf.data["symbols"].get("cap_last_cap").is_none() {
            return Ok(NAMES.len() as i64 - 1);
        }
        let at = self.isf.address("cap_last_cap")?;
        let size = self
            .isf
            .type_size(&self.isf.data["symbols"]["cap_last_cap"]["type"])?;
        ensure!(matches!(size, 1 | 2 | 4 | 8), "cap_last_cap 宽度无效");
        let shift = 64 - size * 8;
        let value = ((self.vm.uint(at, size as usize)? << shift) as i64) >> shift;
        Ok(value)
    }

    fn capability_value(&self, cred: u64, field: &str) -> Result<u64> {
        let ty = self.isf.field("cred", field)?["type"]["name"]
            .as_str()
            .context("能力字段缺少结构类型")?;
        let at = self.field_address(cred, "cred", field)?;
        match ty {
            "kernel_cap_t" => self.number(at, ty, "val"),
            "kernel_cap_struct" => {
                let field = self.isf.field(ty, "cap")?;
                let value_type = &field["type"];
                if value_type["kind"] == "array" {
                    let count = value_type["count"].as_u64().context("cap 数组缺少长度")?;
                    ensure!(matches!(count, 1 | 2), "不支持的 cap 数组长度");
                    ensure!(
                        self.isf.type_size(&value_type["subtype"])? == 4,
                        "cap 数组元素必须为 32 位"
                    );
                    let address = self.field_address(at, ty, "cap")?;
                    let low = self.vm.uint(address, 4)?;
                    Ok(if count == 2 {
                        low | (self.vm.uint(add(address, 4)?, 4)? << 32)
                    } else {
                        low
                    })
                } else {
                    self.number(at, ty, "cap")
                }
            }
            _ => bail!("不支持的能力结构 {ty}"),
        }
    }

    pub(super) fn capabilities(&self, options: &Options, job: &Job) -> Result<Results> {
        let last = self.capabilities_last()?;
        let pids: std::collections::BTreeSet<_> =
            options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.task_identities(Plugin::LinuxCapabilities, job)?;
        for task in tasks {
            job.check()?;
            if !pids.is_empty() && !task.pid.parse::<u32>().is_ok_and(|pid| pids.contains(&pid)) {
                continue;
            }
            let at = task.address;
            let cred = self.number(at, "task_struct", "cred")?;
            let real = self.number(at, "task_struct", "real_cred")?;
            let parent = self.number(at, "task_struct", "real_parent")?;
            let task_size = self.isf.data["user_types"]["task_struct"]["size"]
                .as_u64()
                .context("task_struct 缺少大小")?;
            ensure!(task_size <= 1024 * 1024, "task_struct 超过读取上限");
            let readable = parent != 0
                && self
                    .vm
                    .read(parent, &mut vec![0; task_size as usize])
                    .is_ok();
            let ppid = if readable {
                self.number(parent, "task_struct", "tgid")?
            } else {
                0
            };
            let mut row = vec![
                task.name,
                task.pid,
                self.number(at, "task_struct", "tgid")?.to_string(),
                ppid.to_string(),
                self.credential(cred, "euid")?.to_string(),
            ];
            for field in [
                "cap_inheritable",
                "cap_permitted",
                "cap_effective",
                "cap_bset",
            ] {
                ensure!(last >= -1, "cap_last_cap 导致负数位移");
                row.push(decode(self.capability_value(real, field)?, last));
            }
            row.push(if self.isf.field("cred", "cap_ambient").is_ok() {
                decode(self.capability_value(real, "cap_ambient")?, last)
            } else {
                "N/A".into()
            });
            result.rows.push(row);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::{Value, json};

    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn real_credentials_and_decoded_rows_match_pinned_methods() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/capabilities.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            let kind = case["kind"].as_str().unwrap();
            let value = case["value"].as_str().unwrap().parse::<u64>().unwrap();
            let ty = if kind == "val" {
                "kernel_cap_t"
            } else {
                "kernel_cap_struct"
            };
            let count = kind
                .strip_prefix("array")
                .map(|n| n.parse::<u64>().unwrap());
            let cap_type = if let Some(count) = count {
                json!({"kind":"array","count":count,"subtype":{"kind":"base","name":"u32"}})
            } else {
                json!({"kind":"base","name":if kind=="val" {"u64"} else {"u32"}})
            };
            let size = count
                .map(|c| c * 4)
                .unwrap_or(if kind == "val" { 8 } else { 4 });
            isf.data["user_types"][ty] = json!({"size":size,"fields":{}});
            isf.data["user_types"][ty]["fields"][if kind == "val" { "val" } else { "cap" }] =
                json!({"offset":0,"type":cap_type});
            isf.data["user_types"]["cred"] = json!({"size":96,"fields":{
                "euid":{"offset":80,"type":{"kind":"base","name":"u32"}}}});
            for (index, field) in [
                "cap_inheritable",
                "cap_permitted",
                "cap_effective",
                "cap_bset",
                "cap_ambient",
            ]
            .iter()
            .enumerate()
            {
                if *field == "cap_ambient" && case["ambient"] == false {
                    continue;
                }
                let offset = index * 16;
                isf.data["user_types"]["cred"]["fields"][field] =
                    json!({"offset":offset,"type":{"kind":"struct","name":ty}});
                let available = if size >= 8 {
                    value
                } else {
                    value & 0xffff_ffff
                };
                put(&mut bytes, 0x12000 + offset, available);
            }
            // Override credentials deliberately disagree: EUID comes from cred,
            // capability sets come from real_cred. PID differs from TGID too.
            put(&mut bytes, 0x11050, 1001);
            put(&mut bytes, 0x12050, 2002);
            for (field, offset) in [("cred", 112), ("real_cred", 120)] {
                isf.data["user_types"]["task_struct"]["fields"][field] =
                    json!({"offset":offset,"type":{"kind":"pointer"}});
            }
            put(&mut bytes, 0xa070, 0x11000);
            put(&mut bytes, 0xa078, 0x12000);
            put(&mut bytes, 0x9000, 0xa000);
            put(&mut bytes, 0x9008, 0xa000);
            put(&mut bytes, 0xa000, 0x9000);
            put(&mut bytes, 0xa008, 0x9000);
            put(&mut bytes, 0xa010, 1);
            put(&mut bytes, 0xa018, 101);
            put(&mut bytes, 0x9010, 7);
            put(&mut bytes, 0x9018, 77);
            put(
                &mut bytes,
                0xa020,
                if case["parent_readable"] == false {
                    0x50000
                } else {
                    0x9000
                },
            );
            bytes[0xa028..0xa030].copy_from_slice(b"task\0\0\0\0");
            if let Some(last) = case["last"].as_i64() {
                isf.data["base_types"]["i32"] = json!({"size":4,"signed":true});
                isf.data["symbols"]["cap_last_cap"] =
                    json!({"address":0x10800,"type":{"kind":"base","name":"i32"}});
                put(&mut bytes, 0x10800, last as u64);
            }
            let image = image(&bytes);
            let linux = engine(&image, &isf);
            let result = linux.capabilities(&Options::default(), &Job::default());
            if case.get("error").is_some() {
                assert!(result.is_err(), "{}", case["id"]);
            } else {
                let result = result.unwrap();
                assert!(result.complete, "{} {:?}", case["id"], result.diagnostics);
                assert_eq!(
                    json!(result.rows),
                    json!([case["expected"]]),
                    "{}",
                    case["id"]
                );
                let selected = linux
                    .capabilities(
                        &Options {
                            pid: Some(1),
                            pids: vec![1, 101],
                            ..Default::default()
                        },
                        &Job::default(),
                    )
                    .unwrap();
                assert_eq!(selected.rows, result.rows);
            }
            let excluded = linux
                .capabilities(
                    &Options {
                        pids: vec![101],
                        ..Default::default()
                    },
                    &Job::default(),
                )
                .unwrap();
            assert!(
                excluded.complete && excluded.rows.is_empty(),
                "{}",
                case["id"]
            );
        }
    }
}
