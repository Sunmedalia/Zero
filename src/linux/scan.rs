//! Physical object scans, independent of active task/file linked lists.
use super::*;
use crate::physical::{self, Decision, Object};
impl Linux<'_> {
    pub(super) fn psscan(&self, job: &Job) -> Result<Results> {
        ensure!(
            self.isf.data["base_types"]["pointer"]["size"]
                .as_u64()
                .unwrap_or(8)
                == 8,
            "PsScan 当前仅支持 64 位内核"
        );
        self.require(&[
            ("task_struct", "sched_class"),
            ("task_struct", "exit_state"),
            ("task_struct", "pid"),
            ("task_struct", "tgid"),
            ("task_struct", "comm"),
            ("task_struct", "real_parent"),
        ])?;
        let offset = self.isf.offset("task_struct", "sched_class")?;
        let mut needles = Vec::new();
        for name in self.isf.data["symbols"]
            .as_object()
            .context("ISF symbols 缺失")?
            .keys()
            .filter(|name| name.contains("_sched_class"))
        {
            let mut address = self.isf.address(name)?;
            if !self.arm64() && address < 1 << 48 && address & (1 << 47) != 0 {
                address |= 0xffff_0000_0000_0000;
            }
            needles.push(address);
        }
        let mut result = self.result(Plugin::LinuxPsscan);
        let mut seen = HashSet::new();
        let mut parent_cache: std::collections::HashMap<u64, Option<i64>> = Default::default();
        let mut parent_bytes = 0u64;
        let mut parent_limit_reached = false;
        let mut output_bytes = 0usize;
        ensure!(
            (1..=256).contains(&self.isf.size("task_struct", "comm")?),
            "task comm 长度无效"
        );
        let mut failures = 0u64;
        let mut first_failure = String::new();
        let mut parent_failures = 0u64;
        let task_size = self.isf.data["user_types"]["task_struct"]["size"]
            .as_u64()
            .context("task_struct size 缺失")?;
        ensure!(
            (1..=REGION_LIMIT).contains(&task_size),
            "task_struct size 无效"
        );
        let coverage = physical::pointers(self.vm.image, &needles, 8, job, |hit, _value| {
            let Some(address) = hit.checked_sub(offset) else {
                return Ok(Decision::Reject);
            };
            if !seen.insert(address) {
                return Ok(Decision::Reject);
            }
            let read = (|| -> Result<Option<Vec<String>>> {
                let object = Object {
                    image: self.vm.image,
                    isf: self.isf,
                    address,
                };
                let state = match object.number("task_struct", "exit_state")? {
                    0 => "TASK_RUNNING",
                    16 => "EXIT_DEAD",
                    32 => "EXIT_ZOMBIE",
                    48 => "EXIT_TRACE",
                    _ => return Ok(None),
                };
                let tid = object.number("task_struct", "pid")?;
                if !(1..65535).contains(&tid) {
                    return Ok(None);
                }
                let pid = object.signed("task_struct", "tgid")?;
                let name = object.string("task_struct", "comm")?;
                let parent = object.number("task_struct", "real_parent")?;
                let ppid = if parent == 0 {
                    0
                } else {
                    let entry = if let Some(value) = parent_cache.get(&parent) {
                        *value
                    } else if parent_cache.len() >= 65536
                        || parent_bytes + task_size > 64 * 1024 * 1024
                    {
                        parent_limit_reached = true;
                        None
                    } else {
                        let read = (|| -> Result<i64> {
                            let mut chunk = [0; 4096];
                            let mut offset = 0;
                            while offset < task_size {
                                job.check()?;
                                let count = (task_size - offset).min(4096) as usize;
                                parent_bytes += count as u64;
                                self.vm.read(add(parent, offset)?, &mut chunk[..count])?;
                                offset += count as u64;
                            }
                            let value = self.number(parent, "task_struct", "tgid")?;
                            Ok(match self.isf.size("task_struct", "tgid")? {
                                4 => value as i32 as i64,
                                8 => value as i64,
                                _ => anyhow::bail!("TGID 宽度无效"),
                            })
                        })();
                        job.check()?;
                        let value = read.ok();
                        parent_cache.insert(parent, value);
                        value
                    };
                    match entry {
                        Some(pid) => pid,
                        None => {
                            parent_failures += 1;
                            0
                        }
                    }
                };
                Ok(Some(vec![
                    hex(address),
                    pid.to_string(),
                    tid.to_string(),
                    ppid.to_string(),
                    name,
                    state.into(),
                ]))
            })();
            match read {
                Ok(Some(row)) => {
                    let bytes = row.iter().map(String::len).sum::<usize>();
                    if output_bytes + bytes > 128 * 1024 * 1024 {
                        return Ok(Decision::Stop);
                    }
                    output_bytes += bytes;
                    result.rows.push(row);
                    Ok(Decision::Accept)
                }
                Ok(None) => Ok(Decision::Reject),
                Err(error) => {
                    job.check()?;
                    failures += 1;
                    if first_failure.is_empty() {
                        first_failure = format!("{address:#x}: {error:#}");
                    }
                    Ok(Decision::Reject)
                }
            }
        })?;
        if !coverage.complete() {
            partial(
                &mut result,
                "物理扫描覆盖",
                anyhow::anyhow!(
                    "读取 {} / {} 字节；读取失败 {}；候选/输出上限 {}",
                    coverage.scanned_bytes,
                    coverage.captured_bytes,
                    coverage.read_failures,
                    coverage.limit_reached
                ),
            );
        }
        if failures > 0 {
            partial(
                &mut result,
                "物理任务候选",
                anyhow::anyhow!(
                    "{failures} 个命中无法读取字段（可能为非对象或缺页）；首处 {first_failure}"
                ),
            );
        }
        if parent_failures > 0 {
            partial(
                &mut result,
                "扫描任务父进程",
                anyhow::anyhow!(
                    "{parent_failures} 项父对象不可读；按参考规则显示 PPID 0，不代表已确认无父进程"
                ),
            );
        }
        result
            .rows
            .sort_unstable_by_key(|row| u64::from_str_radix(&row[0][2..], 16).unwrap_or(0));
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        result.kernel_identity["physical_scan"] = serde_json::json!({"coverage":coverage,"member":"task_struct.sched_class","candidate_read_failures":failures,"parent_unreadable":parent_failures,"parent_read_bytes":parent_bytes,"parent_limit_reached":parent_limit_reached,"rules":{"tid_min":1,"tid_max_exclusive":65535,"exit_states":[0,16,32,48]},"source":"physical bytes; independent of init_task.tasks"});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{engine, fixture, image};
    use super::*;
    use serde_json::json;
    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn scan_fixture() -> (Vec<u8>, Isf) {
        let (mut bytes, mut isf) = fixture();
        isf.data["symbols"]["fair_sched_class"] = json!({"address":0x18000});
        isf.data["symbols"]["idle_sched_class"] = json!({"address":0x18100});
        isf.data["user_types"]["task_struct"]["fields"]["sched_class"] =
            json!({"offset":80,"type":{"kind":"pointer"}});
        isf.data["user_types"]["task_struct"]["fields"]["exit_state"] =
            json!({"offset":88,"type":{"kind":"base","name":"u32"}});
        isf.data["user_types"]["task_struct"]["fields"]["tgid"]["type"] =
            json!({"kind":"base","name":"u32"});
        // High virtual alias of physical parent 0xa000. Only virtual dereferencing works.
        put(&mut bytes, 0x1800, 0x2003);
        put(&mut bytes, 0xa018, 42);
        (bytes, isf)
    }
    fn task(bytes: &mut [u8], at: usize, tid: u64, pid: u64, state: u64, parent: u64) {
        put(bytes, at + 16, tid);
        put(bytes, at + 24, pid);
        put(bytes, at + 32, parent);
        bytes[at + 40..at + 48].copy_from_slice(b"unlinked");
        put(bytes, at + 80, 0x18000);
        put(bytes, at + 88, state);
    }
    #[test]
    fn finds_unlinked_tasks_threads_and_all_reference_exit_states() {
        let (mut bytes, isf) = scan_fixture();
        for (i, state) in [0, 16, 32, 48].into_iter().enumerate() {
            task(
                &mut bytes,
                0x19000 + i * 0x100,
                101 + i as u64,
                100,
                state,
                0xffff80000000a000,
            );
        }
        task(&mut bytes, 0x19800, 0, 100, 0, 0);
        task(&mut bytes, 0x19900, 65535, 100, 0, 0);
        task(&mut bytes, 0x19a00, 500, 100, 8, 0);
        let image = image(&bytes);
        let result = engine(&image, &isf).psscan(&Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 4);
        for (i, row) in result.rows.iter().enumerate() {
            assert_eq!(row[0], hex(0x19000 + i as u64 * 0x100));
            assert_eq!(
                &row[1..5],
                &["100", &(101 + i).to_string(), "42", "unlinked"]
            );
        }
        assert_eq!(
            result
                .rows
                .iter()
                .map(|r| r[5].as_str())
                .collect::<Vec<_>>(),
            ["TASK_RUNNING", "EXIT_DEAD", "EXIT_ZOMBIE", "EXIT_TRACE"]
        );
        assert_eq!(
            result.kernel_identity["physical_scan"]["coverage"]["accepted"],
            4
        );
        // No task list traversal: make init_task unavailable and retain the same scan.
        let mut isf = isf;
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("init_task");
        assert_eq!(
            engine(&image, &isf).psscan(&Job::default()).unwrap().rows,
            result.rows
        );
    }
    #[test]
    fn unreadable_parent_is_explicit_partial_and_zero_parent_is_valid() {
        let (mut bytes, isf) = scan_fixture();
        task(&mut bytes, 0x19000, 101, 100, 0, 0xffff90000000a000);
        task(&mut bytes, 0x19100, 102, 100, 0, 0);
        let image = image(&bytes);
        let result = engine(&image, &isf).psscan(&Job::default()).unwrap();
        assert_eq!(result.rows.len(), 2);
        assert!(!result.complete);
        assert_eq!(result.rows[0][3], "0");
        assert_eq!(
            result.kernel_identity["physical_scan"]["parent_unreadable"],
            1
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.contains("不代表已确认无父进程"))
        );
    }
    #[test]
    fn physical_reader_signed_bitfields_and_bounded_strings() {
        let (mut bytes, mut isf) = scan_fixture();
        task(&mut bytes, 0x19000, 101, u32::MAX as u64, 0, 0);
        put(&mut bytes, 0x19000 + 32, 0x18); // sk_type uses a different structure's bitfield at offset 32.
        let image = image(&bytes);
        let object = Object {
            image: &image,
            isf: &isf,
            address: 0x19000,
        };
        assert_eq!(object.signed("task_struct", "tgid").unwrap(), -1);
        assert_eq!(object.number("sock", "sk_type").unwrap(), 3);
        isf.data["user_types"]["task_struct"]["fields"]["comm"]["type"]["count"] = json!(5000);
        assert!(engine(&image, &isf).psscan(&Job::default()).is_err());
    }
}
