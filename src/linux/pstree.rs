//! Volatility-compatible Linux process tree (`linux.pstree.PsTree`).
use super::*;
use crate::analysis::Options;
use crate::bytes::JsonKey as _;
use std::collections::{BTreeSet, HashMap};

struct TreeEntry {
    tid: Option<u64>,
    pid: Option<u64>,
    ppid: Option<u64>,
    row: Vec<String>,
}

impl Linux<'_> {
    pub(super) fn pstree(&self, options: &Options, job: &Job) -> Result<Results> {
        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let mut raw = self.selected_task_list_with_threads(options.include_threads, &pids, job)?;
        let mut result = self.result(Plugin::LinuxPstree);
        result.complete = raw.complete;
        result.diagnostics = std::mem::take(&mut raw.diagnostics);

        let mut entries = Vec::with_capacity(raw.rows.len());
        for row in raw.rows {
            job.check()?;
            let tid_str = row.at(0)?.clone();
            let pid_str = row.at(1)?.clone();
            let mut comm = row.at(3)?.clone();
            let offset_str = row.at(4)?.clone();
            let task =
                u64::from_str_radix(offset_str.strip_prefix("0x").unwrap_or(&offset_str), 16)?;

            let ppid_str = match self.task_parent_tgid(task) {
                Ok(ppid) if ppid <= i32::MAX as u64 => ppid.to_string(),
                Ok(_) => {
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {tid_str} parent TGID 超出 i32 范围"));
                    "0".into()
                }
                Err(error) => {
                    partial(&mut result, format!("PID {tid_str} parent TGID"), error);
                    "0".into()
                }
            };

            if options.decorate_comm {
                match self.number(task, "task_struct", "flags") {
                    Ok(flags) if flags & 0x0020_0000 != 0 => comm = format!("[{comm}]"),
                    Ok(_) if tid_str != pid_str => comm = format!("{{{comm}}}"),
                    Ok(_) => (),
                    Err(error) => {
                        partial(&mut result, format!("PID {tid_str} thread flags"), error);
                    }
                }
            }

            entries.push(TreeEntry {
                tid: tid_str.parse::<u64>().ok(),
                pid: pid_str.parse::<u64>().ok(),
                ppid: ppid_str.parse::<u64>().ok(),
                row: vec![offset_str, pid_str, tid_str, ppid_str, comm],
            });
        }

        // Index first occurrence of each TID to match Volatility 3 parent attachment.
        let mut tid_to_index: HashMap<u64, usize> = HashMap::with_capacity(entries.len());
        for (idx, entry) in entries.iter().enumerate() {
            if let Some(tid) = entry.tid {
                tid_to_index.entry(tid).or_insert(idx);
            }
        }

        let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut roots = Vec::new();
        for (idx, entry) in entries.iter().enumerate() {
            let parent_idx = match (entry.tid, entry.pid, entry.ppid) {
                // User threads attach under their thread-group leader when present.
                (Some(tid), Some(pid), _) if tid != pid => {
                    tid_to_index.get(&pid).copied().filter(|&p| p != idx)
                }
                (Some(tid), _, Some(ppid)) if ppid != 0 && ppid != tid => {
                    tid_to_index.get(&ppid).copied().filter(|&p| p != idx)
                }
                _ => None,
            };
            if let Some(parent) = parent_idx {
                children.entry(parent).or_default().push(idx);
            } else {
                roots.push(idx);
            }
        }

        // DFS emit in stable discovery order; unreachable cycles fall back as roots.
        let mut visited = vec![false; entries.len()];
        let mut order: Vec<(usize, usize)> = Vec::with_capacity(entries.len());
        for start in roots.into_iter().chain(0..entries.len()) {
            if visited.get(start).copied().unwrap_or(true) {
                continue;
            }
            let mut stack = vec![(start, 0usize)];
            while let Some((idx, depth)) = stack.pop() {
                job.check()?;
                if visited.get(idx).copied().unwrap_or(true) {
                    continue;
                }
                if let Some(slot) = visited.get_mut(idx) {
                    *slot = true;
                }
                order.push((idx, depth));
                if let Some(kids) = children.get(&idx) {
                    for &kid in kids.iter().rev() {
                        if !visited.get(kid).copied().unwrap_or(true) {
                            stack.push((kid, depth.saturating_add(1)));
                        }
                    }
                }
            }
        }

        let mut levels = Vec::with_capacity(order.len());
        let mut slots: Vec<Option<Vec<String>>> =
            entries.into_iter().map(|e| Some(e.row)).collect();
        for (idx, depth) in order {
            if let Some(row) = slots.get_mut(idx).and_then(Option::take) {
                result.rows.push(row);
                levels.push(depth);
            }
        }
        *result.kernel_identity.key_mut("pstree_levels")? = serde_json::json!(levels);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;

    fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn pstree_fixture() -> (Vec<u8>, Isf) {
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["task_struct"]["fields"]["flags"] =
            json!({"offset":64,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["task_struct"]["fields"]["thread_group"] =
            json!({"offset":72,"type":{"kind":"struct","name":"list_head"}});
        // init_task (0x9000): pid=0, tgid=0, parent=0x9000, swapper (PF_KTHREAD)
        // proc 1    (0xa000): pid=1, tgid=1, parent=0x9000, init
        // proc 10   (0xb000): pid=10, tgid=10, parent=0xa000, sshd
        // proc 2    (0xc000): pid=2, tgid=2, parent=0x9000, kthreadd (PF_KTHREAD)
        // thread 11 (0xd000): pid=11, tgid=10, parent=0xa000, worker (thread of 10)
        // Circular tasks list: 0x9000 -> 0xc000 -> 0xb000 -> 0xa000 -> 0x9000
        // (intentionally out of parent-first order to prove DFS tree ordering)
        put(&mut b, 0x9000, 0xc000);
        put(&mut b, 0x9008, 0xa000);
        put(&mut b, 0xc000, 0xb000);
        put(&mut b, 0xc008, 0x9000);
        put(&mut b, 0xb000, 0xa000);
        put(&mut b, 0xb008, 0xc000);
        put(&mut b, 0xa000, 0x9000);
        put(&mut b, 0xa008, 0xb000);

        for (addr, pid, tgid, parent, comm, flags) in [
            (
                0x9000usize,
                0u64,
                0u64,
                0x9000u64,
                b"swapper\0",
                0x0020_0000u64,
            ),
            (0xa000, 1, 1, 0x9000, b"init\0\0\0\0", 0),
            (0xb000, 10, 10, 0xa000, b"sshd\0\0\0\0", 0),
            (0xc000, 2, 2, 0x9000, b"kthread\0", 0x0020_0000),
            (0xd000, 11, 10, 0xa000, b"worker\0\0", 0),
        ] {
            put(&mut b, addr + 16, pid);
            put(&mut b, addr + 24, tgid);
            put(&mut b, addr + 32, parent);
            b[addr + 40..addr + 48].copy_from_slice(comm);
            put(&mut b, addr + 64, flags);
            // Default empty thread_group circular list
            put(&mut b, addr + 72, (addr + 72) as u64);
            put(&mut b, addr + 80, (addr + 72) as u64);
        }
        // Attach thread 11 (0xd000) to proc 10 (0xb000)'s thread_group
        put(&mut b, 0xb000 + 72, 0xd000 + 72);
        put(&mut b, 0xb000 + 80, 0xd000 + 72);
        put(&mut b, 0xd000 + 72, 0xb000 + 72);
        put(&mut b, 0xd000 + 80, 0xb000 + 72);

        (b, isf)
    }

    #[test]
    fn pstree_orders_children_under_parents_and_supports_threads_and_decoration() {
        let (bytes, isf) = pstree_fixture();
        let img = image(&bytes);
        let linux = engine(&img, &isf);

        let result = linux
            .pstree(
                &Options {
                    include_threads: true,
                    decorate_comm: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(
            result.columns,
            vec!["OFFSET (V)", "PID", "TID", "PPID", "COMM"]
        );
        // kthread (pid=2, ppid=0) is a root; init (pid=1, ppid=0) is a root whose child is sshd (10) -> worker (11)
        let tids: Vec<&str> = result.rows.iter().map(|r| r[2].as_str()).collect();
        assert_eq!(tids, vec!["2", "1", "10", "11"]);
        let comms: Vec<&str> = result.rows.iter().map(|r| r[4].as_str()).collect();
        assert_eq!(comms, vec!["[kthread]", "init", "sshd", "{worker}"]);
        assert_eq!(result.kernel_identity["pstree_levels"], json!([0, 0, 1, 2]));
    }

    #[test]
    fn pstree_filters_by_pid_union() {
        let (bytes, isf) = pstree_fixture();
        let img = image(&bytes);
        let linux = engine(&img, &isf);

        let result = linux
            .pstree(
                &Options {
                    pid: Some(10),
                    pids: vec![10],
                    include_threads: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete);
        let tids: Vec<&str> = result.rows.iter().map(|r| r[2].as_str()).collect();
        assert_eq!(tids, vec!["10", "11"]);
        assert_eq!(result.kernel_identity["pstree_levels"], json!([0, 1]));
    }
}
