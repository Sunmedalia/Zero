//! Volatility-compatible Linux bash history (`linux.bash.Bash`).
use super::*;
use crate::analysis::Options;
use std::collections::BTreeSet;

impl Linux<'_> {
    pub(super) fn linux_bash(&self, options: &Options, job: &Job) -> Result<Results> {
        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.task_identities(Plugin::LinuxBash, job)?;

        for task in tasks {
            job.check()?;
            if !pids.is_empty() && !task.pid.parse::<u32>().is_ok_and(|pid| pids.contains(&pid)) {
                continue;
            }
            if !matches!(task.name.as_str(), "bash" | "sh" | "dash") {
                continue;
            }
            let addr = task.address;
            let read = (|| -> Result<()> {
                let mm = self.number(addr, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let vm = self.process_vm(addr)?.context("用户地址空间为空")?;
                let nodes = self.vma_nodes(mm, job, &mut result)?;
                let mut scratch = self.result(Plugin::Bash);
                self.bash_history(
                    mm,
                    &vm,
                    &nodes,
                    &[task.pid.clone(), task.name.clone()],
                    &mut scratch,
                    job,
                )?;
                result.complete &= scratch.complete;
                result.diagnostics.extend(scratch.diagnostics);
                for row in scratch.rows {
                    // Legacy bash_history emits [PID, Name, Timestamp, Command, Address];
                    // Volatility 3 linux.bash.Bash emits [PID, Process, CommandTime, Command].
                    result.rows.push(vec![
                        row.at(0)?.clone(),
                        row.at(1)?.clone(),
                        row.at(2)?.clone(),
                        row.at(3)?.clone(),
                    ]);
                }
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(&mut result, format!("PID {} Bash", task.pid), error);
            }
            job.report(format!("linux.bash.Bash: {} 条", result.rows.len()));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};

    fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn linux_bash_emits_4_vol3_columns_and_respects_pid_filter() {
        let (mut b, isf) = fixture();
        // init_task 0x9000 -> task 0xa000 (pid=10, "bash")
        put(&mut b, 0x9000, 0xa000);
        put(&mut b, 0x9008, 0xa000);
        put(&mut b, 0xa000, 0x9000);
        put(&mut b, 0xa008, 0x9000);
        put(&mut b, 0xa010, 10);
        put(&mut b, 0xa018, 10);
        put(&mut b, 0xa020, 0x9000);
        b[0xa028..0xa030].copy_from_slice(b"bash\0\0\0\0");
        put(&mut b, 0xa030, 0xb000); // mm

        // mm at 0xb000: pgd=0x4000, mmap=0xc000
        put(&mut b, 0xb000, 0x4000);
        put(&mut b, 0xb028, 0xc000);

        // VMA [0x200000, 0x201000) rw-p anonymous (phys 0x20000)
        put(&mut b, 0xc000, 0);
        put(&mut b, 0xc008, 0x200000);
        put(&mut b, 0xc010, 0x201000);
        put(&mut b, 0xc018, 3); // rw-p
        put(&mut b, 0xc020, 0);
        put(&mut b, 0xc028, 0);

        // Place HIST_ENTRY { line=0x200100, timestamp=0x200120, data=0 } at 0x200000 (phys 0x20000)
        put(&mut b, 0x20000, 0x200100);
        put(&mut b, 0x20008, 0x200120);
        put(&mut b, 0x20010, 0);
        b[0x20100..0x20106].copy_from_slice(b"id -a\0");
        b[0x20120..0x2012c].copy_from_slice(b"#1700000000\0");

        let img = image(&b);
        let linux = engine(&img, &isf);
        let result = linux
            .linux_bash(&Options::default(), &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].len(), 4);
        assert_eq!(result.rows[0][0], "10");
        assert_eq!(result.rows[0][1], "bash");
        assert_eq!(result.rows[0][3], "id -a");

        let excluded = linux
            .linux_bash(
                &Options {
                    pids: vec![99],
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(excluded.complete);
        assert!(excluded.rows.is_empty());
    }
}
