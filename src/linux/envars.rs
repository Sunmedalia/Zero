//! Reference environment extraction: bounded, wholly captured buffers and ordered pairs.
use super::*;
use crate::analysis::Options;

fn pairs(bytes: &[u8]) -> impl Iterator<Item = (String, String)> + '_ {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |at| at + 1);
    bytes[..end].split(|byte| *byte == 0).map_while(|entry| {
        let entry = String::from_utf8_lossy(entry);
        let (key, value) = entry.split_once('=')?;
        Some((key.to_owned(), value.to_owned()))
    })
}

impl Linux<'_> {
    pub(super) fn envars(&self, options: &Options, job: &Job) -> Result<Results> {
        let (result, tasks) = self.task_identities(Plugin::LinuxEnvars, job)?;
        self.envars_tasks(options, job, result, tasks)
    }
    fn envars_tasks(
        &self,
        options: &Options,
        job: &Job,
        mut result: Results,
        tasks: Vec<Task>,
    ) -> Result<Results> {
        let pids: std::collections::BTreeSet<_> =
            options.pids.iter().copied().chain(options.pid).collect();
        for task in tasks {
            job.check()?;
            if !pids.is_empty() && !task.pid.parse::<u32>().is_ok_and(|pid| pids.contains(&pid)) {
                continue;
            }
            if self.number(task.address, "task_struct", "flags")? & 0x0020_0000 != 0 {
                continue;
            }
            let ppid = self.task_parent_tgid(task.address)?;
            let mm = self.number(task.address, "task_struct", "mm")?;
            let start = self.number(mm, "mm_struct", "env_start")?;
            let end = self.number(mm, "mm_struct", "env_end")?;
            let Some(length) = end
                .checked_sub(start)
                .filter(|length| (1..=8192).contains(length))
            else {
                continue;
            };
            // Missing layout is an unsupported ISF, not a missing captured page.
            self.isf.layout("mm_struct", "pgd")?;
            let Ok(Some(vm)) = self.process_vm(task.address) else {
                continue;
            };
            let mut bytes = vec![0; length as usize];
            if vm.read(start, &mut bytes).is_err() {
                continue;
            }
            for (key, value) in pairs(&bytes) {
                job.check()?;
                result.rows.push(vec![
                    task.pid.clone(),
                    ppid.to_string(),
                    task.name.clone(),
                    key,
                    value,
                ]);
            }
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
    fn bounded_environment_rows_match_pinned_generator() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/envars.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let (mut bytes, mut isf) = fixture();
            isf.data["user_types"]["task_struct"]["fields"]["flags"] =
                json!({"offset":104,"type":{"kind":"base","name":"u64"}});
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
            put(&mut bytes, 0xa068, case["flags"].as_u64().unwrap_or(0));
            bytes[0xa028..0xa030].copy_from_slice(b"task\0\0\0\0");
            let payload = case["payload_hex"].as_str().unwrap();
            let payload: Vec<u8> = payload
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let start = case["start"].as_u64().unwrap();
            put(&mut bytes, 0xb018, start);
            let end = start
                .checked_add_signed(case["length"].as_i64().unwrap_or(payload.len() as i64))
                .unwrap();
            put(&mut bytes, 0xb020, end);
            put(&mut bytes, 0x7010, 0x26003);
            for (index, byte) in payload.into_iter().enumerate() {
                let relative = start as usize - 0x200000 + index;
                let physical = [0x20000, 0x25000, 0x26000][relative / 4096] + relative % 4096;
                bytes[physical] = byte;
            }
            if case["readable"] == false {
                put(&mut bytes, 0x7008, 0);
            }
            if case["layer"] == false {
                put(&mut bytes, 0xb000, 0x50000);
            }
            let image = image(&bytes);
            let linux = engine(&image, &isf);
            // These vectors call the reference generator with supplied task objects.
            // Test extraction separately from the reference task-list admission gate.
            let run = |options: &Options| -> Result<Results> {
                let (result, tasks) = linux.adapter_tasks(Plugin::LinuxEnvars, &Job::default())?;
                linux.envars_tasks(options, &Job::default(), result, tasks)
            };
            let result = run(&Options::default()).unwrap();
            assert!(result.complete, "{} {:?}", case["id"], result.diagnostics);
            assert_eq!(json!(result.rows), case["expected"], "{}", case["id"]);
            let selected = run(&Options {
                pid: Some(1),
                pids: vec![1, 101],
                ..Default::default()
            })
            .unwrap();
            assert_eq!(selected.rows, result.rows, "{}", case["id"]);
            let excluded = run(&Options {
                pids: vec![101],
                ..Default::default()
            })
            .unwrap();
            assert!(
                excluded.complete && excluded.rows.is_empty(),
                "{}",
                case["id"]
            );
        }
    }
}
