//! Process state/capability readers and FD summaries; offsets always come from ISF.
use crate::{
    Job,
    linux::{Linux, Plugin},
    store::Results,
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;
impl Linux<'_> {
    pub(crate) fn run_process_extra(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let state = if self.isf.field("task_struct", "__state").is_ok() {
            "__state"
        } else {
            "state"
        };
        let fields = match plugin {
            Plugin::Psstate => vec![
                ("task_struct", state),
                ("task_struct", "exit_state"),
                ("task_struct", "flags"),
            ],
            Plugin::Capabilities => vec![
                ("task_struct", "cred"),
                ("cred", "cap_inheritable"),
                ("cred", "cap_permitted"),
                ("cred", "cap_effective"),
                ("cred", "cap_bset"),
            ],
            _ => vec![],
        };
        for (structure, field) in fields {
            let size = self
                .isf
                .size(structure, field)
                .with_context(|| format!("不支持: 缺少 {structure}.{field}"))?;
            ensure!(
                (1..=8).contains(&size),
                "不支持: {structure}.{field} 超过 64 位"
            );
        }
        let mut result = self.run(Plugin::Pslist, job)?;
        let tasks = std::mem::take(&mut result.rows);
        result.plugin = plugin.name().into();
        result.columns = plugin
            .descriptor()
            .columns
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut counts: BTreeMap<String, [u64; 4]> = BTreeMap::new();
        if plugin == Plugin::Fdsummary {
            let files = self.run(Plugin::Lsof, job)?;
            result.complete &= files.complete;
            result.diagnostics.extend(files.diagnostics);
            for row in files.rows {
                job.check()?;
                let n = counts.entry(row[0].clone()).or_default();
                n[0] += 1;
                match row[3].as_str() {
                    "Regular" => n[1] += 1,
                    "Socket" => n[2] += 1,
                    "FIFO" => n[3] += 1,
                    _ => {}
                }
            }
        }
        for task in tasks {
            job.check()?;
            let address = u64::from_str_radix(&task[4][2..], 16)?;
            let read = (|| -> Result<Vec<String>> {
                let mut row = vec![task[0].clone(), task[3].clone()];
                match plugin {
                    Plugin::Psstate => {
                        for field in [state, "exit_state", "flags"] {
                            row.push(format!(
                                "{:#018x}",
                                self.number(address, "task_struct", field)?
                            ));
                        }
                    }
                    Plugin::Capabilities => {
                        let cred = self.number(address, "task_struct", "cred")?;
                        ensure!(cred != 0, "空 cred 指针");
                        for field in [
                            "cap_inheritable",
                            "cap_permitted",
                            "cap_effective",
                            "cap_bset",
                        ] {
                            row.push(format!("{:#018x}", self.number(cred, "cred", field)?));
                        }
                        row.push(format!("{cred:#018x}"));
                    }
                    Plugin::Fdsummary => {
                        let n = counts.get(&task[0]).copied().unwrap_or_default();
                        row.extend(n.iter().map(u64::to_string));
                    }
                    _ => unreachable!(),
                }
                Ok(row)
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(e) => {
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {} @ {address:#x}: {e:#}", task[0]));
                }
            }
        }
        Ok(result)
    }
}
