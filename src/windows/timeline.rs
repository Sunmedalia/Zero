//! windows.timeliner: one time-ordered view over the timestamped plugins.
use super::*;

/// FILETIME ticks between 1601-01-01 and the Unix epoch.
const EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// Ticks at end of year 9999; pool 残留的高位垃圾值超出后无法是真实时间。
const MAX_TICKS: u64 = EPOCH_TICKS + 8399 * 366 * 86_400 * 10_000_000;

/// `YYYY-MM-DD HH:MM:SS UTC` for a FILETIME, or empty when out of range.
pub(super) fn filetime_utc(ticks: u64) -> String {
    if !(EPOCH_TICKS..=MAX_TICKS).contains(&ticks) {
        return String::new();
    }
    crate::report::utc(((ticks - EPOCH_TICKS) / 10_000_000) as i64)
}

/// (plugin, timestamp column, event label, description columns).
const SOURCES: &[(Plugin, usize, &str, &[usize])] = &[
    (Plugin::WinPslist, 6, "Process created", &[0, 2]),
    (Plugin::WinPslist, 7, "Process exited", &[0, 2]),
    (
        Plugin::WinNetscan,
        7,
        "Connection created",
        &[1, 2, 3, 5, 6],
    ),
    (Plugin::WinSymlinkscan, 4, "Symbolic link created", &[2, 3]),
    (Plugin::WinUserassist, 6, "UserAssist last run", &[2, 3]),
    (
        Plugin::WinScheduledTasks,
        5,
        "Scheduled task created",
        &[0, 2],
    ),
    (
        Plugin::WinScheduledTasks,
        6,
        "Scheduled task last run",
        &[0, 2],
    ),
    (Plugin::WinAmcache, 5, "Amcache entry written", &[0, 1]),
    (Plugin::WinMftscan, 6, "MFT $SI created", &[4, 1]),
    (Plugin::WinMftscan, 7, "MFT $SI modified", &[4, 1]),
];

impl Windows<'_> {
    pub(super) fn timeliner(&self, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::WinTimeliner);
        let mut events = Vec::new();
        let mut cache: Vec<(Plugin, Results)> = Vec::new();
        for &(plugin, column, label, description) in SOURCES {
            job.check()?;
            if !cache.iter().any(|(p, _)| *p == plugin) {
                match self.run(plugin, &Options::default(), job) {
                    Ok(result) => {
                        if !result.complete {
                            r.complete = false;
                            r.diagnostics.push(format!(
                                "{}: 部分结果（{} 条诊断）",
                                plugin.name(),
                                result.diagnostics.len()
                            ));
                        }
                        cache.push((plugin, result));
                    }
                    Err(e) => {
                        job.check()?;
                        Self::issue(&mut r, plugin.name(), format!("{e:#}"));
                        continue;
                    }
                }
            }
            let Some((_, result)) = cache.iter().find(|(p, _)| *p == plugin) else {
                continue;
            };
            for row in &result.rows {
                let Some(ticks) = row.get(column).and_then(|t| t.parse::<u64>().ok()) else {
                    continue;
                };
                // Carved records can hold garbage; keep 1990-01-01..2100-01-01.
                if !(122_756_544_000_000_000..157_469_184_000_000_000).contains(&ticks) {
                    continue;
                }
                let text = description
                    .iter()
                    .filter_map(|i| row.get(*i))
                    .filter(|t| !t.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
                events.push((ticks, plugin.name(), label, text));
            }
        }
        events.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
        r.rows = events
            .into_iter()
            .map(|(ticks, plugin, label, text)| {
                vec![
                    filetime_utc(ticks),
                    ticks.to_string(),
                    plugin.into(),
                    label.into(),
                    text,
                ]
            })
            .collect();
        r.kernel_identity["coverage"] = serde_json::json!(
            "pslist, netscan, symlinkscan, userassist, scheduled_tasks, amcache and mftscan timestamps"
        );
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetimes_convert_to_utc_and_pre_epoch_is_empty() {
        assert_eq!(filetime_utc(EPOCH_TICKS), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            filetime_utc(131_728_902_999_966_832),
            "2018-06-08 00:11:39 UTC"
        );
        assert_eq!(filetime_utc(1), "");
    }

    #[test]
    fn every_source_column_exists_in_its_plugin() {
        for (plugin, column, _, description) in SOURCES {
            let columns = plugin.descriptor().columns;
            assert!(*column < columns.len(), "{plugin:?}");
            assert!(
                columns[*column].contains("Time")
                    || columns[*column].contains("Created")
                    || columns[*column].contains("Modified")
                    || columns[*column].contains("LastRun")
                    || columns[*column].contains("LastUpdated"),
                "{plugin:?} {}",
                columns[*column]
            );
            assert!(description.iter().all(|i| *i < columns.len()), "{plugin:?}");
        }
    }
}
