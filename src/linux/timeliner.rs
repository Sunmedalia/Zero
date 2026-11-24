//! Cross-plugin Linux timeline aggregation (`linux.timeliner`) with optional SleuthKit 3.x bodyfile export.
use super::*;
use crate::analysis::Options;
use crate::dump::DumpOptions;
use sha2::{Digest, Sha256};
use std::io::Write;

/// Parse an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS...` or `YYYY-MM-DD HH:MM:SS...`)
/// into Unix epoch seconds for SleuthKit bodyfile output.
pub(crate) fn parse_iso_utc_seconds(text: &str) -> Option<i64> {
    let s = text.trim();
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    if !(1970..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }
    // Howard Hinnant's civil_from_days inverse (days since 1970-01-01).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Write a standard SleuthKit 3.x bodyfile (`0|desc|0|---|0|0|0|atime|mtime|ctime|crtime`)
/// atomically and return `(filename, size, sha256)`.
pub(crate) fn write_bodyfile(
    dir: &Path,
    rows: &[(String, &str, &str, String)], // (iso_time, plugin, event, description)
    job: &Job,
) -> Result<(String, u64, String)> {
    crate::dump::directory(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    let mut hash = Sha256::new();
    let mut written = 0u64;
    for (time, plugin, event, desc) in rows {
        job.check()?;
        let epoch = parse_iso_utc_seconds(time).unwrap_or(0);
        let safe_desc = format!("[{plugin}] {event}: {desc}")
            .replace('|', "_")
            .replace(['\r', '\n'], " ");
        let lower = event.to_ascii_lowercase();
        let (atime, mtime, ctime, crtime) = if lower.contains("access") {
            (epoch, 0, 0, 0)
        } else if lower.contains("modif") || lower.contains("written") || lower.contains("run") {
            (0, epoch, 0, 0)
        } else if lower.contains("chang") || lower.contains("exit") || lower.contains("unload") {
            (0, 0, epoch, 0)
        } else {
            (0, 0, 0, epoch)
        };
        let line = format!("0|{safe_desc}|0|---|0|0|0|{atime}|{mtime}|{ctime}|{crtime}\n");
        let bytes = line.as_bytes();
        ensure!(
            written
                .checked_add(bytes.len() as u64)
                .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
            "bodyfile 超过 256 MiB 上限"
        );
        tmp.write_all(bytes)?;
        hash.update(bytes);
        written += bytes.len() as u64;
    }
    job.check()?;
    tmp.as_file().sync_all()?;
    let filename = "timeliner.bodyfile".to_owned();
    let target = dir.join(&filename);
    tmp.persist_noclobber(&target).map_err(|e| e.error)?;
    Ok((filename, written, format!("{:x}", hash.finalize())))
}

impl Linux<'_> {
    pub(super) fn linux_timeliner(&self, dump: Option<&DumpOptions>, job: &Job) -> Result<Results> {
        let mut r = self.result(Plugin::LinuxTimeliner);
        let mut events: Vec<(String, &'static str, &'static str, String)> = Vec::new();
        let mut collect = |plugin_name: &'static str,
                           res: Result<Results>,
                           specs: &[(usize, &'static str, &[usize])]|
         -> Result<()> {
            match res {
                Ok(out) => {
                    if !out.complete {
                        r.complete = false;
                        r.diagnostics.push(format!(
                            "{plugin_name}: 部分结果（{} 条诊断）",
                            out.diagnostics.len()
                        ));
                    }
                    for row in &out.rows {
                        for &(col, label, desc_cols) in specs {
                            let Some(ts) = row.get(col) else {
                                continue;
                            };
                            if parse_iso_utc_seconds(ts).is_none() {
                                continue;
                            }
                            let desc = desc_cols
                                .iter()
                                .filter_map(|i| row.get(*i))
                                .filter(|s| !s.is_empty() && *s != "N/A")
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(" ");
                            events.push((ts.clone(), plugin_name, label, desc));
                        }
                    }
                }
                Err(e) => {
                    job.check()?;
                    partial(&mut r, plugin_name, e);
                }
            }
            Ok(())
        };

        let opts = Options::default();
        collect(
            Plugin::LinuxBoottime.name(),
            self.namespace_boottimes(job),
            &[(1, "System boot", &[0])],
        )?;
        collect(
            Plugin::LinuxPslist.name(),
            self.process_details_with_options(&opts, None, job),
            &[(9, "Process created", &[0, 3])],
        )?;
        collect(
            Plugin::LinuxLsof.name(),
            self.linux_lsof(&opts, job),
            &[
                (9, "File changed", &[0, 2, 4]),
                (10, "File modified", &[0, 2, 4]),
                (11, "File accessed", &[0, 2, 4]),
            ],
        )?;
        collect(
            Plugin::LinuxPagecacheFiles.name(),
            self.linux_pagecache_files(&opts, job),
            &[
                (9, "Pagecache accessed", &[12, 3]),
                (10, "Pagecache modified", &[12, 3]),
                (11, "Pagecache changed", &[12, 3]),
            ],
        )?;
        collect(
            Plugin::LinuxBash.name(),
            self.linux_bash(&opts, job),
            &[(2, "Bash command", &[0, 1, 3])],
        )?;

        events.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));

        if let Some(dump_opts) = dump {
            let (file, size, sha256) = write_bodyfile(&dump_opts.directory, &events, job)?;
            if !r.kernel_identity.is_object() {
                r.kernel_identity = serde_json::json!({});
            }
            if let Some(obj) = r.kernel_identity.as_object_mut() {
                obj.insert(
                    "bodyfile".into(),
                    serde_json::json!({
                        "file": file,
                        "size": size,
                        "sha256": sha256,
                        "events": events.len(),
                    }),
                );
            }
        }

        r.rows = events
            .into_iter()
            .map(|(time, plugin, event, desc)| vec![time, plugin.into(), event.into(), desc])
            .collect();
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iso_timestamps_and_writes_sleuthkit_bodyfile() {
        assert_eq!(
            parse_iso_utc_seconds("1970-01-01T00:00:00.000000+00:00"),
            Some(0)
        );
        assert_eq!(
            parse_iso_utc_seconds("2023-11-14T22:13:20.000000+00:00"),
            Some(1_700_000_000)
        );
        assert_eq!(parse_iso_utc_seconds("N/A"), None);

        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            (
                "2023-11-14T22:13:20.000000+00:00".to_owned(),
                "linux.pslist.PsList",
                "Process created",
                "1 systemd".to_owned(),
            ),
            (
                "2023-11-14T22:13:21.000000+00:00".to_owned(),
                "linux.lsof.Lsof",
                "File modified",
                "1 systemd /etc/hosts".to_owned(),
            ),
        ];
        let (name, size, sha256) = write_bodyfile(dir.path(), &events, &Job::default()).unwrap();
        assert_eq!(name, "timeliner.bodyfile");
        assert!(size > 0 && sha256.len() == 64);
        let content = std::fs::read_to_string(dir.path().join(name)).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "0|[linux.pslist.PsList] Process created: 1 systemd|0|---|0|0|0|0|0|0|1700000000"
        );
        assert_eq!(
            lines[1],
            "0|[linux.lsof.Lsof] File modified: 1 systemd /etc/hosts|0|---|0|0|0|0|1700000001|0|0"
        );
    }
}
