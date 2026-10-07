//! Immutable, process-local analysis snapshots, including incomplete evidence.
use crate::{
    Job,
    resources::Limits,
    store::{self, Results},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::Path,
    time::{Duration, Instant},
};

const STRIDE: usize = 200;
struct Disk {
    file: tempfile::NamedTempFile,
    offsets: Vec<u64>,
}
struct Snapshot {
    result: Results,
    disk: Option<Disk>,
    total: usize,
    bytes: usize,
    touched: Instant,
}
impl Snapshot {
    fn prepare(
        result: Results,
        memory_remaining: usize,
        directory: &Path,
        job: &Job,
    ) -> Result<Self> {
        job.check()?;
        let bytes = result
            .rows
            .capacity()
            .saturating_mul(std::mem::size_of::<Vec<String>>())
            .saturating_add(
                result
                    .rows
                    .iter()
                    .map(|row| {
                        row.capacity()
                            .saturating_mul(std::mem::size_of::<String>())
                            .saturating_add(row.iter().map(String::capacity).sum::<usize>())
                    })
                    .sum::<usize>(),
            );
        let mut snapshot = Snapshot {
            total: result.rows.len(),
            result,
            disk: None,
            bytes,
            touched: Instant::now(),
        };
        if bytes > memory_remaining {
            job.report("结果快照落盘");
            let mut file = tempfile::NamedTempFile::new_in(directory)?;
            let mut offsets = Vec::new();
            {
                let mut writer = BufWriter::new(file.as_file_mut());
                for (i, row) in snapshot.result.rows.iter().enumerate() {
                    job.check()?;
                    if i % STRIDE == 0 {
                        offsets.push(writer.stream_position()?);
                    }
                    serde_json::to_writer(&mut writer, row)?;
                    writer.write_all(b"\n")?;
                }
                writer.flush()?;
            }
            snapshot.result.rows = Vec::new();
            snapshot.disk = Some(Disk { file, offsets });
        }
        job.check()?;
        Ok(snapshot)
    }
}
pub struct Snapshots {
    entries: HashMap<String, Snapshot>,
    limits: Limits,
    directory: tempfile::TempDir,
    sequence: u64,
}
impl Snapshots {
    pub fn new(limits: Limits) -> Result<Self> {
        ensure!(
            limits.snapshot_count > 0 && limits.snapshot_idle_seconds > 0,
            "快照数量和有效期必须大于零"
        );
        Ok(Self {
            entries: HashMap::new(),
            limits,
            directory: tempfile::Builder::new()
                .prefix("zero-snapshots-")
                .tempdir()?,
            sequence: 0,
        })
    }
    pub fn expire(&mut self) {
        let ttl = Duration::from_secs(self.limits.snapshot_idle_seconds);
        self.entries.retain(|_, s| s.touched.elapsed() < ttl);
    }
    pub fn insert(&mut self, result: Results, job: &Job) -> Result<String> {
        self.expire();
        job.check()?;
        let snapshot =
            Snapshot::prepare(result, self.memory_remaining(), self.directory.path(), job)?;
        self.commit(snapshot, job)
    }
    fn memory_remaining(&self) -> usize {
        let used: usize = self
            .entries
            .values()
            .map(|s| if s.disk.is_none() { s.bytes } else { 0 })
            .sum();
        self.limits.snapshot_memory_bytes.saturating_sub(used)
    }
    /// Slow spill IO must not hold the catalog lock: the protocol thread needs to process cancellation.
    pub fn insert_shared(
        shared: &std::sync::Mutex<Self>,
        result: Results,
        job: &Job,
    ) -> Result<String> {
        let (remaining, directory) = {
            let mut store = shared.lock().map_err(|_| anyhow::anyhow!("快照锁不可用"))?;
            store.expire();
            (store.memory_remaining(), store.directory.path().to_owned())
        };
        let snapshot = Snapshot::prepare(result, remaining, &directory, job)?;
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("快照锁不可用"))?
            .commit(snapshot, job)
    }
    fn commit(&mut self, snapshot: Snapshot, job: &Job) -> Result<String> {
        ensure!(
            snapshot.disk.is_some() || snapshot.bytes <= self.memory_remaining(),
            "快照内存预算已被另一个写入占用；请重试"
        );
        job.check()?;
        while self.entries.len() >= self.limits.snapshot_count {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, s)| s.touched)
                .map(|(id, _)| id.clone())
                .context("快照淘汰失败")?;
            self.entries.remove(&oldest);
        }
        self.sequence += 1;
        use sha2::{Digest, Sha256};
        let id = format!(
            "{:x}",
            Sha256::digest(format!(
                "{}:{}",
                self.directory.path().display(),
                self.sequence
            ))
        );
        self.entries.insert(id.clone(), snapshot);
        Ok(id)
    }
    pub fn page(
        &mut self,
        id: &str,
        offset: usize,
        limit: usize,
        output: Option<&Path>,
        job: &Job,
    ) -> Result<Value> {
        ensure!((1..=200).contains(&limit), "limit 必须在 1..=200");
        self.expire();
        let snapshot = self
            .entries
            .get_mut(id)
            .context("result_id 已过期、被淘汰或不属于此服务；请重新执行 zero_analyze")?;
        snapshot.touched = Instant::now();
        if let Some(output) = output {
            if let Some(disk) = &snapshot.disk {
                store::export_fallible(
                    output,
                    &snapshot.result,
                    DiskRows::new(disk, 0)?.take(snapshot.total),
                    job,
                )?;
            } else {
                store::export_rows(output, &snapshot.result, snapshot.result.rows.iter(), job)?;
            }
        }
        let rows: Vec<Vec<String>> = if offset >= snapshot.total {
            Vec::new()
        } else if let Some(disk) = &snapshot.disk {
            DiskRows::new(disk, offset)?
                .take(limit)
                .collect::<Result<_>>()?
        } else {
            snapshot
                .result
                .rows
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect()
        };
        let next = offset.saturating_add(rows.len());
        let mut value = serde_json::to_value(snapshot.result.metadata())?;
        value["rows"] = json!(rows);
        value["result_id"] = json!(id);
        value["total_rows"] = json!(snapshot.total);
        value["offset"] = json!(offset);
        value["next_offset"] = if next < snapshot.total {
            json!(next)
        } else {
            Value::Null
        };
        if let Some(output) = output {
            value["output"] = json!(output);
        }
        Ok(value)
    }
}
struct DiskRows {
    reader: BufReader<File>,
}
impl DiskRows {
    fn new(disk: &Disk, offset: usize) -> Result<Self> {
        let mut reader = BufReader::new(File::open(disk.file.path())?);
        reader.seek(SeekFrom::Start(
            *disk.offsets.get(offset / STRIDE).unwrap_or(&0),
        ))?;
        let mut skip = String::new();
        for _ in 0..offset % STRIDE {
            skip.clear();
            reader.read_line(&mut skip)?;
        }
        Ok(Self { reader })
    }
}
impl Iterator for DiskRows {
    type Item = Result<Vec<String>>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(serde_json::from_str(&line).map_err(Into::into)),
            Err(e) => Some(Err(e.into())),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn result() -> Results {
        serde_json::from_value(json!({"plugin":"test","columns":["PID"],"rows":(0..405).map(|i|vec![i.to_string()]).collect::<Vec<_>>(),"complete":false,"diagnostics":["missing page"],"banner":"","symbol":"","page_table":0,"historical":false})).unwrap()
    }
    #[test]
    fn cancellation_during_spill_keeps_catalog_available_and_removes_temporary_file() -> Result<()>
    {
        use std::sync::{Arc, Barrier, Mutex};
        let snapshots = Arc::new(Mutex::new(Snapshots::new(Limits {
            snapshot_memory_bytes: 0,
            ..Default::default()
        })?));
        let barrier = Arc::new(Barrier::new(2));
        let checkpoint = barrier.clone();
        let job = Job::new(move |message| {
            if message == "结果快照落盘" {
                checkpoint.wait();
                checkpoint.wait();
            }
        });
        let worker_job = job.clone();
        let store = snapshots.clone();
        let worker =
            std::thread::spawn(move || Snapshots::insert_shared(&store, result(), &worker_job));
        barrier.wait();
        let available = snapshots.try_lock().is_ok();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        barrier.wait();
        assert!(worker.join().unwrap().is_err());
        assert!(
            available,
            "spilling must not block catalog access and protocol cancellation"
        );
        let snapshots = snapshots.lock().unwrap();
        assert!(snapshots.entries.is_empty());
        assert_eq!(std::fs::read_dir(snapshots.directory.path())?.count(), 0);
        Ok(())
    }
    #[test]
    fn spills_pages_exports_expires_and_evicts_without_losing_diagnostics() -> Result<()> {
        let mut snapshots = Snapshots::new(Limits {
            snapshot_memory_bytes: 0,
            snapshot_count: 1,
            ..Default::default()
        })?;
        let job = Job::default();
        let id = snapshots.insert(result(), &job)?;
        let page = snapshots.page(&id, 199, 3, None, &job)?;
        assert_eq!(page["rows"], json!([["199"], ["200"], ["201"]]));
        assert_eq!(page["complete"], false);
        assert_eq!(page["diagnostics"], json!(["missing page"]));
        assert_eq!(
            snapshots.page(&id, usize::MAX, 2, None, &job)?["rows"],
            json!([])
        );
        let directory = tempfile::tempdir()?;
        snapshots.page(&id, 0, 1, Some(&directory.path().join("all.json")), &job)?;
        assert_eq!(
            store::exported(&directory.path().join("all.json"))?.rows,
            result().rows
        );
        let disk = snapshots.entries[&id]
            .disk
            .as_ref()
            .unwrap()
            .file
            .path()
            .to_owned();
        let next = snapshots.insert(result(), &job)?;
        assert!(!disk.exists());
        assert!(snapshots.page(&id, 0, 1, None, &job).is_err());
        snapshots.entries.get_mut(&next).unwrap().touched =
            Instant::now() - Duration::from_secs(1801);
        assert!(snapshots.page(&next, 0, 1, None, &job).is_err());
        Ok(())
    }
}
