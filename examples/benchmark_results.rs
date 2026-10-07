//! Reproducible synthetic result benchmark. Each export mode runs in its own process for RSS.
use anyhow::{Result, ensure};
use serde_json::json;
use std::{collections::HashSet, hint::black_box, time::Instant};
use zero_tui::{
    Job,
    resources::Limits,
    result_view,
    snapshots::Snapshots,
    store::{self, Results},
};
fn fixture(count: usize, complete: bool) -> Results {
    Results {
        plugin: "benchmark".into(),
        columns: vec!["PID".into(), "Name".into(), "Path".into()],
        rows: (0..count)
            .rev()
            .map(|i| {
                vec![
                    i.to_string(),
                    format!("process-{i}"),
                    format!("/synthetic/path/{}/{}", i % 71, "x".repeat(128)),
                ]
            })
            .collect(),
        complete,
        diagnostics: if complete {
            vec![]
        } else {
            vec!["synthetic missing page".into()]
        },
        banner: String::new(),
        symbol: String::new(),
        page_table: 0,
        historical: false,
        system: "synthetic".into(),
        kernel_identity: serde_json::Value::Null,
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("views");
    let count = args
        .get(2)
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(100_000);
    let result = fixture(count, true);
    let dir = tempfile::tempdir()?;
    let job = Job::default();
    if mode == "views" {
        let collapsed = HashSet::new();
        let start = Instant::now();
        let index = result_view::Index::build(&result, "process", Some(0), false, None, &collapsed);
        let build = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let mut previous = Vec::new();
        for _ in 0..20 {
            // Previous draw path: visible(), rows().len(), visible().len().
            for _ in 0..3 {
                previous = result.filtered("process");
                previous.sort_by(|a, b| result_view::compare(&a[0], &b[0]));
                black_box(&previous);
            }
        }
        let legacy = start.elapsed().as_secs_f64();
        let start = Instant::now();
        for frame in 0..20 {
            for row in frame * 50..(frame + 1) * 50 {
                black_box(index.row(&result, row));
            }
        }
        let indexed = start.elapsed().as_secs_f64();
        ensure!(
            index
                .filtered
                .iter()
                .map(|&i| &result.rows[i])
                .eq(previous.iter()),
            "view content changed"
        );
        println!(
            "{}",
            json!({"mode":mode,"rows":count,"frames":20,"legacy_seconds":legacy,"index_build_seconds":build,"indexed_frames_seconds":indexed})
        );
    } else if mode.starts_with("export-") {
        let extension = if mode.ends_with("csv") { "csv" } else { "json" };
        let output = dir.path().join(format!("result.{extension}"));
        let start = Instant::now();
        if mode.contains("legacy") {
            let rows = result.rows.clone();
            let bytes = if extension == "json" {
                let mut copy = result.clone();
                copy.rows = rows;
                serde_json::to_vec_pretty(&copy)?
            } else {
                let mut writer = csv::Writer::from_writer(Vec::new());
                writer.write_record(&result.columns)?;
                for row in rows {
                    writer.write_record(row)?;
                }
                writer.into_inner()?.to_vec()
            };
            store::atomic_write(&output, &bytes)?;
        } else {
            store::export_rows(&output, &result, result.rows.iter(), &job)?;
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "{}",
            json!({"mode":mode,"rows":count,"seconds":elapsed,"bytes":std::fs::metadata(output)?.len()})
        );
    } else if mode == "snapshots" {
        for complete in [true, false] {
            let mut snapshots = Snapshots::new(Limits {
                snapshot_memory_bytes: 0,
                ..Default::default()
            })?;
            let start = Instant::now();
            let id = snapshots.insert(fixture(count, complete), &job)?;
            let create = start.elapsed().as_secs_f64();
            let start = Instant::now();
            for page in 0..20 {
                black_box(snapshots.page(&id, page * 50, 50, None, &job)?);
            }
            println!(
                "{}",
                json!({"mode":mode,"rows":count,"complete":complete,"snapshot_seconds":create,"pages":20,"page_seconds":start.elapsed().as_secs_f64(),"analysis_reruns":0})
            );
        }
    } else {
        anyhow::bail!("unknown mode: {mode}");
    }
    Ok(())
}
