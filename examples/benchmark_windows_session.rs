//! Compare repeated standalone symbol resolution with a prepared Session on the same image.
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use zero_tui::{
    Job,
    analysis::{self, Options, Session},
    linux::{Outcome, Plugin, Request},
    windows,
};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let image = PathBuf::from(args.get(1).context("IMAGE SYMBOLS required")?);
    let symbols = PathBuf::from(args.get(2).context("IMAGE SYMBOLS required")?);
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let job = Job::new(move |m| {
        if m.contains("复用精确匹配") {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let cache = Path::new(".zero/rust");
    let mut session = Session::default();
    let start = Instant::now();
    let prepared = session.prepare_image(&image, cache, &job)?;
    let prepare = start.elapsed().as_secs_f64();
    let mut old = Vec::new();
    let mut new = Vec::new();
    for round in 0..3 {
        for plugin in [Plugin::WinPslist, Plugin::WinModules] {
            let request = Request {
                image: &image,
                symbols: &symbols,
                choice: None,
                plugin,
                cache,
                use_cache: false,
                network: false,
            };
            let mut results = Vec::new();
            for reused in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let start = Instant::now();
                let outcome = if reused {
                    analysis::analyze(&mut session, &request, None, &Options::default(), &job)?
                } else {
                    windows::analyze(&prepared, &request, None, &Options::default(), &job)?
                };
                if reused {
                    new.push(start.elapsed().as_secs_f64());
                } else {
                    old.push(start.elapsed().as_secs_f64());
                }
                let Outcome::Ready(result) = outcome else {
                    anyhow::bail!("ambiguous symbols")
                };
                results.push(result);
            }
            ensure!(results[0] == results[1], "symbol reuse changed evidence");
        }
    }
    println!(
        "{}",
        serde_json::json!({"prepare_seconds":prepare,"standalone_seconds":old,"session_seconds":new,"symbol_cache_hits":hits.load(Ordering::Relaxed)})
    );
    Ok(())
}
