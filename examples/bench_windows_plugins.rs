//! Locate Windows analysis-engine hot spots on a real image.
//!
//!   bench_windows_plugins IMAGE SYMBOLS [ROUNDS]
//!
//! Prints the median wall time of every Windows plugin. Symbol preparation is
//! excluded by preparing the image first, so the numbers describe plugin work
//! rather than PDB conversion.
use anyhow::Result;
use std::{path::Path, path::PathBuf, time::Instant};
use zero_tui::{
    Job,
    analysis::{self, Options},
    linux::{Outcome, PLUGINS, Request, Session},
};

fn main() -> Result<()> {
    let image = PathBuf::from(std::env::args().nth(1).expect("IMAGE"));
    let symbols = PathBuf::from(std::env::args().nth(2).expect("SYMBOLS"));
    let rounds: usize = std::env::args()
        .nth(3)
        .and_then(|n| n.parse().ok())
        .unwrap_or(3);
    // Optional filter: only run plugins whose name contains this substring.
    let filter = std::env::args().nth(4).unwrap_or_default();
    let cache = Path::new(".zero/rust");
    let job = Job::default();
    let mut session = Session::default();
    let start = Instant::now();
    session.prepare_image(&image, cache, &job)?;
    println!("prepare_image = {:?}\n", start.elapsed());
    let mut rows = Vec::new();
    for d in PLUGINS.iter().filter(|d| {
        d.plugin.is_windows()
            && !d.plugin.is_dump()
            && (filter.is_empty() || d.plugin.name().contains(&filter))
    }) {
        let request = Request {
            image: &image,
            symbols: &symbols,
            choice: None,
            plugin: d.plugin,
            cache,
            use_cache: false,
            network: false,
        };
        let mut times = Vec::new();
        let mut count = 0;
        let mut failed = false;
        for _ in 0..rounds {
            let start = Instant::now();
            let outcome =
                analysis::analyze(&mut session, &request, None, &Options::default(), &job);
            times.push(start.elapsed());
            match outcome {
                Ok(Outcome::Ready(r)) => count = r.rows.len(),
                _ => failed = true,
            }
        }
        times.sort();
        let median = times[times.len() / 2];
        let min = times[0];
        rows.push((median, min, d.plugin.name(), count, failed));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).reverse());
    for (median, min, name, count, failed) in rows {
        let note = if failed { " (needs symbols)" } else { "" };
        println!("{median:>10.2?} median {min:>10.2?} min  {name:<24} {count} rows{note}");
    }
    Ok(())
}
