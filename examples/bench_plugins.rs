//! Locate analysis-engine hot spots on a real image.
//!
//!   bench_plugins IMAGE SYMBOLS [ROUNDS]
//!
//! Prints the median wall time of every Linux plugin, then the cost of the
//! per-field read path that each plugin row pays for. Timings are indicative:
//! the first plugin also absorbs symbol loading, which is why the median of
//! several rounds is reported.
use anyhow::Result;
use std::{path::PathBuf, time::Instant};
use zero_tui::{
    Job,
    image::{Image, VirtualMemory},
    linux::{self, Outcome, PLUGINS, Request, discover},
    symbols,
};

fn main() -> Result<()> {
    let image = PathBuf::from(std::env::args().nth(1).expect("IMAGE"));
    let symbol_path = PathBuf::from(std::env::args().nth(2).expect("SYMBOLS"));
    let rounds: usize = std::env::args()
        .nth(3)
        .and_then(|n| n.parse().ok())
        .unwrap_or(3);
    let cache = PathBuf::from(".zero/rust");
    let job = Job::default();
    let mut session = linux::Session::default();
    let mut rows = Vec::new();
    for d in PLUGINS
        .iter()
        .filter(|d| !d.plugin.is_windows() && !d.plugin.is_dump())
    {
        let request = Request {
            image: &image,
            symbols: &symbol_path,
            choice: None,
            plugin: d.plugin,
            cache: &cache,
            use_cache: false,
            network: false,
        };
        let mut times = Vec::new();
        let mut count = 0;
        for _ in 0..rounds {
            let start = Instant::now();
            let outcome = session.analyze(&request, &job);
            times.push(start.elapsed());
            if let Ok(Outcome::Ready(r)) = &outcome {
                count = r.rows.len();
            }
        }
        times.sort();
        rows.push((times[times.len() / 2], d.plugin.name(), count));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).reverse());
    for (elapsed, name, count) in rows {
        println!("{elapsed:>12.2?}  {name:<20} {count} rows");
    }

    // Cost of one object field read, the unit every plugin row is built from.
    let img = Image::open(&image, &cache, &job)?;
    let isf = symbols::matching(&symbol_path, &img, &job)?
        .into_iter()
        .next()
        .expect("one exact ISF");
    let root = discover(&img, &isf, &job)?;
    let vm = VirtualMemory::new(&img, root);
    let va = isf.address("init_task")?;
    let n = 200_000;
    let start = Instant::now();
    for _ in 0..n {
        std::hint::black_box(vm.uint(va, 8)?);
    }
    println!("\nvm.uint              = {:?}", start.elapsed() / n);
    let start = Instant::now();
    for _ in 0..n {
        std::hint::black_box(vm.translate(va)?);
    }
    println!("vm.translate         = {:?}", start.elapsed() / n);
    let start = Instant::now();
    for _ in 0..n {
        std::hint::black_box(isf.layout("vm_area_struct", "vm_start")?);
    }
    println!("isf.layout (cached)  = {:?}", start.elapsed() / n);
    Ok(())
}
