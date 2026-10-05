//! Read-only sample validation and performance measurements; outputs stay in /tmp.
use anyhow::{Result, ensure};
use std::{path::PathBuf, time::Instant};
use zero_tui::{
    Job,
    image::Image,
    linux::{Outcome, PLUGINS, Plugin, Request, Session},
    store,
};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: verify_samples IMAGE SYMBOLS OUTPUT_PREFIX"
    );
    let image = PathBuf::from(&args[1]);
    let symbols = PathBuf::from(&args[2]);
    let cache = PathBuf::from(".zero/rust");
    let job = Job::default();
    let mut session = Session::default();
    let started = Instant::now();
    let prepared = session.prepare_image(&image, &cache, &job)?;
    println!(
        "prepare {:.3}s sha256 {}",
        started.elapsed().as_secs_f64(),
        prepared.digest
    );
    drop(prepared);
    for descriptor in PLUGINS {
        let started = Instant::now();
        match session.analyze(
            &Request {
                image: &image,
                symbols: &symbols,
                choice: None,
                plugin: descriptor.plugin,
                cache: &cache,
                use_cache: false,
                network: false,
            },
            &job,
        ) {
            Ok(Outcome::Ready(result)) => {
                store::export(
                    &PathBuf::from(format!("{}{}.json", args[3], descriptor.name)),
                    &result,
                    result.rows.clone(),
                )?;
                println!(
                    "{} {} complete={} diagnostics={} {:.3}s",
                    descriptor.name,
                    result.rows.len(),
                    result.complete,
                    result.diagnostics.len(),
                    started.elapsed().as_secs_f64()
                );
            }
            Ok(Outcome::Choose(_)) => anyhow::bail!("ambiguous symbols"),
            Err(e) => println!("{} unsupported/failure: {e:#}", descriptor.name),
        }
    }
    drop(session);
    let mut times = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        let prepared = Image::open(&image, &cache, &job)?;
        println!(
            "reopen {:.3}s {} banners",
            started.elapsed().as_secs_f64(),
            prepared.banners(&job)?.len()
        );
        times.push(started.elapsed().as_secs_f64());
    }
    times.sort_by(f64::total_cmp);
    println!("reopen median {:.3}s", times[2]);
    let mut session = Session::default();
    session.analyze(
        &Request {
            image: &image,
            symbols: &symbols,
            choice: None,
            plugin: Plugin::Pslist,
            cache: &cache,
            use_cache: false,
            network: false,
        },
        &job,
    )?;
    let started = Instant::now();
    session.analyze(
        &Request {
            image: &image,
            symbols: &symbols,
            choice: None,
            plugin: Plugin::Pslist,
            cache: &cache,
            use_cache: false,
            network: false,
        },
        &job,
    )?;
    println!(
        "same-session pslist {:.3}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
