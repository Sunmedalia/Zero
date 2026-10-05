//! Compare the previous digest-then-scan read pattern with fused preparation.
use anyhow::{Result, ensure};
use std::{fs::File, path::PathBuf, time::Instant};
use zero_tui::{
    Job,
    image::{Image, digest_reader},
};
fn main() -> Result<()> {
    let path = PathBuf::from(std::env::args().nth(1).expect("IMAGE"));
    let cache = PathBuf::from(".zero/rust");
    let job = Job::default();
    let warm = Image::open(&path, &cache, &job)?;
    let expected = warm.banners(&job)?.clone();
    let digest = warm.digest.clone();
    let mut magic = [0; 2];
    std::io::Read::read_exact(&mut File::open(&path)?, &mut magic)?;
    let gzip = magic == [0x1f, 0x8b];
    let prepared = if gzip {
        cache.join(format!(
            "{}.image",
            digest_reader(File::open(&path)?, &job)?
        ))
    } else {
        path.clone()
    };
    drop(warm);
    let mut old = vec![];
    let mut new = vec![];
    for round in 0..5 {
        for fused in if round % 2 == 0 {
            [true, false]
        } else {
            [false, true]
        } {
            let start = Instant::now();
            let image = if fused {
                Image::open(&path, &cache, &job)?
            } else {
                if gzip {
                    digest_reader(File::open(&path)?, &job)?;
                }
                let hash = digest_reader(File::open(&prepared)?, &job)?;
                let image = Image::from_file(File::open(&prepared)?, hash)?;
                image.banners(&job)?;
                image
            };
            let elapsed = start.elapsed().as_secs_f64();
            ensure!(
                image.digest == digest && image.banners(&job)? == expected,
                "accuracy changed"
            );
            if fused {
                new.push(elapsed)
            } else {
                old.push(elapsed)
            };
            println!(
                "round {} {} {:.3}s",
                round + 1,
                if fused { "fused" } else { "previous" },
                elapsed
            );
        }
    }
    old.sort_by(f64::total_cmp);
    new.sort_by(f64::total_cmp);
    println!(
        "median previous {:.3}s fused {:.3}s reduction {:.1}%",
        old[2],
        new[2],
        100.0 * (old[2] - new[2]) / old[2]
    );
    Ok(())
}
