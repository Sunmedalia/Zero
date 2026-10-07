use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use zero_tui::{
    Job,
    analysis::{self, Options},
    linux::{self, Outcome, Plugin},
    store, windows_symbols,
};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let image = PathBuf::from(args.get(1).context("image")?);
    let prefix = args.get(2).context("output prefix")?;
    let selected: Option<Vec<Plugin>> = args
        .get(3)
        .map(|list| {
            list.split(',')
                .map(|name| {
                    <Plugin as clap::ValueEnum>::from_str(name, true).map_err(anyhow::Error::msg)
                })
                .collect::<Result<_>>()
        })
        .transpose()?;
    let job = Job::new(|s| eprintln!("{s}"));
    let cache = Path::new(".zero/rust");
    let mut session = linux::Session::default();
    let image_prepared = session.prepare_image(&image, cache, &job)?;
    let symbols = args.get(4).map(Path::new).unwrap_or(Path::new("symbols"));
    let isfs = windows_symbols::resolve(symbols, &image_prepared, cache, true, &job)?;
    let symbol = isfs
        .iter()
        .find(|s| {
            windows_symbols::PdbIdentity::from_isf(s).is_ok_and(|i| {
                matches!(
                    i.name.as_str(),
                    "ntkrnlmp.pdb" | "ntoskrnl.pdb" | "ntkrnlpa.pdb" | "ntkrpamp.pdb"
                )
            })
        })
        .context("exact kernel symbols")?;
    let mut failures = Vec::new();
    for descriptor in linux::PLUGINS.iter().filter(|d| {
        selected
            .as_ref()
            .is_none_or(|plugins| plugins.contains(&d.plugin))
            && d.plugin.is_windows()
            && !d.plugin.is_dump()
            && d.plugin != Plugin::WinPrintkey
            && (d.plugin != Plugin::WinCrashinfo || image_prepared.windows_container.is_some())
    }) {
        let request = linux::Request {
            image: &image,
            symbols: Path::new(&symbol.label),
            choice: Some(&symbol.label),
            plugin: descriptor.plugin,
            cache,
            use_cache: false,
            network: false,
        };
        match analysis::analyze(&mut session, &request, None, &Options::default(), &job) {
            Ok(Outcome::Ready(result)) => {
                store::export_rows(
                    Path::new(&format!("{prefix}{}.json", descriptor.name)),
                    &result,
                    result.rows.iter(),
                    &job,
                )?;
                eprintln!(
                    "RESULT {} rows={} complete={} diagnostics={}",
                    descriptor.name,
                    result.rows.len(),
                    result.complete,
                    result.diagnostics.len()
                );
            }
            Ok(_) => anyhow::bail!("ambiguous"),
            Err(e) => {
                eprintln!("FAILED {}: {e:#}", descriptor.name);
                failures.push(descriptor.name);
            }
        }
    }
    anyhow::ensure!(failures.is_empty(), "failed plugins: {failures:?}");
    Ok(())
}
