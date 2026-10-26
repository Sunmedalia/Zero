//! Generate README figures with the native application, renderer and real engine.
use anyhow::{Context, Result};
use std::path::PathBuf;
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let image = PathBuf::from(
        args.next()
            .context("usage: screenshots IMAGE SYMBOLS [OUTPUT]")?,
    );
    let symbols = PathBuf::from(args.next().context("missing SYMBOLS")?);
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("docs/assets"));
    zero_tui::tui::screenshots(&image, &symbols, &output)
}
