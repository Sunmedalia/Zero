//! Bounded, read-only file picker; selection never copies or deletes evidence.
use anyhow::{Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    Images,
    Symbols,
    Exports,
    Directories,
}
#[derive(Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub directory: bool,
}
pub fn entries(root: &Path, filter: Filter) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for (index, entry) in fs::read_dir(root)?.enumerate() {
        let entry = entry?;
        ensure!(index < 10000, "目录超过 10000 项，请选择更具体的目录");
        let path = entry.path();
        let metadata = fs::metadata(&path)?;
        let directory = metadata.is_dir();
        let name = entry.file_name().to_string_lossy().to_lowercase();
        let keep = directory
            || metadata.is_file()
                && match filter {
                    Filter::Images => [".raw", ".bin", ".lime", ".mem", ".dump", ".gz"]
                        .iter()
                        .any(|s| name.ends_with(s)),
                    Filter::Symbols => {
                        [".json", ".json.xz", ".zip"]
                            .iter()
                            .any(|s| name.ends_with(s))
                            && !name.ends_with(".source.json")
                            && name != "banners_plain.json"
                    }
                    Filter::Exports => {
                        (name.ends_with(".csv") || name.ends_with(".json"))
                            && !name.ends_with(".source.json")
                    }
                    Filter::Directories => false,
                };
        if keep {
            entries.push(Entry { path, directory });
        }
    }
    entries.sort_by(|a, b| {
        b.directory
            .cmp(&a.directory)
            .then_with(|| a.path.file_name().cmp(&b.path.file_name()))
    });
    Ok(entries)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directories_first_and_sidecars_are_not_symbols() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("nested"))?;
        for name in ["one.raw", "one.json.xz", "one.source.json", "one.csv"] {
            fs::write(dir.path().join(name), b"")?;
        }
        for filter in [Filter::Images, Filter::Symbols, Filter::Exports] {
            let entries = entries(dir.path(), filter)?;
            assert_eq!(entries.len(), 2);
            assert!(entries[0].directory);
        }
        Ok(())
    }
}
