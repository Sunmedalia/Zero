//! Bounded, read-only file picker; selection never copies or deletes evidence.
use anyhow::{Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    Files,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Image,
    Symbols,
    Other,
}
pub fn file_kind(path: &Path) -> FileKind {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    if [".json", ".json.xz", ".zip"]
        .iter()
        .any(|s| name.ends_with(s))
        && !name.ends_with(".source.json")
        && !name.starts_with("banners_plain")
    {
        FileKind::Symbols
    } else if [
        ".raw", ".bin", ".lime", ".avml", ".mem", ".dump", ".gz", ".zst", ".xz", ".dmp", ".vmem",
        ".vmsn", ".vmss", ".vmsst", ".elf", ".core", ".img",
    ]
    .iter()
    .any(|s| name.ends_with(s))
    {
        FileKind::Image
    } else {
        FileKind::Other
    }
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
                    Filter::Files => true,
                    Filter::Images => {
                        !name.ends_with(".json.xz")
                            && [
                                ".raw", ".bin", ".lime", ".avml", ".mem", ".dump", ".gz", ".zst",
                                ".xz", ".dmp", ".vmem", ".vmsn", ".vmss", ".vmsst", ".elf",
                                ".core", ".img",
                            ]
                            .iter()
                            .any(|s| name.ends_with(s))
                    }
                    Filter::Symbols => {
                        [".json", ".json.xz", ".zip"]
                            .iter()
                            .any(|s| name.ends_with(s))
                            && !name.ends_with(".source.json")
                            && !name.starts_with("banners_plain")
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
    #[test]
    fn linux_sample_and_zip_are_supported_by_directory_filters() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("linux-sample-1.bin.gz"), b"")?;
        fs::write(dir.path().join("linux.zip"), b"")?;
        let images = entries(dir.path(), Filter::Images)?;
        let symbols = entries(dir.path(), Filter::Symbols)?;
        assert_eq!(images.len(), 1);
        assert!(images[0].path.ends_with("linux-sample-1.bin.gz"));
        assert_eq!(symbols.len(), 1);
        assert!(symbols[0].path.ends_with("linux.zip"));
        Ok(())
    }
    #[test]
    fn virtualization_and_compressed_formats_are_classified_as_images() -> Result<()> {
        let dir = tempfile::tempdir()?;
        for name in [
            "guest.elf",
            "guest.core",
            "vm.vmem",
            "vm.vmsn",
            "vm.vmss",
            "vm.vmsst",
            "cloud.avml",
            "dump.raw.zst",
            "dump.raw.xz",
        ] {
            let path = dir.path().join(name);
            fs::write(&path, b"")?;
            assert_eq!(file_kind(&path), FileKind::Image, "{name}");
        }
        let isf = dir.path().join("kernel.json.xz");
        fs::write(&isf, b"")?;
        assert_eq!(file_kind(&isf), FileKind::Symbols);
        let images = entries(dir.path(), Filter::Images)?;
        assert_eq!(images.len(), 9);
        assert!(!images.iter().any(|e| e.path.ends_with("kernel.json.xz")));
        Ok(())
    }
}
