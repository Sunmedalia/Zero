//! VMCOREINFO notes left in memory by the running kernel (`crash_save_vmcoreinfo`).
//!
//! Only notes whose `OSRELEASE` equals the image banner's release are read, and
//! the caller accepts one only after every exported `SYMBOL()` it shares with
//! the decoded kallsyms agrees exactly. The note is text the kernel formats
//! itself: `KEY=value` lines, hex for addresses and decimal for numbers.
use crate::{Job, image::Image};
use anyhow::Result;
use std::collections::BTreeMap;

/// The kernel allocates one page for the note text.
const MAX_NOTE: usize = 4096;
pub(super) const ANCHOR: &[u8] = b"OSRELEASE=";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Vmcoreinfo {
    pub physical: u64,
    pub kernel_offset: Option<u64>,
    pub symbols: BTreeMap<String, u64>,
    pub numbers: BTreeMap<String, i64>,
}

fn parse(text: &str, release: &str, physical: u64) -> Option<Vmcoreinfo> {
    let mut lines = text.lines();
    if lines.next()?.strip_prefix("OSRELEASE=")? != release {
        return None;
    }
    let mut info = Vmcoreinfo {
        physical,
        kernel_offset: None,
        symbols: BTreeMap::new(),
        numbers: BTreeMap::new(),
    };
    let mut seen = BTreeMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if (key == "OSRELEASE"
            || key == "KERNELOFFSET"
            || key.starts_with("SYMBOL(")
            || key.starts_with("NUMBER("))
            && seen
                .insert(key, value)
                .is_some_and(|previous| previous != value)
        {
            return None;
        }
        if key == "OSRELEASE" && value != release {
            return None;
        }
        if key == "KERNELOFFSET" {
            info.kernel_offset = Some(u64::from_str_radix(value, 16).ok()?);
        } else if let Some(name) = key
            .strip_prefix("SYMBOL(")
            .and_then(|k| k.strip_suffix(')'))
        {
            info.symbols
                .insert(name.to_owned(), u64::from_str_radix(value, 16).ok()?);
        } else if let Some(name) = key
            .strip_prefix("NUMBER(")
            .and_then(|k| k.strip_suffix(')'))
        {
            // Most numbers are decimal; a few (VMALLOC_START) are printed as hex.
            let number = match value.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok().map(u64::cast_signed),
                None => value.parse().ok(),
            };
            if let Some(number) = number {
                info.numbers.insert(name.to_owned(), number);
            }
        }
    }
    Some(info)
}

/// Every distinct note for `release`, with its physical address.
pub(super) fn find(image: &Image, release: &str, job: &Job) -> Result<Vec<Vmcoreinfo>> {
    let mut out: Vec<Vmcoreinfo> = Vec::new();
    for hit in image.scan(ANCHOR, job)? {
        job.check()?;
        let Some((_, end)) = super::image_kallsyms::run(image, hit) else {
            continue;
        };
        let length = usize::try_from((end - hit).min(u64::try_from(MAX_NOTE)?))?;
        let mut bytes = vec![0; length];
        image.read(hit, &mut bytes)?;
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        let Some(text) = bytes.get(..end).and_then(|b| std::str::from_utf8(b).ok()) else {
            continue;
        };
        // A clipped final line cannot establish a complete address or offset.
        let text = if end == bytes.len() {
            text.rfind('\n')
                .and_then(|at| text.get(..=at))
                .unwrap_or("")
        } else {
            text
        };
        if let Some(info) = parse(text, release, hit)
            && !out.iter().any(|o| {
                o.kernel_offset == info.kernel_offset
                    && o.symbols == info.symbols
                    && o.numbers == info.numbers
            })
        {
            out.push(info);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_matching_release_and_exact_fields() {
        let text = "OSRELEASE=6.12.74+deb13+1-cloud-amd64\nPAGESIZE=4096\nSYMBOL(init_top_pgt)=ffffffffae622000\nNUMBER(phys_base)=-304087040\nNUMBER(pgtable_l5_enabled)=0\nKERNELOFFSET=2ba00000\n";
        let info = parse(text, "6.12.74+deb13+1-cloud-amd64", 0x1000).unwrap();
        assert_eq!(info.kernel_offset, Some(0x2ba0_0000));
        assert_eq!(info.symbols["init_top_pgt"], 0xffff_ffff_ae62_2000);
        assert_eq!(info.numbers["phys_base"], -304_087_040);
        assert!(parse(text, "6.12.74", 0).is_none());
        let hex = parse(
            "OSRELEASE=x\nNUMBER(VMALLOC_START)=0xffffcdff00000000\n",
            "x",
            0,
        )
        .unwrap();
        assert_eq!(
            hex.numbers["VMALLOC_START"].cast_unsigned(),
            0xffff_cdff_0000_0000
        );
        assert!(parse("OSRELEASE=x\nKERNELOFFSET=zz\n", "x", 0).is_none());
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use std::io::Write;

    fn image(parts: &[(u64, &[u8])]) -> Image {
        let mut file = tempfile::tempfile().unwrap();
        for (address, bytes) in parts {
            for word in [
                0x0000_0001_4c69_4d45,
                *address,
                address + bytes.len() as u64 - 1,
                0,
            ] {
                file.write_all(&word.to_le_bytes()).unwrap();
            }
            file.write_all(bytes).unwrap();
        }
        Image::from_file(file, "fixture".into()).unwrap()
    }

    #[test]
    fn clips_exactly_at_segment_end_and_crosses_only_adjacent_segments() {
        let note = b"OSRELEASE=x\nSYMBOL(init_top_pgt)=ffffffff80001000\nKERNELOFFSET=12345000\n\0";
        let cut = 19;
        for parts in [
            vec![(0x1000, note.as_slice())],
            vec![(0x1000, &note[..cut]), (0x1000 + cut as u64, &note[cut..])],
        ] {
            let found = find(&image(&parts), "x", &Job::default()).unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].kernel_offset, Some(0x12345000));
            assert_eq!(found[0].symbols["init_top_pgt"], 0xffffffff80001000);
        }
        let before_hole = b"OSRELEASE=x\nKERNELOFFSET=1234";
        let found = find(
            &image(&[(0x1000, before_hole), (0x2000, b"5000\n\0")]),
            "x",
            &Job::default(),
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].kernel_offset, None,
            "incomplete final field is ignored"
        );
    }

    #[test]
    fn conflicting_duplicate_fields_are_rejected_and_equal_values_are_allowed() {
        for fields in [
            "KERNELOFFSET=1\nKERNELOFFSET=2\n",
            "SYMBOL(x)=1\nSYMBOL(x)=2\n",
            "NUMBER(x)=1\nNUMBER(x)=2\n",
            "OSRELEASE=y\n",
        ] {
            assert!(parse(&format!("OSRELEASE=x\n{fields}"), "x", 0).is_none());
        }
        assert!(parse("OSRELEASE=x\nKERNELOFFSET=1\nKERNELOFFSET=1\n", "x", 0).is_some());
    }
}
