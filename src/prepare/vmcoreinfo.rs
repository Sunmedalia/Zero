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
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
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
    for hit in image.scan(b"OSRELEASE=", job)? {
        job.check()?;
        let mut bytes = vec![0; MAX_NOTE];
        // Clip a note at the end of a segment instead of skipping it.
        let mut length = MAX_NOTE;
        while length > 0
            && image
                .read(hit, bytes.get_mut(..length).unwrap_or_default())
                .is_err()
        {
            length /= 2;
        }
        bytes.truncate(length);
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        let Some(text) = bytes.get(..end).and_then(|b| std::str::from_utf8(b).ok()) else {
            continue;
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
