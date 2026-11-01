//! Read policy of the pinned Windows Intel layers, without native prototype/store recovery.
use super::*;
use crate::bytes::Checked as _;

impl Memory<'_> {
    pub(super) fn scan_reference(
        &self,
        regex: &crate::byte_regex::ByteRegex,
        regions: &[(u64, u64)],
        budget: &mut crate::regex_scan::Budget,
        job: &Job,
        visit: impl FnMut(u64) -> Result<bool>,
    ) -> Result<crate::regex_scan::Coverage> {
        use crate::intel_scan::{Kind, Mapper};
        let geometry = self.paging()?;
        if geometry.arch == Architecture::Arm64 {
            return crate::regex_scan::scan_sparse(
                regex,
                regions,
                budget,
                job,
                |at, out| self.read(at, out),
                visit,
                |at, end| self.absent_end(at, end),
            );
        }
        let kind = if geometry.arch == Architecture::X64 {
            Kind::Windows64
        } else if geometry.pae {
            Kind::WindowsPae
        } else {
            Kind::Windows32
        };
        let mapper = std::cell::RefCell::new(Mapper::new(self.image, self.root, kind));
        crate::regex_scan::scan_mapped(
            regex,
            regions,
            budget,
            job,
            |start, end| {
                mapper
                    .borrow_mut()
                    .mappings(start, end, job, |index, offset, size| {
                        self.sources
                            .is_some_and(|s| s.mapping_valid(index, offset, size))
                    })
                    .map(|maps| maps.into_iter().map(|m| (m.start, m.end)).collect())
            },
            |at, out| {
                mapper.borrow_mut().read(at, out, |index, offset, bytes| {
                    self.sources
                        .context("未附加分页文件")?
                        .read(index, offset, bytes)
                })
            },
            visit,
        )
    }

    fn reference_swap(&self, va: u64) -> Result<(u8, u64, u64)> {
        let geometry = self.paging()?;
        let va = geometry.translation_address(va);
        let mut table = self.root & geometry.root_mask();
        for (level, &shift) in geometry.shifts().iter().enumerate() {
            let index = usize::try_from((va >> shift) & (geometry.entries(level) as u64 - 1))?;
            let mut entry = self.captured_table_entry(geometry, table, index)?;
            // Intel._translate_entry clears a large descriptor's PAT bit even
            // before deciding whether that descriptor is valid or swapped.
            if geometry.block(entry, shift) {
                entry &= !(1 << 12);
            }
            let valid = entry & 1 != 0 || entry & (1 << 11) != 0 && entry & (1 << 10) == 0;
            if !valid {
                // WindowsMixin._translate_swap uses fixed bits, not the ISF software PTE.
                ensure!(
                    entry & ((1 << 11) | (1 << 10) | 1) == 0 && entry & (1 << 7) != 0,
                    "参考 Intel 层不读取此软件／prototype PTE"
                );
                let bit_offset = if geometry.arch == Architecture::X86 && !geometry.pae {
                    12
                } else {
                    32
                };
                let page = entry >> bit_offset;
                ensure!(page != 0 && page <= u64::MAX >> shift, "参考分页偏移无效");
                // The pinned method deliberately returns this base without the VA's
                // low bits. Preserve actual layer.read behavior for unaligned calls.
                return Ok((
                    ((entry >> 1) & 15) as u8,
                    page << shift,
                    (1u64 << shift) - (va & ((1u64 << shift) - 1)),
                ));
            }
            ensure!(!geometry.block(entry, shift), "参考分页路径遇到驻留大页");
            table = entry & geometry.mask();
        }
        bail!("参考分页路径没有软件 PTE")
    }

    pub(super) fn read_reference(&self, mut va: u64, mut out: &mut [u8]) -> Result<()> {
        // The pinned reference does not offer a Windows ARM64 layer; retain the
        // native ARM64 reader without treating it as reference parity evidence.
        if self.paging()?.arch == Architecture::Arm64 {
            return self.read(va, out);
        }
        if !out.is_empty() {
            va.checked_add(out.len() as u64 - 1)
                .context("Windows 读取越界")?;
        }
        while !out.is_empty() {
            let n = match self.translate_span(va) {
                Ok((physical, available)) => {
                    let n = usize::try_from(available.min(out.len() as u64))?;
                    self.image.read(physical, out.at_mut(..n)?)?;
                    n
                }
                Err(original) => {
                    let (file, offset, available) = self
                        .reference_swap(va)
                        .with_context(|| format!("{original:#}"))?;
                    let n = usize::try_from(available.min(out.len() as u64))?;
                    self.sources.context("参考 Intel 层未附加分页文件")?.read(
                        file,
                        offset,
                        out.at_mut(..n)?,
                    )?;
                    n
                }
            };
            out = out.at_mut(n..)?;
            if !out.is_empty() {
                va = add(va, n as u64)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::tests::{fixture, image};
    use serde_json::{Value, json};

    #[test]
    fn reads_match_actual_pinned_intel_and_swap_layers() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/windows-layer-read.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let (_, mut isf) = fixture();
            let width = case["width"].as_u64().unwrap() as usize;
            let x86 = case["arch"] != "x64";
            isf.data["base_types"]["pointer"]["size"] = json!(if x86 { 4 } else { 8 });
            isf.data["metadata"]["windows"]["pdb"]["machine_type"] =
                json!(if x86 { 0x14c } else { 0x8664 });
            isf.data["metadata"]["windows"]["paging"] = json!(if case["arch"] == "pae" {
                "pae"
            } else {
                "normal"
            });
            isf.invalidate_layouts();
            let mut bytes = vec![0u8; 0x20000];
            for write in case["writes"].as_array().unwrap() {
                let at = write[0].as_u64().unwrap() as usize;
                let value = write[1].as_u64().unwrap().to_le_bytes();
                bytes[at..at + width].copy_from_slice(&value[..width]);
            }
            for (at, byte) in bytes.iter_mut().enumerate().take(0xc000).skip(0x8000) {
                *byte = ((at * 17 + 3) % 251) as u8;
            }
            let mut image = image(&bytes);
            image.segments.clear();
            let mut start = 0;
            for hole in case["holes"].as_array().unwrap() {
                let end = hole[0].as_u64().unwrap();
                if end > start {
                    image.segments.push(crate::image::Segment {
                        start,
                        end,
                        file_offset: start,
                    });
                }
                start = hole[1].as_u64().unwrap();
            }
            image.segments.push(crate::image::Segment {
                start,
                end: bytes.len() as u64,
                file_offset: start,
            });
            let directory = tempfile::tempdir().unwrap();
            let mut options = Options::default();
            if let Some(index) = case["attached"].as_u64() {
                let data: Vec<u8> = (0..case["pagefile_length"].as_u64().unwrap())
                    .map(|at| ((at * 13 + 7) % 251) as u8)
                    .collect();
                let path = directory.path().join("pagefile.sys");
                std::fs::write(&path, data).unwrap();
                options.pagefiles.push(paging::Attachment {
                    index: index as u8,
                    path,
                });
            }
            let sources = paging::Sources::open(&options, &Job::default()).unwrap();
            let vm = Memory::new(&image, 0x1000, &isf, Some(&sources));
            for query in case["queries"].as_array().unwrap() {
                let mut output = vec![0u8; query["length"].as_u64().unwrap() as usize];
                let actual = vm.read_reference(query["address"].as_u64().unwrap(), &mut output);
                if query["error"].is_null() {
                    actual.unwrap_or_else(|e| panic!("{} {query}: {e:#}", case["id"]));
                    let encoded: String = output.iter().map(|byte| format!("{byte:02x}")).collect();
                    assert_eq!(
                        encoded,
                        query["expected_hex"].as_str().unwrap(),
                        "{} {query}",
                        case["id"]
                    );
                } else {
                    assert!(actual.is_err(), "{} {query}", case["id"]);
                }
            }
        }
    }
}
