//! Volatility-compatible Linux injected-code detector (`linux.malware.malfind.Malfind`).
use super::*;
use crate::analysis::Options;
use crate::bytes::JsonKey as _;
use crate::dump::DumpOptions;
use capstone::prelude::*;
use std::collections::BTreeSet;

pub(super) const MALFIND_HEXDUMP_DEFAULT: usize = 64;
const MALFIND_HEXDUMP_MAX: usize = 4096;
const MALFIND_DIRTY_PAGES_LIMIT: usize = 4096;

fn format_hexdump(base: u64, bytes: &[u8]) -> String {
    let mut lines = Vec::new();
    for (idx, chunk) in bytes.chunks(16).enumerate() {
        let addr = base.saturating_add((idx * 16) as u64);
        let hex_part = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..=0x7e).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        lines.push(format!("{addr:#018x}  {hex_part:<47}  |{ascii}|"));
    }
    lines.join("\n")
}

fn disassemble_bytes(base: u64, bytes: &[u8], arm64: bool, ptr_size: usize) -> String {
    if bytes.is_empty() || arm64 {
        return String::new();
    }
    let cs = if ptr_size == 4 {
        Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode32)
            .build()
    } else {
        Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .build()
    };
    let Ok(cs) = cs else {
        return String::new();
    };
    let Ok(insns) = cs.disasm_all(bytes, base) else {
        return String::new();
    };
    insns
        .iter()
        .map(|i| {
            let mnem = i.mnemonic().unwrap_or("");
            let ops = i.op_str().unwrap_or("");
            if ops.is_empty() {
                format!("{:#x}: {mnem}", i.address())
            } else {
                format!("{:#x}: {mnem} {ops}", i.address())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

impl Linux<'_> {
    pub(super) fn linux_malfind(
        &self,
        options: &Options,
        dump: Option<&DumpOptions>,
        job: &Job,
    ) -> Result<Results> {
        self.require(&[
            ("task_struct", "mm"),
            (
                "mm_struct",
                if self.isf.field("mm_struct", "mmap").is_ok() {
                    "mmap"
                } else {
                    "mm_mt"
                },
            ),
            ("vm_area_struct", "vm_start"),
            ("vm_area_struct", "vm_end"),
            ("vm_area_struct", "vm_flags"),
            ("vm_area_struct", "vm_file"),
        ])?;

        let arm64 = self
            .vm
            .image
            .arm64_va_bits
            .load(std::sync::atomic::Ordering::Relaxed)
            != 0;
        let ptr_size = usize::try_from(
            self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .unwrap_or(8),
        )?;
        let hexdump_size = options
            .hexdump_size
            .unwrap_or(MALFIND_HEXDUMP_DEFAULT)
            .min(MALFIND_HEXDUMP_MAX);
        let max_dump = match options.maxsize {
            Some(v) if v <= 0 => 0,
            Some(v) => u64::try_from(v)?.min(crate::dump::MAX_DUMP_BYTES),
            None => crate::dump::MAX_DUMP_BYTES,
        };

        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.task_identities(Plugin::LinuxMalfind, job)?;

        for task in tasks {
            job.check()?;
            if !pids.is_empty() && !task.pid.parse::<u32>().is_ok_and(|pid| pids.contains(&pid)) {
                continue;
            }
            let addr = task.address;
            let read = (|| -> Result<()> {
                let mm = self.number(addr, "task_struct", "mm")?;
                if mm == 0 {
                    return Ok(());
                }
                let Some(vm) = self.process_vm(addr)? else {
                    return Ok(());
                };
                let nodes = self.vma_nodes(mm, job, &mut result)?;
                let root = self.process_root(addr).ok();
                let vdso = self.number(mm, "mm_struct", "context.vdso").ok();

                for node in nodes {
                    job.check()?;
                    let scan = (|| -> Result<()> {
                        let start = self.number(node, "vm_area_struct", "vm_start")?;
                        let end = self.number(node, "vm_area_struct", "vm_end")?;
                        ensure!(start < end, "VMA 地址倒置");
                        let flags = self.number(node, "vm_area_struct", "vm_flags")?;
                        let file = self.number(node, "vm_area_struct", "vm_file")?;

                        // Volatility 3 Malfind heuristic: executable AND (writable OR anonymous),
                        // skipping known kernel vDSO mappings.
                        let is_exec = flags & 4 != 0;
                        let is_write = flags & 2 != 0;
                        if !is_exec || (!is_write && file != 0) {
                            return Ok(());
                        }
                        if file == 0 && vdso.is_some_and(|v| v != 0 && v == start) {
                            return Ok(());
                        }

                        let path = if file == 0 {
                            "Anonymous Mapping".into()
                        } else {
                            match root.map_or_else(
                                || self.file_path(addr, file, job),
                                |root| self.file_path_from(root, file, job),
                            ) {
                                Ok(p) => p,
                                Err(error) => {
                                    job.check()?;
                                    partial(
                                        &mut result,
                                        format!("PID {} VMA {} 路径", task.pid, hex(node)),
                                        error,
                                    );
                                    "[unresolved]".into()
                                }
                            }
                        };
                        let prot = permissions(flags);

                        // Inspect resident pages for non-zero bytes.
                        let mut regions: Vec<(u64, u64, Vec<u8>)> = Vec::new();
                        let mut page = start & !0xfff;
                        let mut checked = 0usize;
                        let mut page_buf = [0u8; 4096];
                        while page < end && checked < MALFIND_DIRTY_PAGES_LIMIT {
                            job.check()?;
                            checked += 1;
                            let seg_start = page.max(start);
                            let seg_end = page.saturating_add(4096).min(end);
                            let take = usize::try_from(seg_end - seg_start)?;
                            let slice = page_buf.at_mut(..take)?;
                            if vm.read(seg_start, slice).is_ok() && slice.iter().any(|&b| b != 0) {
                                let preview = slice.at(..take.min(hexdump_size))?.to_vec();
                                if options.show_all_dirty_pages {
                                    regions.push((seg_start, seg_end, preview));
                                } else {
                                    regions.push((start, end, preview));
                                    break;
                                }
                            }
                            page = page.saturating_add(4096);
                        }

                        for (reg_start, reg_end, preview) in regions {
                            let hexdump = format_hexdump(reg_start, &preview);
                            let disasm = disassemble_bytes(reg_start, &preview, arm64, ptr_size);
                            let file_output = if let Some(dump) = dump {
                                let size = reg_end - reg_start;
                                if size > max_dump {
                                    "Error outputting file".into()
                                } else {
                                    match self.dump_vma_region(
                                        &vm,
                                        &task.pid,
                                        reg_start,
                                        reg_end,
                                        dump,
                                        &mut result,
                                        job,
                                    ) {
                                        Ok(name) => name,
                                        Err(error) => {
                                            job.check()?;
                                            partial(
                                                &mut result,
                                                format!(
                                                    "PID {} Malfind {} 导出",
                                                    task.pid,
                                                    hex(reg_start)
                                                ),
                                                error,
                                            );
                                            "Error outputting file".into()
                                        }
                                    }
                                }
                            } else {
                                "Disabled".into()
                            };

                            result.rows.push(vec![
                                task.pid.clone(),
                                task.name.clone(),
                                hex(reg_start),
                                hex(reg_end),
                                path.clone(),
                                prot.clone(),
                                hexdump,
                                disasm,
                                file_output,
                            ]);
                        }
                        Ok(())
                    })();
                    if let Err(error) = scan {
                        job.check()?;
                        partial(
                            &mut result,
                            format!("PID {} VMA {}", task.pid, hex(node)),
                            error,
                        );
                    }
                }
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(
                    &mut result,
                    format!("PID {} @ {}", task.pid, hex(addr)),
                    error,
                );
            }
            job.report(format!(
                "linux.malware.malfind.Malfind: {} 条",
                result.rows.len()
            ));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};

    fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn linux_malfind_detects_rwx_code_disassembles_and_supports_dirty_pages() {
        let (mut b, isf) = fixture();
        // init_task 0x9000 -> task 0xa000 (pid=1, "evil")
        put(&mut b, 0x9000, 0xa000);
        put(&mut b, 0x9008, 0xa000);
        put(&mut b, 0xa000, 0x9000);
        put(&mut b, 0xa008, 0x9000);
        put(&mut b, 0xa010, 1);
        put(&mut b, 0xa018, 1);
        put(&mut b, 0xa020, 0x9000);
        b[0xa028..0xa030].copy_from_slice(b"evil\0\0\0\0");
        put(&mut b, 0xa030, 0xb000); // mm

        // mm at 0xb000: pgd=0x4000, mmap=0xc000
        put(&mut b, 0xb000, 0x4000);
        put(&mut b, 0xb028, 0xc000);

        // VMA [0x200000, 0x202000): rwxp anonymous (2 resident pages at phys 0x20000 & 0x25000)
        put(&mut b, 0xc000, 0);
        put(&mut b, 0xc008, 0x200000);
        put(&mut b, 0xc010, 0x202000);
        put(&mut b, 0xc018, 7); // rwxp
        put(&mut b, 0xc020, 0);
        put(&mut b, 0xc028, 0); // anonymous

        // Put x86_64 instructions on both pages: nop (0x90), ret (0xc3)
        b[0x20000] = 0x90;
        b[0x20001] = 0xc3;
        b[0x25000] = 0x90;
        b[0x25001] = 0xc3;

        let img = image(&b);
        let linux = engine(&img, &isf);

        let default = linux
            .linux_malfind(
                &Options {
                    hexdump_size: Some(16),
                    ..Default::default()
                },
                None,
                &Job::default(),
            )
            .unwrap();
        assert!(default.complete, "{:?}", default.diagnostics);
        assert_eq!(default.rows.len(), 1);
        assert_eq!(default.rows[0][0], "1");
        assert_eq!(default.rows[0][4], "Anonymous Mapping");
        assert_eq!(default.rows[0][5], "rwxp");
        assert!(default.rows[0][6].contains("90 c3"));
        assert!(default.rows[0][7].contains("nop"));
        assert!(default.rows[0][7].contains("ret"));
        assert_eq!(default.rows[0][8], "Disabled");

        let all_pages = linux
            .linux_malfind(
                &Options {
                    hexdump_size: Some(16),
                    show_all_dirty_pages: true,
                    ..Default::default()
                },
                None,
                &Job::default(),
            )
            .unwrap();
        assert_eq!(all_pages.rows.len(), 2);
        assert_eq!(all_pages.rows[0][2], "0x0000000000200000");
        assert_eq!(all_pages.rows[1][2], "0x0000000000201000");
    }
}
