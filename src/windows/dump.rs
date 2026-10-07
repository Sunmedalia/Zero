use super::*;
use sha2::{Digest, Sha256};
use std::io::Write;
impl Windows<'_> {
    pub(super) fn run_dump(&self, p: Plugin, options: &DumpOptions, job: &Job) -> Result<Results> {
        options.validate(p)?;
        let (processes, diagnostics) = self.processes_partial(job)?;
        let process = processes
            .into_iter()
            .find(|p| p.pid == u64::from(options.pid))
            .context("目标 PID 不存在")?;
        let vm = self.process_memory(&process)?;
        let mut r = self.result(p);
        r.complete = diagnostics.is_empty();
        r.diagnostics = diagnostics;
        let mut regions = if p == Plugin::WinMemdump {
            vec![(
                options.start.context("range 需要 start")?,
                options.end.context("range 需要 end")?,
            )]
        } else {
            self.vads(&process, job)?
                .into_iter()
                .filter(|v| v.protection & 7 != 0)
                .map(|v| (v.start, v.end))
                .collect()
        };
        if p == Plugin::WinProcdump
            && let (Some(start), Some(end)) = (options.start, options.end)
        {
            regions = regions
                .into_iter()
                .filter_map(|(a, b)| {
                    let a = a.max(start);
                    let b = b.min(end);
                    (a < b).then_some((a, b))
                })
                .collect();
        }
        if p == Plugin::WinPedump {
            let mut candidates: BTreeMap<u64, u64> = regions.into_iter().collect();
            match self.dlls(&process, job, &mut r) {
                Ok(dlls) => {
                    for (base, size, _, _) in dlls {
                        candidates.insert(base, add(base, size)?);
                    }
                }
                Err(e) => Self::issue(&mut r, "DLL 转储候选", e),
            }
            regions = candidates.into_iter().collect();
        }
        crate::dump::directory(&options.directory)?;
        let mut total = 0u64;
        for (start, end) in regions {
            job.check()?;
            if p == Plugin::WinPedump {
                let mut magic = [0; 2];
                if vm.read(start, &mut magic).is_err() || magic != *b"MZ" {
                    continue;
                }
            }
            let read = (|| -> Result<Vec<String>> {
                let mut tmp = tempfile::NamedTempFile::new_in(&options.directory)?;
                let mut hash = Sha256::new();
                let size = if p == Plugin::WinPedump {
                    self.write_pe(&vm, start, &mut tmp, &mut hash, job)?
                } else {
                    let size = end.checked_sub(start).context("转储地址倒置")?;
                    ensure!(
                        total
                            .checked_add(size)
                            .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
                        "转储超过 256 MiB 限制"
                    );
                    write_region(&vm, start, size, &mut tmp, &mut hash, job)?;
                    size
                };
                ensure!(
                    total
                        .checked_add(size)
                        .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
                    "转储超过 256 MiB 限制"
                );
                job.check()?;
                tmp.as_file().sync_all()?;
                let digest = format!("{:x}", hash.finalize());
                let target = options.directory.join(format!(
                    "windows-pid{}-{start:016x}-{}.{}",
                    process.pid,
                    &digest[..16],
                    if p == Plugin::WinPedump { "pe" } else { "bin" }
                ));
                if target.exists() {
                    ensure!(
                        std::fs::read(&target)? == std::fs::read(tmp.path())?,
                        "已有同名转储内容不同"
                    );
                } else {
                    tmp.persist(&target).map_err(|e| e.error)?;
                }
                total += size;
                Ok(vec![
                    process.pid.to_string(),
                    process.name.clone(),
                    hex(start),
                    hex(end),
                    size.to_string(),
                    digest,
                    target.display().to_string(),
                ])
            })();
            match read {
                Ok(row) => r.rows.push(row),
                Err(e) => {
                    job.check()?;
                    Self::issue(
                        &mut r,
                        format!("PID {} range {start:#x}..{end:#x}", process.pid),
                        format!("{e:#}"),
                    );
                }
            }
        }
        Ok(r)
    }
    fn write_pe(
        &self,
        vm: &Memory<'_>,
        base: u64,
        file: &mut impl Write,
        hash: &mut Sha256,
        job: &Job,
    ) -> Result<u64> {
        reconstruct_pe(
            &mut |address, bytes| vm.read(address, bytes),
            base,
            file,
            hash,
            job,
        )
    }
}
pub(super) fn reconstruct_pe(
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
    base: u64,
    file: &mut impl Write,
    hash: &mut Sha256,
    job: &Job,
) -> Result<u64> {
    let mut b = [0; 4096];
    read(base, &mut b)?;
    let (image_size, _) = pe_header(&b)?;
    let pe = u32::from_le_bytes(b[60..64].try_into()?) as usize;
    let sections = u16::from_le_bytes(b[pe + 6..pe + 8].try_into()?) as usize;
    let optional = u16::from_le_bytes(b[pe + 20..pe + 22].try_into()?) as usize;
    ensure!(
        sections <= 96 && pe + 24 + optional + sections * 40 <= 4096,
        "PE 节表越界"
    );
    let headers = u32::from_le_bytes(b[pe + 84..pe + 88].try_into()?) as u64;
    ensure!(
        headers <= 4096 && headers >= ((pe + 24 + optional + sections * 40) as u64),
        "PE SizeOfHeaders 无效"
    );
    let mut ranges = vec![(0, headers, 0)];
    let mut size = headers;
    for i in 0..sections {
        let section = pe + 24 + optional + i * 40;
        let rva = u32::from_le_bytes(b[section + 12..section + 16].try_into()?) as u64;
        let len = u32::from_le_bytes(b[section + 16..section + 20].try_into()?) as u64;
        let raw = u32::from_le_bytes(b[section + 20..section + 24].try_into()?) as u64;
        if len == 0 {
            continue;
        }
        ensure!(
            rva.checked_add(len)
                .is_some_and(|end| end <= u64::from(image_size)),
            "PE section VA 越界"
        );
        ensure!(raw >= headers, "PE section 与头重叠");
        size = size.max(raw.checked_add(len).context("PE 大小溢出")?);
        ranges.push((raw, len, rva));
    }
    ensure!(size <= crate::dump::MAX_DUMP_BYTES, "PE 转储超过限制");
    ranges.sort_unstable();
    ensure!(
        ranges.windows(2).all(|r| r[0].0 + r[0].1 <= r[1].0),
        "PE raw sections 重叠"
    );
    let mut position = 0;
    let zeros = [0; 4096];
    for (raw, len, rva) in ranges {
        while position < raw {
            job.check()?;
            let n = ((raw - position) as usize).min(zeros.len());
            file.write_all(&zeros[..n])?;
            hash.update(&zeros[..n]);
            position += n as u64;
        }
        write_reader(read, add(base, rva)?, len, file, hash, job)?;
        position += len;
    }
    Ok(size)
}
fn write_region(
    vm: &Memory<'_>,
    address: u64,
    size: u64,
    file: &mut impl Write,
    hash: &mut Sha256,
    job: &Job,
) -> Result<()> {
    write_reader(
        &mut |address, bytes| vm.read(address, bytes),
        address,
        size,
        file,
        hash,
        job,
    )
}
pub(super) fn write_reader(
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
    mut address: u64,
    mut size: u64,
    file: &mut impl Write,
    hash: &mut Sha256,
    job: &Job,
) -> Result<()> {
    let mut b = vec![0; 1024 * 1024];
    while size > 0 {
        job.check()?;
        let n = (size as usize).min(b.len());
        read(address, &mut b[..n])?;
        file.write_all(&b[..n])?;
        hash.update(&b[..n]);
        address += n as u64;
        size -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image};
    use super::*;
    #[test]
    fn pe_reconstruction_preserves_headers_sections_and_hash() {
        let (mut b, isf) = fixture();
        b[0x8086..0x8088].copy_from_slice(&1u16.to_le_bytes());
        b[0x8094..0x8096].copy_from_slice(&240u16.to_le_bytes());
        b[0x80d4..0x80d8].copy_from_slice(&512u32.to_le_bytes());
        let section = 0x8188;
        b[section + 12..section + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
        b[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
        b[0xb000..0xb200].fill(0x5a);
        let image = image(&b);
        let engine = Windows {
            vm: Memory::new(&image, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut out = Vec::new();
        let mut hash = Sha256::new();
        assert_eq!(
            engine
                .write_pe(&engine.vm, K, &mut out, &mut hash, &Job::default())
                .unwrap(),
            1024
        );
        assert_eq!(&out[..512], &b[0x8000..0x8200]);
        assert_eq!(&out[512..], &b[0xb000..0xb200]);
        assert_eq!(hash.finalize().as_slice(), Sha256::digest(&out).as_slice());
    }
}
