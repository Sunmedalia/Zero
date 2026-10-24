//! In-memory PE metadata: the import address table of each process image
//! and the fixed version resource of loaded modules.
use super::*;

const IMPORT_LIMIT: usize = 65536;
const RESOURCE_LIMIT: usize = 4096;
const VS_FIXED_SIGNATURE: u32 = 0xfeef_04bd;
const RT_VERSION: u32 = 16;

/// The parts of a mapped PE header these plugins read.
#[derive(Debug, PartialEq)]
pub(super) struct Header {
    pub wide: bool,
    pub size: u32,
    /// (RVA, size) of the import and resource data directories.
    pub imports: (u32, u32),
    pub resources: (u32, u32),
}

pub(super) fn parse_header(bytes: &[u8]) -> Result<Header> {
    ensure!(bytes.len() >= 0x40 && &bytes[..2] == b"MZ", "缺少 MZ 头");
    let at = u32::from_le_bytes(bytes[0x3c..0x40].try_into()?) as usize;
    let nt = bytes.get(at..at + 24).context("PE 头越界")?;
    ensure!(&nt[..4] == b"PE\0\0", "缺少 PE 签名");
    let optional = at + 24;
    let magic = u16::from_le_bytes(
        bytes
            .get(optional..optional + 2)
            .context("可选头越界")?
            .try_into()?,
    );
    let wide = match magic {
        0x10b => false,
        0x20b => true,
        _ => bail!("可选头 magic 无效: {magic:#x}"),
    };
    let u32_at = |offset: usize| -> Result<u32> {
        Ok(u32::from_le_bytes(
            bytes
                .get(optional + offset..optional + offset + 4)
                .context("可选头越界")?
                .try_into()?,
        ))
    };
    let directories = if wide { 112 } else { 96 };
    let count = u32_at(directories - 4)?;
    let directory = |index: u32| -> Result<(u32, u32)> {
        if index >= count {
            return Ok((0, 0));
        }
        let offset = directories + index as usize * 8;
        Ok((u32_at(offset)?, u32_at(offset + 4)?))
    };
    Ok(Header {
        wide,
        size: u32_at(56)?,
        imports: directory(1)?,
        resources: directory(2)?,
    })
}

/// Decode a VS_VERSIONINFO block into `major.minor.build.revision` file
/// and product versions.
pub(super) fn fixed_version(bytes: &[u8]) -> Option<(String, String)> {
    let at = memchr::memmem::find(bytes, &VS_FIXED_SIGNATURE.to_le_bytes())?;
    let fixed = bytes.get(at..at + 52)?;
    let word = |offset: usize| u32::from_le_bytes(fixed[offset..offset + 4].try_into().unwrap());
    let format =
        |ms: u32, ls: u32| format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff);
    Some((format(word(8), word(12)), format(word(16), word(20))))
}

impl Windows<'_> {
    fn read_image(&self, vm: &Memory<'_>, base: u64, rva: u32, out: &mut [u8]) -> Result<()> {
        vm.read(add(base, u64::from(rva))?, out)
    }
    fn image_header(&self, vm: &Memory<'_>, base: u64) -> Result<Header> {
        let mut bytes = vec![0; 4096];
        vm.read(base, &mut bytes)?;
        parse_header(&bytes)
    }
    fn ascii_at(&self, vm: &Memory<'_>, base: u64, rva: u32) -> Result<String> {
        let mut bytes = vec![0; 256];
        // Names may end near a page boundary; shrink until the read succeeds.
        let mut length = bytes.len();
        loop {
            match self.read_image(vm, base, rva, &mut bytes[..length]) {
                Ok(()) => break,
                Err(e) if length <= 16 => return Err(e),
                Err(_) => length /= 2,
            }
        }
        let end = bytes[..length]
            .iter()
            .position(|b| *b == 0)
            .context("导入名称未终止")?;
        ensure!(
            bytes[..end].iter().all(|b| b.is_ascii_graphic()),
            "导入名称包含非 ASCII 字符"
        );
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }
    /// windows.iat: the import table of each process's main image.
    pub(super) fn iat(&self, p: &Process, r: &mut Results, job: &Job) -> Result<()> {
        let vm = self.process_memory(p)?;
        let (base, ..) = self
            .dlls_partial(p, job, None)?
            .into_iter()
            .next()
            .context("进程没有主映像")?;
        let header = self.image_header(&vm, base)?;
        let (directory, size) = header.imports;
        if directory == 0 || size == 0 {
            return Ok(());
        }
        let width = if header.wide { 8 } else { 4 };
        let ordinal = if header.wide { 1u64 << 63 } else { 1 << 31 };
        for index in 0..IMPORT_LIMIT as u32 {
            job.check()?;
            let mut descriptor = [0u8; 20];
            self.read_image(&vm, base, directory + index * 20, &mut descriptor)?;
            let word = |at: usize| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
            let (lookup, name, thunks) = (word(0), word(12), word(16));
            if name == 0 && thunks == 0 {
                break;
            }
            let library = self
                .ascii_at(&vm, base, name)
                .unwrap_or_else(|_| "[unreadable]".into());
            let lookup = if lookup == 0 { thunks } else { lookup };
            for slot in 0..IMPORT_LIMIT as u32 {
                let read = (|| -> Result<Option<Vec<String>>> {
                    let mut entry = [0u8; 8];
                    self.read_image(
                        &vm,
                        base,
                        lookup + slot * width,
                        &mut entry[..width as usize],
                    )?;
                    let value = u64::from_le_bytes(entry);
                    if value == 0 {
                        return Ok(None);
                    }
                    let function = if value & ordinal != 0 {
                        format!("Ordinal#{}", value & 0xffff)
                    } else {
                        self.ascii_at(&vm, base, (value as u32).wrapping_add(2))?
                    };
                    let mut bound = [0u8; 8];
                    self.read_image(
                        &vm,
                        base,
                        thunks + slot * width,
                        &mut bound[..width as usize],
                    )?;
                    Ok(Some(vec![
                        p.pid.to_string(),
                        p.name.clone(),
                        library.clone(),
                        function,
                        hex(u64::from_le_bytes(bound)),
                    ]))
                })();
                match read {
                    Ok(Some(row)) => r.rows.push(row),
                    Ok(None) => break,
                    Err(e) => {
                        Self::issue(
                            r,
                            format!("PID {} {library}[{slot}]", p.pid),
                            format!("{e:#}"),
                        );
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    /// The RT_VERSION resource of a mapped image, if present and resident.
    fn image_version(&self, vm: &Memory<'_>, base: u64) -> Result<Option<(String, String)>> {
        let header = self.image_header(vm, base)?;
        let (root, size) = header.resources;
        if root == 0 || size == 0 {
            return Ok(None);
        }
        // Walk type -> name -> language, taking the first entry below RT_VERSION.
        let entries = |offset: u32| -> Result<Vec<(u32, u32)>> {
            let mut directory = [0u8; 16];
            self.read_image(vm, base, root + offset, &mut directory)?;
            let count = u32::from(u16::from_le_bytes([directory[12], directory[13]]))
                + u32::from(u16::from_le_bytes([directory[14], directory[15]]));
            ensure!(count as usize <= RESOURCE_LIMIT, "资源目录项超限");
            let mut raw = vec![0u8; count as usize * 8];
            self.read_image(vm, base, root + offset + 16, &mut raw)?;
            Ok(raw
                .chunks_exact(8)
                .map(|e| {
                    (
                        u32::from_le_bytes(e[..4].try_into().unwrap()),
                        u32::from_le_bytes(e[4..].try_into().unwrap()),
                    )
                })
                .collect())
        };
        let Some(&(_, version)) = entries(0)?.iter().find(|(id, _)| *id == RT_VERSION) else {
            return Ok(None);
        };
        let mut offset = version;
        for _ in 0..2 {
            ensure!(offset & 0x8000_0000 != 0, "资源目录层级无效");
            let Some(&(_, next)) = entries(offset & 0x7fff_ffff)?.first() else {
                return Ok(None);
            };
            offset = next;
        }
        ensure!(offset & 0x8000_0000 == 0, "资源数据项无效");
        let mut data = [0u8; 16];
        self.read_image(vm, base, root + offset, &mut data)?;
        let rva = u32::from_le_bytes(data[..4].try_into()?);
        let length = u32::from_le_bytes(data[4..8].try_into()?).min(4096);
        let mut block = vec![0u8; length as usize];
        self.read_image(vm, base, rva, &mut block)?;
        Ok(fixed_version(&block))
    }
    /// windows.verinfo: file and product versions of process DLLs.
    pub(super) fn verinfo(&self, p: &Process, r: &mut Results, job: &Job) -> Result<()> {
        let vm = self.process_memory(p)?;
        for (base, _, path, _) in self.dlls_partial(p, job, None)? {
            job.check()?;
            match self.image_version(&vm, base) {
                Ok(Some((file, product))) => r.rows.push(vec![
                    p.pid.to_string(),
                    p.name.clone(),
                    hex(base),
                    path,
                    file,
                    product,
                ]),
                Ok(None) => {}
                Err(e) => Self::issue(r, format!("PID {} {path}", p.pid), format!("{e:#}")),
            }
        }
        Ok(())
    }
    /// Kernel modules' versions, reported with PID 0 like the System image.
    pub(super) fn module_versions(&self, r: &mut Results, job: &Job) -> Result<()> {
        let modules = self.modules(Plugin::WinModules, job)?;
        if !modules.complete {
            r.complete = false;
            r.diagnostics.extend(modules.diagnostics.clone());
        }
        for module in modules.rows {
            job.check()?;
            let base = u64::from_str_radix(module[1].trim_start_matches("0x"), 16)?;
            match self.image_version(&self.vm, base) {
                Ok(Some((file, product))) => r.rows.push(vec![
                    "0".into(),
                    "[kernel]".into(),
                    module[1].clone(),
                    module[3].clone(),
                    file,
                    product,
                ]),
                Ok(None) => {}
                Err(e) => Self::issue(r, format!("module {}", module[0]), format!("{e:#}")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(wide: bool) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let optional = 0x98;
        b[optional..optional + 2]
            .copy_from_slice(&(if wide { 0x20bu16 } else { 0x10b }).to_le_bytes());
        b[optional + 56..optional + 60].copy_from_slice(&0x5000u32.to_le_bytes());
        let directories = optional + if wide { 112 } else { 96 };
        b[directories - 4..directories].copy_from_slice(&16u32.to_le_bytes());
        for (index, rva, size) in [(1usize, 0x2000u32, 40u32), (2, 0x3000, 0x100)] {
            let at = directories + index * 8;
            b[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        }
        b
    }

    #[test]
    fn headers_of_both_widths_expose_import_and_resource_directories() {
        for wide in [false, true] {
            assert_eq!(
                parse_header(&pe(wide)).unwrap(),
                Header {
                    wide,
                    size: 0x5000,
                    imports: (0x2000, 40),
                    resources: (0x3000, 0x100)
                }
            );
        }
        let mut broken = pe(true);
        broken[0x98] = 0;
        assert!(parse_header(&broken).is_err());
        assert!(parse_header(b"ZZ").is_err());
    }

    #[test]
    fn fixed_version_decodes_file_and_product_versions() {
        let mut block = vec![0u8; 128];
        block[40..44].copy_from_slice(&VS_FIXED_SIGNATURE.to_le_bytes());
        for (offset, value) in [
            (48usize, 0x000a_0000u32),
            (52, 0x4a61_0001),
            (56, 0x000a_0000),
            (60, 0x4a61_0000),
        ] {
            block[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(
            fixed_version(&block).unwrap(),
            ("10.0.19041.1".into(), "10.0.19041.0".into())
        );
        assert!(fixed_version(&[0; 64]).is_none());
    }
}
