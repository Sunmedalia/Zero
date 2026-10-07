//! Pool candidates require structure checks and a verified virtual object type.
use super::*;
use objects::physical_number;
use std::collections::BTreeSet;
/// Pool tags read by the scanning plugins; the first scan finds all of them in
/// one pass so the remaining scans in a session reuse the hits.
const POOL_TAGS: &[&[u8]] = &[
    b"File", b"Fil\xe5", b"Muta", b"Mut\xe1", b"Driv", b"Dri\xf6", b"Proc", b"Pro\xe3", b"TcpL",
    b"UdpA", b"TcpE", b"TTcb",
];
impl Windows<'_> {
    pub(super) fn prefetch_pool_tags(&self, job: &Job) -> Result<()> {
        self.vm.image.prefetch_scans(POOL_TAGS, job)
    }
    pub(super) fn pool_blocks(
        &self,
        tags: &[&[u8]],
        minimum: u64,
        job: &Job,
    ) -> Result<Vec<(u64, u64)>> {
        let isf = self.vm.isf;
        let size = isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 pool header 大小")?;
        ensure!((8..=64).contains(&size), "pool header 大小无效");
        let offset = isf.offset("_POOL_HEADER", "PoolTag")?;
        ensure!(offset + 4 <= size, "pool tag 越界");
        let align = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let mut blocks = BTreeSet::new();
        self.prefetch_pool_tags(job)?;
        for tag in tags {
            for hit in self.vm.image.scan(tag, job)? {
                job.check()?;
                let Some(header) = hit.checked_sub(offset) else {
                    continue;
                };
                if !header.is_multiple_of(align) {
                    continue;
                }
                let mut b = vec![0; size as usize];
                if self.vm.image.read(header, &mut b).is_err() {
                    continue;
                }
                let block = physical_number(isf, &b, "_POOL_HEADER", "BlockSize")?
                    .checked_mul(align)
                    .context("pool block 溢出")?;
                if block < size + minimum || block > 4096 {
                    continue;
                }
                blocks.insert((add(header, size)?, block - size));
                ensure!(blocks.len() <= MAX_OBJECTS, "pool 分配数量超限");
            }
        }
        Ok(blocks.into_iter().collect())
    }
    pub(super) fn pool_artifacts(&self, p: Plugin, job: &Job) -> Result<Results> {
        let mut r = self.result(p);
        let read = self.pool_rows(p, &mut r, job);
        if let Err(e) = read {
            job.check()?;
            Self::issue(&mut r, p.name(), format!("{e:#}"));
        }
        Ok(r)
    }
    fn pool_rows(&self, p: Plugin, r: &mut Results, job: &Job) -> Result<()> {
        let (ty, kind, tags): (_, _, &[&[u8]]) = if p == Plugin::WinFilescan {
            ("_FILE_OBJECT", "File", &[b"File", b"Fil\xe5"])
        } else {
            ("_KMUTANT", "Mutant", &[b"Muta", b"Mut\xe1"])
        };
        let size = self.vm.isf.data["user_types"][ty]["size"]
            .as_u64()
            .context("缺少对象类型大小")?;
        ensure!((16..=4096).contains(&size), "pool 对象大小无效");
        let body_offset = self.vm.isf.offset("_OBJECT_HEADER", "Body")?;
        ensure!((8..=256).contains(&body_offset), "对象头 Body 偏移无效");
        let align = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let mut candidates = BTreeSet::new();
        for (start, length) in self.pool_blocks(tags, size + body_offset, job)? {
            for delta in (body_offset..=length - size).step_by(align as usize) {
                job.check()?;
                let physical = add(start, delta)?;
                let mut bytes = vec![0; size as usize];
                if self.vm.image.read(physical, &mut bytes).is_err() {
                    continue;
                }
                let valid = if p == Plugin::WinFilescan {
                    physical_number(self.vm.isf, &bytes, ty, "Type").is_ok_and(|n| n == 5)
                        && physical_number(self.vm.isf, &bytes, ty, "Size").is_ok_and(|n| n == size)
                } else {
                    physical_number(self.vm.isf, &bytes, ty, "Header.Type").is_ok_and(|n| n == 2)
                        && physical_number(self.vm.isf, &bytes, ty, "Header.Size")
                            .is_ok_and(|n| n == 0 || n == size / 4)
                };
                if valid {
                    candidates.insert(physical);
                    ensure!(candidates.len() <= MAX_OBJECTS, "pool 对象数量超限");
                }
            }
        }
        let mut mapped = BTreeMap::new();
        let mut seen = HashSet::new();
        let mut budget = MAX_OBJECTS;
        reverse_objects(
            self.vm.image,
            self.vm.root,
            self.vm.paging()?,
            0,
            0,
            &candidates,
            &mut mapped,
            &mut seen,
            &mut budget,
            job,
        )?;
        let mut unmatched = 0;
        for physical in candidates {
            job.check()?;
            let Some(addresses) = mapped.get(&physical) else {
                unmatched += 1;
                continue;
            };
            let mut matched = false;
            for &address in addresses {
                let read = (|| -> Result<Option<Vec<String>>> {
                    let header = address.checked_sub(body_offset).context("对象头下溢")?;
                    if self.object_type(header)? != kind {
                        return Ok(None);
                    }
                    matched = true;
                    let mut name = String::new();
                    let readname = if p == Plugin::WinFilescan {
                        self.vm.unicode(self.field(address, ty, "FileName")?)
                    } else {
                        self.object_name(header)
                    };
                    match readname {
                        Ok(n) => name = n,
                        Err(e) => {
                            Self::issue(r, format!("{kind} name {address:#x}"), format!("{e:#}"))
                        }
                    }
                    if let Some(at) = name.find('\0') {
                        Self::issue(
                            r,
                            format!("{kind} name {address:#x}"),
                            "对象名称包含 NUL；仅显示首个 NUL 前的文本",
                        );
                        name.truncate(at);
                    }
                    let prefix = vec![format!("physical:{physical:#x}"), hex(address), name];
                    let mut row = prefix;
                    if p == Plugin::WinFilescan {
                        let device = self.number(address, ty, "DeviceObject")?;
                        ensure!(
                            device == 0 || self.vm.kernel(device),
                            "无效 DeviceObject 指针"
                        );
                        row.push(hex(device));
                        for field in ["ReadAccess", "WriteAccess", "DeleteAccess"] {
                            row.push(self.number(address, ty, field)?.to_string());
                        }
                    } else {
                        let owner = self.number(address, ty, "OwnerThread")?;
                        ensure!(owner == 0 || self.vm.kernel(owner), "无效互斥 OwnerThread");
                        row.push(hex(owner));
                        let signal = self.number(address, ty, "Header.SignalState")?;
                        row.push((signal as u32 as i32).to_string());
                    }
                    Ok(Some(row))
                })();
                match read {
                    Ok(Some(row)) => {
                        r.rows.push(row);
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => Self::issue(r, format!("{kind} {address:#x}"), format!("{e:#}")),
                }
            }
            if !matched {
                unmatched += 1;
            }
        }
        if unmatched > 0 {
            Self::issue(
                r,
                "pool coverage",
                format!("{unmatched} 个结构候选没有可验证的虚拟对象类型；未输出这些候选"),
            );
        }
        r.kernel_identity["pool_scan"] = serde_json::json!({"object_type":kind,"validation":"structure and mapped object header type","scope":"mapped live or retained pool objects; unmapped freed candidates excluded"});
        Ok(())
    }
}
/// Bound repeated table aliases. BTreeSet ranges avoid candidates × pages scans.
#[allow(clippy::too_many_arguments)]
fn reverse_objects(
    image: &Image,
    table: u64,
    geometry: Paging,
    level: usize,
    prefix: u64,
    wanted: &BTreeSet<u64>,
    out: &mut BTreeMap<u64, Vec<u64>>,
    seen: &mut HashSet<(u64, usize)>,
    budget: &mut usize,
    job: &Job,
) -> Result<()> {
    if wanted.is_empty() {
        return Ok(());
    }
    job.check()?;
    if !seen.insert((table, level)) {
        return Ok(());
    }
    ensure!(*budget > 0, "对象虚拟地址映射搜索超限");
    *budget -= 1;
    let shift = geometry.shifts()[level];
    let mut bytes = vec![0; geometry.entries(level) * geometry.width()];
    if image.read(table, &mut bytes).is_err() {
        return Ok(());
    }
    for (i, b) in bytes.chunks_exact(geometry.width()).enumerate() {
        if level == 0 && i < geometry.entries(level) / 2 {
            continue;
        }
        let mut raw = [0; 8];
        raw[..b.len()].copy_from_slice(b);
        let entry = u64::from_le_bytes(raw);
        if entry & 1 == 0 {
            continue;
        }
        let va = prefix | ((i as u64) << shift);
        let pa = entry & geometry.mask();
        if shift == 12 || geometry.block(entry, shift) {
            let mask = (1u64 << shift) - 1;
            let base = pa & !mask;
            for &physical in wanted.range(base..=base + mask) {
                let address = geometry.extend(va | (physical - base));
                if geometry.arch.kernel(address) {
                    out.entry(physical).or_default().push(address);
                }
            }
        } else if level + 1 < geometry.shifts().len() {
            // Self-referencing page-table branches do not map pool objects.
            if geometry.arch == Architecture::X64 && level == 0 && pa == table {
                continue;
            }
            reverse_objects(
                image,
                pa,
                geometry,
                level + 1,
                va,
                wanted,
                out,
                seen,
                budget,
                job,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn pool_scan_validates_type_and_keeps_missing_names_partial() {
        for x86 in [false, true] {
            let (mut b, mut isf) = fixture();
            let k = if x86 { 0x80000000 } else { K };
            let width = if x86 { 4 } else { 8 };
            let field = |offset, ty| json!({"offset":offset,"type":{"kind":"base","name":ty}});
            for (n, size) in [("u32", 4), ("u8", 1)] {
                isf.data["base_types"][n] = json!({"size":size});
            }
            if x86 {
                isf.data["base_types"]["pointer"]["size"] = json!(4);
                isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
                b[0x1000..0x3000].fill(0);
                b[0x1800..0x1804].copy_from_slice(&0x2003u32.to_le_bytes());
                for i in 0..32 {
                    b[0x2000 + i * 4..0x2000 + i * 4 + 4]
                        .copy_from_slice(&(0x8003 + i as u32 * 4096).to_le_bytes());
                }
                isf.data["user_types"]["_UNICODE_STRING"]["fields"]["Buffer"]["offset"] = json!(4);
            }
            isf.data["user_types"]["_QUAD"] = json!({"size":8,"fields":{}});
            isf.data["user_types"]["_POOL_HEADER"] =
                json!({"size":16,"fields":{"BlockSize":field(0,"u16"),"PoolTag":field(4,"u32")}});
            isf.data["user_types"]["_OBJECT_HEADER"] = json!({"size":24,"fields":{"Type":field(0,"pointer"),"NameInfoOffset":field(8,"u8"),"Body":{"offset":16,"type":{"kind":"struct","name":"_QUAD"}}}});
            isf.data["user_types"]["_OBJECT_HEADER_NAME_INFO"] = json!({"size":32,"fields":{"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
            isf.data["user_types"]["_OBJECT_TYPE"] = json!({"size":16,"fields":{"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
            isf.data["user_types"]["_FILE_OBJECT"] = json!({"size":64,"fields":{"Type":field(0,"u16"),"Size":field(2,"u16"),"DeviceObject":field(8,"pointer"),"FileName":{"offset":16,"type":{"kind":"struct","name":"_UNICODE_STRING"}},"ReadAccess":field(40,"u8"),"WriteAccess":field(41,"u8"),"DeleteAccess":field(42,"u8")}});
            isf.data["user_types"]["_DISPATCHER_HEADER"] = json!({"size":8,"fields":{"Type":field(0,"u8"),"Size":field(2,"u8"),"SignalState":field(4,"u32")}});
            isf.data["user_types"]["_KMUTANT"] = json!({"size":32,"fields":{"Header":{"offset":0,"type":{"kind":"struct","name":"_DISPATCHER_HEADER"}},"OwnerThread":field(8,"pointer")}});
            let align = if x86 { 8 } else { 16 };
            b[0xc000..0xc002].copy_from_slice(&(96u16 / align).to_le_bytes());
            b[0xc004..0xc008].copy_from_slice(b"File");
            put(&mut b, 0xc010, k + 0x5000);
            b[0xc020..0xc024].copy_from_slice(&[5, 0, 64, 0]);
            put(&mut b, 0xc028, k + 0x7000);
            b[0xc030..0xc034].copy_from_slice(&[8, 0, 8, 0]);
            put(&mut b, 0xc030 + width, k + 0x200000);
            b[0xc048] = 1;
            b[0xd000..0xd004].copy_from_slice(&[8, 0, 8, 0]);
            put(&mut b, 0xd000 + width, k + 0x6000);
            b[0xe000..0xe008].copy_from_slice(&[b'F', 0, b'i', 0, b'l', 0, b'e', 0]);
            b[0xc100..0xc102].copy_from_slice(&(96u16 / align).to_le_bytes());
            b[0xc104..0xc108].copy_from_slice(b"Muta");
            put(&mut b, 0xc130, k + 0x5100);
            b[0xc138] = 32;
            b[0xc110..0xc114].copy_from_slice(&[12, 0, 12, 0]);
            put(&mut b, 0xc110 + width, k + 0x6100);
            b[0xc140] = 2;
            put(&mut b, 0xc148, k + 0x8000);
            b[0xd100..0xd104].copy_from_slice(&[12, 0, 12, 0]);
            put(&mut b, 0xd100 + width, k + 0x6100);
            b[0xe100..0xe10c]
                .copy_from_slice(&[b'M', 0, b'u', 0, b't', 0, b'a', 0, b'n', 0, b't', 0]);
            let img = image(&b);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: k,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let r = w
                .pool_artifacts(Plugin::WinFilescan, &Job::default())
                .unwrap();
            assert_eq!(r.rows.len(), 1, "{:#?}", r.diagnostics);
            assert!(r.rows[0][2].is_empty());
            assert!(!r.complete);
            let r = w
                .pool_artifacts(Plugin::WinMutantscan, &Job::default())
                .unwrap();
            assert_eq!(r.rows.len(), 1, "{:#?}", r.diagnostics);
            assert_eq!(r.rows[0][2], "Mutant");
            assert_eq!(r.rows[0][3], hex(k + 0x8000));
            assert!(r.complete);
            b[0xc010..0xc018].copy_from_slice(&(k + 0x5100).to_le_bytes());
            let img = image(&b);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base: k,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let r = w
                .pool_artifacts(Plugin::WinFilescan, &Job::default())
                .unwrap();
            assert!(r.rows.is_empty());
            assert!(!r.complete);
            let job = Job::default();
            job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            for plugin in [
                Plugin::WinCallbacks,
                Plugin::WinUnloadedmodules,
                Plugin::WinFilescan,
                Plugin::WinMutantscan,
                Plugin::WinGetsids,
                Plugin::WinConnscan,
                Plugin::WinSockscan,
            ] {
                assert!(w.run(plugin, &Options::default(), &job).is_err());
            }
        }
    }
}
