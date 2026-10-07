//! Driver pool candidates validated against a mapped DRIVER_EXTENSION back-reference.
use super::*;
impl Windows<'_> {
    pub(super) fn drivers(&self, plugin: Plugin, job: &Job) -> Result<Results> {
        let isf = self.vm.isf;
        let size = isf.data["user_types"]["_DRIVER_OBJECT"]["size"]
            .as_u64()
            .context("缺少 DRIVER_OBJECT")?;
        let header_size = isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 POOL_HEADER")?;
        let tag_offset = isf.offset("_POOL_HEADER", "PoolTag")?;
        let alignment = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        ensure!(
            size > 0 && size <= 4096 && header_size > 0 && header_size <= 4096,
            "driver/pool 尺寸无效"
        );
        let modules = self.modules(Plugin::WinModules, job)?;
        let mut r = self.result(plugin);
        r.complete = modules.complete;
        r.diagnostics = modules.diagnostics.clone();
        let mut seen = HashSet::new();
        self.prefetch_pool_tags(job)?;
        for tag in [b"Driv".as_slice(), b"Dri\xf6".as_slice()] {
            for hit in self.vm.image.scan(tag, job)? {
                job.check()?;
                let Some(header) = hit.checked_sub(tag_offset) else {
                    continue;
                };
                if !header.is_multiple_of(alignment) {
                    continue;
                }
                let mut pool = vec![0; header_size as usize];
                if self.vm.image.read(header, &mut pool).is_err() {
                    continue;
                }
                let block = objects::physical_number(isf, &pool, "_POOL_HEADER", "BlockSize")?
                    .checked_mul(alignment)
                    .context("pool 尺寸溢出")?;
                if block < header_size + size || block > 4096 {
                    continue;
                }
                for delta in (header_size..=block - size).step_by(alignment as usize) {
                    let physical = add(header, delta)?;
                    let mut b = vec![0; size as usize];
                    if self.vm.image.read(physical, &mut b).is_err() {
                        continue;
                    }
                    let validated = (|| -> Result<(u64, u64, u64)> {
                        ensure!(
                            objects::physical_number(isf, &b, "_DRIVER_OBJECT", "Type")? == 4
                                && objects::physical_number(isf, &b, "_DRIVER_OBJECT", "Size")?
                                    == size,
                            "非驱动对象"
                        );
                        let extension =
                            objects::physical_number(isf, &b, "_DRIVER_OBJECT", "DriverExtension")?;
                        ensure!(self.vm.kernel(extension), "驱动扩展无效");
                        let address =
                            self.number(extension, "_DRIVER_EXTENSION", "DriverObject")?;
                        ensure!(
                            self.vm.kernel(address) && self.vm.translate(address)? == physical,
                            "驱动回引用不一致"
                        );
                        let base =
                            objects::physical_number(isf, &b, "_DRIVER_OBJECT", "DriverStart")?;
                        let length =
                            objects::physical_number(isf, &b, "_DRIVER_OBJECT", "DriverSize")?;
                        ensure!(
                            self.vm.kernel(base)
                                && length > 0
                                && length <= 1024 * 1024 * 1024
                                && base.checked_add(length).is_some(),
                            "驱动范围无效"
                        );
                        Ok((address, base, length))
                    })();
                    let Ok((address, base, length)) = validated else {
                        continue;
                    };
                    if !seen.insert(address) {
                        break;
                    }
                    let read = (|| -> Result<()> {
                        let name = self.vm.unicode(self.field(
                            address,
                            "_DRIVER_OBJECT",
                            "DriverName",
                        )?)?;
                        let init = self.number(address, "_DRIVER_OBJECT", "DriverInit")?;
                        if plugin == Plugin::WinDriverscan {
                            r.rows.push(vec![
                                hex(address),
                                name,
                                hex(base),
                                length.to_string(),
                                module_at(&modules, base),
                                hex(init),
                            ]);
                        } else {
                            let offset = isf.offset("_DRIVER_OBJECT", "MajorFunction")?;
                            ensure!(
                                offset
                                    .checked_add(28 * self.vm.pointer_size() as u64)
                                    .is_some_and(|end| end <= size),
                                "MajorFunction 越界"
                            );
                            for n in 0..28 {
                                job.check()?;
                                let target = self.vm.pointer(add(
                                    address,
                                    offset + n * self.vm.pointer_size() as u64,
                                )?)?;
                                r.rows.push(vec![
                                    hex(address),
                                    name.clone(),
                                    format!("MajorFunction[{n}]"),
                                    hex(target),
                                    module_at(&modules, target),
                                    (target >= base && target < base + length).to_string(),
                                ]);
                            }
                            for field in ["DriverInit", "DriverStartIo", "DriverUnload"] {
                                let target = self.number(address, "_DRIVER_OBJECT", field)?;
                                r.rows.push(vec![
                                    hex(address),
                                    name.clone(),
                                    field.into(),
                                    hex(target),
                                    module_at(&modules, target),
                                    (target >= base && target < base + length).to_string(),
                                ]);
                            }
                        }
                        Ok(())
                    })();
                    if let Err(e) = read {
                        job.check()?;
                        Self::issue(&mut r, hex(address), e);
                    }
                    break;
                }
            }
        }
        r.kernel_identity["coverage"] = serde_json::json!(
            "pool candidates with mapped extension back-reference; unavailable/freed objects may be absent; dispatch differences do not imply malicious behavior"
        );
        Ok(r)
    }
}
pub(super) fn module_at(modules: &Results, address: u64) -> String {
    modules
        .rows
        .iter()
        .find(|m| {
            let base = u64::from_str_radix(m[1].trim_start_matches("0x"), 16).unwrap_or(0);
            let size = m[2].parse::<u64>().unwrap_or(0);
            address != 0
                && address >= base
                && base.checked_add(size).is_some_and(|end| address < end)
        })
        .map(|m| m[0].clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn driver_scan_requires_extension_back_reference_and_bounds_dispatch() {
        let (mut b, mut isf) = fixture();
        let number = |offset| json!({"offset":offset,"type":{"kind":"base","name":"u16"}});
        let ptr = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_POOL_HEADER"] = json!({"size":16,"fields":{"BlockSize":number(0),"PoolTag":{"offset":4,"type":{"kind":"array","count":4}}}});
        isf.data["user_types"]["_DRIVER_OBJECT"] = json!({"size":304,"fields":{"Type":number(0),"Size":number(2),"DriverExtension":ptr(8),"DriverStart":ptr(16),"DriverSize":ptr(24),"DriverName":{"offset":32,"type":{"kind":"struct","name":"_UNICODE_STRING"}},"DriverInit":ptr(48),"DriverStartIo":ptr(56),"DriverUnload":ptr(64),"MajorFunction":{"offset":80,"type":{"kind":"array","count":28,"subtype":{"kind":"pointer"}}}}});
        isf.data["user_types"]["_DRIVER_EXTENSION"] =
            json!({"size":8,"fields":{"DriverObject":ptr(0)}});
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":16,"fields":{"InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}});
        b[0xb000..0xb002].copy_from_slice(&20u16.to_le_bytes());
        b[0xb004..0xb008].copy_from_slice(b"Driv");
        b[0xb010..0xb012].copy_from_slice(&4u16.to_le_bytes());
        b[0xb012..0xb014].copy_from_slice(&304u16.to_le_bytes());
        put(&mut b, 0xb018, K + 0x4000);
        put(&mut b, 0xb020, K + 0x6000);
        put(&mut b, 0xb028, 4096);
        put(&mut b, 0xc000, K + 0x3010);
        let text: Vec<u8> = "\\Driver\\Test"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b[0xb030..0xb032].copy_from_slice(&(text.len() as u16).to_le_bytes());
        b[0xb032..0xb034].copy_from_slice(&(text.len() as u16).to_le_bytes());
        put(&mut b, 0xb038, K + 0x5000);
        b[0xd000..0xd000 + text.len()].copy_from_slice(&text);
        put(&mut b, 0xb060, K + 0x6010);
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = engine
            .drivers(Plugin::WinDriverscan, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][1], "\\Driver\\Test");
        let r = engine
            .drivers(Plugin::WinDrivercheck, &Job::default())
            .unwrap();
        assert_eq!(r.rows.len(), 31);
        assert_eq!(r.rows[0][5], "true");
        put(&mut b, 0xc000, K + 0x3020);
        let img = image(&b);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(
            engine
                .drivers(Plugin::WinDriverscan, &Job::default())
                .unwrap()
                .rows
                .is_empty()
        );
    }
}
