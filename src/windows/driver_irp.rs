//! Symbol-driven driver pool objects and independent dispatch-entry reads.
use super::dispatch::DispatchModules;
use super::*;
use std::collections::BTreeSet;

const IRPS: [&str; 28] = [
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
];
const OPTIONAL_HEADERS: [&str; 9] = [
    "CREATOR_INFO",
    "NAME_INFO",
    "HANDLE_INFO",
    "QUOTA_INFO",
    "PROCESS_INFO",
    "AUDIT_INFO",
    "EXTENDED_INFO",
    "HANDLE_REVOCATION_INFO",
    "PADDING_INFO",
];

impl Windows<'_> {
    /// Pool bodies are retained independently of DriverStart/extension state.
    fn dispatch_drivers(&self, r: &mut Results, job: &Job) -> Result<Vec<(u64, u64)>> {
        let isf = self.vm.isf;
        let build = self.build_number()?;
        let modern = build >= 9200;
        let virtual_scan = build >= 10240;
        let alignment = if self.vm.pointer_size() == 4 { 8 } else { 16 };
        let body = isf.offset("_OBJECT_HEADER", "Body")?;
        ensure!((8..=256).contains(&body), "对象头 Body 偏移无效");
        let pool_size = isf.data["user_types"]["_POOL_HEADER"]["size"]
            .as_u64()
            .context("缺少 pool 大小")?;
        let driver_size = isf.data["user_types"]["_DRIVER_OBJECT"]["size"]
            .as_u64()
            .context("缺少驱动大小")?;
        ensure!((16..=4096).contains(&driver_size), "驱动对象尺寸无效");
        ensure!((8..=64).contains(&pool_size), "pool header 大小无效");
        let optional: Vec<_> = OPTIONAL_HEADERS
            .iter()
            .filter_map(|name| {
                isf.data["user_types"][format!("_OBJECT_HEADER_{name}")]["size"].as_u64()
            })
            .collect();
        let optional_limit = optional.iter().try_fold(0u64, |total, size| {
            ensure!(*size <= 4096, "可选对象头大小无效");
            total.checked_add(*size).context("可选对象头大小溢出")
        })?;
        ensure!(
            !modern || (1..=4096).contains(&optional_limit),
            "缺少或无效可选对象头大小"
        );
        let info_offset = if modern {
            Some(isf.offset("_OBJECT_HEADER", "InfoMask")? as usize)
        } else {
            None
        };
        ensure!(
            info_offset.is_none_or(|offset| offset < body as usize),
            "InfoMask 越界"
        );
        let mut candidates = BTreeSet::new();
        let mut pool_header = vec![0; pool_size as usize];
        let mut object_bytes = vec![0; body as usize];
        let tag_offset = isf.offset("_POOL_HEADER", "PoolTag")? as usize;
        ensure!(
            tag_offset
                .checked_add(4)
                .is_some_and(|end| end <= pool_header.len()),
            "PoolTag 越界"
        );
        for (start, length) in self.pool_blocks(&[b"Driv", b"Dri\xf6"], 1, job)? {
            job.check()?;
            let header = start.checked_sub(pool_size).context("池头下溢")?;
            self.vm.image.read(header, &mut pool_header)?;
            let page_type =
                objects::physical_number(isf, &pool_header, "_POOL_HEADER", "PoolType")?;
            let nonpaged = if build >= 6000 {
                page_type > 0 && page_type % 2 == 0
            } else {
                page_type % 2 == 1
            };
            if page_type != 0 && !nonpaged {
                continue;
            }
            if length + pool_size < 248 {
                continue;
            }
            if modern {
                for delta in (0..optional_limit.min(length + pool_size)).step_by(alignment as usize)
                {
                    job.check()?;
                    let object_header = add(start, delta)?;
                    if self
                        .vm
                        .image
                        .read(object_header, &mut object_bytes)
                        .is_err()
                    {
                        continue;
                    }
                    let count = objects::physical_number(
                        isf,
                        &object_bytes,
                        "_OBJECT_HEADER",
                        "PointerCount",
                    )?;
                    if let Some(info_offset) = info_offset {
                        let mask = object_bytes[info_offset];
                        let selected: u64 = optional
                            .iter()
                            .enumerate()
                            .filter(|(bit, _)| u16::from(mask) & (1u16 << bit) != 0)
                            .map(|(_, size)| size)
                            .sum();
                        if isf.data["user_types"]["_OBJECT_HEADER_PADDING_INFO"]["size"]
                            .as_u64()
                            .is_some()
                        {
                            let bit = optional.len() - 1;
                            if bit < 8 && u16::from(mask) & (1u16 << bit) != 0 {
                                let Some(padding_address) = object_header
                                    .checked_sub(selected)
                                    .filter(|_| selected <= delta)
                                else {
                                    continue;
                                };
                                let mut padding = [0u8; 4];
                                if self.vm.image.read(padding_address, &mut padding).is_err() {
                                    continue;
                                }
                                let Some(extra) = u64::from(u32::from_le_bytes(padding))
                                    .checked_sub(optional[bit])
                                else {
                                    continue;
                                };
                                if selected
                                    .checked_add(extra)
                                    .is_none_or(|length| length > delta)
                                {
                                    continue;
                                }
                            }
                        }
                    }
                    if count >= 0x1000000 {
                        continue;
                    }
                    candidates.insert(add(object_header, body)?);
                }
            } else {
                let extension = if &pool_header[tag_offset..tag_offset + 4] == b"Dri\xf6" {
                    let size = isf.data["user_types"]["_DRIVER_EXTENSION"]["size"]
                        .as_u64()
                        .context("缺少 DRIVER_EXTENSION 大小")?;
                    ensure!(size <= 4096, "DRIVER_EXTENSION 大小无效");
                    size
                } else {
                    0
                };
                let size = driver_size
                    .checked_add(extension)
                    .context("驱动分配大小溢出")?;
                let size = size.checked_add(alignment - 1).context("驱动对齐溢出")? / alignment
                    * alignment;
                if let Some(physical) = add(start, length)?.checked_sub(size)
                    && physical >= start
                {
                    candidates.insert(physical);
                }
            }
            ensure!(candidates.len() <= MAX_OBJECTS, "驱动候选数量超限");
        }
        let mapped = if virtual_scan {
            self.mapped_pool_candidates(&candidates, job)?
        } else {
            BTreeMap::new()
        };
        let layout = self.object_header_layout();
        let mut out = Vec::new();
        let mut unmapped = 0;
        for physical in candidates {
            job.check()?;
            if !virtual_scan {
                let read = (|| -> Result<bool> {
                    let header = physical.checked_sub(body).context("物理驱动对象头下溢")?;
                    if self.physical_object_type(header)? != "Driver" {
                        return Ok(false);
                    }
                    let base = self.physical_field(physical, "_DRIVER_OBJECT", "DriverStart")?;
                    Ok(base == 0 || self.vm.kernel(base))
                })();
                if matches!(read, Ok(true)) {
                    out.push((physical, physical));
                }
                continue;
            }
            let Some(aliases) = mapped.get(&physical) else {
                unmapped += 1;
                continue;
            };
            for &address in aliases {
                let read = (|| -> Result<bool> {
                    let h = address.checked_sub(body).context("驱动对象头下溢")?;
                    if self.object_type(h, &layout)? != "Driver" {
                        return Ok(false);
                    }
                    let base = self.number(address, "_DRIVER_OBJECT", "DriverStart")?;
                    Ok(base == 0 || self.vm.kernel(base))
                })();
                if matches!(read, Ok(true)) {
                    out.push((if virtual_scan { address } else { physical }, address));
                }
            }
        }
        if unmapped > 0 {
            Self::issue(
                r,
                "驱动池覆盖",
                format!("{unmapped} 个池内位置缺少可验证内核映射，未输出这些候选"),
            );
        }
        r.kernel_identity["driver_pool"] = serde_json::json!({"source":"versioned pool object headers","offset_layer":if virtual_scan {"kernel virtual"} else {"physical"},"unmapped_positions":unmapped,"driver_count":out.len()});
        Ok(out)
    }
    pub(super) fn driver_irp(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "DriverIrp 仅支持 x86/x64"
        );
        let mut r = self.result(Plugin::WinDriverIrp);
        if let Err(e) = self.driver_irp_rows(&mut r, job) {
            job.check()?;
            Self::issue(&mut r, "DriverIrp", format!("{e:#}"));
        }
        Ok(r)
    }
    fn driver_irp_rows(&self, r: &mut Results, job: &Job) -> Result<()> {
        let modules = self.modules_partial(job, r)?;
        let modules = DispatchModules::new(modules, self.vm.isf, self.base, job)?;
        let field = self.vm.isf.field("_DRIVER_OBJECT", "MajorFunction")?;
        ensure!(
            field["type"]["kind"] == "array"
                && field["type"]["count"] == 28
                && field["type"]["subtype"]["kind"] == "pointer",
            "MajorFunction 布局不是 28 个指针"
        );
        let major = self.vm.isf.offset("_DRIVER_OBJECT", "MajorFunction")?;
        let size = self.vm.isf.data["user_types"]["_DRIVER_OBJECT"]["size"]
            .as_u64()
            .context("缺少驱动大小")?;
        ensure!(
            major
                .checked_add(28 * self.vm.pointer_size() as u64)
                .is_some_and(|end| end <= size),
            "MajorFunction 越界"
        );
        let header_layout = self.object_header_layout();
        let physical_scan = self.build_number()? < 10240;
        let mut text_bytes = 0usize;
        for (offset, address) in self.dispatch_drivers(r, job)? {
            let header = address
                .checked_sub(self.vm.isf.offset("_OBJECT_HEADER", "Body")?)
                .context("对象头下溢")?;
            let name = match if physical_scan {
                self.physical_object_name(header)
            } else {
                self.object_name(header, &header_layout)
            } {
                Ok(name) => name.split('\0').next().unwrap_or_default().to_string(),
                Err(e) => {
                    Self::issue(r, "driver name", format!("{e:#}"));
                    String::new()
                }
            };
            for (index, irp) in IRPS.iter().enumerate() {
                job.check()?;
                let slot = add(
                    add(address, major)?,
                    index as u64 * self.vm.pointer_size() as u64,
                )?;
                let target = if physical_scan {
                    let mut bytes = [0u8; 8];
                    self.vm
                        .image
                        .read(slot, &mut bytes[..self.vm.pointer_size()])
                        .map(|()| u64::from_le_bytes(bytes))
                } else {
                    self.vm.pointer(slot)
                };
                match target {
                    Ok(target) if self.vm.kernel(target) => {
                        for (module, symbol) in modules.at(target) {
                            ensure!(r.rows.len() < 100_000, "IRP 结果数量超限");
                            let row = vec![
                                hex(offset),
                                name.clone(),
                                (*irp).into(),
                                hex(target),
                                module,
                                symbol,
                            ];
                            let added: usize = row.iter().map(String::len).sum();
                            text_bytes =
                                text_bytes.checked_add(added).context("IRP 文本大小溢出")?;
                            ensure!(text_bytes <= 128 * 1024 * 1024, "IRP 文本大小超限");
                            r.rows.push(row);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        Self::issue(r, format!("driver {address:#x} {irp}"), format!("{e:#}"))
                    }
                }
            }
        }
        r.kernel_identity["dispatch_symbols"] = serde_json::json!({"scope":"exact kernel PDB only; external module symbols unavailable","match":"exact address; all aliases; half-open module ranges"});
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;

    fn driver_fixture(x86: bool, modern: bool, protected: bool) -> (Vec<u8>, Isf, u64, u64) {
        let (mut bytes, mut isf) = fixture();
        let base = if x86 { 0x80000000 } else { K };
        let width = if x86 { 4 } else { 8 };
        let alignment = if x86 { 8 } else { 16 };
        let scalar = |offset, name| json!({"offset":offset,"type":{"kind":"base","name":name}});
        for (name, size) in [("u8", 1), ("u32", 4)] {
            isf.data["base_types"][name] = json!({"size":size});
        }
        if x86 {
            isf.data["base_types"]["pointer"]["size"] = json!(4);
            isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0x14c);
            bytes[0x1000..0x3000].fill(0);
            bytes[0x1800..0x1804].copy_from_slice(&0x2003u32.to_le_bytes());
            for i in 0..32 {
                bytes[0x2000 + i * 4..0x2004 + i * 4]
                    .copy_from_slice(&(0x8003 + i as u32 * 4096).to_le_bytes());
            }
            isf.data["user_types"]["_UNICODE_STRING"]["fields"]["Buffer"]["offset"] = json!(4);
        }
        put(&mut bytes, 0x8200, if modern { 15063 } else { 6001 });
        isf.data["user_types"]["_POOL_HEADER"] = json!({"size":16,"fields":{"BlockSize":scalar(0,"u16"),"PoolType":scalar(2,"u16"),"PoolTag":scalar(4,"u32")}});
        isf.data["user_types"]["_OBJECT_HEADER"] = json!({"size":56,"fields":{"PointerCount":scalar(0,"pointer"),"Type":scalar(8,"pointer"),"NameInfoOffset":scalar(16,"u8"),"InfoMask":scalar(17,"u8"),"Body":{"offset":48,"type":{"kind":"struct","name":"_QUAD"}}}});
        isf.data["user_types"]["_QUAD"] = json!({"size":8,"fields":{}});
        isf.data["user_types"]["_OBJECT_TYPE"] = json!({"size":16,"fields":{"Name":{"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}}}});
        isf.data["user_types"]["_OBJECT_HEADER_NAME_INFO"] = json!({"size":32,"fields":{}});
        isf.data["user_types"]["_DRIVER_EXTENSION"] = json!({"size":32,"fields":{}});
        isf.data["user_types"]["_DRIVER_OBJECT"] = json!({"size":304,"fields":{"DriverStart":scalar(16,"pointer"),"MajorFunction":{"offset":80,"type":{"kind":"array","count":28,"subtype":{"kind":"pointer"}}}}});
        bytes[0xb000..0xb002].copy_from_slice(&(512u16 / alignment).to_le_bytes());
        bytes[0xb002..0xb004].copy_from_slice(&2u16.to_le_bytes());
        bytes[0xb004..0xb008].copy_from_slice(if protected { b"Dri\xf6" } else { b"Driv" });
        let physical = if modern {
            0xb040
        } else {
            0xb200 - 304 - if protected { 32 } else { 0 }
        };
        put(&mut bytes, physical - 48, 1);
        put(&mut bytes, physical - 40, base + 0x9000);
        put(&mut bytes, 0x11000, 12 | (12 << 16));
        put(&mut bytes, 0x11000 + width, base + 0xa000);
        for (index, word) in "Driver".encode_utf16().enumerate() {
            bytes[0x12000 + index * 2..0x12002 + index * 2].copy_from_slice(&word.to_le_bytes());
        }
        put(&mut bytes, physical + 80, base + 0x1234);
        (bytes, isf, base, physical as u64)
    }

    #[test]
    fn pool_driver_location_depends_on_version_and_protected_tag() {
        for x86 in [false, true] {
            for modern in [false, true] {
                for protected in [false, true] {
                    let (bytes, isf, base, physical) = driver_fixture(x86, modern, protected);
                    let img = image(&bytes);
                    let w = Windows {
                        vm: Memory::new(&img, 0x1000, &isf, None),
                        base,
                        pdb: PdbIdentity::from_isf(&isf).unwrap(),
                    };
                    let mut result = w.result(Plugin::WinDriverIrp);
                    let drivers = w.dispatch_drivers(&mut result, &Job::default()).unwrap();
                    let virtual_address = base + physical - 0x8000;
                    assert_eq!(
                        drivers,
                        vec![(
                            if modern { virtual_address } else { physical },
                            if modern { virtual_address } else { physical }
                        )],
                        "x86={x86} modern={modern} protected={protected}"
                    );
                    // DriverStart is zero and there is no live DriverExtension backlink.
                    let job = Job::default();
                    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    assert!(w.dispatch_drivers(&mut result, &job).is_err());
                }
            }
        }
    }

    #[test]
    fn virtual_pool_scan_keeps_distinct_aliases_of_the_same_physical_body() {
        let (mut bytes, isf, base, physical) = driver_fixture(false, true, false);
        put(&mut bytes, 0x3008, 0x4003);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut result = w.result(Plugin::WinDriverIrp);
        let drivers = w.dispatch_drivers(&mut result, &Job::default()).unwrap();
        let address = base + physical - 0x8000;
        assert_eq!(
            drivers,
            vec![(address, address), (address + 0x200000, address + 0x200000)]
        );
    }

    #[test]
    fn old_physical_driver_survives_without_a_virtual_body_mapping() {
        let (mut bytes, isf, base, physical) = driver_fixture(false, false, true);
        put(&mut bytes, 0x4018, 0);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut result = w.result(Plugin::WinDriverIrp);
        assert_eq!(
            w.dispatch_drivers(&mut result, &Job::default()).unwrap(),
            vec![(physical, physical)]
        );
        assert!(result.complete, "{:?}", result.diagnostics);
    }

    #[test]
    fn dispatch_reads_each_handler_and_rejects_malformed_layouts() {
        let (mut bytes, mut isf, base, physical) = driver_fixture(false, false, false);
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":64,"fields":{"InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}});
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let result = w.driver_irp(&Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0],
            vec![
                hex(physical),
                String::new(),
                "IRP_MJ_CREATE".into(),
                hex(base + 0x1234),
                String::new(),
                String::new()
            ]
        );
        // A bad object name cannot suppress readable handlers.
        bytes[physical as usize - 31] = 2;
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let result = w.driver_irp(&Job::default()).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert!(!result.complete);
        isf.data["user_types"]["_DRIVER_OBJECT"]["fields"]["MajorFunction"]["type"]["count"] =
            json!(27);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let result = w.driver_irp(&Job::default()).unwrap();
        assert!(!result.complete);
        assert!(result.rows.is_empty());
    }

    #[test]
    fn missing_handler_page_preserves_readable_dispatch_entries() {
        let (mut bytes, mut isf, base, _) = driver_fixture(false, false, false);
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":64,"fields":{"InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}});
        // A retained pool allocation spans two pages; the handler array begins
        // with two resident entries and continues into an absent virtual page.
        bytes[0xb000..0xb008].fill(0);
        bytes[0xbf60..0xbf62].copy_from_slice(&32u16.to_le_bytes());
        bytes[0xbf62..0xbf64].copy_from_slice(&2u16.to_le_bytes());
        bytes[0xbf64..0xbf68].copy_from_slice(b"Driv");
        put(&mut bytes, 0x8200, 15063);
        put(&mut bytes, 0xbf70, 1);
        put(&mut bytes, 0xbf78, base + 0x9000);
        put(&mut bytes, 0xbff0, base + 0x1234);
        put(&mut bytes, 0xbff8, base + 0x1238);
        put(&mut bytes, 0x4020, 0);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let result = w.driver_irp(&Job::default()).unwrap();
        assert_eq!(result.rows.len(), 2, "{:?}", result.diagnostics);
        assert_eq!(result.rows[0][2], "IRP_MJ_CREATE");
        assert_eq!(result.rows[1][2], "IRP_MJ_CREATE_NAMED_PIPE");
        assert!(!result.complete);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("IRP_MJ_CLOSE"))
        );
    }

    #[test]
    fn module_alias_names_reserve_existing_numeric_suffixes() {
        let (_, isf) = fixture();
        let module = |name: &str, base| KernelModule {
            name: name.into(),
            base,
            size: 16,
            path: String::new(),
        };
        let index = DispatchModules::new(
            vec![
                module("srv2.sys", K + 0x1000),
                module("srv.sys", K + 0x2000),
            ],
            &isf,
            K,
            &Job::default(),
        )
        .unwrap();
        assert_eq!(index.at(K + 0x2000), vec![("srv1".into(), String::new())]);
    }

    #[test]
    fn module_attribution_retains_aliases_and_never_borrows_external_symbols() {
        let (_, mut isf) = fixture();
        isf.data["symbols"] = json!({"AliasB":{"address":16},"AliasA":{"address":16}});
        let module = |name: &str, base, size| KernelModule {
            name: name.into(),
            base,
            size,
            path: String::new(),
        };
        let index = DispatchModules::new(
            vec![
                module("nt.exe", K, 32),
                module("driver.sys", K + 8, 32),
                module("overflow.sys", u64::MAX - 1, 32),
            ],
            &isf,
            K,
            &Job::default(),
        )
        .unwrap();
        assert_eq!(
            index.at(K + 16),
            vec![
                ("nt".into(), "AliasA".into()),
                ("nt".into(), "AliasB".into()),
                ("driver".into(), String::new())
            ]
        );
        assert_eq!(index.at(K + 32), vec![("driver".into(), String::new())]);
        assert_eq!(index.at(K + 40), vec![(String::new(), String::new())]);
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(DispatchModules::new(vec![], &isf, K, &job).is_err());
    }
}
