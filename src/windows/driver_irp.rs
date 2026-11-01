//! Symbol-driven driver pool objects and independent dispatch-entry reads.
use super::dispatch::DispatchModules;
use super::*;

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
impl Windows<'_> {
    pub(super) fn driver_address_mask(&self) -> u64 {
        if self.vm.pointer_size() == 4 {
            0xffff_ffff
        } else {
            0xffff_ffff_ffff
        }
    }
    pub(super) fn driver_kernel_start(&self) -> Result<u64> {
        let at = self.symbol("MmSystemRangeStart")?;
        let default = if self.vm.pointer_size() == 4 {
            0x8000_0000
        } else {
            0xffff_8000_0000_0000
        };
        Ok(
            self.vm.uint(at, self.vm.pointer_size()).unwrap_or(default)
                & self.driver_address_mask(),
        )
    }
    fn driver_target(&self, raw: u64, kernel_start: u64) -> Option<u64> {
        let masked = raw & self.driver_address_mask();
        (masked >= kernel_start).then(|| {
            if self.vm.pointer_size() == 8 && masked & (1 << 47) != 0 {
                masked | 0xffff_0000_0000_0000
            } else {
                masked
            }
        })
    }
    pub(super) fn driver_name(&self, header: u64, physical: bool) -> Result<Option<String>> {
        let read = |at, size| -> Result<u64> {
            ensure!(matches!(size, 1 | 2 | 4 | 8), "驱动名称标量宽度无效");
            if physical {
                let mut bytes = [0; 8];
                self.vm.image.read(at, bytes.at_mut(..size)?)?;
                Ok(u64::from_le_bytes(bytes))
            } else {
                self.vm.uint(at, size)
            }
        };
        let offset = if self.vm.isf.has_field("_OBJECT_HEADER", "NameInfoOffset") {
            let at = add(
                header,
                self.vm.isf.offset("_OBJECT_HEADER", "NameInfoOffset")?,
            )?;
            read(at, self.vm.isf.size("_OBJECT_HEADER", "NameInfoOffset")?)?
        } else {
            let at = add(header, self.vm.isf.offset("_OBJECT_HEADER", "InfoMask")?)?;
            let mask = read(at, self.vm.isf.size("_OBJECT_HEADER", "InfoMask")?)?;
            self.vm
                .uint(add(self.symbol("ObpInfoMaskToOffset")?, mask & 3)?, 1)?
        };
        // NameInfo raises ValueError for zero, which DriverIrp renders as N/A.
        if offset == 0 {
            return Ok(None);
        }
        let info = header.checked_sub(offset).context("驱动名称头地址下溢")?;
        let descriptor = add(
            info,
            self.vm.isf.offset("_OBJECT_HEADER_NAME_INFO", "Name")?,
        )?;
        self.driver_unicode(descriptor, physical).map(Some)
    }
    /// Direct UNICODE_STRING.String, including native pointer masking and the
    /// reference decoder. MaximumLength is not consulted by this property.
    pub(super) fn driver_unicode(&self, descriptor: u64, physical: bool) -> Result<String> {
        let read = |at, size| -> Result<u64> {
            if physical {
                let mut bytes = [0; 8];
                self.vm.image.read(at, bytes.at_mut(..size)?)?;
                Ok(u64::from_le_bytes(bytes))
            } else {
                self.vm.uint(at, size)
            }
        };
        let length = read(
            add(descriptor, self.vm.isf.offset("_UNICODE_STRING", "Length")?)?,
            2,
        )?;
        let raw = read(
            add(descriptor, self.vm.isf.offset("_UNICODE_STRING", "Buffer")?)?,
            self.vm.pointer_size(),
        )?;
        let masked = raw & self.driver_address_mask();
        let buffer = if self.vm.pointer_size() == 8 && masked & (1 << 47) != 0 {
            masked | 0xffff_0000_0000_0000
        } else {
            masked
        };
        // Direct NameInfo.Name.String does not apply get_name's maximum-length
        // sanity checks; read exactly Length with the reference String decoder.
        let mut bytes = vec![0; usize::try_from(length)?];
        self.vm.read(buffer, &mut bytes)?;
        Ok(windowstations::reference_unicode_name(&bytes))
    }
    /// Pool bodies are retained independently of DriverStart/extension state.
    pub(super) fn dispatch_drivers(&self, r: &mut Results, job: &Job) -> Result<Vec<(u64, u64)>> {
        self.reference_dispatch_drivers(r, job)
    }
    pub(super) fn driver_irp(&self, job: &Job) -> Result<Results> {
        self.driver_irp_with_symbols(job, None)
    }
    pub(super) fn driver_irp_with_symbols(
        &self,
        job: &Job,
        resources: Option<(&std::path::Path, bool)>,
    ) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "DriverIrp 仅支持 x86/x64"
        );
        let mut r = self.result(Plugin::WinDriverIrp);
        if let Err(e) = self.driver_irp_rows(&mut r, job, resources) {
            job.check()?;
            Self::issue(&mut r, "DriverIrp", format!("{e:#}"));
        }
        Ok(r)
    }
    fn driver_irp_rows(
        &self,
        r: &mut Results,
        job: &Job,
        resources: Option<(&std::path::Path, bool)>,
    ) -> Result<()> {
        let modules = self.modules_partial(job, r)?;
        let mut modules = DispatchModules::reference(modules, self.vm.isf, self.base, job)?;
        let kernel_start = self.driver_kernel_start()?;
        let field = self.vm.isf.field("_DRIVER_OBJECT", "MajorFunction")?;
        ensure!(
            *field["type"].key("kind") == "array"
                && *field["type"].key("count") == 28
                && field["type"].key("subtype")["kind"] == "pointer",
            "MajorFunction 布局不是 28 个指针"
        );
        let major = self.vm.isf.offset("_DRIVER_OBJECT", "MajorFunction")?;
        let size = self.vm.isf.data.key("user_types")["_DRIVER_OBJECT"]
            .key("size")
            .as_u64()
            .context("缺少驱动大小")?;
        ensure!(
            major
                .checked_add(28 * self.vm.pointer_size() as u64)
                .is_some_and(|end| end <= size),
            "MajorFunction 越界"
        );
        let physical_scan = self.build_number()? < 10240;
        let mut text_bytes = 0usize;
        for (offset, address) in self.dispatch_drivers(r, job)? {
            let header = address
                .checked_sub(self.vm.isf.offset("_OBJECT_HEADER", "Body")?)
                .context("对象头下溢")?;
            let name = match self.driver_name(header, physical_scan) {
                Ok(name) => name.unwrap_or_else(|| "N/A".into()),
                Err(e) => {
                    Self::issue(r, "driver name", format!("{e:#}"));
                    "N/A".into()
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
                        .read(slot, bytes.at_mut(..self.vm.pointer_size())?)
                        .map(|()| u64::from_le_bytes(bytes))
                } else {
                    self.vm.pointer(slot)
                };
                match target {
                    Ok(raw) if self.driver_target(raw, kernel_start).is_some() => {
                        let Some(target) = self.driver_target(raw, kernel_start) else {
                            continue;
                        };
                        modules.resolve_at(target, &self.vm, resources, r, job)?;
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
        *r.kernel_identity.key_mut("dispatch_symbols")? = modules.evidence(resources);
        *r.kernel_identity.key_mut("driver_kernel_space_start")? =
            serde_json::json!(hex(kernel_start));
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{K, fixture, image, put};
    use super::*;
    use serde_json::json;
    #[test]
    fn driver_constraints_are_interleaved_in_scan_address_order() {
        for x86 in [false, true] {
            for modern in [false, true] {
                let (mut bytes, isf, base, plain) = driver_fixture(x86, modern, false);
                let (protected_bytes, _, _, protected) = driver_fixture(x86, modern, true);
                let plain_bytes = bytes[0xb000..0xb200].to_vec();
                bytes[0xb400..0xb600].copy_from_slice(&protected_bytes[0xb000..0xb200]);
                bytes[0xb800..0xba00].copy_from_slice(&plain_bytes);
                let snapshot = image(&bytes);
                let windows = Windows {
                    vm: Memory::new(&snapshot, 0x1000, &isf, None),
                    base,
                    pdb: PdbIdentity::from_isf(&isf).unwrap(),
                };
                let mut result = windows.result(Plugin::WinDriverIrp);
                let actual = windows
                    .dispatch_drivers(&mut result, &Job::default())
                    .unwrap();
                let expected: Vec<_> = [plain, protected + 0x400, plain + 0x800]
                    .into_iter()
                    .map(|at| if modern { base + at - 0x8000 } else { at })
                    .map(|at| (at, at))
                    .collect();
                assert_eq!(
                    actual, expected,
                    "x86={x86} modern={modern}: {:?}",
                    result.diagnostics
                );
                assert!(result.complete, "{:?}", result.diagnostics);
            }
        }
    }

    #[test]
    fn dispatch_uses_shared_signed_padding_and_exact_unaligned_pool_headers() {
        let (mut bytes, mut isf, base, _) = driver_fixture(false, true, false);
        isf.data["user_types"]["_OBJECT_HEADER_PADDING_INFO"] = json!({"size":4,"fields":{}});
        bytes[0xb010..0xb060].fill(0);
        put(&mut bytes, 0xb020, 1);
        put(&mut bytes, 0xb028, base + 0x9000);
        bytes[0xb031] = 2;
        // PADDING_INFO at start+16-4 is zero; the reference keeps signed -4.
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut result = windows.result(Plugin::WinDriverIrp);
        let drivers = windows
            .dispatch_drivers(&mut result, &Job::default())
            .unwrap();
        assert_eq!(drivers, [(base + 0x3050, base + 0x3050)]);
        let (mut bytes, isf, base, physical) = driver_fixture(false, false, false);
        bytes.copy_within(0xb000..0xb200, 0xb003);
        bytes[0xb000..0xb003].fill(0);
        let snapshot = image(&bytes);
        let windows = Windows {
            vm: Memory::new(&snapshot, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let mut result = windows.result(Plugin::WinDriverIrp);
        assert_eq!(
            windows
                .dispatch_drivers(&mut result, &Job::default())
                .unwrap(),
            [(physical + 3, physical + 3)]
        );
    }
    #[test]
    fn direct_driver_name_matches_reference_location_and_string_semantics() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/driver-names.json"
        ))
        .unwrap();
        for x86 in [false, true] {
            for physical in [false, true] {
                for case in vectors["cases"].as_array().unwrap() {
                    let (mut bytes, mut isf, base, _) = driver_fixture(x86, false, false);
                    if x86 {
                        bytes[0x1000..0x1004].copy_from_slice(&0x2003u32.to_le_bytes());
                    } else {
                        put(&mut bytes, 0x1000, 0x2003);
                    }
                    isf.data["symbols"]["ObpInfoMaskToOffset"] = json!({"address":0x500});
                    isf.data["user_types"]["_OBJECT_HEADER_NAME_INFO"]["fields"]["Name"] =
                        json!({"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}});
                    let descriptor = 0xc0e0;
                    bytes[descriptor..descriptor + 16].fill(0);
                    let payload: Vec<_> = case["hex"]
                        .as_str()
                        .unwrap()
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                        .collect();
                    bytes[descriptor..descriptor + 2]
                        .copy_from_slice(&(payload.len() as u16).to_le_bytes());
                    bytes[descriptor + 2..descriptor + 4]
                        .copy_from_slice(&(case["maximum"].as_u64().unwrap() as u16).to_le_bytes());
                    let raw = case["buffer"].as_u64().unwrap();
                    let pointer = if x86 { raw & 0xffff_ffff } else { raw };
                    let buffer_offset = if x86 { 4 } else { 8 };
                    put(&mut bytes, descriptor + buffer_offset, pointer);
                    bytes[0xa100..0xa100 + payload.len()].copy_from_slice(&payload);
                    if let Some(offset) = case["old_offset"].as_u64() {
                        bytes[0xc110] = offset as u8;
                    } else {
                        isf.data["user_types"]["_OBJECT_HEADER"]["fields"]
                            .as_object_mut()
                            .unwrap()
                            .remove("NameInfoOffset");
                    }
                    bytes[0xc111] = case["mask"].as_u64().unwrap() as u8;
                    bytes[0x8500 + (case["mask"].as_u64().unwrap() as usize & 3)] =
                        case["table_delta"].as_u64().unwrap() as u8;
                    let snapshot = image(&bytes);
                    let windows = Windows {
                        vm: Memory::new(&snapshot, 0x1000, &isf, None),
                        base,
                        pdb: PdbIdentity::from_isf(&isf).unwrap(),
                    };
                    let result = windows
                        .driver_name(if physical { 0xc100 } else { base + 0x4100 }, physical);
                    if case["error"] == "InvalidAddressException" {
                        assert!(
                            result.is_err(),
                            "{} x86={x86} physical={physical}",
                            case["id"]
                        );
                    } else {
                        assert_eq!(
                            json!(result.unwrap()),
                            case["expected"],
                            "{} x86={x86} physical={physical}",
                            case["id"]
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn kernel_range_pointer_mask_and_boundary_gate_match_actual_reference_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/driver-targets.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let x86 = case["width"] == 4;
            let (mut bytes, mut isf, base, _) = driver_fixture(x86, false, false);
            if let Some(start) = case["start"].as_u64() {
                put(&mut bytes, 0x8280, start);
            } else {
                isf.data["symbols"]["MmSystemRangeStart"] = json!({"address":0x30000});
            }
            let snapshot = image(&bytes);
            let windows = Windows {
                vm: Memory::new(&snapshot, 0x1000, &isf, None),
                base,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let start = windows.driver_kernel_start().unwrap();
            assert_eq!(
                start,
                case["expected_start"].as_u64().unwrap(),
                "{}",
                case["id"]
            );
            let values = case["raw_values"].as_array().unwrap();
            let mut found = Vec::new();
            for (index, value) in values.iter().enumerate() {
                if let Some(target) = windows.driver_target(value.as_u64().unwrap(), start) {
                    found.push(
                        json!({"irp":IRPS[index],"target":target&windows.driver_address_mask()}),
                    );
                }
            }
            if let Some(target) =
                windows.driver_target(values.last().unwrap().as_u64().unwrap(), start)
            {
                found.push(json!({"irp":IRPS[values.len()+1],"target":target&windows.driver_address_mask()}));
            }
            assert_eq!(json!(found), case["expected"], "{}", case["id"]);
        }
    }

    pub(in crate::windows) fn driver_fixture(
        x86: bool,
        modern: bool,
        protected: bool,
    ) -> (Vec<u8>, Isf, u64, u64) {
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
        isf.data["symbols"]["MmSystemRangeStart"] = json!({"address":0x280});
        put(&mut bytes, 0x8280, base);
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
                "N/A".into(),
                "IRP_MJ_CREATE".into(),
                hex(base + 0x1234),
                String::new(),
                String::new()
            ]
        );
        // A bad object name cannot suppress readable handlers.
        bytes[physical as usize - 32] = 2;
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
