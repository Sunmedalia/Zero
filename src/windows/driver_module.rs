//! Cross-view driver starts against loaded module intervals.
use super::*;

const KNOWN_DRIVERS: [&str; 6] = [
    "ACPI_HAL",
    "PnpManager",
    "RAW",
    "WMIxWDM",
    "Win32k",
    "Fs_Rec",
];

fn in_module(modules: &[KernelModule], address: u64) -> bool {
    // Python module.offset + module.size does not wrap at the pointer width.
    modules.iter().any(|module| {
        address >= module.base
            && u128::from(address) <= u128::from(module.base) + u128::from(module.size)
    })
}

fn driver_module_orphan(modules: &[KernelModule], start: u64, range_start: u64) -> bool {
    (start == 0 || start >= range_start) && !in_module(modules, start)
}

impl Windows<'_> {
    pub(super) fn driver_module(&self, job: &Job) -> Result<Results> {
        ensure!(
            matches!(
                Architecture::from_isf(self.vm.isf)?,
                Architecture::X86 | Architecture::X64
            ),
            "DriverModule 仅支持 x86/x64"
        );
        let mut r = self.result(Plugin::WinDriverModule);
        if let Err(error) = self.driver_module_rows(&mut r, job) {
            job.check()?;
            Self::issue(&mut r, "DriverModule", format!("{error:#}"));
        }
        Ok(r)
    }

    /// LIST_ENTRY.to_list uses only forward links. Walking Blink as a recovery
    /// path can add stale entries that incorrectly claim an orphan driver's range.
    fn driver_module_links(
        &self,
        head: u64,
        offset: u64,
        r: &mut Results,
        job: &Job,
    ) -> Result<Vec<u64>> {
        let flink = self.vm.isf.offset("_LIST_ENTRY", "Flink")?;
        let size = self.vm.isf.data.key("user_types")["_LIST_ENTRY"]
            .key("size")
            .as_u64()
            .context("缺少 LIST_ENTRY 大小")?;
        ensure!(size <= 4096, "LIST_ENTRY 大小超限");
        let mut bytes = vec![0; usize::try_from(size)?];
        let native = |raw| {
            let masked = raw & self.driver_address_mask();
            if self.vm.pointer_size() == 8 && masked & (1 << 47) != 0 {
                masked | 0xffff_0000_0000_0000
            } else {
                masked
            }
        };
        let next = |at| -> Result<u64> {
            let mut pointer = [0; 8];
            self.vm
                .read_captured(add(at, flink)?, pointer.at_mut(..self.vm.pointer_size())?)?;
            Ok(native(u64::from_le_bytes(pointer)))
        };
        let mut entries = Vec::new();
        let mut seen = HashSet::from([head]);
        let walk = (|| -> Result<()> {
            self.vm.read_captured(head, &mut [0])?;
            let mut current = next(head)?;
            while current != 0 && seen.insert(current) {
                job.check()?;
                ensure!(entries.len() < MAX_OBJECTS, "模块链表数量超限");
                // Pointer.is_readable validates the entire LIST_ENTRY, while
                // the yielded containing object only needs its first byte.
                self.vm.read_captured(current, &mut bytes)?;
                let object = current
                    .checked_sub(offset)
                    .context("模块链表成员地址下溢")?;
                self.vm.read_captured(object, &mut [0])?;
                entries.push(object);
                current = next(current)?;
            }
            Ok(())
        })();
        if let Err(error) = walk {
            job.check()?;
            Self::issue(r, "PsLoadedModuleList forward traversal", error);
        }
        Ok(entries)
    }

    /// SSDT's collection only reads BaseDllName, DllBase and SizeOfImage.
    /// An unreadable name skips that module; a readable empty name still owns
    /// its interval. Do not require FullDllName or a nonempty module stem.
    fn driver_module_intervals(&self, r: &mut Results, job: &Job) -> Result<Vec<KernelModule>> {
        let ty = self.module_type()?;
        let entries = self.driver_module_links(
            self.symbol("PsLoadedModuleList")?,
            self.vm.isf.offset(ty, "InLoadOrderLinks")?,
            r,
            job,
        )?;
        let mut out = Vec::new();
        for address in entries {
            job.check()?;
            let module = (|| -> Result<KernelModule> {
                let name = self.driver_unicode(self.field(address, ty, "BaseDllName")?, false)?;
                Ok(KernelModule {
                    name,
                    base: self.number(address, ty, "DllBase")? & self.driver_address_mask(),
                    size: self.number(address, ty, "SizeOfImage")?,
                    path: String::new(),
                })
            })();
            match module {
                Ok(module) => out.push(module),
                Err(error) => Self::issue(r, format!("module {address:#x}"), error),
            }
        }
        Ok(out)
    }

    fn driver_module_rows(&self, r: &mut Results, job: &Job) -> Result<()> {
        let modules = self.driver_module_intervals(r, job)?;
        let range_start = self.driver_kernel_start()?;
        let physical = self.build_number()? < 10240;
        let body = self.vm.isf.offset("_OBJECT_HEADER", "Body")?;
        let mut text_bytes = 0usize;
        for (offset, address) in self.dispatch_drivers(r, job)? {
            job.check()?;
            let number = |field| {
                if physical {
                    self.physical_field(address, "_DRIVER_OBJECT", field)
                } else {
                    self.number(address, "_DRIVER_OBJECT", field)
                }
            };
            let start = match number("DriverStart") {
                Ok(start) => start & self.driver_address_mask(),
                Err(error) => {
                    Self::issue(
                        r,
                        format!("driver {offset:#x} DriverStart"),
                        format!("{error:#}"),
                    );
                    continue;
                }
            };
            if !driver_module_orphan(&modules, start, range_start) {
                continue;
            }
            // Each name is independent; an unreadable extension must not hide a
            // readable object name or alternate DRIVER_OBJECT name.
            let names = [
                (|| {
                    let header = address.checked_sub(body).context("驱动对象头下溢")?;
                    Ok(self.driver_name(header, physical)?.unwrap_or_default())
                })(),
                (|| {
                    let raw = number("DriverExtension")? & self.driver_address_mask();
                    let extension = if self.vm.pointer_size() == 8 && raw & (1 << 47) != 0 {
                        raw | 0xffff_0000_0000_0000
                    } else {
                        raw
                    };
                    self.driver_unicode(
                        self.field(extension, "_DRIVER_EXTENSION", "ServiceKeyName")?,
                        false,
                    )
                })(),
                (|| {
                    let descriptor = self.field(address, "_DRIVER_OBJECT", "DriverName")?;
                    self.driver_unicode(descriptor, physical)
                })(),
            ];
            let mut values = Vec::with_capacity(3);
            for (field, name) in ["Driver Name", "Service Key", "Alternative Name"]
                .into_iter()
                .zip(names)
            {
                match name {
                    Ok(name) => {
                        values.push(name.split('\0').next().unwrap_or_default().to_string())
                    }
                    Err(error) => {
                        Self::issue(
                            r,
                            format!("driver {offset:#x} {field}"),
                            format!("{error:#}"),
                        );
                        values.push(String::new());
                    }
                }
            }
            if values.iter().all(String::is_empty) {
                continue;
            }
            ensure!(r.rows.len() < 100_000, "DriverModule 结果数量超限");
            let known = KNOWN_DRIVERS.contains(&values.at(0)?.as_str());
            let mut row = vec![hex(offset), known.to_string()];
            row.extend(values);
            let added: usize = row.iter().map(String::len).sum();
            text_bytes = text_bytes
                .checked_add(added)
                .context("DriverModule 文本大小溢出")?;
            ensure!(text_bytes <= 128 * 1024 * 1024, "DriverModule 文本大小超限");
            r.rows.push(row);
        }
        *r.kernel_identity.key_mut("driver_module")? = serde_json::json!({
            "module_ranges":"inclusive; readable BaseDllName including empty names; native pointer domain",
            "module_traversal":"forward LIST_ENTRY only; full link readability; no Blink recovery", "kernel_space_start":hex(range_start),
            "source":"versioned driver pool cross-view; zero DriverStart retained", "known_exceptions":KNOWN_DRIVERS
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{image, put};
    use super::*;
    use serde_json::json;

    fn unicode(bytes: &mut [u8], at: usize, buffer: usize, va: u64, width: usize, text: &str) {
        let words: Vec<_> = text.encode_utf16().collect();
        let length = (words.len() * 2) as u16;
        bytes[at..at + 2].copy_from_slice(&length.to_le_bytes());
        bytes[at + 2..at + 4].copy_from_slice(&length.to_le_bytes());
        bytes[at + width..at + width * 2].copy_from_slice(&va.to_le_bytes()[..width]);
        for (index, word) in words.into_iter().enumerate() {
            bytes[buffer + index * 2..buffer + index * 2 + 2].copy_from_slice(&word.to_le_bytes());
        }
    }
    fn fixture(x86: bool, modern: bool, start: u64, name: &str) -> (Vec<u8>, Isf, u64, u64) {
        let (mut bytes, mut isf, base, physical) =
            super::super::driver_irp::tests::driver_fixture(x86, modern, true);
        let physical = physical as usize;
        let width = if x86 { 4 } else { 8 };
        isf.data["symbols"]["MmSystemRangeStart"] = json!({"address":0x290});
        isf.data["symbols"]["ObpInfoMaskToOffset"] = json!({"address":0x280});
        bytes[0x8282] = 32;
        put(&mut bytes, 0x8290, base);
        for at in [0x8700, 0x8700 + width] {
            bytes[at..at + width].copy_from_slice(&(base + 0x700).to_le_bytes()[..width]);
        }
        isf.data["user_types"]["_LDR_DATA_TABLE_ENTRY"] = json!({"size":64,"fields":{"InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}}}});
        isf.data["user_types"]["_OBJECT_HEADER_NAME_INFO"]["fields"]["Name"] =
            json!({"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}});
        isf.data["user_types"]["_DRIVER_OBJECT"]["fields"]["DriverExtension"] =
            json!({"offset":8,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_DRIVER_OBJECT"]["fields"]["DriverName"] =
            json!({"offset":32,"type":{"kind":"struct","name":"_UNICODE_STRING"}});
        isf.data["user_types"]["_DRIVER_EXTENSION"]["fields"]["ServiceKeyName"] =
            json!({"offset":0,"type":{"kind":"struct","name":"_UNICODE_STRING"}});
        put(&mut bytes, physical + 16, start);
        put(&mut bytes, physical + 8, base + 0xd000);
        bytes[physical - 48 + 16] = 32;
        bytes[physical - 48 + 17] = 2;
        unicode(
            &mut bytes,
            physical - 80,
            0x16000,
            base + 0xe000,
            width,
            name,
        );
        unicode(
            &mut bytes,
            0x15000,
            0x16800,
            base + 0xe800,
            width,
            "service",
        );
        unicode(
            &mut bytes,
            physical + 32,
            0x17000,
            base + 0xf000,
            width,
            "\\Driver\\alternate",
        );
        (bytes, isf, base, physical as u64)
    }
    #[test]
    fn zero_start_and_all_names_survive_physical_and_virtual_pool_carving() {
        for x86 in [false, true] {
            for modern in [false, true] {
                let (bytes, isf, base, physical) = fixture(x86, modern, 0, "RAW");
                let img = image(&bytes);
                let w = Windows {
                    vm: Memory::new(&img, 0x1000, &isf, None),
                    base,
                    pdb: PdbIdentity::from_isf(&isf).unwrap(),
                };
                let result = w.driver_module(&Job::default()).unwrap();
                assert_eq!(
                    result.rows,
                    vec![vec![
                        hex(if modern {
                            base + physical - 0x8000
                        } else {
                            physical
                        }),
                        "true".into(),
                        "RAW".into(),
                        "service".into(),
                        "\\Driver\\alternate".into()
                    ]],
                    "x86={x86} modern={modern} {:?}",
                    result.diagnostics
                );
                assert!(result.complete, "{:?}", result.diagnostics);
                let job = Job::default();
                job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                assert!(w.driver_module(&job).is_err());
            }
        }
    }
    #[test]
    fn invalid_extension_keeps_other_names_and_marks_partial() {
        let (mut bytes, isf, base, physical) = fixture(false, false, 0, "raw");
        put(&mut bytes, physical as usize + 8, 0);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = w.driver_module(&Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(
            &r.rows[0][1..],
            &["false", "raw", "", "\\Driver\\alternate"]
        );
        assert!(!r.complete);
        assert!(r.diagnostics.iter().any(|s| s.contains("Service Key")));
    }
    #[test]
    fn direct_driver_strings_do_not_require_maximum_length_or_kernel_extension() {
        for x86 in [false, true] {
            for modern in [false, true] {
                for low_extension in [false, true] {
                    let (mut bytes, isf, base, physical) = fixture(x86, modern, 0, "RAW");
                    let physical = physical as usize;
                    for descriptor in [physical - 80, 0x15000, physical + 32] {
                        bytes[descriptor + 2..descriptor + 4].fill(0);
                    }
                    if low_extension {
                        // A readable user-half extension is accepted by the
                        // native pointer dereference; no kernel-only gate.
                        if x86 {
                            bytes[0x1000..0x1004].copy_from_slice(&0x2003u32.to_le_bytes());
                        } else {
                            put(&mut bytes, 0x1000, 0x2003);
                        }
                        put(&mut bytes, physical + 8, 0xd000);
                    } else if !x86 {
                        put(&mut bytes, physical + 8, 0x1234_8000_0000_d000);
                    }
                    // Odd-length UTF16 is decoded with replacement, not rejected.
                    bytes[physical + 32..physical + 34].copy_from_slice(&3u16.to_le_bytes());
                    bytes[0x17000..0x17003].copy_from_slice(&[b'a', 0, b'x']);
                    let img = image(&bytes);
                    let w = Windows {
                        vm: Memory::new(&img, 0x1000, &isf, None),
                        base,
                        pdb: PdbIdentity::from_isf(&isf).unwrap(),
                    };
                    let r = w.driver_module(&Job::default()).unwrap();
                    // Modern scanning preserves the new user/kernel alias pair.
                    assert_eq!(
                        r.rows.len(),
                        if modern && low_extension { 2 } else { 1 },
                        "x86={x86} modern={modern} low={low_extension}: {:?}",
                        r.diagnostics
                    );
                    for row in &r.rows {
                        assert_eq!(&row[1..], &["true", "RAW", "service", "a\u{fffd}"]);
                    }
                    assert!(r.complete, "{:?}", r.diagnostics);
                }
            }
        }
    }

    #[test]
    fn nameless_candidates_and_user_starts_do_not_produce_rows() {
        for nameless in [false, true] {
            let (mut bytes, isf, base, physical) =
                fixture(false, true, if nameless { 0 } else { 0x4000 }, "");
            if nameless {
                bytes[0x15000..0x15004].fill(0);
                bytes[physical as usize + 32..physical as usize + 36].fill(0);
            }
            let img = image(&bytes);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            assert!(w.driver_module(&Job::default()).unwrap().rows.is_empty());
        }
    }
    #[test]
    fn loaded_module_cross_view_excludes_only_starts_inside_its_range() {
        for (delta, rows) in [(0, 0), (0xfff, 0), (0x1000, 0), (0x1001, 1)] {
            let base = super::super::tests::K;
            let (mut bytes, mut isf, _, _) = fixture(false, true, base + 0x2000 + delta, "orphan");
            let fields = &mut isf.data["user_types"]["_LDR_DATA_TABLE_ENTRY"]["fields"];
            fields["DllBase"] = json!({"offset":16,"type":{"kind":"pointer"}});
            fields["SizeOfImage"] = json!({"offset":24,"type":{"kind":"base","name":"u64"}});
            for (name, offset) in [("BaseDllName", 32), ("FullDllName", 48)] {
                fields[name] =
                    json!({"offset":offset,"type":{"kind":"struct","name":"_UNICODE_STRING"}});
            }
            put(&mut bytes, 0x8700, base + 0x10000);
            put(&mut bytes, 0x8708, base + 0x10000);
            put(&mut bytes, 0x18000, base + 0x700);
            put(&mut bytes, 0x18008, base + 0x700);
            put(&mut bytes, 0x18010, base + 0x2000);
            put(&mut bytes, 0x18018, 0x1000);
            unicode(
                &mut bytes,
                0x18020,
                0x19000,
                base + 0x11000,
                8,
                "loaded.sys",
            );
            unicode(
                &mut bytes,
                0x18030,
                0x19800,
                base + 0x11800,
                8,
                "loaded.sys",
            );
            let img = image(&bytes);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let result = w.driver_module(&Job::default()).unwrap();
            assert_eq!(
                result.rows.len(),
                rows,
                "delta={delta:#x} {:?}",
                result.diagnostics
            );
            assert!(result.complete, "{:?}", result.diagnostics);
        }
    }

    #[test]
    fn range_read_failure_uses_reference_default_without_extra_failure() {
        let (bytes, mut isf, base, _) = fixture(false, true, 0, "RAW");
        isf.data["symbols"]["MmSystemRangeStart"]["address"] = json!(0x800000);
        let img = image(&bytes);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let r = w.driver_module(&Job::default()).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(r.complete, "{:?}", r.diagnostics);
        isf.data["metadata"]["windows"]["pdb"]["machine_type"] = json!(0xaa64);
        let w = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        assert!(
            w.driver_module(&Job::default())
                .unwrap_err()
                .to_string()
                .contains("x86/x64")
        );
    }

    #[test]
    fn module_membership_is_inclusive_and_uses_python_integer_bounds() {
        let modules = vec![
            KernelModule {
                name: "test.sys".into(),
                base: 0x1000,
                size: 0x1000,
                path: String::new(),
            },
            KernelModule {
                name: "overflow".into(),
                base: u64::MAX - 3,
                size: 8,
                path: String::new(),
            },
            KernelModule {
                name: String::new(),
                base: 0x3000,
                size: 0x1000,
                path: String::new(),
            },
        ];
        for (address, expected) in [
            (0, false),
            (0xfff, false),
            (0x1000, true),
            (0x1fff, true),
            (0x2000, true),
            (0x3000, true),
            (u64::MAX - 1, true),
        ] {
            assert_eq!(in_module(&modules, address), expected, "{address:#x}");
        }
    }
    #[test]
    fn module_forward_links_match_actual_list_entry_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/driver-module.json"
        ))
        .unwrap();
        for case in vectors["links"].as_array().unwrap() {
            let width = case["width"].as_u64().unwrap() as usize;
            let (mut bytes, mut isf, base, _) = fixture(width == 4, true, 0, "RAW");
            isf.data["user_types"]["_LIST_ENTRY"]["size"] = json!(width * 2);
            let first = case["first"].as_u64().unwrap();
            put(&mut bytes, 0x8700, base + first);
            // A backward recovery would reach this node even for reverse-only.
            put(&mut bytes, 0x8700 + width, base + 0x10000);
            for node in case["nodes"].as_array().unwrap() {
                let at = node[0].as_u64().unwrap() as usize + 0x8000;
                let pointer = |value: u64| if value == 0 { 0 } else { base + value };
                put(&mut bytes, at, pointer(node[1].as_u64().unwrap()));
                put(&mut bytes, at + width, pointer(node[2].as_u64().unwrap()));
            }
            let img = image(&bytes);
            let w = Windows {
                vm: Memory::new(&img, 0x1000, &isf, None),
                base,
                pdb: PdbIdentity::from_isf(&isf).unwrap(),
            };
            let mut r = w.result(Plugin::WinDriverModule);
            let entries = w
                .driver_module_links(
                    base + 0x700,
                    case["relative"].as_u64().unwrap(),
                    &mut r,
                    &Job::default(),
                )
                .unwrap();
            assert_eq!(
                json!(entries.iter().map(|at| at - base).collect::<Vec<_>>()),
                case["expected"],
                "{}: {:?}",
                case["id"],
                r.diagnostics
            );
        }
    }

    #[test]
    fn pinned_driver_module_generator_and_name_fallback_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/reference/parity/fixtures/driver-module.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let width = case["width"].as_u64().unwrap() as usize;
            for modern in [false, true] {
                let start = case["start"].as_u64().unwrap();
                let (mut bytes, mut isf, base, physical) = fixture(width == 4, modern, start, "");
                let fields = &mut isf.data["user_types"]["_LDR_DATA_TABLE_ENTRY"]["fields"];
                fields["DllBase"] = json!({"offset":16,"type":{"kind":"pointer"}});
                fields["SizeOfImage"] = json!({"offset":24,"type":{"kind":"base","name":"u64"}});
                fields["BaseDllName"] =
                    json!({"offset":32,"type":{"kind":"struct","name":"_UNICODE_STRING"}});
                // FullDllName deliberately absent: SSDT never reads that field.
                for (at, value) in [
                    (0x8700, base + 0x10000),
                    (0x8700 + width, base + 0x10000),
                    (0x18000, base + 0x700),
                    (0x18000 + width, base + 0x700),
                    (0x18010, case["module_base"].as_u64().unwrap()),
                    (0x18018, case["module_size"].as_u64().unwrap()),
                ] {
                    put(&mut bytes, at, value);
                }
                unicode(
                    &mut bytes,
                    0x18020,
                    0x19000,
                    base + 0x11000,
                    width,
                    case["module_name"].as_str().unwrap_or("bad"),
                );
                if case["module_name"].is_null() {
                    put(&mut bytes, 0x18020 + width, base + 0x800000);
                }
                for (index, (descriptor, buffer)) in [
                    (physical as usize - 80, 0x16000),
                    (0x15000, 0x16800),
                    (physical as usize + 32, 0x17000),
                ]
                .into_iter()
                .enumerate()
                {
                    unicode(
                        &mut bytes,
                        descriptor,
                        buffer,
                        base + buffer as u64 - 0x8000,
                        width,
                        case["names"][index].as_str().unwrap_or("bad"),
                    );
                    if case["names"][index].is_null() {
                        put(&mut bytes, descriptor + width, base + 0x800000);
                    }
                }
                let img = image(&bytes);
                let w = Windows {
                    vm: Memory::new(&img, 0x1000, &isf, None),
                    base,
                    pdb: PdbIdentity::from_isf(&isf).unwrap(),
                };
                let r = w.driver_module(&Job::default()).unwrap();
                let actual: Vec<Vec<String>> = r.rows.iter().map(|row| row[1..].to_vec()).collect();
                let expected: Vec<Vec<String>> = case["expected"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| {
                        row.as_array()
                            .unwrap()
                            .iter()
                            .map(|value| {
                                value
                                    .as_str()
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| value.as_bool().unwrap().to_string())
                            })
                            .collect()
                    })
                    .collect();
                if case["id"]
                    .as_str()
                    .unwrap()
                    .ends_with("equal-kernel-boundary")
                {
                    // Actual generator accepts equality, but the upstream scanner
                    // rejects it. Keep both stage contracts explicit.
                    assert!(driver_module_orphan(&[], base, base));
                    assert_eq!(expected.len(), 1);
                    assert!(actual.is_empty());
                } else {
                    assert_eq!(
                        actual, expected,
                        "{} modern={modern}: {:?}",
                        case["id"], r.diagnostics
                    );
                }
            }
        }
    }
}
