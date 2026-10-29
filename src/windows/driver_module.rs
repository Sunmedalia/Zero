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
    modules.iter().any(|module| {
        !module.name.is_empty()
            && address >= module.base
            && module
                .base
                .checked_add(module.size)
                .is_some_and(|end| address < end)
    })
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

    fn driver_module_rows(&self, r: &mut Results, job: &Job) -> Result<()> {
        let modules = self.modules_partial(job, r)?;
        let range_symbol = self.symbol("MmSystemRangeStart")?;
        let range_start = match self.vm.pointer(range_symbol) {
            Ok(start) => {
                ensure!(self.vm.kernel(start), "MmSystemRangeStart 无效");
                start
            }
            Err(error) => {
                Self::issue(
                    r,
                    "MmSystemRangeStart 使用架构默认边界",
                    format!("{error:#}"),
                );
                if self.vm.pointer_size() == 4 {
                    0x80000000
                } else {
                    0xffff800000000000
                }
            }
        };
        let physical = self.build_number()? < 10240;
        let header_layout = self.object_header_layout();
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
                Ok(start) => start,
                Err(error) => {
                    Self::issue(
                        r,
                        format!("driver {offset:#x} DriverStart"),
                        format!("{error:#}"),
                    );
                    continue;
                }
            };
            if (start > 0 && start <= range_start) || in_module(&modules, start) {
                continue;
            }
            // Each name is independent; an unreadable extension must not hide a
            // readable object name or alternate DRIVER_OBJECT name.
            let names = [
                (|| {
                    let header = address.checked_sub(body).context("驱动对象头下溢")?;
                    if physical {
                        self.physical_object_name(header)
                    } else {
                        self.object_name(header, &header_layout)
                    }
                })(),
                (|| {
                    let extension = number("DriverExtension")?;
                    ensure!(self.vm.kernel(extension), "驱动扩展指针无效");
                    self.vm
                        .unicode(self.field(extension, "_DRIVER_EXTENSION", "ServiceKeyName")?)
                })(),
                (|| {
                    let descriptor = self.field(address, "_DRIVER_OBJECT", "DriverName")?;
                    if physical {
                        self.physical_unicode(descriptor)
                    } else {
                        self.vm.unicode(descriptor)
                    }
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
            let known = KNOWN_DRIVERS.contains(&values[0].as_str());
            let mut row = vec![hex(offset), known.to_string()];
            row.extend(values);
            let added: usize = row.iter().map(String::len).sum();
            text_bytes = text_bytes
                .checked_add(added)
                .context("DriverModule 文本大小溢出")?;
            ensure!(text_bytes <= 128 * 1024 * 1024, "DriverModule 文本大小超限");
            r.rows.push(row);
        }
        r.kernel_identity["driver_module"] = serde_json::json!({
            "module_ranges":"half-open; named loaded modules only", "kernel_space_start":hex(range_start),
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
        for (delta, rows) in [(0, 0), (0xfff, 0), (0x1000, 1)] {
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
    fn range_read_failure_uses_default_with_explicit_partial_diagnostic() {
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
        assert!(!r.complete);
        assert!(
            r.diagnostics
                .iter()
                .any(|s| s.contains("MmSystemRangeStart"))
        );
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
    fn module_membership_is_half_open_and_overflow_safe() {
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
            (0x2000, false),
            (0x3000, false),
            (u64::MAX - 1, false),
        ] {
            assert_eq!(in_module(&modules, address), expected, "{address:#x}");
        }
    }
}
