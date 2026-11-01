use super::*;
use serde_json::json;
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
#[test]
fn elf_headers_match_actual_pinned_32_and_64_bit_methods() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/module-elf-headers.json"
    ))
    .unwrap();
    let encoded = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for case in vectors["headers"].as_array().unwrap() {
        let actual = elf_header(
            case["bits"] == 32,
            case["offset"].as_u64().unwrap(),
            case["count"].as_u64().unwrap() as u16,
        );
        if case["error"] == "struct.error" {
            assert!(actual.is_err());
        } else {
            assert_eq!(
                encoded(&actual.unwrap()),
                case["expected_hex"].as_str().unwrap()
            );
        }
    }
    for case in vectors["sections"].as_array().unwrap() {
        let a = &case["args"];
        let section = Section {
            name: a[2].as_str().unwrap().into(),
            address: a[3].as_u64().unwrap(),
            offset: a[5].as_u64().unwrap(),
            bytes: vec![0; a[4].as_u64().unwrap().min(0x123) as usize],
        };
        // Test oversized lengths without allocating their payload.
        let actual = section_header_sized(
            a[1].as_u64().unwrap() as u32,
            &section,
            a[6].as_u64().unwrap() as u32,
            a[7].as_u64().unwrap() as u32,
            a[0] == 32,
            a[4].as_u64().unwrap(),
        );
        if case["expected_hex"].is_null() {
            assert!(actual.is_err());
        } else {
            assert_eq!(
                encoded(&actual.unwrap()),
                case["expected_hex"].as_str().unwrap()
            );
        }
    }
}
#[test]
fn symbol_records_match_actual_pinned_normalization_for_both_widths() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/reference/parity/fixtures/module-elf-symbols.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let symbol = SymbolRecord {
            name: case["name"].as_u64().unwrap() as u32,
            address: case["address"].as_u64().unwrap(),
            size: case["size"].as_u64().unwrap(),
            other: case["other"].as_u64().unwrap() as u8,
            shndx: case["shndx"].as_u64().unwrap() as u16,
        };
        let matched = fixture["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| {
                let start = s[2].as_u64().unwrap();
                start <= symbol.address && symbol.address - start < s[3].as_u64().unwrap()
            })
            .map(|s| {
                (
                    s[0].as_str().unwrap(),
                    s[2].as_u64().unwrap(),
                    s[1].as_u64().unwrap() as u16,
                )
            });
        let actual = symbol.encode(case["bits"] == 32, matched);
        if case["error"] == "struct.error" {
            assert!(actual.is_err(), "{case}");
        } else {
            let hex: String = actual.unwrap().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, case["expected_hex"].as_str().unwrap(), "{case}");
        }
    }
}
fn fixture() -> (Vec<u8>, Isf) {
    let (mut bytes, mut isf) = super::super::tests::fixture();
    let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
    isf.data["user_types"]["module"] = json!({"size":48,"fields":{
        "name":{"offset":0,"type":{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}},
        "sect_attrs":pointer(16),"symtab":pointer(24),"strtab":pointer(32),
        "num_symtab":{"offset":40,"type":{"kind":"base","name":"u64"}}
    }});
    isf.data["user_types"]["module_sect_attrs"] = json!({"size":8,"fields":{
        "nsections":{"offset":0,"type":{"kind":"base","name":"u64"}},
        "attrs":{"offset":8,"type":{"kind":"array","count":0,"subtype":{"kind":"struct","name":"module_sect_attr"}}}
    }});
    isf.data["user_types"]["module_sect_attr"] = json!({"size":16,"fields":{
        "name":pointer(0),"address":{"offset":8,"type":{"kind":"base","name":"u64"}}
    }});
    isf.data["user_types"]["Elf64_Sym"] = json!({"size":24,"fields":{
        "st_name":{"offset":0,"type":{"kind":"base","name":"u32"}},
        "st_info":{"offset":4,"type":{"kind":"base","name":"char"}},
        "st_other":{"offset":5,"type":{"kind":"base","name":"char"}},
        "st_shndx":{"offset":6,"type":{"kind":"base","name":"u16"}},
        "st_value":{"offset":8,"type":{"kind":"base","name":"u64"}},
        "st_size":{"offset":16,"type":{"kind":"base","name":"u64"}}
    }});
    isf.data["base_types"]["u16"] = json!({"size":2});
    bytes[0x30000..0x30004].copy_from_slice(b"test");
    for (at, value) in [
        (0x30010, 0x31000),
        (0x30018, 0x32000),
        (0x30020, 0x33000),
        (0x30028, 3),
        (0x31000, 4),
        (0x35000, 0x18000),
        (0x35008, 0x1c000),
    ] {
        put(&mut bytes, at, value);
    }
    for (index, name, address) in [
        (0, b".data".as_slice(), 0x19000),
        (1, b".text".as_slice(), 0x18000),
        (2, b".strtab".as_slice(), 0x1a000),
        (3, b".symtab".as_slice(), 0x1b000),
    ] {
        let string = 0x34000 + index * 32;
        bytes[string..string + name.len()].copy_from_slice(name);
        put(&mut bytes, 0x31008 + index * 16, string as u64);
        put(&mut bytes, 0x31010 + index * 16, address);
    }
    bytes[0x18000..0x19000].fill(0x90);
    bytes[0x19000..0x1a000].fill(0x51);
    bytes[0x33000..0x3300f].copy_from_slice(b"\0entry\0extern\0\0");
    bytes[0x32018..0x3201c].copy_from_slice(&1u32.to_le_bytes());
    put(&mut bytes, 0x32020, 0x18003);
    put(&mut bytes, 0x32028, 5);
    bytes[0x32030..0x32034].copy_from_slice(&7u32.to_le_bytes());
    for (name, address) in [("module_addr_min", 0x35000), ("module_addr_max", 0x35008)] {
        isf.data["symbols"][name] = json!({"address":address});
    }
    (bytes, isf)
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn options(directory: &Path) -> DumpOptions {
    DumpOptions {
        pid: 0,
        start: Some(0x30000),
        end: None,
        directory: directory.into(),
    }
}
#[test]
fn lsmod_exports_existing_reconstruction_and_preserves_conflicts() {
    let (mut bytes, mut isf) = fixture();
    for (name, offset) in [
        ("list", 48),
        ("module_core", 64),
        ("core_size", 72),
        ("init_size", 80),
        ("taints", 88),
    ] {
        isf.data["user_types"]["module"]["fields"][name] = if name == "list" {
            json!({"offset":offset,"type":{"kind":"struct","name":"list_head"}})
        } else {
            json!({"offset":offset,"type":{"kind":"base","name":"u64"}})
        };
    }
    isf.data["user_types"]["module"]["size"] = json!(96);
    isf.data["symbols"]["modules"] = json!({"address":0x37000});
    for (at, value) in [
        (0x37000, 0x30030),
        (0x37008, 0x30030),
        (0x30030, 0x37000),
        (0x30038, 0x37000),
        (0x30040, 0x18000),
        (0x30048, 0x4000),
    ] {
        put(&mut bytes, at, value);
    }
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let expected = linux
        .reconstructed_module_elf(0x30000, &Job::default())
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut dump = options(directory.path());
    dump.start = None;
    let result = linux.lsmod_with_dump(&dump, &Job::default()).unwrap();
    let filename = "kernel_module.test.0x30000.elf";
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][5], filename);
    assert_eq!(
        std::fs::read(directory.path().join(filename)).unwrap(),
        expected.bytes
    );
    let conflict = linux.lsmod_with_dump(&dump, &Job::default()).unwrap();
    assert!(!conflict.complete);
    assert_eq!(conflict.rows[0][5], "-");
    assert_eq!(
        std::fs::read(directory.path().join(filename)).unwrap(),
        expected.bytes
    );
}

#[test]
fn exported_module_names_keep_reference_punctuation_and_replace_separators() {
    for (name, cleaned) in [
        ("a ()[]{}!$%^#~,", "a ()[]{}!$%^#~,"),
        ("a/b\\c:d*e?f", "a_b_c_d_e_f"),
        ("模块é", "___"),
    ] {
        let (mut bytes, isf) = fixture();
        bytes[0x30000..0x30010].fill(0);
        bytes[0x30000..0x30000 + name.len()].copy_from_slice(name.as_bytes());
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        let directory = tempfile::tempdir().unwrap();
        let result = linux
            .extract_module(&options(directory.path()), &Job::default())
            .unwrap();
        let filename = format!("kernel_module.{cleaned}.0x30000.elf");
        assert_eq!(result.rows[0][2], filename, "{name}");
        assert!(directory.path().join(filename).is_file());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}

#[test]
fn readable_empty_module_name_still_exports_elf() {
    let (mut bytes, isf) = fixture();
    bytes[0x30000..0x30010].fill(0);
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let directory = tempfile::tempdir().unwrap();
    let result = linux
        .extract_module(&options(directory.path()), &Job::default())
        .unwrap();
    assert_eq!(result.rows[0][2], "kernel_module..0x30000.elf");
    assert!(directory.path().join(&result.rows[0][2]).is_file());
}

#[test]
fn reconstructed_elf_contains_ordered_payloads_and_normalized_symbols() {
    let (bytes, isf) = fixture();
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let elf = linux
        .reconstructed_module_elf(0x30000, &Job::default())
        .unwrap();
    assert!(elf.padding.is_empty());
    assert_eq!(&elf.bytes[..7], b"\x7fELF\x02\x01\x01");
    let table = u64_at(&elf.bytes, 40) as usize;
    let headers = &elf.bytes[table..];
    assert_eq!(u16::from_le_bytes(elf.bytes[60..62].try_into().unwrap()), 6);
    assert_eq!(&elf.bytes[64..64 + 4096], &bytes[0x18000..0x19000]);
    assert_eq!(&elf.bytes[64 + 4096..64 + 8192], &bytes[0x19000..0x1a000]);
    let symtab = u64_at(headers, 4 * 64 + 24) as usize;
    assert_eq!(u64_at(&elf.bytes, symtab + 24 + 8), 3); // captured address becomes relative
    assert_eq!(elf.bytes[symtab + 24 + 4], 0x12); // named function, not loader's mangled type
    assert_eq!(u64_at(&elf.bytes, symtab + 48 + 8), 0); // unresolved external stays zero
    assert!(elf.terminal_section.is_none());
}
#[test]
fn padded_output_records_holes_and_atomic_export_never_overwrites() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x35008, 0x60000);
    put(&mut bytes, 0x31010, 0x50000);
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let directory = tempfile::tempdir().unwrap();
    let result = linux
        .extract_module(&options(directory.path()), &Job::default())
        .unwrap();
    assert!(!result.complete);
    assert_eq!(result.rows.len(), 1);
    let metadata = &result.kernel_identity["module_extract"];
    assert_eq!(metadata["padding"][0]["address"], json!(0x50000));
    assert_eq!(metadata["padding"][0]["length"], json!(0x10000));
    assert_eq!(metadata["terminal_section_assumed_64k"], ".data");
    let target = directory.path().join(&result.rows[0][2]);
    let original = std::fs::read(&target).unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(
        metadata["sha256"],
        format!("{:x}", Sha256::digest(&original))
    );
    let offset = metadata["padding"][0]["file_offset"].as_u64().unwrap() as usize;
    assert!(original[offset..offset + 0x10000].iter().all(|b| *b == 0));
    assert!(
        linux
            .extract_module(&options(directory.path()), &Job::default())
            .is_err()
    );
    assert_eq!(std::fs::read(&target).unwrap(), original);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
#[test]
fn out_of_allocation_sections_are_skipped_before_reading_stale_names() {
    let (mut bytes, isf) = fixture();
    let original = {
        let image = super::super::tests::image(&bytes);
        super::super::tests::engine(&image, &isf)
            .reconstructed_module_elf(0x30000, &Job::default())
            .unwrap()
            .bytes
    };
    put(&mut bytes, 0x31000, 5);
    put(&mut bytes, 0x31048, 0x70000); // unreadable name on a freed, zero-address init section
    put(&mut bytes, 0x31050, 0);
    let image = super::super::tests::image(&bytes);
    let elf = super::super::tests::engine(&image, &isf)
        .reconstructed_module_elf(0x30000, &Job::default())
        .unwrap();
    assert_eq!(elf.bytes, original);
}
#[test]
fn missing_symbol_table_and_cancellation_do_not_publish_a_file() {
    let (mut bytes, isf) = fixture();
    put(&mut bytes, 0x30018, 0x70000);
    let image = super::super::tests::image(&bytes);
    let linux = super::super::tests::engine(&image, &isf);
    let directory = tempfile::tempdir().unwrap();
    let job = Job::default();
    let result = linux
        .extract_module(&options(directory.path()), &job)
        .unwrap();
    assert!(!result.complete);
    assert!(result.rows.is_empty());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        linux
            .extract_module(&options(directory.path()), &job)
            .is_err()
    );
}
#[test]
fn reconstructed_elf32_uses_complete_header_section_and_symbol_layouts() {
    let (mut bytes, mut isf) = fixture();
    isf.data["base_types"]["pointer"]["size"] = json!(4);
    isf.data["user_types"]["Elf32_Sym"] = json!({"size":16,"fields":{
        "st_name":{"offset":0,"type":{"kind":"base","name":"u32"}},
        "st_value":{"offset":4,"type":{"kind":"base","name":"u32"}},
        "st_size":{"offset":8,"type":{"kind":"base","name":"u32"}},
        "st_info":{"offset":12,"type":{"kind":"base","name":"char"}},
        "st_other":{"offset":13,"type":{"kind":"base","name":"char"}},
        "st_shndx":{"offset":14,"type":{"kind":"base","name":"u16"}}
    }});
    bytes[0x32000..0x32048].fill(0);
    bytes[0x32010..0x32014].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x32014..0x32018].copy_from_slice(&0x18003u32.to_le_bytes());
    bytes[0x32018..0x3201c].copy_from_slice(&5u32.to_le_bytes());
    bytes[0x32020..0x32024].copy_from_slice(&7u32.to_le_bytes());
    // Adjacent bytes must not become the upper half of an allocator bound.
    bytes[0x35004..0x35008].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    bytes[0x3500c..0x35010].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    let image = super::super::tests::image(&bytes);
    let engine = super::super::tests::engine(&image, &isf);
    assert_eq!(
        engine.module_extraction_bounds().unwrap(),
        (vec![(0x18000, 0x1c000)], true)
    );
    let elf = engine
        .reconstructed_module_elf(0x30000, &Job::default())
        .unwrap();
    let u16_at = |at| u16::from_le_bytes(elf.bytes[at..at + 2].try_into().unwrap());
    let u32_at = |at| u32::from_le_bytes(elf.bytes[at..at + 4].try_into().unwrap()) as usize;
    assert_eq!(&elf.bytes[..5], b"\x7fELF\x01");
    assert_eq!(u16_at(18), 3);
    assert_eq!(u16_at(40), 52);
    assert_eq!(u16_at(46), 40);
    assert_eq!(u16_at(48), 6);
    assert_eq!(u16_at(50), 5);
    let headers = u32_at(32);
    assert_eq!(&elf.bytes[headers..headers + 40], &[0; 40]);
    assert_eq!(u32_at(headers + 40 + 16), 52);
    let sym_header = headers + 4 * 40;
    assert_eq!(u32_at(sym_header + 20), 48);
    assert_eq!(u32_at(sym_header + 36), 16);
    let sym = u32_at(sym_header + 16);
    assert_eq!(elf.bytes[sym + 12], 3);
    assert_eq!(u32_at(sym + 16), 1);
    assert_eq!(u32_at(sym + 20), 3);
    assert_eq!(u32_at(sym + 24), 5);
    assert_eq!(elf.bytes[sym + 28], 0x12);
    assert_eq!(u16_at(sym + 30), 2);
    assert_eq!(u32_at(sym + 32), 7);
    assert_eq!(elf.bytes[sym + 44], 0x10);
}
#[test]
fn section_pointer_arrays_use_isf_width_and_stop_at_four_byte_null() {
    for field in ["attrs", "bin_attrs"] {
        let (mut bytes, mut isf) = fixture();
        isf.data["base_types"]["pointer"]["size"] = json!(4);
        isf.data["user_types"]["module_sect_attrs"]["fields"]
            .as_object_mut()
            .unwrap()
            .remove("nsections");
        isf.data["user_types"]["module_sect_attrs"]["fields"]["grp"] =
            json!({"offset":0,"type":{"kind":"struct","name":"attribute_group"}});
        isf.data["user_types"]["attribute_group"] = json!({"size":4,"fields":{
            field:{"offset":0,"type":{"kind":"pointer"}}
        }});
        put(&mut bytes, 0x31000, 0x36000);
        // Four populated slots, then a four-byte null with a nonzero neighbor.
        // Eight-byte reads would merge slots and miss the terminator.
        for index in 0..4 {
            bytes[0x36000 + index * 4..0x36004 + index * 4]
                .copy_from_slice(&(0x38000u32 + index as u32 * 4).to_le_bytes());
        }
        bytes[0x36010..0x36014].fill(0);
        bytes[0x36014..0x36018].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        let image = super::super::tests::image(&bytes);
        let sections = super::super::tests::engine(&image, &isf)
            .module_sections(0x30000, None, &Job::default())
            .unwrap();
        assert_eq!(sections.len(), 4, "grp.{field}");
        assert_eq!(sections[0].name, ".data");
        assert_eq!(sections[1].name, ".text");
    }
}
#[test]
fn newer_kallsyms_bin_attributes_and_section_count_match_old_layout() {
    let (mut bytes, mut isf) = fixture();
    let original = {
        let image = super::super::tests::image(&bytes);
        super::super::tests::engine(&image, &isf)
            .reconstructed_module_elf(0x30000, &Job::default())
            .unwrap()
            .bytes
    };
    let fields = isf.data["user_types"]["module"]["fields"]
        .as_object_mut()
        .unwrap();
    for field in ["symtab", "strtab", "num_symtab"] {
        fields.remove(field);
    }
    fields.insert("kallsyms".into(),json!({"offset":24,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"mod_kallsyms"}}}));
    isf.data["user_types"]["mod_kallsyms"] = json!({"size":24,"fields":{
        "symtab":{"offset":0,"type":{"kind":"pointer"}},"strtab":{"offset":8,"type":{"kind":"pointer"}},
        "num_symtab":{"offset":16,"type":{"kind":"base","name":"u64"}}
    }});
    put(&mut bytes, 0x30018, 0x37000);
    put(&mut bytes, 0x37000, 0x32000);
    put(&mut bytes, 0x37008, 0x33000);
    put(&mut bytes, 0x37010, 3);
    isf.data["user_types"]["module_sect_attrs"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("nsections");
    isf.data["user_types"]["module_sect_attrs"]["fields"]["grp"] =
        json!({"offset":0,"type":{"kind":"struct","name":"attribute_group"}});
    isf.data["user_types"]["attribute_group"] =
        json!({"size":8,"fields":{"bin_attrs":{"offset":0,"type":{"kind":"pointer"}}}});
    put(&mut bytes, 0x31000, 0x36000);
    for index in 0..4 {
        put(&mut bytes, 0x36000 + index * 8, 0x38000 + index as u64 * 8);
    }
    isf.data["user_types"]["module_sect_attr"]["fields"]["battr"] =
        json!({"offset":0,"type":{"kind":"struct","name":"bin_attribute"}});
    isf.data["user_types"]["bin_attribute"] = json!({"size":8,"fields":{"attr":{"offset":0,"type":{"kind":"struct","name":"attribute"}}}});
    isf.data["user_types"]["attribute"] =
        json!({"size":8,"fields":{"name":{"offset":0,"type":{"kind":"pointer"}}}});
    let image = super::super::tests::image(&bytes);
    let modern = super::super::tests::engine(&image, &isf)
        .reconstructed_module_elf(0x30000, &Job::default())
        .unwrap();
    assert_eq!(modern.bytes, original);
}
