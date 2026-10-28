//! Reconstruct a reference-compatible ELF from captured module sections/symbols.
//! This is a reconstructed analysis artifact, never the original on-disk module.
use super::*;
use crate::dump::{DumpOptions, MAX_DUMP_BYTES};
use serde::Serialize;

#[derive(Clone)]
pub(super) struct ModuleSection {
    pub name: String,
    pub address: u64,
}
pub(super) struct ModuleSymbols {
    pub table: u64,
    pub strings: u64,
    pub count: u64,
}
#[derive(Serialize)]
struct Padding {
    section: String,
    address: u64,
    length: u64,
    file_offset: u64,
}
struct Section {
    name: String,
    address: u64,
    offset: u64,
    bytes: Vec<u8>,
}
struct Elf {
    bytes: Vec<u8>,
    padding: Vec<Padding>,
    terminal_section: Option<String>,
}
fn append(target: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    ensure!(
        target
            .len()
            .checked_add(bytes.len())
            .is_some_and(|n| n as u64 <= MAX_DUMP_BYTES),
        "重建 ELF 超过 256 MiB 上限"
    );
    target.extend_from_slice(bytes);
    Ok(())
}
fn section_header(name_offset: u32, section: &Section, strings: u32, symbols: u32) -> Vec<u8> {
    let name = section.name.as_str();
    let kind: u32 = if name.contains(".rela.") {
        4
    } else {
        match name {
            ".symtab" => 2,
            ".strtab" | ".shstrtab" => 3,
            ".note.gnu.build-id" => 7,
            _ => 1,
        }
    };
    let flags: u64 = 2 | match name {
        ".text" | ".init.text" | ".exit.text" | ".static_call.text" => 4,
        ".data"
        | ".init.data"
        | ".exit.data"
        | ".bss"
        | "__tracepoints"
        | ".data.once"
        | "_ftrace_events"
        | ".gnu.linkonce.this_module" => 1,
        _ => 0,
    };
    let link = if name.contains(".rela.") {
        symbols
    } else if kind == 2 {
        strings
    } else {
        0
    };
    let entsize: u64 = if name.contains(".rela.") || kind == 2 {
        24
    } else {
        0
    };
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&name_offset.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    for value in [
        flags,
        section.address,
        section.offset,
        section.bytes.len() as u64,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&link.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u64.to_le_bytes());
    bytes.extend_from_slice(&entsize.to_le_bytes());
    bytes
}
impl Linux<'_> {
    /// Resolve old direct symbol tables and newer mod_kallsyms pointers once.
    pub(super) fn module_symbols(&self, module: u64) -> Result<ModuleSymbols> {
        let (base, ty) = if self.isf.has_field("module", "kallsyms") {
            let base = self.number(module, "module", "kallsyms")?;
            ensure!(base != 0, "module.kallsyms 为空");
            let ty = self.isf.field("module", "kallsyms")?["type"]["subtype"]["name"]
                .as_str()
                .context("module.kallsyms 类型缺失")?;
            (base, ty)
        } else {
            (module, "module")
        };
        let table = self.number(base, ty, "symtab")?;
        let strings = self.number(base, ty, "strtab")?;
        let count = self.number(base, ty, "num_symtab")?;
        ensure!(
            table != 0 && strings != 0 && (1..=OBJECT_LIMIT).contains(&count),
            "模块符号表指针/数量无效"
        );
        Ok(ModuleSymbols {
            table,
            strings,
            count,
        })
    }
    pub(super) fn module_sections(
        &self,
        module: u64,
        ranges: Option<&[(u64, u64)]>,
        job: &Job,
    ) -> Result<Vec<ModuleSection>> {
        let attrs = self.number(module, "module", "sect_attrs")?;
        ensure!(attrs != 0, "module.sect_attrs 为空");
        let count = if self.isf.has_field("module_sect_attrs", "nsections") {
            self.number(attrs, "module_sect_attrs", "nsections")?
        } else {
            let field = if self.isf.has_field("module_sect_attrs", "grp.bin_attrs") {
                "grp.bin_attrs"
            } else {
                "grp.attrs"
            };
            let array = self.number(attrs, "module_sect_attrs", field)?;
            ensure!(array != 0, "模块 section 属性数组为空");
            let mut count = 0;
            loop {
                job.check()?;
                ensure!(count < 100, "模块 section 属性超过 100 项上限");
                if self.vm.uint(add(array, count * 8)?, 8)? == 0 {
                    break;
                }
                count += 1;
            }
            count
        };
        ensure!(
            (1..=4096).contains(&count),
            "模块 section 数量无效/超过 4096 项"
        );
        let array = self.field_address(attrs, "module_sect_attrs", "attrs")?;
        ensure!(
            self.isf.field("module_sect_attrs", "attrs")?["type"]["kind"] == "array",
            "模块 section attrs 不是内联数组"
        );
        let size = self.isf.data["user_types"]["module_sect_attr"]["size"]
            .as_u64()
            .context("module_sect_attr size 缺失")?;
        ensure!((1..=4096).contains(&size), "module_sect_attr size 无效");
        let mut sections = Vec::new();
        for index in 0..count {
            job.check()?;
            let section = add(array, index * size)?;
            let address = self.number(section, "module_sect_attr", "address")?;
            // Freed init sections can retain unusable name pointers. As in the
            // reference, exclude out-of-allocation addresses before reading names.
            if ranges.is_some_and(|ranges| {
                !ranges
                    .iter()
                    .any(|(start, end)| *start <= address && address < *end)
            }) {
                continue;
            }
            let name = if self.isf.has_field("module_sect_attr", "battr") {
                self.kernel_text(
                    self.number(section, "module_sect_attr", "battr.attr.name")?,
                    255,
                )?
            } else {
                let read = (|| -> Result<String> {
                    if self.isf.field("module_sect_attr", "name")?["type"]["kind"] == "array" {
                        self.string(section, "module_sect_attr", "name")
                    } else {
                        self.kernel_text(self.number(section, "module_sect_attr", "name")?, 255)
                    }
                })();
                read.or_else(|_| {
                    self.kernel_text(
                        self.number(section, "module_sect_attr", "mattr.attr.name")?,
                        255,
                    )
                })?
            };
            ensure!(
                !name.is_empty() && name.len() <= 255 && !name.bytes().any(|b| b < 32 || b == 127),
                "模块 section 名称无效"
            );
            sections.push(ModuleSection { name, address });
        }
        Ok(sections)
    }
    /// ELF payload padding is explicit and separate from ordinary VM reads.
    fn module_section_data(
        &self,
        name: &str,
        address: u64,
        length: u64,
        string_table: bool,
        job: &Job,
    ) -> Result<(Vec<u8>, Vec<Padding>)> {
        ensure!(
            length <= MAX_DUMP_BYTES,
            "模块 section 读取超过 256 MiB 上限"
        );
        add(address, length)?;
        let mut bytes = Vec::new();
        let mut padding: Vec<Padding> = Vec::new();
        while (bytes.len() as u64) < length {
            job.check()?;
            let at = add(address, bytes.len() as u64)?;
            let count = (4096 - (at & 4095)).min(length - bytes.len() as u64) as usize;
            let mut page = vec![0; count];
            if self.vm.read(at, &mut page).is_err() {
                page.fill(0);
                if let Some(last) = padding.last_mut().filter(|p| p.address + p.length == at) {
                    last.length += count as u64;
                } else {
                    padding.push(Padding {
                        section: name.into(),
                        address: at,
                        length: count as u64,
                        file_offset: bytes.len() as u64,
                    });
                }
            }
            let previous = bytes.len();
            append(&mut bytes, &page)?;
            if string_table
                && let Some(end) = bytes[previous.saturating_sub(1)..]
                    .windows(2)
                    .position(|b| b == [0, 0])
            {
                bytes.truncate(previous.saturating_sub(1) + end + 1);
                break;
            }
        }
        let end = add(address, bytes.len() as u64)?;
        padding.retain_mut(|p| {
            p.length = p.length.min(end.saturating_sub(p.address));
            p.length > 0
        });
        Ok((bytes, padding))
    }
    fn reconstructed_module_elf(&self, module: u64, job: &Job) -> Result<Elf> {
        ensure!(
            !self.arm64(),
            "不支持: ModuleExtract 的参考 ELF 格式仅适用于 x86_64"
        );
        ensure!(
            self.isf.data["base_types"]["pointer"]["size"]
                .as_u64()
                .unwrap_or(8)
                == 8,
            "不支持: ModuleExtract 尚未实现 32 位 ELF 重建"
        );
        let symbols = self.module_symbols(module)?;
        let (ranges, proven) = self.module_extraction_bounds()?;
        ensure!(proven, "模块提取需要分配器边界");
        let mut original: Vec<ModuleSection> = Vec::new();
        for section in self.module_sections(module, Some(&ranges), job)? {
            if !ranges
                .iter()
                .any(|(start, end)| *start <= section.address && section.address < *end)
            {
                continue;
            }
            if let Some(existing) = original.iter_mut().find(|s| s.address == section.address) {
                existing.name = section.name;
            } else {
                original.push(section);
            }
        }
        ensure!(!original.is_empty(), "没有分配器范围内的模块 section");
        let mut ordered = original.clone();
        ordered.sort_by_key(|s| s.address);
        let mut sections = Vec::new();
        let mut sizes = BTreeMap::new();
        let mut offset = 64u64;
        let mut strtab_index = None;
        let mut symtab_address = None;
        let mut padding = Vec::new();
        let mut terminal_section = None;
        for (index, section) in ordered.iter().enumerate() {
            job.check()?;
            if section.name == ".symtab" {
                symtab_address = Some(section.address);
                continue;
            }
            let (address, length, strings) = if section.name == ".strtab" {
                strtab_index = Some(index as u32);
                (
                    symbols.strings,
                    symbols.count.checked_mul(256).context("strtab size 溢出")?,
                    true,
                )
            } else {
                let length = if let Some(next) = ordered.get(index + 1) {
                    next.address - section.address
                } else {
                    terminal_section = Some(section.name.clone());
                    0x10000
                };
                (section.address, length, false)
            };
            ensure!(
                add(offset, length)? <= MAX_DUMP_BYTES,
                "模块 section 总量超过 256 MiB 上限"
            );
            let (bytes, holes) =
                self.module_section_data(&section.name, address, length, strings, job)?;
            sizes.insert(section.address, bytes.len() as u64);
            for mut hole in holes {
                hole.file_offset = add(offset, hole.file_offset)?;
                padding.push(hole);
            }
            sections.push(Section {
                name: section.name.clone(),
                address: section.address,
                offset,
                bytes,
            });
            offset = add(offset, sections.last().unwrap().bytes.len() as u64)?;
        }
        let symtab_address = symtab_address.context("模块缺少 .symtab section")?;
        let strtab_index = strtab_index.context("模块缺少 .strtab section")?;
        let symtab_index = sections.len() as u32;
        let sym_size = self.isf.data["user_types"]["Elf64_Sym"]["size"]
            .as_u64()
            .context("Elf64_Sym 类型缺失")?;
        ensure!(sym_size == 24, "Elf64_Sym 布局大小无效");
        let mut table = Vec::new();
        let mut lookup_budget = 16_000_000u64;
        for index in 0..symbols.count {
            job.check()?;
            let at = add(symbols.table, index * 24)?;
            let name = u32::try_from(self.number(at, "Elf64_Sym", "st_name")?)?;
            let other = u8::try_from(self.number(at, "Elf64_Sym", "st_other")?)?;
            let size = self.number(at, "Elf64_Sym", "st_size")?;
            let address = self.number(at, "Elf64_Sym", "st_value")?;
            let mut matched = None;
            for (index, section) in original.iter().enumerate() {
                ensure!(lookup_budget > 0, "模块符号 section 查找超过 1600 万次上限");
                lookup_budget -= 1;
                if section.name != ".symtab"
                    && section.address <= address
                    && sizes
                        .get(&section.address)
                        .is_some_and(|size| address - section.address < *size)
                {
                    matched = Some((index, section));
                    break;
                }
            }
            let (value, shndx) = if let Some((index, section)) = matched {
                (address - section.address, u16::try_from(index + 1)?)
            } else {
                (
                    address,
                    u16::try_from(self.number(at, "Elf64_Sym", "st_shndx")?)?,
                )
            };
            let info: u8 = if name == 0 {
                3
            } else {
                0x10 | if address == 0 {
                    0
                } else if let Some((_, s)) = matched {
                    if s.name.contains(".text") && !s.name.contains(".rela") {
                        2
                    } else {
                        1
                    }
                } else {
                    0
                }
            };
            append(&mut table, &name.to_le_bytes())?;
            append(&mut table, &[info, other])?;
            append(&mut table, &shndx.to_le_bytes())?;
            append(&mut table, &value.to_le_bytes())?;
            append(&mut table, &size.to_le_bytes())?;
        }
        sections.push(Section {
            name: ".symtab".into(),
            address: symtab_address,
            offset,
            bytes: table,
        });
        let mut names = vec![0];
        let mut headers = vec![0; 64];
        let mut name_offset = 1u32;
        for section in &sections {
            append(
                &mut headers,
                &section_header(name_offset, section, strtab_index, symtab_index),
            )?;
            append(&mut names, section.name.as_bytes())?;
            append(&mut names, &[0])?;
            name_offset = name_offset
                .checked_add(u32::try_from(section.name.chars().count() + 1)?)
                .context("section name offset 溢出")?;
        }
        append(&mut names, b".shstrtab\0")?;
        let last = sections.last().context("没有 ELF section")?;
        let names_section = Section {
            name: ".shstrtab".into(),
            address: 0,
            offset: add(last.offset, last.bytes.len() as u64)?,
            bytes: names,
        };
        append(
            &mut headers,
            &section_header(name_offset, &names_section, strtab_index, symtab_index),
        )?;
        let shstrndx = u16::try_from(sections.len() + 1)?;
        sections.push(names_section);
        let mut output = vec![0; 64];
        for section in sections {
            append(&mut output, &section.bytes)?;
        }
        let shoff = output.len() as u64;
        append(&mut output, &headers)?;
        output[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        output[16..18].copy_from_slice(&1u16.to_le_bytes());
        output[18..20].copy_from_slice(&62u16.to_le_bytes());
        output[20..24].copy_from_slice(&1u32.to_le_bytes());
        output[40..48].copy_from_slice(&shoff.to_le_bytes());
        output[52..54].copy_from_slice(&64u16.to_le_bytes());
        output[58..60].copy_from_slice(&64u16.to_le_bytes());
        output[60..62].copy_from_slice(&(shstrndx + 1).to_le_bytes());
        output[62..64].copy_from_slice(&shstrndx.to_le_bytes());
        Ok(Elf {
            bytes: output,
            padding,
            terminal_section,
        })
    }
    pub(crate) fn extract_module(&self, options: &DumpOptions, job: &Job) -> Result<Results> {
        let requested_base = options
            .start
            .context("ModuleExtract 必须填写 --base / Start（struct module 地址）")?;
        // Volatility's Intel layer also accepts a masked 48-bit kernel address.
        // Preserve the requested address in row/filename, canonicalize only reads.
        let module = if requested_base < (1u64 << 48) && requested_base & (1u64 << 47) != 0 {
            requested_base | 0xffff_0000_0000_0000
        } else {
            requested_base
        };
        let mut result = self.result(Plugin::ModuleExtract);
        let elf = match self.reconstructed_module_elf(module, job) {
            Ok(elf) => elf,
            Err(error) => {
                job.check()?;
                partial(&mut result, format!("module {module:#x}"), error);
                return Ok(result);
            }
        };
        let name = self.string(module, "module", "name")?;
        ensure!(!name.is_empty(), "模块名称为空");
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._-".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let filename = format!("kernel_module.{name}.{requested_base:#x}.elf");
        crate::dump::directory(&options.directory)?;
        let target = options.directory.join(&filename);
        let digest = crate::dump::write_artifact(&target, &elf.bytes, job)?;
        if !elf.padding.is_empty() {
            partial(
                &mut result,
                "模块 ELF 补零",
                anyhow::anyhow!(
                    "{} 个缺失范围已按参考重建格式补零；范围详见 module_extract 元数据",
                    elf.padding.len()
                ),
            );
        }
        if !result.kernel_identity.is_object() {
            result.kernel_identity = serde_json::json!({});
        }
        if let Some(identity) = result.kernel_identity.as_object_mut() {
            identity.insert("module_extract".into(),serde_json::json!({"schema_version":1,"reconstructed":true,"requested_base":hex(requested_base),"module_address":hex(module),"path":target.display().to_string(),"sha256":digest,"padding":elf.padding,"terminal_section_assumed_64k":elf.terminal_section,"size_inference":"adjacent section addresses"}));
        }
        result.rows.push(vec![
            hex(requested_base),
            elf.bytes.len().to_string(),
            filename,
        ]);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn put(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
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
}
