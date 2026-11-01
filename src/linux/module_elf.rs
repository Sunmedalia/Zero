//! Reconstruct a reference-compatible ELF from captured module sections/symbols.
//! This is a reconstructed analysis artifact, never the original on-disk module.
use super::*;
use crate::bytes::{Checked as _, JsonKey as _};
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
struct SymbolRecord {
    name: u32,
    address: u64,
    size: u64,
    other: u8,
    shndx: u16,
}
impl SymbolRecord {
    fn encode(&self, elf32: bool, matched: Option<(&str, u64, u16)>) -> Result<Vec<u8>> {
        let value = matched.map_or(self.address, |(_, base, _)| self.address - base);
        let shndx = matched.map_or(self.shndx, |(_, _, index)| index);
        let info = if self.name == 0 {
            3
        } else {
            0x10 | if self.address == 0 {
                0
            } else if let Some((name, _, _)) = matched {
                if name.contains(".text") && !name.contains(".rela") {
                    2
                } else {
                    1
                }
            } else {
                0
            }
        };
        let mut bytes = self.name.to_le_bytes().to_vec();
        if elf32 {
            bytes.extend_from_slice(&u32::try_from(value)?.to_le_bytes());
            bytes.extend_from_slice(&u32::try_from(self.size)?.to_le_bytes());
            bytes.extend_from_slice(&[info, self.other]);
            bytes.extend_from_slice(&shndx.to_le_bytes());
        } else {
            bytes.extend_from_slice(&[info, self.other]);
            bytes.extend_from_slice(&shndx.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&self.size.to_le_bytes());
        }
        Ok(bytes)
    }
}
fn section_header_width(
    name_offset: u32,
    section: &Section,
    strings: u32,
    symbols: u32,
    elf32: bool,
) -> Result<Vec<u8>> {
    section_header_sized(
        name_offset,
        section,
        strings,
        symbols,
        elf32,
        section.bytes.len() as u64,
    )
}
fn section_header_sized(
    name_offset: u32,
    section: &Section,
    strings: u32,
    symbols: u32,
    elf32: bool,
    size: u64,
) -> Result<Vec<u8>> {
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
    let entsize: u64 = if name.contains(".rela.") {
        24
    } else if kind == 2 {
        if elf32 { 16 } else { 24 }
    } else {
        0
    };
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&name_offset.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    for value in [flags, section.address, section.offset, size] {
        if elf32 {
            bytes.extend_from_slice(
                &u32::try_from(value)
                    .context("ELF32 section 字段溢出")?
                    .to_le_bytes(),
            );
        } else {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&link.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    if elf32 {
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(entsize).unwrap_or(u32::MAX).to_le_bytes());
    } else {
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&entsize.to_le_bytes());
    }
    Ok(bytes)
}
fn elf_header(elf32: bool, shoff: u64, shstrndx: u16) -> Result<Vec<u8>> {
    let mut output = vec![0; if elf32 { 52 } else { 64 }];
    output
        .at_mut(..16)?
        .copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    *output.at_mut(4)? = if elf32 { 1 } else { 2 };
    output.at_mut(16..18)?.copy_from_slice(&1u16.to_le_bytes());
    output
        .at_mut(18..20)?
        .copy_from_slice(&(if elf32 { 3u16 } else { 62u16 }).to_le_bytes());
    output.at_mut(20..24)?.copy_from_slice(&1u32.to_le_bytes());
    let count = shstrndx.checked_add(1).context("ELF section 数量溢出")?;
    if elf32 {
        output
            .at_mut(32..36)?
            .copy_from_slice(&u32::try_from(shoff)?.to_le_bytes());
        output.at_mut(40..42)?.copy_from_slice(&52u16.to_le_bytes());
        output.at_mut(46..48)?.copy_from_slice(&40u16.to_le_bytes());
        output.at_mut(48..50)?.copy_from_slice(&count.to_le_bytes());
        output
            .at_mut(50..52)?
            .copy_from_slice(&shstrndx.to_le_bytes());
    } else {
        output.at_mut(40..48)?.copy_from_slice(&shoff.to_le_bytes());
        output.at_mut(52..54)?.copy_from_slice(&64u16.to_le_bytes());
        output.at_mut(58..60)?.copy_from_slice(&64u16.to_le_bytes());
        output.at_mut(60..62)?.copy_from_slice(&count.to_le_bytes());
        output
            .at_mut(62..64)?
            .copy_from_slice(&shstrndx.to_le_bytes());
    }
    Ok(output)
}
impl Linux<'_> {
    /// Resolve old direct symbol tables and newer mod_kallsyms pointers once.
    pub(super) fn module_symbols(&self, module: u64) -> Result<ModuleSymbols> {
        let (base, ty) = if self.isf.has_field("module", "kallsyms") {
            let base = self.number(module, "module", "kallsyms")?;
            ensure!(base != 0, "module.kallsyms 为空");
            let ty = self.isf.field("module", "kallsyms")?["type"].key("subtype")["name"]
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
            let width = self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .context("模块 section 属性指针宽度缺失")?;
            ensure!(matches!(width, 4 | 8), "模块 section 属性指针宽度无效");
            let mut count = 0;
            loop {
                job.check()?;
                ensure!(count < 100, "模块 section 属性超过 100 项上限");
                if self
                    .vm
                    .uint(add(array, count * width)?, usize::try_from(width)?)?
                    == 0
                {
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
            *self.isf.field("module_sect_attrs", "attrs")?["type"].key("kind") == "array",
            "模块 section attrs 不是内联数组"
        );
        let size = self.isf.data.key("user_types")["module_sect_attr"]
            .key("size")
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
                    if *self.isf.field("module_sect_attr", "name")?["type"].key("kind") == "array" {
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
            let count = usize::try_from((4096 - (at & 4095)).min(length - bytes.len() as u64))?;
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
                && let Some(end) = bytes
                    .at(previous.saturating_sub(1)..)?
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
            "不支持: ModuleExtract 的参考 ELF 格式仅适用于 Intel"
        );
        let width = self.isf.data.key("base_types")["pointer"]
            .key("size")
            .as_u64()
            .context("模块 ELF 指针宽度缺失")?;
        ensure!(matches!(width, 4 | 8), "模块 ELF 指针宽度无效");
        let elf32 = width == 4;
        let header_size = if elf32 { 52 } else { 64 };
        let section_size = if elf32 { 40 } else { 64 };
        let symbol_type = if elf32 { "Elf32_Sym" } else { "Elf64_Sym" };
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
        let mut offset = header_size as u64;
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
                strtab_index = Some(u32::try_from(index)?);
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
            let length = bytes.len() as u64;
            sections.push(Section {
                name: section.name.clone(),
                address: section.address,
                offset,
                bytes,
            });
            offset = add(offset, length)?;
        }
        let symtab_address = symtab_address.context("模块缺少 .symtab section")?;
        let strtab_index = strtab_index.context("模块缺少 .strtab section")?;
        let symtab_index = u32::try_from(sections.len())?;
        let sym_size = self.isf.data.key("user_types")[symbol_type]
            .key("size")
            .as_u64()
            .with_context(|| format!("{symbol_type} 类型缺失"))?;
        ensure!(
            sym_size == if elf32 { 16 } else { 24 },
            "{symbol_type} 布局大小无效"
        );
        let mut table = Vec::new();
        let mut lookup_budget = 16_000_000u64;
        for index in 0..symbols.count {
            job.check()?;
            let at = add(
                symbols.table,
                index.checked_mul(sym_size).context("符号偏移溢出")?,
            )?;
            let name = u32::try_from(self.number(at, symbol_type, "st_name")?)?;
            let other = u8::try_from(self.number(at, symbol_type, "st_other")?)?;
            let size = self.number(at, symbol_type, "st_size")?;
            let address = self.number(at, symbol_type, "st_value")?;
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
            let section = matched
                .map(|(index, section)| -> Result<_> {
                    Ok((
                        section.name.as_str(),
                        section.address,
                        u16::try_from(index + 1)?,
                    ))
                })
                .transpose()?;
            let symbol = SymbolRecord {
                name,
                address,
                size,
                other,
                shndx: if section.is_some() {
                    0
                } else {
                    u16::try_from(self.number(at, symbol_type, "st_shndx")?)?
                },
            };
            append(&mut table, &symbol.encode(elf32, section)?)?;
        }
        sections.push(Section {
            name: ".symtab".into(),
            address: symtab_address,
            offset,
            bytes: table,
        });
        let mut names = vec![0];
        let mut headers = vec![0; section_size];
        let mut name_offset = 1u32;
        for section in &sections {
            append(
                &mut headers,
                &section_header_width(name_offset, section, strtab_index, symtab_index, elf32)?,
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
            &section_header_width(
                name_offset,
                &names_section,
                strtab_index,
                symtab_index,
                elf32,
            )?,
        )?;
        let shstrndx = u16::try_from(sections.len() + 1)?;
        sections.push(names_section);
        let mut output = vec![0; header_size];
        for section in sections {
            append(&mut output, &section.bytes)?;
        }
        let shoff = output.len() as u64;
        append(&mut output, &headers)?;
        output
            .at_mut(..header_size)?
            .copy_from_slice(&elf_header(elf32, shoff, shstrndx)?);
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
        let name = self.module_name(module, job)?;
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._- ()[]{}!$%^#~,".contains(c) {
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
mod tests;
