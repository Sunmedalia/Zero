//! Bounded native enumeration of compressed core, module, ftrace and BPF symbols.
use super::*;
use crate::analysis::KallsymsOptions;

fn canonical(address: u64) -> u64 {
    if address < 1 << 48 && address & (1 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}
fn description(kind: &str) -> &'static str {
    match kind {
        "N" => "Symbol is a debugging symbol",
        "U" => "Symbol is undefined",
        "V" => "Symbol is a weak object, with a default value",
        "W" => {
            "Symbol is a weak symbol but not marked as a weak object symbol, with a default value"
        }
        _ => match kind.to_ascii_lowercase().as_str() {
            "a" => "Symbol is absolute and doesn't change during linking",
            "b" => {
                "Symbol in the BSS section, typically holding zero-initialized or uninitialized data"
            }
            "c" => "Symbol is common, typically holding uninitialized data",
            "d" => "Symbol is in the initialized data section",
            "g" => "Symbol is in an initialized data section for small objects",
            "i" => "Symbol is an indirect reference to another symbol",
            "n" => "Symbol is in a non-data, non-code, non-debug read-only section",
            "p" => "Symbol is in a stack unwind section",
            "r" => "Symbol is in a read only data section",
            "s" => {
                "Symbol is in an uninitialized or zero-initialized data section for small objects"
            }
            "t" => "Symbol is in the text (code) section",
            "u" => "Symbol is a unique global symbol",
            "v" => "Symbol is a weak object",
            "w" => "Symbol is a weak symbol but not marked as a weak object symbol",
            "?" => "Symbol type is unknown",
            _ => "",
        },
    }
}
fn global(kind: &str) -> Option<bool> {
    if kind.is_empty() {
        None
    } else {
        Some(kind.chars().any(char::is_uppercase) || matches!(kind, "u" | "v" | "w"))
    }
}
struct Symbol<'a> {
    address: u64,
    kind: &'a str,
    size: Option<u64>,
    exported: Option<bool>,
    source: &'a str,
    module: &'a str,
    name: &'a str,
}
fn push(result: &mut Results, budget: &mut u64, s: Symbol<'_>) -> Result<()> {
    let row = vec![
        hex(s.address),
        s.kind.into(),
        s.size
            .filter(|size| *size > 0)
            .map(|v| v.to_string())
            .unwrap_or_default(),
        s.exported.map(|v| v.to_string()).unwrap_or_default(),
        s.source.into(),
        s.module.into(),
        s.name.into(),
        description(s.kind).into(),
    ];
    let bytes = row.iter().map(|s| s.len() as u64).sum::<u64>();
    ensure!(
        result.rows.len() < LIMIT && *budget >= bytes,
        "Kallsyms 超过 100 万行或 128 MiB 文本上限"
    );
    *budget -= bytes;
    result.rows.push(row);
    Ok(())
}
struct CoreNames {
    names: u64,
    tokens: Vec<String>,
    index: [u16; 256],
}
impl CoreNames {
    fn decode(
        &self,
        linux: &Linux<'_>,
        offset: u64,
        job: &Job,
        budget: &mut u64,
    ) -> Result<(String, String, u64)> {
        let mut at = add(self.names, offset)?;
        let first = linux.vm.uint(at, 1)?;
        at = add(at, 1)?;
        let length = if first & 128 != 0 {
            let high = linux.vm.uint(at, 1)?;
            at = add(at, 1)?;
            (high << 7) | (first & 127)
        } else {
            first
        };
        ensure!((1..=32767).contains(&length), "kallsyms 压缩长度无效");
        ensure!(*budget >= length, "kallsyms 压缩解码总量超过 64 MiB 上限");
        *budget -= length;
        let mut text = String::new();
        for i in 0..length {
            job.check()?;
            let token = linux.vm.uint(add(at, i)?, 1)? as usize;
            let value = &self.tokens[usize::from(self.index[token])];
            ensure!(
                text.len() + value.len() <= 32768,
                "kallsyms 展开名称超过 32 KiB"
            );
            text.push_str(value);
        }
        let mut chars = text.chars();
        let kind = chars.next().context("kallsyms 类型为空")?.to_string();
        Ok((kind, chars.collect(), add(at - self.names, length)?))
    }
}
impl Linux<'_> {
    fn core_names(&self, job: &Job) -> Result<CoreNames> {
        let names = self.isf.address("kallsyms_names")?;
        let table = self.isf.address("kallsyms_token_table")?;
        let index_address = self.isf.address("kallsyms_token_index")?;
        let mut index = [0u16; 256];
        // Map byte offsets to compact entries, avoiding an allocation per offset.
        let mut offsets = BTreeMap::new();
        let mut tokens = Vec::new();
        for (i, entry) in index.iter_mut().enumerate() {
            job.check()?;
            let offset = self.vm.uint(add(index_address, i as u64 * 2)?, 2)?;
            let next = tokens.len();
            let mapped = if let Some(mapped) = offsets.get(&offset) {
                *mapped
            } else {
                let token = self.kernel_text(add(table, offset)?, 4096)?;
                tokens.push(token);
                offsets.insert(offset, next);
                next
            };
            *entry = u16::try_from(mapped)?;
        }
        Ok(CoreNames {
            names,
            tokens,
            index,
        })
    }
    fn core_symbol_addresses(
        &self,
        count: u64,
        result: &mut Results,
        job: &Job,
    ) -> Result<Vec<Option<u64>>> {
        if let Ok(offsets) = self.isf.address("kallsyms_offsets") {
            let base = self
                .vm
                .uint(self.isf.address("kallsyms_relative_base")?, 8)?;
            let anchors: HashSet<u64> = [
                "_stext",
                "_etext",
                "linux_banner",
                "_sinittext",
                "_einittext",
            ]
            .into_iter()
            .filter_map(|name| self.isf.address(name).ok())
            .filter(|address| *address != 0)
            .collect();
            let mut signed = Vec::with_capacity(count as usize);
            let mut unsigned = Vec::with_capacity(count as usize);
            let mut signed_hits = HashSet::new();
            let mut unsigned_hits = HashSet::new();
            for i in 0..count {
                job.check()?;
                let raw = self.vm.uint(add(offsets, i * 4)?, 4).ok().map(|v| v as u32);
                let signed_value = raw.and_then(|value| {
                    let value = value as i32;
                    if value < 0 {
                        base.checked_add((-1i64 - i64::from(value)) as u64)
                    } else {
                        Some(value as u64)
                    }
                });
                let unsigned_value = raw.and_then(|value| base.checked_add(u64::from(value)));
                for (value, hits) in [
                    (signed_value, &mut signed_hits),
                    (unsigned_value, &mut unsigned_hits),
                ] {
                    if let Some(value) = value
                        && anchors.contains(&value)
                    {
                        hits.insert(value);
                    }
                }
                signed.push(signed_value);
                unsigned.push(unsigned_value);
            }
            let signed_count = signed_hits.len();
            let unsigned_count = unsigned_hits.len();
            ensure!(
                signed_count.max(unsigned_count) >= 2 && signed_count != unsigned_count,
                "无法用至少两个独立 ISF 地址确认 kallsyms 相对地址配置（signed={signed_count}, unsigned={unsigned_count}）"
            );
            let unsigned_selected = unsigned_count > signed_count;
            if !result.kernel_identity.is_object() {
                result.kernel_identity = serde_json::json!({});
            }
            result.kernel_identity["kallsyms_address_mode"] = serde_json::json!({"mode":if unsigned_selected {"base-relative unsigned"}else{"absolute-percpu signed"},"anchor_matches":signed_count.max(unsigned_count)});
            Ok(if unsigned_selected { unsigned } else { signed })
        } else {
            let addresses = self
                .isf
                .address("kallsyms_addresses")
                .context("没有 kallsyms 地址表")?;
            let mut output = Vec::with_capacity(count as usize);
            for i in 0..count {
                job.check()?;
                output.push(self.vm.uint(add(addresses, i * 8)?, 8).ok());
            }
            Ok(output)
        }
    }
    fn core_kallsyms(&self, result: &mut Results, budget: &mut u64, job: &Job) -> Result<()> {
        let symbol = &self.isf.data["symbols"]["kallsyms_num_syms"];
        let width = self.isf.type_size(&symbol["type"])?;
        ensure!(matches!(width, 4 | 8), "kallsyms_num_syms 类型无效");
        let count = self
            .vm
            .uint(self.isf.address("kallsyms_num_syms")?, width as usize)?;
        ensure!(count > 0 && count <= OBJECT_LIMIT, "kallsyms 数量无效/超限");
        let names = self.core_names(job)?;
        let mask = if self.arm64() {
            u64::MAX
        } else {
            0x0000_ffff_ffff_ffff
        };
        let addresses = self
            .core_symbol_addresses(count, result, job)?
            .into_iter()
            .map(|address| address.map(|value| value & mask))
            .collect::<Vec<_>>();
        if let Some(index) = addresses
            .windows(2)
            .position(|pair| matches!((pair[0],pair[1]),(Some(a),Some(b)) if a>b))
        {
            partial(
                result,
                "kallsyms 地址顺序",
                anyhow::anyhow!("index {} 的地址不递增，尺寸信息可能受损", index + 1),
            );
        }
        let mut sizes = vec![None; count as usize];
        let mut i = 0;
        while i < addresses.len() {
            job.check()?;
            let Some(start) = addresses[i] else {
                i += 1;
                continue;
            };
            let mut end = i + 1;
            while end < addresses.len() && addresses[end] == Some(start) {
                end += 1;
            }
            let next = if end < addresses.len() {
                addresses[end]
            } else {
                let init = self
                    .isf
                    .address("_sinittext")
                    .ok()
                    .zip(self.isf.address("_einittext").ok())
                    .map(|(low, high)| (low & mask, high & mask));
                if let Some((low, high)) = init.filter(|(low, high)| *low <= start && start < *high)
                {
                    let _ = low;
                    Some(high)
                } else {
                    self.isf
                        .address("_end")
                        .or_else(|_| self.isf.address("_etext"))
                        .ok()
                        .map(|end| end & mask)
                }
            };
            let size = next
                .and_then(|next| next.checked_sub(start))
                .filter(|size| *size > 0);
            sizes[i..end].fill(size);
            i = end;
        }
        let unreadable = addresses.iter().filter(|a| a.is_none()).count();
        if unreadable > 0 {
            partial(
                result,
                "kallsyms 地址表",
                anyhow::anyhow!("{unreadable} 项无法读取；关联尺寸无法确认"),
            );
        }
        let mut index = 0usize;
        let mut offset = 0;
        let mut decode_budget = 64 * 1024 * 1024;
        while index < count as usize {
            job.check()?;
            let decoded = names.decode(self, offset, job, &mut decode_budget);
            match decoded {
                Ok((kind, name, next)) => {
                    if let Some(address) = addresses[index] {
                        push(
                            result,
                            budget,
                            Symbol {
                                address: if self.arm64() {
                                    address
                                } else {
                                    canonical(address)
                                },
                                kind: &kind,
                                size: sizes[index],
                                exported: global(&kind),
                                source: "core",
                                module: "kernel",
                                name: &name,
                            },
                        )?;
                    }
                    offset = next;
                    index += 1;
                }
                Err(error) => {
                    job.check()?;
                    let exhausted = error.to_string().contains("压缩解码总量");
                    partial(result, format!("kallsyms 名称 index {index}"), error);
                    if exhausted {
                        break;
                    }
                    let next = (index / 256 + 1) * 256;
                    if next >= count as usize {
                        break;
                    }
                    let marker = self.isf.address("kallsyms_markers").and_then(|base| {
                        self.vm
                            .uint(add(base, (next / 256) as u64 * width)?, width as usize)
                    });
                    match marker {
                        Ok(marker) => {
                            result
                                .diagnostics
                                .push(format!("kallsyms markers 恢复：跳过 index {index}..{next}"));
                            offset = marker;
                            index = next;
                        }
                        Err(_) => break,
                    }
                }
            }
            if index.is_multiple_of(4096) {
                job.report(format!("kallsyms core: {index}/{count}"));
            }
        }
        Ok(())
    }
    fn kernel_export(
        &self,
        module: u64,
        name: &str,
        address: u64,
        job: &Job,
    ) -> Result<Option<bool>> {
        let count = self.number(module, "module", "num_syms")?;
        if count == 0 {
            return Ok(Some(false));
        }
        ensure!(count <= OBJECT_LIMIT, "模块导出符号数量超过上限");
        let mut base = self.number(module, "module", "syms")?;
        let size = self.isf.data["user_types"]["kernel_symbol"]["size"]
            .as_u64()
            .context("kernel_symbol size 缺失")?;
        ensure!((1..=4096).contains(&size), "kernel_symbol size 无效");
        let mut remaining = count;
        while remaining > 0 {
            job.check()?;
            let at = add(base, remaining / 2 * size)?;
            let read_pointer = |field: &str, relative: &str| -> Result<u64> {
                if self.isf.has_field("kernel_symbol", relative) {
                    let value = self.number(at, "kernel_symbol", relative)? as u32 as i32;
                    // Preserve the reference object's masked-base relative semantics.
                    Ok((at
                        & if self.arm64() {
                            u64::MAX
                        } else {
                            0x0000_ffff_ffff_ffff
                        })
                    .wrapping_add_signed(i64::from(value)))
                } else {
                    self.number(at, "kernel_symbol", field)
                }
            };
            let other = self.kernel_text(canonical(read_pointer("name", "name_offset")?), 512)?;
            match name.cmp(other.as_str()) {
                std::cmp::Ordering::Equal => {
                    return Ok(Some(
                        read_pointer("value", "value_offset")?
                            == (address
                                & if self.arm64() {
                                    u64::MAX
                                } else {
                                    0x0000_ffff_ffff_ffff
                                }),
                    ));
                }
                std::cmp::Ordering::Greater => {
                    base = add(at, size)?;
                    remaining -= 1;
                }
                _ => {}
            }
            remaining /= 2;
        }
        Ok(None)
    }
    fn module_kallsyms(&self, result: &mut Results, budget: &mut u64, job: &Job) -> Result<()> {
        let mut attempts = OBJECT_LIMIT;
        for module in self.listed_modules(job)? {
            job.check()?;
            ensure!(attempts > 0, "模块符号读取超过 100 万项总上限");
            let read = (|| -> Result<()> {
                let name = self.string(module, "module", "name")?;
                let symbols = self.module_symbols(module)?;
                let types = if self.isf.has_field("module", "kallsyms") {
                    let kallsyms = self.number(module, "module", "kallsyms")?;
                    let ty = self.isf.field("module", "kallsyms")?["type"]["subtype"]["name"]
                        .as_str()
                        .context("mod_kallsyms 类型缺失")?;
                    if self.isf.has_field(ty, "typetab") {
                        Some(self.number(kallsyms, ty, "typetab")?)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let mut export_unreadable = false;
                let mut failed = 0u64;
                let mut first_error = String::new();
                for index in 0..symbols.count {
                    job.check()?;
                    ensure!(attempts > 0, "模块符号读取超过 100 万项总上限");
                    attempts -= 1;
                    let read = (|| -> Result<()> {
                        let symbol = add(symbols.table, index * 24)?;
                        let offset = self.number(symbol, "Elf64_Sym", "st_name")?;
                        let sym_name = self.kernel_text(add(symbols.strings, offset)?, 512)?;
                        if sym_name.is_empty() {
                            return Ok(());
                        }
                        let address = self.number(symbol, "Elf64_Sym", "st_value")?;
                        let size = self.number(symbol, "Elf64_Sym", "st_size")?;
                        let kind = self.vm.uint(
                            if let Some(types) = types {
                                add(types, index)?
                            } else {
                                self.field_address(symbol, "Elf64_Sym", "st_info")?
                            },
                            1,
                        )? as u8 as char;
                        let exported = if export_unreadable {
                            None
                        } else {
                            match self.kernel_export(module, &sym_name, address, job) {
                                Ok(value) => value,
                                Err(error) => {
                                    job.check()?;
                                    partial(result, format!("module {name} exports"), error);
                                    export_unreadable = true;
                                    None
                                }
                            }
                        };
                        let kind = if exported == Some(true) {
                            kind.to_ascii_uppercase()
                        } else {
                            kind.to_ascii_lowercase()
                        }
                        .to_string();
                        push(
                            result,
                            budget,
                            Symbol {
                                address,
                                kind: &kind,
                                size: Some(size),
                                exported,
                                source: "module",
                                module: &name,
                                name: &sym_name,
                            },
                        )
                    })();
                    if let Err(error) = read {
                        job.check()?;
                        if result.rows.len() >= LIMIT || *budget < 256 {
                            return Err(error);
                        }
                        failed += 1;
                        if first_error.is_empty() {
                            first_error = format!("symbol {index}: {error:#}");
                        }
                    }
                }
                if failed > 0 {
                    partial(
                        result,
                        format!("module {name} symbols"),
                        anyhow::anyhow!("{failed} 项无法读取；首处 {first_error}"),
                    );
                }
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(result, format!("module {module:#x} kallsyms"), error);
            }
        }
        Ok(())
    }
    fn ftrace_kallsyms(&self, result: &mut Results, budget: &mut u64, job: &Job) -> Result<()> {
        if self.isf.data["user_types"]["ftrace_mod_map"].is_object()
            && self.isf.data["user_types"]["ftrace_mod_func"].is_object()
        {
            for map in self.list_objects(
                self.isf.address("ftrace_mod_maps")?,
                self.isf.offset("ftrace_mod_map", "list")?,
                job,
            )? {
                let module = self.number(map, "ftrace_mod_map", "mod")?;
                let name = self.string(module, "module", "name")?;
                for function in self.list_objects(
                    self.field_address(map, "ftrace_mod_map", "funcs")?,
                    self.isf.offset("ftrace_mod_func", "list")?,
                    job,
                )? {
                    job.check()?;
                    let sym_name =
                        self.kernel_text(self.number(function, "ftrace_mod_func", "name")?, 512)?;
                    let address = self.number(function, "ftrace_mod_func", "ip")?;
                    let size = self.number(function, "ftrace_mod_func", "size")?;
                    push(
                        result,
                        budget,
                        Symbol {
                            address,
                            kind: "T",
                            size: Some(size),
                            exported: Some(true),
                            source: "ftrace",
                            module: &name,
                            name: &sym_name,
                        },
                    )?;
                }
            }
        }
        if let Ok(head) = self.isf.address("ftrace_ops_trampoline_list") {
            for ops in self.list_objects(head, self.isf.offset("ftrace_ops", "list")?, job)? {
                job.check()?;
                push(
                    result,
                    budget,
                    Symbol {
                        address: self.number(ops, "ftrace_ops", "trampoline")?,
                        kind: "t",
                        size: Some(self.number(ops, "ftrace_ops", "trampoline_size")?),
                        exported: Some(false),
                        source: "ftrace",
                        module: "__builtin__ftrace",
                        name: "ftrace_trampoline",
                    },
                )?;
            }
        }
        Ok(())
    }
    fn bpf_kallsyms(&self, result: &mut Results, budget: &mut u64, job: &Job) -> Result<()> {
        let Ok(head) = self.isf.address("bpf_kallsyms") else {
            return Ok(());
        };
        let modern = self.isf.data["user_types"]["bpf_ksym"].is_object();
        let (ty, member) = if modern {
            ("bpf_ksym", "lnode")
        } else if self.isf.data["user_types"]["bpf_prog_aux"].is_object() {
            ("bpf_prog_aux", "ksym_lnode")
        } else {
            return Ok(());
        };
        for object in self.list_objects(head, self.isf.offset(ty, member)?, job)? {
            job.check()?;
            let read = (|| -> Result<()> {
                let (name, address, size) = if modern {
                    let address = self.number(object, ty, "start")?;
                    (
                        self.string(object, ty, "name")?,
                        address,
                        self.number(object, ty, "end")?
                            .checked_sub(address)
                            .context("bpf_ksym 范围倒置")?,
                    )
                } else {
                    let program = self.number(object, ty, "prog")?;
                    ensure!(program != 0, "BPF prog 指针为空");
                    let aux = self.number(program, "bpf_prog", "aux")?;
                    ensure!(aux != 0, "BPF aux 指针为空");
                    let name = if self.isf.has_field(ty, "name") {
                        self.string(aux, ty, "name")?
                    } else {
                        String::new()
                    };
                    let address = self.number(program, "bpf_prog", "bpf_func")?;
                    let packed = self.isf.has_field(ty, "use_bpf_prog_pack")
                        && self.number(aux, ty, "use_bpf_prog_pack")? != 0;
                    let start = address & if packed { !63u64 } else { !4095u64 };
                    let pages = if self.isf.has_field("bpf_binary_header", "pages") {
                        self.number(start, "bpf_binary_header", "pages")?
                    } else {
                        self.vm.uint(start, 4)?
                    };
                    (
                        name,
                        address,
                        pages.checked_mul(4096).context("BPF 大小溢出")?,
                    )
                };
                push(
                    result,
                    budget,
                    Symbol {
                        address,
                        kind: "t",
                        size: Some(size),
                        exported: Some(false),
                        source: "bpf",
                        module: "bpf",
                        name: &name,
                    },
                )
            })();
            if let Err(error) = read {
                job.check()?;
                partial(result, format!("bpf symbol {object:#x}"), error);
            }
        }
        Ok(())
    }
    pub(super) fn kallsyms(&self, options: KallsymsOptions, job: &Job) -> Result<Results> {
        ensure!(
            self.isf.data["base_types"]["pointer"]["size"]
                .as_u64()
                .unwrap_or(8)
                == 8,
            "Kallsyms 当前仅支持 64 位内核"
        );
        let mut result = self.result(Plugin::Kallsyms);
        let mut budget = 128 * 1024 * 1024;
        let selected = options.selected();
        for (index, enabled) in selected.into_iter().enumerate() {
            if !enabled {
                continue;
            }
            job.check()?;
            let read = match index {
                0 => self.core_kallsyms(&mut result, &mut budget, job),
                1 => self.module_kallsyms(&mut result, &mut budget, job),
                2 => self.ftrace_kallsyms(&mut result, &mut budget, job),
                _ => self.bpf_kallsyms(&mut result, &mut budget, job),
            };
            if let Err(error) = read {
                job.check()?;
                partial(
                    &mut result,
                    format!("kallsyms {}", ["core", "module", "ftrace", "bpf"][index]),
                    error,
                );
            }
        }
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
    fn field(offset: u64) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"base","name":"u64"}})
    }
    fn chars(offset: u64, count: u64) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"array","count":count,"subtype":{"kind":"base","name":"char"}}})
    }
    fn list(offset: u64) -> serde_json::Value {
        json!({"offset":offset,"type":{"kind":"struct","name":"list_head"}})
    }
    fn fixture() -> (Vec<u8>, Isf) {
        let (mut bytes, mut isf) = super::super::tests::fixture();
        for (name, address) in [
            ("kallsyms_num_syms", 0x30000),
            ("kallsyms_addresses", 0x30010),
            ("kallsyms_names", 0x30100),
            ("kallsyms_token_table", 0x30200),
            ("kallsyms_token_index", 0x30300),
            ("_end", 0x18040),
            ("_stext", 0x18000),
            ("_etext", 0x18010),
            ("modules", 0x31000),
        ] {
            isf.data["symbols"][name] =
                json!({"address":address,"type":{"kind":"base","name":"u64"}});
        }
        put(&mut bytes, 0x30000, 4);
        for (i, address) in [0x18000, 0x18000, 0x18010, 0x18020].into_iter().enumerate() {
            put(&mut bytes, 0x30010 + i * 8, address);
        }
        bytes[0x30100..0x30108].copy_from_slice(&[1, 0, 1, 1, 1, 2, 1, 3]);
        let mut offset = 0;
        for (index, token) in [b"Tentry".as_slice(), b"talias", b"Dvalue", b"tlast"]
            .into_iter()
            .enumerate()
        {
            bytes[0x30200 + offset..0x30200 + offset + token.len()].copy_from_slice(token);
            bytes[0x30300 + index * 2..0x30302 + index * 2]
                .copy_from_slice(&(offset as u16).to_le_bytes());
            offset += token.len() + 1;
        }
        isf.data["user_types"]["module"] = json!({"size":72,"fields":{"list":list(0),"name":chars(16,16),"symtab":field(32),"strtab":field(40),"num_symtab":field(48),"num_syms":field(56),"syms":field(64)}});
        isf.data["user_types"]["Elf64_Sym"] = json!({"size":24,"fields":{"st_name":{"offset":0,"type":{"kind":"base","name":"u32"}},"st_info":{"offset":4,"type":{"kind":"base","name":"char"}},"st_value":field(8),"st_size":field(16)}});
        for (at, value) in [
            (0x31000, 0x32000),
            (0x31008, 0x32000),
            (0x32000, 0x31000),
            (0x32008, 0x31000),
            (0x32020, 0x33000),
            (0x32028, 0x34000),
            (0x32030, 2),
            (0x33020, 0x18001),
            (0x33028, 4),
        ] {
            put(&mut bytes, at, value);
        }
        bytes[0x32010..0x32013].copy_from_slice(b"mod");
        bytes[0x34000..0x34006].copy_from_slice(b"\0work\0");
        bytes[0x33018..0x3301c].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x3301c] = b'T';
        (bytes, isf)
    }
    #[test]
    fn absolute_addresses_alias_sizes_and_module_symbols_are_independent() {
        let (bytes, isf) = fixture();
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        let result = linux
            .kallsyms(
                KallsymsOptions {
                    core: true,
                    modules: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 5);
        assert_eq!(
            &result.rows[0][1..7],
            ["T", "16", "true", "core", "kernel", "entry"]
        );
        assert_eq!(result.rows[1][2], "16");
        assert_eq!(result.rows[3][2], "32");
        assert_eq!(
            &result.rows[4][1..7],
            ["t", "4", "false", "module", "mod", "work"]
        );
    }
    #[test]
    fn relative_absolute_percpu_offsets_decode_signed_and_absolute_entries() {
        let (mut bytes, mut isf) = fixture();
        isf.data["symbols"]["kallsyms_offsets"] = json!({"address":0x30600});
        isf.data["symbols"]["kallsyms_relative_base"] = json!({"address":0x30700});
        put(&mut bytes, 0x30700, 0x18000);
        for (index, offset) in [5i32, -1, -17, -33].into_iter().enumerate() {
            bytes[0x30600 + index * 4..0x30604 + index * 4].copy_from_slice(&offset.to_le_bytes());
        }
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    core: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete);
        assert_eq!(result.rows[0][0], hex(5));
        assert_eq!(result.rows[1][0], hex(0x18000));
        assert_eq!(result.rows[2][0], hex(0x18010));
    }
    #[test]
    fn unsigned_relative_offsets_require_independent_anchor_matches() {
        let (mut bytes, mut isf) = fixture();
        isf.data["symbols"]["kallsyms_offsets"] = json!({"address":0x30600});
        isf.data["symbols"]["kallsyms_relative_base"] = json!({"address":0x30700});
        put(&mut bytes, 0x30700, 0x18000);
        for (index, value) in [0u32, 16, 32, 64].into_iter().enumerate() {
            bytes[0x30600 + index * 4..0x30604 + index * 4].copy_from_slice(&value.to_le_bytes());
        }
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    core: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows[0][0], hex(0x18000));
        assert_eq!(
            result.kernel_identity["kallsyms_address_mode"]["mode"],
            "base-relative unsigned"
        );
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("_stext");
        isf.data["symbols"]
            .as_object_mut()
            .unwrap()
            .remove("_etext");
        let unknown = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    core: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(!unknown.complete);
        assert!(unknown.rows.is_empty());
    }
    #[test]
    fn extended_compressed_lengths_advance_past_both_header_bytes() {
        let (mut bytes, isf) = fixture();
        let stream = &mut bytes[0x30100..0x30200];
        stream.fill(0);
        stream[0] = 0x81;
        stream[1] = 1;
        stream[131..137].copy_from_slice(&[1, 1, 1, 2, 1, 3]);
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    core: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete);
        assert_eq!(result.rows[0][6].len(), 129 * 6 - 1);
        assert_eq!(result.rows[1][6], "alias");
    }
    #[test]
    fn ftrace_maps_trampolines_and_bpf_have_positive_symbols() {
        let (mut bytes, mut isf) = fixture();
        for (name, address) in [
            ("ftrace_mod_maps", 0x35000),
            ("ftrace_ops_trampoline_list", 0x35500),
            ("bpf_kallsyms", 0x36000),
        ] {
            isf.data["symbols"][name] = json!({"address":address});
        }
        isf.data["user_types"]["ftrace_mod_map"] =
            json!({"size":40,"fields":{"list":list(0),"funcs":list(16),"mod":field(32)}});
        isf.data["user_types"]["ftrace_mod_func"] = json!({"size":40,"fields":{"list":list(0),"name":field(16),"ip":field(24),"size":field(32)}});
        isf.data["user_types"]["ftrace_ops"] = json!({"size":32,"fields":{"list":list(0),"trampoline":field(16),"trampoline_size":field(24)}});
        isf.data["user_types"]["bpf_ksym"] = json!({"size":48,"fields":{"lnode":list(0),"name":chars(16,16),"start":field(32),"end":field(40)}});
        for (at, value) in [
            (0x35000, 0x35100),
            (0x35008, 0x35100),
            (0x35100, 0x35000),
            (0x35108, 0x35000),
            (0x35110, 0x35200),
            (0x35118, 0x35200),
            (0x35120, 0x32000),
            (0x35200, 0x35110),
            (0x35208, 0x35110),
            (0x35210, 0x35400),
            (0x35218, 0x18002),
            (0x35220, 8),
            (0x35500, 0x35600),
            (0x35508, 0x35600),
            (0x35600, 0x35500),
            (0x35608, 0x35500),
            (0x35610, 0x18003),
            (0x35618, 8),
            (0x36000, 0x36100),
            (0x36008, 0x36100),
            (0x36100, 0x36000),
            (0x36108, 0x36000),
            (0x36120, 0x18004),
            (0x36128, 0x1800c),
        ] {
            put(&mut bytes, at, value);
        }
        bytes[0x35400..0x35408].copy_from_slice(b"trace_me");
        bytes[0x36110..0x36118].copy_from_slice(b"bpf_test");
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        let result = linux.kallsyms(Default::default(), &Job::default()).unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 8);
        assert_eq!(&result.rows[5][3..7], ["true", "ftrace", "mod", "trace_me"]);
        assert_eq!(
            &result.rows[6][3..7],
            ["false", "ftrace", "__builtin__ftrace", "ftrace_trampoline"]
        );
        assert_eq!(&result.rows[7][3..7], ["false", "bpf", "bpf", "bpf_test"]);
    }
    #[test]
    fn module_typetab_and_export_table_have_positive_data_symbols() {
        let (mut bytes, mut isf) = fixture();
        let fields = isf.data["user_types"]["module"]["fields"]
            .as_object_mut()
            .unwrap();
        for name in ["symtab", "strtab", "num_symtab"] {
            fields.remove(name);
        }
        fields.insert("kallsyms".into(),json!({"offset":32,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"mod_kallsyms"}}}));
        isf.data["user_types"]["mod_kallsyms"] = json!({"size":32,"fields":{"symtab":field(0),"strtab":field(8),"num_symtab":field(16),"typetab":field(24)}});
        isf.data["user_types"]["kernel_symbol"] =
            json!({"size":16,"fields":{"value":field(0),"name":field(8)}});
        for (at, value) in [
            (0x32020, 0x37000),
            (0x37000, 0x33000),
            (0x37008, 0x34000),
            (0x37010, 2),
            (0x37018, 0x37100),
            (0x32038, 1),
            (0x32040, 0x37200),
            (0x37200, 0x18001),
            (0x37208, 0x34001),
        ] {
            put(&mut bytes, at, value);
        }
        bytes[0x37101] = b'D';
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    modules: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][1], "D");
        assert_eq!(result.rows[0][3], "true");
    }
    #[test]
    fn legacy_bpf_aux_list_reads_program_pages_and_name() {
        let (mut bytes, mut isf) = fixture();
        isf.data["symbols"]["bpf_kallsyms"] = json!({"address":0x36000});
        isf.data["user_types"]["bpf_prog_aux"] = json!({"size":48,"fields":{"ksym_lnode":list(0),"name":chars(16,16),"prog":field(32),"use_bpf_prog_pack":field(40)}});
        isf.data["user_types"]["bpf_prog"] =
            json!({"size":16,"fields":{"bpf_func":field(0),"aux":field(8)}});
        for (at, value) in [
            (0x36000, 0x36100),
            (0x36008, 0x36100),
            (0x36100, 0x36000),
            (0x36108, 0x36000),
            (0x36120, 0x36200),
            (0x36200, 0x18005),
            (0x36208, 0x36100),
            (0x18000, 2),
        ] {
            put(&mut bytes, at, value);
        }
        bytes[0x36110..0x36116].copy_from_slice(b"oldbpf");
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    bpf: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][2], "8192");
        assert_eq!(result.rows[0][6], "oldbpf");
    }
    #[test]
    fn broken_name_block_resumes_at_an_independent_marker() {
        let (mut bytes, mut isf) = fixture();
        isf.data["symbols"]["kallsyms_names"]["address"] = json!(0x30800);
        isf.data["symbols"]["kallsyms_addresses"]["address"] = json!(0x33000);
        isf.data["symbols"]["kallsyms_markers"] = json!({"address":0x30900});
        put(&mut bytes, 0x30000, 257);
        put(&mut bytes, 0x30908, 2);
        bytes[0x30800..0x30804].copy_from_slice(&[0, 0, 1, 0]);
        for index in 0..257 {
            put(&mut bytes, 0x33000 + index * 8, 0x18000 + index as u64 * 16);
        }
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    core: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][6], "entry");
        assert_eq!(result.rows[0][0], hex(0x19000));
        assert!(result.diagnostics.iter().any(|d| d.contains("0..256")));
    }
    #[test]
    fn unreadable_export_table_keeps_symbol_fields_and_marks_export_unknown() {
        let (mut bytes, mut isf) = fixture();
        put(&mut bytes, 0x32038, 1);
        put(&mut bytes, 0x32040, 0x70000);
        isf.data["user_types"]["kernel_symbol"] =
            json!({"size":16,"fields":{"value":field(0),"name":field(8)}});
        let image = super::super::tests::image(&bytes);
        let result = super::super::tests::engine(&image, &isf)
            .kallsyms(
                KallsymsOptions {
                    modules: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][6], "work");
        assert_eq!(result.rows[0][3], "");
    }
    #[test]
    fn unreadable_core_does_not_erase_other_sources_and_cancellation_stops() {
        let (bytes, mut isf) = fixture();
        isf.data["symbols"]["kallsyms_token_index"]["address"] = json!(0x70000);
        let image = super::super::tests::image(&bytes);
        let linux = super::super::tests::engine(&image, &isf);
        let job = Job::default();
        let result = linux.kallsyms(Default::default(), &job).unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][6], "work");
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(linux.kallsyms(Default::default(), &job).is_err());
    }
}
