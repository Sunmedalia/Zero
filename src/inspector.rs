//! Live Memory, ISF/PDB Struct & Capstone Disassembly Inspector.
//!
//! Reads kernel virtual, process virtual (by PID), or physical memory read-only,
//! preserving per-page missing/unmapped boundaries (`??`) rather than failing the
//! entire view when a page is absent.
use crate::{
    Job,
    analysis::{Options, Os},
    bytes::{Checked as _, JsonKey as _},
    dossier::resolve_target_os,
    image::{Image, VirtualMemory},
    linux::{Linux, Plugin, Session},
    symbols::Isf,
    windows::{self, Architecture, Windows},
    windows_symbols,
};
use anyhow::{Context, Result, bail, ensure};
use capstone::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::Path, sync::Arc};

pub const DEFAULT_INSPECT_BYTES: usize = 256;
pub const MAX_INSPECT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaceKind {
    #[default]
    Kernel,
    Physical,
    Pid,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InspectView {
    #[default]
    All,
    Hex,
    Struct,
    Disasm,
}

#[derive(Clone, Debug)]
pub struct InspectRequest<'a> {
    pub image: &'a Path,
    pub symbols: &'a Path,
    pub choice: Option<&'a str>,
    pub cache: &'a Path,
    pub network: bool,
    pub options: &'a Options,
    pub space: SpaceKind,
    pub pid: Option<u32>,
    pub address: Option<u64>,
    pub symbol_name: Option<&'a str>,
    pub length: usize,
    pub struct_name: Option<&'a str>,
    pub disasm: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageTranslation {
    pub va: u64,
    pub pa: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructFieldView {
    pub offset: u64,
    pub size: u64,
    pub name: String,
    pub type_desc: String,
    pub value: String,
    pub valid: bool,
    pub follow_address: Option<u64>,
    pub follow_type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructInspection {
    pub type_name: String,
    pub size: u64,
    pub fields: Vec<StructFieldView>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisasmLine {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub op_str: String,
    pub annotation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspectReport {
    pub os: String,
    pub arch: String,
    pub space: String,
    pub pid: Option<u32>,
    pub address: u64,
    pub resolved_symbol: Option<String>,
    pub length: usize,
    pub complete: bool,
    pub banner: String,
    pub symbol_label: String,
    pub bytes: Vec<u8>,
    pub valid_mask: Vec<bool>,
    pub translations: Vec<PageTranslation>,
    pub hex_lines: Vec<String>,
    pub structure: Option<StructInspection>,
    pub disasm: Vec<DisasmLine>,
    pub diagnostics: Vec<String>,
}

pub enum InspectOutcome {
    Ready(Box<InspectReport>),
    Choose(Vec<String>),
}

struct SparseRead {
    bytes: Vec<u8>,
    valid: Vec<bool>,
    translations: Vec<PageTranslation>,
    diagnostics: Vec<String>,
}

/// Abstract read-only byte reader supporting kernel VA, process VA, or physical memory.
trait ByteReader {
    fn translate(&self, addr: u64) -> Result<u64>;
    fn read_exact(&self, addr: u64, out: &mut [u8]) -> Result<()>;
}

struct PhysicalReader<'a>(&'a Image);
impl ByteReader for PhysicalReader<'_> {
    fn translate(&self, addr: u64) -> Result<u64> {
        Ok(addr)
    }
    fn read_exact(&self, addr: u64, out: &mut [u8]) -> Result<()> {
        self.0.read(addr, out)
    }
}

struct LinuxVmReader<'a>(VirtualMemory<'a>);
impl ByteReader for LinuxVmReader<'_> {
    fn translate(&self, addr: u64) -> Result<u64> {
        self.0.translate(addr)
    }
    fn read_exact(&self, addr: u64, out: &mut [u8]) -> Result<()> {
        self.0.read(addr, out)
    }
}

struct WindowsVmReader<'a>(windows::Memory<'a>);
impl ByteReader for WindowsVmReader<'_> {
    fn translate(&self, addr: u64) -> Result<u64> {
        self.0.translate(addr)
    }
    fn read_exact(&self, addr: u64, out: &mut [u8]) -> Result<()> {
        self.0.read(addr, out)
    }
}

/// Read up to `length` bytes page-by-page so missing pages yield `false` in `valid_mask`
/// instead of aborting the whole inspection.
fn read_sparse(
    reader: &dyn ByteReader,
    start: u64,
    length: usize,
    job: &Job,
) -> Result<SparseRead> {
    let mut bytes = vec![0u8; length];
    let mut valid = vec![false; length];
    let mut translations = Vec::new();
    let mut diagnostics = Vec::new();
    let mut pos = 0usize;
    while pos < length {
        job.check()?;
        let va = start.wrapping_add(pos as u64);
        let page_rem = usize::try_from(4096 - (va & 4095)).unwrap_or(4096);
        let chunk_len = page_rem.min(length - pos);
        match reader.translate(va) {
            Ok(pa) => {
                translations.push(PageTranslation {
                    va,
                    pa: Some(pa),
                    error: None,
                });
                let dst = bytes.at_mut(pos..pos + chunk_len)?;
                match reader.read_exact(va, dst) {
                    Ok(()) => {
                        for flag in valid.at_mut(pos..pos + chunk_len)? {
                            *flag = true;
                        }
                    }
                    Err(err) => {
                        diagnostics.push(format!("{va:#x} (PA {pa:#x}) 读取失败: {err:#}"));
                    }
                }
            }
            Err(err) => {
                let msg = format!("{err:#}");
                translations.push(PageTranslation {
                    va,
                    pa: None,
                    error: Some(msg.clone()),
                });
                diagnostics.push(format!("{va:#x} 地址转换失败: {msg}"));
            }
        }
        pos += chunk_len;
    }
    Ok(SparseRead {
        bytes,
        valid,
        translations,
        diagnostics,
    })
}

/// Format bytes + valid mask into classic 16-byte Hex + ASCII lines (`??` for absent bytes).
pub fn format_hex_lines(start: u64, bytes: &[u8], valid: &[bool]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let addr = start.wrapping_add(offset as u64);
        let end = (offset + 16).min(bytes.len());
        let mut hex_part = String::with_capacity(50);
        let mut ascii_part = String::with_capacity(16);
        for i in 0..16usize {
            if i == 8 {
                hex_part.push(' ');
            }
            let idx = offset + i;
            if idx < end {
                let ok = valid.get(idx).copied().unwrap_or(false);
                if ok {
                    let b = bytes.get(idx).copied().unwrap_or(0);
                    hex_part.push_str(&format!("{b:02x} "));
                    ascii_part.push(if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    });
                } else {
                    hex_part.push_str("?? ");
                    ascii_part.push('?');
                }
            } else {
                hex_part.push_str("   ");
            }
        }
        lines.push(format!("{addr:016x}  {hex_part} |{ascii_part}|"));
        offset = end;
    }
    lines
}

/// List available `user_types` in an ISF matching an optional case-insensitive substring.
pub fn list_struct_types(isf: &Isf, query: &str, limit: usize) -> Vec<String> {
    let Some(map) = isf.data.key("user_types").as_object() else {
        return Vec::new();
    };
    let needle = query.trim().to_ascii_lowercase();
    let mut names: Vec<String> = map
        .keys()
        .filter(|name| needle.is_empty() || name.to_ascii_lowercase().contains(&needle))
        .cloned()
        .collect();
    names.sort();
    names.truncate(limit);
    names
}

/// Resolve a kernel symbol name to its runtime virtual address.
pub fn resolve_symbol_address(isf: &Isf, windows_base: Option<u64>, name: &str) -> Result<u64> {
    if let Some(base) = windows_base {
        let rva = isf.raw_address(name)?;
        base.checked_add(rva).context("Windows 符号地址溢出")
    } else {
        isf.address(name)
    }
}

/// Find the closest kernel symbol at or below `addr` (within 64 KiB) for annotating
/// disassembly jump/call targets and pointer fields.
pub fn nearest_symbol(isf: &Isf, windows_base: Option<u64>, addr: u64) -> Option<String> {
    let symbols = isf.data.key("symbols").as_object()?;
    let slide = isf.slide.load(std::sync::atomic::Ordering::Relaxed);
    let mut best: Option<(&str, u64)> = None;
    for (name, entry) in symbols {
        let Some(raw) = entry.get("address").and_then(Value::as_u64) else {
            continue;
        };
        let runtime = match windows_base {
            Some(base) => base.wrapping_add(raw),
            None => raw.wrapping_add(slide),
        };
        if runtime <= addr {
            let delta = addr - runtime;
            if delta <= 0x10000 && best.is_none_or(|(_, best_delta)| delta < best_delta) {
                best = Some((name.as_str(), delta));
                if delta == 0 {
                    break;
                }
            }
        }
    }
    best.map(|(name, delta)| {
        if delta == 0 {
            name.to_owned()
        } else {
            format!("{name}+{delta:#x}")
        }
    })
}

/// Decode all fields of `struct_name` at `address` using ISF metadata.
pub fn decode_struct(
    isf: &Isf,
    windows_base: Option<u64>,
    struct_name: &str,
    address: u64,
    bytes: &[u8],
    valid: &[bool],
) -> Result<StructInspection> {
    let ut = isf
        .data
        .key("user_types")
        .get(struct_name)
        .with_context(|| format!("ISF 中未找到结构体 {struct_name}"))?;
    let size = ut
        .key("size")
        .as_u64()
        .with_context(|| format!("ISF 结构体 {struct_name} 缺少 size"))?;
    let fields_obj = ut
        .key("fields")
        .as_object()
        .with_context(|| format!("ISF 结构体 {struct_name} 缺少 fields"))?;

    let mut entries: Vec<(&String, u64, &Value)> = fields_obj
        .iter()
        .filter_map(|(name, def)| Some((name, def.get("offset")?.as_u64()?, def)))
        .collect();
    entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)));

    let mut fields = Vec::with_capacity(entries.len());
    let mut diagnostics = Vec::new();
    let ptr_width = isf
        .data
        .key("base_types")
        .key("pointer")
        .key("size")
        .as_u64()
        .unwrap_or(8);

    for (name, offset, def) in entries {
        let ty = &def["type"];
        let field_size = isf.type_size(ty).unwrap_or(0);
        let type_desc = describe_type(ty);
        let off_usize = usize::try_from(offset).unwrap_or(usize::MAX);
        let len_usize = usize::try_from(field_size).unwrap_or(0);
        let (field_bytes, all_valid) = if off_usize < bytes.len()
            && len_usize > 0
            && off_usize.saturating_add(len_usize) <= bytes.len()
        {
            let slice = bytes.get(off_usize..off_usize + len_usize).unwrap_or(&[]);
            let ok = valid
                .get(off_usize..off_usize + len_usize)
                .is_some_and(|v| v.iter().all(|b| *b));
            (slice, ok)
        } else {
            (&[][..], false)
        };

        let (value, follow_address, follow_type) = if !all_valid {
            (
                if off_usize >= bytes.len() {
                    format!("<超出当前读取范围 {} B>", bytes.len())
                } else {
                    String::from("<缺页 / 不可读>")
                },
                None,
                None,
            )
        } else {
            decode_field_value(
                isf,
                windows_base,
                ty,
                address.wrapping_add(offset),
                field_bytes,
                ptr_width,
            )
        };

        fields.push(StructFieldView {
            offset,
            size: field_size,
            name: name.clone(),
            type_desc,
            value,
            valid: all_valid,
            follow_address,
            follow_type,
        });
    }

    if size > bytes.len() as u64 {
        diagnostics.push(format!(
            "结构体 {struct_name} 总大小 {size} 字节，当前仅读取前 {} 字节",
            bytes.len()
        ));
    }

    Ok(StructInspection {
        type_name: struct_name.to_owned(),
        size,
        fields,
        diagnostics,
    })
}

fn describe_type(ty: &Value) -> String {
    match ty["kind"].as_str() {
        Some("pointer") => {
            if let Some(sub) = ty.get("subtype") {
                format!("*{}", describe_type(sub))
            } else {
                String::from("void*")
            }
        }
        Some("base") => ty["name"].as_str().unwrap_or("base").to_owned(),
        Some("struct") => format!("struct {}", ty["name"].as_str().unwrap_or("?")),
        Some("union") => format!("union {}", ty["name"].as_str().unwrap_or("?")),
        Some("enum") => format!("enum {}", ty["name"].as_str().unwrap_or("?")),
        Some("array") => {
            let count = ty["count"].as_u64().unwrap_or(0);
            let sub = ty
                .get("subtype")
                .map(describe_type)
                .unwrap_or_else(|| String::from("u8"));
            format!("{sub}[{count}]")
        }
        Some("bitfield") => {
            let pos = ty["bit_position"].as_u64().unwrap_or(0);
            let len = ty["bit_length"].as_u64().unwrap_or(0);
            format!("bitfield({pos}:{len})")
        }
        Some("function") => String::from("fn(...)"),
        Some(other) => other.to_owned(),
        None => String::from("unknown"),
    }
}

fn read_le_u64(slice: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let n = slice.len().min(8);
    if let (Some(dst), Some(src)) = (buf.get_mut(..n), slice.get(..n)) {
        dst.copy_from_slice(src);
    }
    u64::from_le_bytes(buf)
}

fn decode_field_value(
    isf: &Isf,
    windows_base: Option<u64>,
    ty: &Value,
    field_addr: u64,
    bytes: &[u8],
    ptr_width: u64,
) -> (String, Option<u64>, Option<String>) {
    match ty["kind"].as_str() {
        Some("pointer") => {
            let ptr = read_le_u64(bytes);
            let target_type = ty
                .get("subtype")
                .and_then(|sub| match sub["kind"].as_str() {
                    Some("struct" | "union") => sub["name"].as_str().map(str::to_owned),
                    _ => None,
                });
            if ptr == 0 {
                (String::from("0x0 (NULL)"), None, None)
            } else {
                let sym = nearest_symbol(isf, windows_base, ptr);
                let text = match sym {
                    Some(s) => format!("{ptr:#x} ({s})"),
                    None => format!("{ptr:#x}"),
                };
                (text, Some(ptr), target_type)
            }
        }
        Some("base") => {
            let name = ty["name"].as_str().unwrap_or("");
            let signed = isf
                .data
                .key("base_types")
                .key(name)
                .key("signed")
                .as_bool()
                .unwrap_or(false);
            let raw = read_le_u64(bytes);
            if bytes.len() <= 8 {
                if signed {
                    let sval = sign_extend(raw, bytes.len());
                    (format!("{sval} ({raw:#x})"), None, None)
                } else {
                    (format!("{raw:#x} ({raw})"), None, None)
                }
            } else {
                (format!("<{} bytes>", bytes.len()), None, None)
            }
        }
        Some("bitfield") => {
            let raw = read_le_u64(bytes);
            let pos = ty["bit_position"].as_u64().unwrap_or(0);
            let len = ty["bit_length"].as_u64().unwrap_or(0);
            let val = if len > 0 && pos + len <= 64 {
                (raw >> pos) & (u64::MAX >> (64 - len))
            } else {
                0
            };
            (format!("{val:#x} ({val})"), None, None)
        }
        Some("enum") => {
            let raw = read_le_u64(bytes);
            let enum_name = ty["name"].as_str().unwrap_or("");
            let variant = isf
                .data
                .key("enums")
                .key(enum_name)
                .key("constants")
                .as_object()
                .and_then(|consts| {
                    consts
                        .iter()
                        .find_map(|(k, v)| (v.as_u64() == Some(raw)).then_some(k.as_str()))
                });
            let text = match variant {
                Some(v) => format!("{v} ({raw})"),
                None => format!("{raw:#x} ({raw})"),
            };
            (text, None, None)
        }
        Some("struct" | "union") => {
            let sname = ty["name"].as_str().unwrap_or("");
            if (sname == "list_head" || sname == "_LIST_ENTRY")
                && bytes.len() >= usize::try_from(ptr_width * 2).unwrap_or(16)
            {
                let w = usize::try_from(ptr_width).unwrap_or(8);
                let next = read_le_u64(bytes.get(..w).unwrap_or(&[]));
                let prev = read_le_u64(bytes.get(w..w * 2).unwrap_or(&[]));
                let follow = (next != 0).then_some(next);
                return (
                    format!("next={next:#x}, prev={prev:#x}"),
                    follow,
                    Some(sname.to_owned()),
                );
            }
            // Allow drilling into embedded struct at its in-place address.
            (
                format!("<inline {sname} @ {field_addr:#x}>"),
                Some(field_addr),
                Some(sname.to_owned()),
            )
        }
        Some("array") => {
            let sub_name = ty
                .get("subtype")
                .and_then(|s| s.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if matches!(sub_name, "char" | "unsigned char" | "signed char") {
                let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                let preview = bytes.get(..nul.min(64)).unwrap_or(&[]);
                let text = String::from_utf8_lossy(preview)
                    .chars()
                    .map(|c| if c.is_control() { '.' } else { c })
                    .collect::<String>();
                (format!("\"{text}\""), None, None)
            } else {
                let preview = bytes
                    .iter()
                    .take(16)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let suffix = if bytes.len() > 16 { " ..." } else { "" };
                (format!("[{preview}{suffix}]"), None, None)
            }
        }
        _ => {
            let preview = bytes
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            (preview, None, None)
        }
    }
}

fn sign_extend(raw: u64, width: usize) -> i64 {
    let bits = u32::try_from(width.min(8) * 8).unwrap_or(64);
    if bits == 64 {
        raw as i64
    } else {
        let shift = 64 - bits;
        ((raw << shift) as i64) >> shift
    }
}

/// Disassemble contiguous valid byte runs using Capstone (x86/x86_64) and annotate
/// immediate jump/call targets with ISF kernel symbols.
pub fn disassemble_bytes(
    start: u64,
    bytes: &[u8],
    valid: &[bool],
    mode_32: bool,
    isf: Option<&Isf>,
    windows_base: Option<u64>,
) -> Result<Vec<DisasmLine>> {
    let cs = Capstone::new()
        .x86()
        .mode(if mode_32 {
            capstone::arch::x86::ArchMode::Mode32
        } else {
            capstone::arch::x86::ArchMode::Mode64
        })
        .syntax(capstone::arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .context("初始化 Capstone 反汇编器失败")?;

    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        // Skip invalid/unmapped bytes.
        while pos < bytes.len() && !valid.get(pos).copied().unwrap_or(false) {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        let run_start = pos;
        while pos < bytes.len() && valid.get(pos).copied().unwrap_or(false) {
            pos += 1;
        }
        let slice = bytes.get(run_start..pos).unwrap_or(&[]);
        let base_va = start.wrapping_add(run_start as u64);
        let insns = cs
            .disasm_all(slice, base_va)
            .context("Capstone 反汇编失败")?;
        for insn in insns.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("?").to_owned();
            let op_str = insn.op_str().unwrap_or("").to_owned();
            let annotation = isf.and_then(|symbols| {
                extract_branch_target(&mnemonic, &op_str)
                    .and_then(|target| nearest_symbol(symbols, windows_base, target))
                    .map(|sym| format!("-> {sym}"))
            });
            let raw_bytes = insn
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            out.push(DisasmLine {
                address: insn.address(),
                bytes: raw_bytes,
                mnemonic,
                op_str,
                annotation,
            });
        }
    }
    Ok(out)
}

fn extract_branch_target(mnemonic: &str, op_str: &str) -> Option<u64> {
    if !(mnemonic == "call" || mnemonic.starts_with('j')) {
        return None;
    }
    let hex = op_str
        .trim()
        .strip_prefix("0x")
        .or_else(|| op_str.trim().strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}

/// Inspect a kernel VA, process VA (by PID), or physical address across Linux & Windows.
pub fn inspect(
    session: &mut Session,
    req: &InspectRequest<'_>,
    job: &Job,
) -> Result<InspectOutcome> {
    job.check()?;
    let length = if req.length == 0 {
        DEFAULT_INSPECT_BYTES
    } else {
        req.length.min(MAX_INSPECT_BYTES)
    };

    // Physical inspection without symbols works directly on the raw image!
    if req.space == SpaceKind::Physical && req.symbol_name.is_none() && req.struct_name.is_none() {
        let addr = req
            .address
            .context("物理内存检查需要 --address（十六进制或十进制）")?;
        let image = session.prepare_image(req.image, req.cache, job)?;
        let reader = PhysicalReader(&image);
        let SparseRead {
            bytes,
            valid,
            translations,
            diagnostics,
        } = read_sparse(&reader, addr, length, job)?;
        let hex_lines = format_hex_lines(addr, &bytes, &valid);
        let disasm = if req.disasm {
            disassemble_bytes(
                addr,
                &bytes,
                &valid,
                req.options.arch == Architecture::X86,
                None,
                None,
            )?
        } else {
            Vec::new()
        };
        let complete = valid.iter().all(|v| *v);
        return Ok(InspectOutcome::Ready(Box::new(InspectReport {
            os: "physical".into(),
            arch: format!("{:?}", req.options.arch).to_ascii_lowercase(),
            space: "physical".into(),
            pid: None,
            address: addr,
            resolved_symbol: None,
            length,
            complete,
            banner: String::new(),
            symbol_label: String::new(),
            bytes,
            valid_mask: valid,
            translations,
            hex_lines,
            structure: None,
            disasm,
            diagnostics,
        })));
    }

    let target_os = resolve_target_os(
        session,
        req.image,
        req.symbols,
        req.cache,
        req.options.os,
        job,
    )?;
    if target_os == Os::Windows {
        inspect_windows(session, req, length, job)
    } else {
        inspect_linux(session, req, length, job)
    }
}

fn inspect_linux(
    session: &mut Session,
    req: &InspectRequest<'_>,
    length: usize,
    job: &Job,
) -> Result<InspectOutcome> {
    let image = session.prepare_image(req.image, req.cache, job)?;
    let symbols = crate::symbols::resolve(req.symbols, &image, req.cache, req.network, job)?;
    let isf: Arc<Isf> = if let Some(choice) = req.choice {
        Arc::new(
            symbols
                .into_iter()
                .find(|s| s.label == choice)
                .context("指定 Linux 符号不在精确匹配候选中")?,
        )
    } else if symbols.len() > 1 {
        return Ok(InspectOutcome::Choose(
            symbols.into_iter().map(|s| s.label).collect(),
        ));
    } else {
        Arc::new(
            symbols
                .into_iter()
                .next()
                .context("未找到精确匹配的 Linux 符号")?,
        )
    };

    let root = crate::linux::discover(&image, &isf, job)?;
    let kernel_vm = crate::linux::discover_kernel_vm(&image, &isf, root);
    let engine = Linux {
        vm: kernel_vm,
        isf: &isf,
    };

    let (address, resolved_symbol) = if let Some(sym_name) = req.symbol_name {
        let addr = resolve_symbol_address(&isf, None, sym_name)?;
        (addr, Some(sym_name.to_owned()))
    } else {
        let addr = req.address.context("内存检查需要 --address 或 --symbol")?;
        let sym = nearest_symbol(&isf, None, addr);
        (addr, sym)
    };

    // If a struct is requested and its size exceeds length (up to MAX_INSPECT_BYTES), read enough for it.
    let read_len = req
        .struct_name
        .and_then(|s| isf.data.key("user_types").key(s).key("size").as_u64())
        .and_then(|sz| usize::try_from(sz).ok())
        .map_or(length, |sz| sz.max(length).min(MAX_INSPECT_BYTES));

    let (read, space_label) = match req.space {
        SpaceKind::Physical => {
            let reader = PhysicalReader(&image);
            (
                read_sparse(&reader, address, read_len, job)?,
                String::from("physical"),
            )
        }
        SpaceKind::Kernel => {
            let reader = LinuxVmReader(crate::linux::discover_kernel_vm(&image, &isf, root));
            (
                read_sparse(&reader, address, read_len, job)?,
                String::from("kernel"),
            )
        }
        SpaceKind::Pid => {
            let pid = req.pid.context("进程地址空间检查需要 --pid")?;
            let (_, tasks) = engine.tasks(Plugin::LinuxPslist, job)?;
            let pid_str = pid.to_string();
            let task = tasks
                .into_iter()
                .find(|t| t.pid == pid_str)
                .with_context(|| format!("未在 Linux 进程表中找到 PID {pid}"))?;
            let vm = engine
                .process_vm(task.address)?
                .with_context(|| format!("PID {pid} 为内核线程，没有用户态页表"))?;
            let reader = LinuxVmReader(vm);
            (
                read_sparse(&reader, address, read_len, job)?,
                format!("pid:{pid}"),
            )
        }
    };
    let SparseRead {
        bytes,
        valid,
        translations,
        mut diagnostics,
    } = read;

    let hex_lines = format_hex_lines(address, &bytes, &valid);
    let structure = if let Some(sname) = req.struct_name {
        match decode_struct(&isf, None, sname, address, &bytes, &valid) {
            Ok(s) => {
                diagnostics.extend(s.diagnostics.clone());
                Some(s)
            }
            Err(err) => {
                diagnostics.push(format!("结构体解析失败: {err:#}"));
                None
            }
        }
    } else {
        None
    };

    let is_arm64 = image
        .arm64_va_bits
        .load(std::sync::atomic::Ordering::Relaxed)
        != 0
        || String::from_utf8_lossy(&isf.banner).contains("aarch64");
    let mode_32 = isf
        .data
        .key("base_types")
        .key("pointer")
        .key("size")
        .as_u64()
        == Some(4);
    let disasm = if req.disasm {
        if is_arm64 {
            diagnostics.push(
                "当前 Capstone 构建仅启用 x86/x86_64 反汇编，ARM64 暂不支持反汇编视图".into(),
            );
            Vec::new()
        } else {
            disassemble_bytes(address, &bytes, &valid, mode_32, Some(&isf), None)?
        }
    } else {
        Vec::new()
    };

    let complete = valid.iter().all(|v| *v);
    let banner = String::from_utf8_lossy(&isf.banner)
        .trim_end_matches('\0')
        .to_owned();

    Ok(InspectOutcome::Ready(Box::new(InspectReport {
        os: "linux".into(),
        arch: if is_arm64 {
            "arm64"
        } else if mode_32 {
            "x86"
        } else {
            "x64"
        }
        .into(),
        space: space_label,
        pid: req.pid,
        address,
        resolved_symbol,
        length: read_len,
        complete,
        banner,
        symbol_label: isf.label.clone(),
        bytes,
        valid_mask: valid,
        translations,
        hex_lines,
        structure,
        disasm,
        diagnostics,
    })))
}

fn inspect_windows(
    session: &mut Session,
    req: &InspectRequest<'_>,
    length: usize,
    job: &Job,
) -> Result<InspectOutcome> {
    let image = session.prepare_image(req.image, req.cache, job)?;
    let symbols = windows_symbols::resolve(req.symbols, &image, req.cache, req.network, job)?;
    let isf: Arc<Isf> = if let Some(choice) = req.choice {
        Arc::new(
            symbols
                .into_iter()
                .find(|s| s.label == choice)
                .context("指定 Windows 符号不在精确匹配候选中")?,
        )
    } else if symbols.len() > 1 {
        return Ok(InspectOutcome::Choose(
            symbols.into_iter().map(|s| s.label).collect(),
        ));
    } else {
        Arc::new(
            symbols
                .into_iter()
                .next()
                .context("未找到精确匹配的 Windows 符号")?,
        )
    };

    let arch = Architecture::from_isf(&isf)?;
    let (root, base) = windows::discover(&image, &isf, job)?;
    let pdb = windows_symbols::PdbIdentity::from_isf(&isf)?;
    let engine = Windows {
        vm: windows::Memory::new(&image, root, &isf, None),
        base,
        pdb,
    };

    let (address, resolved_symbol) = if let Some(sym_name) = req.symbol_name {
        let addr = resolve_symbol_address(&isf, Some(base), sym_name)?;
        (addr, Some(sym_name.to_owned()))
    } else {
        let addr = req.address.context("内存检查需要 --address 或 --symbol")?;
        let sym = nearest_symbol(&isf, Some(base), addr);
        (addr, sym)
    };

    let read_len = req
        .struct_name
        .and_then(|s| isf.data.key("user_types").key(s).key("size").as_u64())
        .and_then(|sz| usize::try_from(sz).ok())
        .map_or(length, |sz| sz.max(length).min(MAX_INSPECT_BYTES));

    let (read, space_label) = match req.space {
        SpaceKind::Physical => {
            let reader = PhysicalReader(&image);
            (
                read_sparse(&reader, address, read_len, job)?,
                String::from("physical"),
            )
        }
        SpaceKind::Kernel => {
            let reader = WindowsVmReader(windows::Memory::new(&image, root, &isf, None));
            (
                read_sparse(&reader, address, read_len, job)?,
                String::from("kernel"),
            )
        }
        SpaceKind::Pid => {
            let pid = req.pid.context("进程地址空间检查需要 --pid")?;
            let (processes, _) = engine.processes_partial(job)?;
            let proc = processes
                .into_iter()
                .find(|p| p.pid == u64::from(pid))
                .with_context(|| format!("未在 Windows 进程表中找到 PID {pid}"))?;
            let vm = engine.process_memory(&proc)?;
            let reader = WindowsVmReader(vm);
            (
                read_sparse(&reader, address, read_len, job)?,
                format!("pid:{pid}"),
            )
        }
    };
    let SparseRead {
        bytes,
        valid,
        translations,
        mut diagnostics,
    } = read;

    let hex_lines = format_hex_lines(address, &bytes, &valid);
    let structure = if let Some(sname) = req.struct_name {
        match decode_struct(&isf, Some(base), sname, address, &bytes, &valid) {
            Ok(s) => {
                diagnostics.extend(s.diagnostics.clone());
                Some(s)
            }
            Err(err) => {
                diagnostics.push(format!("结构体解析失败: {err:#}"));
                None
            }
        }
    } else {
        None
    };

    let disasm = if req.disasm {
        if arch == Architecture::Arm64 {
            diagnostics.push(
                "当前 Capstone 构建仅启用 x86/x86_64 反汇编，ARM64 暂不支持反汇编视图".into(),
            );
            Vec::new()
        } else {
            disassemble_bytes(
                address,
                &bytes,
                &valid,
                arch == Architecture::X86,
                Some(&isf),
                Some(base),
            )?
        }
    } else {
        Vec::new()
    };

    let complete = valid.iter().all(|v| *v);
    let banner = String::from_utf8_lossy(&isf.banner)
        .trim_end_matches('\0')
        .to_owned();

    Ok(InspectOutcome::Ready(Box::new(InspectReport {
        os: "windows".into(),
        arch: match arch {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::Arm64 => "arm64",
            Architecture::Auto => "auto",
        }
        .into(),
        space: space_label,
        pid: req.pid,
        address,
        resolved_symbol,
        length: read_len,
        complete,
        banner,
        symbol_label: isf.label.clone(),
        bytes,
        valid_mask: valid,
        translations,
        hex_lines,
        structure,
        disasm,
        diagnostics,
    })))
}

impl InspectReport {
    /// Render the selected view (or all views) into readable Chinese text.
    pub fn render_text(&self, view: InspectView) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "内存检查器 · {:#x} ({}, {}, {} B)\n",
            self.address, self.space, self.arch, self.length
        ));
        if let Some(sym) = &self.resolved_symbol {
            out.push_str(&format!("符号定位: {sym}\n"));
        }
        if !self.banner.is_empty() {
            out.push_str(&format!("目标: {}\n", self.banner));
        }
        if let Some(first) = self.translations.first() {
            match first.pa {
                Some(pa) => {
                    out.push_str(&format!("页表映射: VA {:#x} -> PA {:#x}\n", first.va, pa))
                }
                None => out.push_str(&format!(
                    "页表映射: VA {:#x} -> 不可转换 ({})\n",
                    first.va,
                    first.error.as_deref().unwrap_or("缺页")
                )),
            }
        }
        if !self.diagnostics.is_empty() {
            out.push_str(&format!("诊断: {}\n", self.diagnostics.join("; ")));
        }

        if matches!(view, InspectView::All | InspectView::Hex) {
            out.push_str("\n=== Hex / ASCII ===\n");
            for line in &self.hex_lines {
                out.push_str(line);
                out.push('\n');
            }
        }

        if matches!(view, InspectView::All | InspectView::Struct)
            && let Some(st) = &self.structure
        {
            out.push_str(&format!(
                "\n=== 结构体 {} ({} B) ===\n",
                st.type_name, st.size
            ));
            for field in &st.fields {
                let ptr_hint = if field.follow_address.is_some() {
                    " [Enter 跳转]"
                } else {
                    ""
                };
                out.push_str(&format!(
                    "  +{:#06x}  {:<28} {:<24} = {}{}\n",
                    field.offset, field.name, field.type_desc, field.value, ptr_hint
                ));
            }
        }

        if matches!(view, InspectView::All | InspectView::Disasm) && !self.disasm.is_empty() {
            out.push_str("\n=== Capstone 反汇编 ===\n");
            for line in &self.disasm {
                let note = line
                    .annotation
                    .as_deref()
                    .map(|a| format!("  ; {a}"))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  {:016x}  {:<24} {:<8} {}{}\n",
                    line.address, line.bytes, line.mnemonic, line.op_str, note
                ));
            }
        }
        out
    }
}

/// Ensure the chosen space + pid combination is valid.
pub fn validate_space(space: SpaceKind, pid: Option<u32>) -> Result<()> {
    match space {
        SpaceKind::Pid => {
            ensure!(pid.is_some(), "space=pid 必须指定 --pid");
        }
        SpaceKind::Kernel | SpaceKind::Physical => {
            if pid.is_some() && space == SpaceKind::Physical {
                bail!("物理地址空间不接受 --pid");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn synthetic_isf() -> Isf {
        let banner = STANDARD.encode(b"Linux version 6.1.0-test\0");
        let json = serde_json::json!({
            "metadata": { "format": "6.2.0" },
            "base_types": {
                "pointer": { "size": 8, "signed": false, "kind": "int", "endian": "little" },
                "int": { "size": 4, "signed": true, "kind": "int", "endian": "little" },
                "unsigned int": { "size": 4, "signed": false, "kind": "int", "endian": "little" },
                "char": { "size": 1, "signed": true, "kind": "char", "endian": "little" }
            },
            "enums": {
                "task_state": {
                    "size": 4,
                    "base": "unsigned int",
                    "constants": { "RUNNING": 0, "INTERRUPTIBLE": 1 }
                }
            },
            "user_types": {
                "list_head": {
                    "kind": "struct",
                    "size": 16,
                    "fields": {
                        "next": { "offset": 0, "type": { "kind": "pointer", "subtype": { "kind": "struct", "name": "list_head" } } },
                        "prev": { "offset": 8, "type": { "kind": "pointer", "subtype": { "kind": "struct", "name": "list_head" } } }
                    }
                },
                "demo_task": {
                    "kind": "struct",
                    "size": 48,
                    "fields": {
                        "pid": { "offset": 0, "type": { "kind": "base", "name": "int" } },
                        "state": { "offset": 4, "type": { "kind": "enum", "name": "task_state" } },
                        "parent": { "offset": 8, "type": { "kind": "pointer", "subtype": { "kind": "struct", "name": "demo_task" } } },
                        "tasks": { "offset": 16, "type": { "kind": "struct", "name": "list_head" } },
                        "comm": { "offset": 32, "type": { "kind": "array", "count": 16, "subtype": { "kind": "base", "name": "char" } } }
                    }
                }
            },
            "symbols": {
                "linux_banner": { "address": 0xffffffff81000000u64, "constant_data": banner },
                "init_task": { "address": 0xffffffff81200000u64 },
                "sys_open": { "address": 0xffffffff81300000u64 }
            }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        Isf::parse(&bytes, "synthetic.isf.json".into()).unwrap()
    }

    #[test]
    fn hex_dump_marks_missing_bytes_with_question_marks() {
        let bytes = [0x48, 0x89, 0xe5, 0x90, 0x41, 0x42];
        let valid = [true, true, false, false, true, true];
        let lines = format_hex_lines(0x1000, &bytes, &valid);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("48 89 ?? ?? 41 42"));
        assert!(lines[0].contains("|H.??AB|"));
    }

    #[test]
    fn decodes_struct_fields_pointers_list_head_and_strings() {
        let isf = synthetic_isf();
        let mut buf = vec![0u8; 48];
        buf[0..4].copy_from_slice(&42i32.to_le_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // INTERRUPTIBLE
        buf[8..16].copy_from_slice(&0xffff_ffff_8120_0000u64.to_le_bytes()); // init_task
        buf[16..24].copy_from_slice(&0xffff_8880_0000_1234u64.to_le_bytes()); // next
        buf[24..32].copy_from_slice(&0xffff_8880_0000_5678u64.to_le_bytes()); // prev
        buf[32..36].copy_from_slice(b"sshd");
        let valid = vec![true; 48];

        let st =
            decode_struct(&isf, None, "demo_task", 0xffff_8880_0000_1000, &buf, &valid).unwrap();
        assert_eq!(st.type_name, "demo_task");
        assert_eq!(st.fields.len(), 5);
        assert!(st.fields[0].value.starts_with("42 "));
        assert_eq!(st.fields[1].value, "INTERRUPTIBLE (1)");
        assert_eq!(st.fields[2].follow_address, Some(0xffff_ffff_8120_0000));
        assert_eq!(st.fields[2].follow_type.as_deref(), Some("demo_task"));
        assert!(st.fields[2].value.contains("init_task"));
        assert_eq!(st.fields[3].follow_address, Some(0xffff_8880_0000_1234));
        assert_eq!(st.fields[4].value, "\"sshd\"");
        assert_eq!(list_struct_types(&isf, "demo", 10), vec!["demo_task"]);
    }

    #[test]
    fn disassembles_x64_and_annotates_branch_target() {
        let isf = synthetic_isf();
        // At 0xffffffff812ffffb: call +0 (target = 0xffffffff81300000 = sys_open); ret
        let code = [0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let valid = [true; 6];
        let lines = disassemble_bytes(
            0xffff_ffff_812f_fffb,
            &code,
            &valid,
            false,
            Some(&isf),
            None,
        )
        .unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].mnemonic, "call");
        assert_eq!(lines[0].annotation.as_deref(), Some("-> sys_open"));
        assert_eq!(lines[1].mnemonic, "ret");
    }

    #[test]
    fn physical_inspect_reads_bytes_and_preserves_oob_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("phys.raw");
        let mut data = vec![0x90u8; 32];
        data[0] = 0x55; // push rbp
        data[1] = 0x48;
        data[2] = 0x89;
        data[3] = 0xe5; // mov rbp, rsp
        data[4] = 0xc3; // ret
        std::fs::write(&img_path, &data).unwrap();

        let mut session = Session::default();
        let options = Options::default();
        let cache = dir.path().join("cache");
        let req = InspectRequest {
            image: &img_path,
            symbols: dir.path(),
            choice: None,
            cache: &cache,
            network: false,
            options: &options,
            space: SpaceKind::Physical,
            pid: None,
            address: Some(0),
            symbol_name: None,
            length: 16,
            struct_name: None,
            disasm: true,
        };
        let InspectOutcome::Ready(report) = inspect(&mut session, &req, &Job::default()).unwrap()
        else {
            panic!("expected Ready");
        };
        assert!(report.complete);
        assert_eq!(report.space, "physical");
        assert!(report.disasm.iter().any(|d| d.mnemonic == "push"));
        assert!(
            report
                .render_text(InspectView::All)
                .contains("Capstone 反汇编")
        );
    }
}
