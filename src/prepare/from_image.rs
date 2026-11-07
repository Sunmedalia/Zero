//! Generate a Linux ISF from the memory image alone: types from the kernel's
//! embedded BTF (`CONFIG_DEBUG_INFO_BTF`) and addresses from its compressed
//! core kallsyms (`CONFIG_KALLSYMS_ALL`).
//!
//! Every link in the chain is checked against an independent fact in the
//! image: `kallsyms_num_syms` and the other table symbols must name the exact
//! physical tables that were decoded, `linux_banner` must translate to a banner
//! the image scan found, VMCOREINFO (when present) must agree with every symbol
//! it exports, and the finished ISF must pass the engine's page-table
//! validation with the expected KASLR slide before anything is written.
//! Global variable types exist only where BTF records them (normally the
//! per-cpu section); other symbols carry an address only and the metadata says
//! so, so plugins needing such a type fail explicitly instead of guessing.
mod artifact;

use super::{btf, image_kallsyms, vmcoreinfo};
use crate::{Job, bytes::JsonKey as _, image::Image, store, symbols::Isf};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Version of this generator; part of the ISF metadata and cache identity.
pub const GENERATOR: &str = "zero-image-btf-3";
/// Missing image-only prerequisites may use a separately verified local ISF.
/// Validation failures and cancellation must never take that fallback.
#[derive(Debug)]
pub(super) struct Unavailable(String);
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "不支持从此镜像独立生成完整符号表：{}。可复用精确本地 ISF，或使用 --auto / --elf 获取调试类型；不会猜测缺失类型",
            self.0
        )
    }
}
impl std::error::Error for Unavailable {}
fn unavailable(reason: impl Into<String>) -> anyhow::Error {
    Unavailable(reason.into()).into()
}

/// `__START_KERNEL_map`: the x86_64 kernel image mapping base.
const START_KERNEL_MAP: u64 = 0xffff_ffff_8000_0000;
const MAX_BTF: u64 = 64 * 1024 * 1024;

/// Symbols the tables describe; each present one must sit at the decoded table.
const TABLE_SYMBOLS: [&str; 6] = [
    "kallsyms_num_syms",
    "kallsyms_names",
    "kallsyms_markers",
    "kallsyms_token_table",
    "kallsyms_token_index",
    "kallsyms_offsets",
];

/// VMCOREINFO `SYMBOL()` entries that the kernel exports as the object's own address.
const ADDRESS_EXPORTS: [&str; 10] = [
    "_stext",
    "init_top_pgt",
    "swapper_pg_dir",
    "init_uts_ns",
    "kallsyms_names",
    "kallsyms_num_syms",
    "kallsyms_token_table",
    "kallsyms_token_index",
    "kallsyms_offsets",
    "kallsyms_relative_base",
];

fn release(banner: &[u8]) -> Result<String> {
    String::from_utf8_lossy(banner)
        .strip_prefix("Linux version ")
        .and_then(|s| s.split_whitespace().next())
        .map(str::to_owned)
        .context("banner 缺少内核版本")
}

/// The single symbol with this name, or `None` when absent or ambiguous.
fn unique<'a>(
    tables: &'a image_kallsyms::Tables,
    name: &str,
) -> Option<&'a image_kallsyms::Symbol> {
    let mut found = tables.symbols.iter().filter(|s| s.name == name);
    let first = found.next()?;
    found.all(|s| s.runtime == first.runtime).then_some(first)
}

struct Located {
    tables: image_kallsyms::Tables,
    /// Kernel image virtual address minus physical address.
    delta: u64,
    banner: Vec<u8>,
    banner_physical: u64,
}

fn locate(image: &Image, job: &Job) -> Result<Located> {
    let banners = image.banners(job)?;
    ensure!(!banners.is_empty(), "镜像中没有 Linux banner");
    job.report("从镜像定位 kallsyms 表");
    let candidates = image_kallsyms::locate(image, job)?;
    if candidates.is_empty() {
        return Err(unavailable(
            "没有可验证的相对地址核心 kallsyms 表；旧内核可能使用尚不支持的绝对地址表，缺少 BTF 的内核也无法提供结构类型",
        ));
    }
    let required = [
        "kallsyms_num_syms",
        "linux_banner",
        "init_task",
        "__start_BTF",
        "__stop_BTF",
    ];
    if candidates
        .iter()
        .all(|tables| required.iter().any(|name| unique(tables, name).is_none()))
    {
        let details = candidates
            .iter()
            .map(|tables| {
                let missing = required
                    .iter()
                    .filter(|name| unique(tables, name).is_none())
                    .copied()
                    .collect::<Vec<_>>();
                format!(
                    "已解码 {} 个符号的 kallsyms（物理 {:#x}），缺少 {}",
                    tables.symbols.len(),
                    tables.token_table,
                    missing.join("、")
                )
            })
            .collect::<Vec<_>>()
            .join("；");
        return Err(unavailable(format!(
            "{details}；镜像内符号表不足以定位全局对象，需 CONFIG_KALLSYMS_ALL 和 CONFIG_DEBUG_INFO_BTF"
        )));
    }
    let mut located = Vec::new();
    let mut rejected = Vec::new();
    for tables in candidates {
        job.check()?;
        let token_table = tables.token_table;
        let checked = (|| -> Result<Located> {
            let num_syms = unique(&tables, "kallsyms_num_syms")
                .filter(|s| s.relocated)
                .context("kallsyms 不含 kallsyms_num_syms；需要 CONFIG_KALLSYMS_ALL")?;
            let delta = num_syms.runtime.wrapping_sub(tables.num_syms);
            ensure!(delta & 4095 == 0, "内核虚拟／物理映射未按页对齐");
            let physical = [
                tables.num_syms,
                tables.names,
                tables.markers,
                tables.token_table,
                tables.token_index,
                tables.offsets,
            ];
            for (name, at) in TABLE_SYMBOLS.iter().zip(physical) {
                if let Some(symbol) = unique(&tables, name) {
                    ensure!(
                        symbol.runtime.wrapping_sub(delta) == at,
                        "{name} 与解码出的物理表位置不一致"
                    );
                }
            }
            let banner = unique(&tables, "linux_banner")
                .filter(|s| s.relocated)
                .context("kallsyms 缺少 linux_banner")?;
            let banner_physical = banner.runtime.wrapping_sub(delta);
            let bytes = banners
                .iter()
                .find(|(at, _)| *at == banner_physical)
                .map(|(_, bytes)| bytes.clone())
                .with_context(|| {
                    format!("linux_banner 映射到物理 {banner_physical:#x}，该处不是镜像 banner")
                })?;
            Ok(Located {
                tables,
                delta,
                banner: bytes,
                banner_physical,
            })
        })();
        match checked {
            Ok(found) => located.push(found),
            Err(e) => rejected.push(format!("词表 {:#x}: {e:#}", token_table)),
        }
    }
    match located.len() {
        1 => located.pop().context("kallsyms 候选为空"),
        0 => bail!("kallsyms 候选均未通过物理位置校验：{}", rejected.join("；")),
        n => bail!(
            "镜像中有 {n} 组互不相同且都自洽的内核 kallsyms（{}），无法确定当前内核",
            located
                .iter()
                .map(|l| format!("{:#x}", l.tables.token_table))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The KASLR offset from VMCOREINFO notes that agree with the decoded symbols.
fn kaslr(
    image: &Image,
    located: &Located,
    release: &str,
    job: &Job,
) -> Result<(Option<u64>, Option<i64>, Value)> {
    let notes = vmcoreinfo::find(image, release, job)?;
    let mut agreeing = Vec::new();
    let mut disagreeing = 0usize;
    for note in &notes {
        let mut compared = 0usize;
        let mut consistent = true;
        for (name, value) in &note.symbols {
            // Other SYMBOL() lines may export a pointer's value (mem_section, prb).
            if !ADDRESS_EXPORTS.contains(&name.as_str()) {
                continue;
            }
            if let Some(symbol) = unique(&located.tables, name) {
                compared += 1;
                consistent &= symbol.runtime == *value;
            }
        }
        if let Some(phys_base) = note.numbers.get("phys_base") {
            consistent &= START_KERNEL_MAP.wrapping_sub(phys_base.cast_unsigned()) == located.delta;
        }
        if consistent && compared > 0 {
            agreeing.push((note, compared));
        } else {
            disagreeing += 1;
        }
    }
    let offsets: std::collections::BTreeSet<_> = agreeing
        .iter()
        .filter_map(|(n, _)| n.kernel_offset)
        .collect();
    let summary = json!({
        "notes": notes.len(),
        "agreeing": agreeing.len(),
        "disagreeing": disagreeing,
        "physical": agreeing.iter().map(|(n, _)| format!("{:#x}", n.physical)).collect::<Vec<_>>(),
        "compared_symbols": agreeing.iter().map(|(_, c)| *c).max().unwrap_or(0),
    });
    let l5 = agreeing
        .iter()
        .find_map(|(n, _)| n.numbers.get("pgtable_l5_enabled").copied());
    if offsets.len() == 1 {
        let offset = offsets.into_iter().next().context("KASLR 偏移为空")?;
        ensure!(offset & 4095 == 0, "VMCOREINFO KERNELOFFSET 未按页对齐");
        if let Some(text) = unique(&located.tables, "_text") {
            ensure!(
                text.runtime.wrapping_sub(offset) >= START_KERNEL_MAP,
                "VMCOREINFO KERNELOFFSET 与 _text 不一致"
            );
        }
        return Ok((Some(offset), l5, summary));
    }
    if offsets.len() > 1 {
        job.report("VMCOREINFO 给出多个 KASLR 偏移；地址保持运行时值");
    }
    Ok((None, l5, summary))
}

/// Choose one address per name. A name with several distinct addresses and no
/// single global is ambiguous: it gets no forward entry, and every one of its
/// addresses is returned for reverse (address -> name) lookup only.
type SymbolAddresses = (BTreeMap<String, u64>, Vec<(String, u64)>);

fn symbol_addresses(
    tables: &image_kallsyms::Tables,
    offset: u64,
    job: &Job,
) -> Result<SymbolAddresses> {
    let mut groups: BTreeMap<&str, Vec<&image_kallsyms::Symbol>> = BTreeMap::new();
    for (i, symbol) in tables.symbols.iter().enumerate() {
        if i % 4096 == 0 {
            job.check()?;
        }
        groups.entry(symbol.name.as_str()).or_default().push(symbol);
    }
    let address = |s: &image_kallsyms::Symbol| {
        if s.relocated {
            s.runtime.wrapping_sub(offset)
        } else {
            s.runtime
        }
    };
    let mut out = BTreeMap::new();
    let mut ambiguous = Vec::new();
    for (i, (name, entries)) in groups.into_iter().enumerate() {
        if i % 4096 == 0 {
            job.check()?;
        }
        let first = entries.first().map(|s| address(s));
        let chosen = if entries.iter().all(|s| Some(address(s)) == first) {
            first
        } else {
            let mut globals = entries.iter().filter(|s| s.kind.is_ascii_uppercase());
            match (globals.next(), globals.next()) {
                (Some(global), None) => Some(address(global)),
                _ => None,
            }
        };
        match chosen {
            Some(value) => {
                out.insert(name.to_owned(), value);
            }
            None => {
                let mut seen = std::collections::BTreeSet::new();
                for (i, symbol) in entries.into_iter().enumerate() {
                    if i % 4096 == 0 {
                        job.check()?;
                    }
                    if seen.insert(address(symbol)) {
                        ambiguous.push((name.to_owned(), address(symbol)));
                    }
                }
            }
        }
    }
    Ok((out, ambiguous))
}

/// Types of the kallsyms tables themselves, from the widths and lengths just
/// decoded (reading each with these types reproduces the verified values).
fn measured_types(
    tables: &image_kallsyms::Tables,
    base_types: &Map<String, Value>,
) -> Vec<(&'static str, Value)> {
    let base = |name: &str| json!({"kind":"base","name":name});
    let array = |count: u64, name: &str| json!({"kind":"array","count":count,"subtype":{"kind":"base","name":name}});
    let count = u64::try_from(tables.symbols.len()).unwrap_or(0);
    let markers = count.div_ceil(256);
    let marker = if tables.marker_width == 4 {
        "unsigned int"
    } else {
        "long unsigned int"
    };
    let measured = [
        ("kallsyms_num_syms", base("unsigned int"), "unsigned int"),
        (
            "kallsyms_names",
            array(tables.names_len, "unsigned char"),
            "unsigned char",
        ),
        ("kallsyms_markers", array(markers, marker), marker),
        (
            "kallsyms_token_table",
            array(tables.token_table_len, "char"),
            "char",
        ),
        (
            "kallsyms_token_index",
            array(256, "short unsigned int"),
            "short unsigned int",
        ),
        ("kallsyms_offsets", array(count, "int"), "int"),
        (
            "kallsyms_relative_base",
            base("long unsigned int"),
            "long unsigned int",
        ),
    ];
    measured
        .into_iter()
        .filter(|(_, _, needed)| base_types.contains_key(*needed))
        .map(|(name, ty, _)| (name, ty))
        .collect()
}

fn read_btf(image: &Image, located: &Located, job: &Job) -> Result<Vec<u8>> {
    let start = unique(&located.tables, "__start_BTF")
        .filter(|s| s.relocated)
        .ok_or_else(|| {
            unavailable("kallsyms 缺少 __start_BTF；内核需启用 CONFIG_DEBUG_INFO_BTF")
        })?;
    let stop = unique(&located.tables, "__stop_BTF")
        .filter(|s| s.relocated)
        .ok_or_else(|| unavailable("kallsyms 缺少 __stop_BTF"))?;
    let length = stop
        .runtime
        .checked_sub(start.runtime)
        .filter(|l| (24..=MAX_BTF).contains(l))
        .context("内核 BTF 长度无效")?;
    let mut bytes = vec![0; usize::try_from(length)?];
    image_kallsyms::read(
        image,
        start.runtime.wrapping_sub(located.delta),
        &mut bytes,
        job,
    )
    .context("内核 BTF 所在物理页不在镜像中")?;
    Ok(bytes)
}

/// Build, validate and store the ISF; returns its cache path.
pub fn generate(image: &Image, cache: &Path, job: &Job) -> Result<PathBuf> {
    job.check()?;
    let _lock = crate::cache::lock(cache, false)?;
    image.ensure_unchanged()?;
    let stamp = image.stamp()?;
    ensure!(
        !image.digest.is_empty(),
        "镜像缺少已验证摘要；请重新打开镜像"
    );
    let build = artifact::build_path(image, cache);
    let _generation_lock =
        super::stages::artifact_lock(&build.join("generation.lock"), "该镜像符号正在生成", job)?;
    if let Some(path) = artifact::reuse(image, cache, &build, &stamp, job)? {
        return Ok(path);
    }
    job.report("扫描 kallsyms / VMCOREINFO 锚点");
    image.prefetch_scans(&[image_kallsyms::DIGITS, vmcoreinfo::ANCHOR], job)?;
    let located = locate(image, job)?;
    let banner_text = String::from_utf8_lossy(&located.banner)
        .trim_end_matches(['\0', '\n'])
        .to_owned();
    if banner_text.contains("aarch64") || banner_text.contains("arm64") {
        return Err(unavailable(
            "独立镜像生成目前仅支持 x86_64；ARM64 可复用精确本地 ISF",
        ));
    }
    ensure!(
        located
            .tables
            .symbols
            .iter()
            .filter(|s| s.relocated)
            .all(|s| s.runtime >= START_KERNEL_MAP),
        "kallsyms 地址不在 x86_64 内核映射范围；从镜像生成符号目前仅支持 x86_64 内核"
    );
    job.report(format!(
        "kallsyms 已与镜像 banner 对应：物理 {:#x} · 映射差 {:#x}",
        located.banner_physical, located.delta
    ));
    let release = release(&located.banner)?;
    let (offset, l5, vmcoreinfo) = kaslr(image, &located, &release, job)?;
    match offset {
        Some(offset) => job.report(format!("VMCOREINFO 已核对：KASLR 偏移 {offset:#x}")),
        None => job.report("镜像未提供可核对的 KASLR 偏移；符号使用运行时地址"),
    }
    job.report("读取并转换内核 BTF");
    let btf_bytes = read_btf(image, &located, job)?;
    let btf = btf::Btf::parse(&btf_bytes, job)?;
    ensure!(
        btf.has_struct("task_struct"),
        "内核 BTF 不含 task_struct；不是 vmlinux 的基础 BTF"
    );
    let types = btf::convert(&btf, 8, job)?;
    let btf_sha256 = format!("{:x}", Sha256::digest(&btf_bytes));
    let btf_length = btf_bytes.len();
    let btf_types = btf.len();
    drop(btf_bytes);
    drop(btf);
    let (addresses, ambiguous) = symbol_addresses(&located.tables, offset.unwrap_or(0), job)?;
    let measured = measured_types(&located.tables, &types.base_types);
    let mut symbols = Map::new();
    let mut typed = 0usize;
    job.report("构建 ISF 符号与类型");
    for (i, (name, address)) in addresses.iter().enumerate() {
        if i % 4096 == 0 {
            job.check()?;
        }
        let mut entry = Map::new();
        entry.insert("address".into(), json!(address));
        let ty = types
            .variables
            .get(name)
            .or_else(|| measured.iter().find(|(n, _)| n == name).map(|(_, ty)| ty));
        if let Some(ty) = ty {
            entry.insert("type".into(), ty.clone());
            typed += 1;
        }
        if name == "linux_banner" {
            entry.insert(
                "constant_data".into(),
                json!(base64::engine::general_purpose::STANDARD.encode(&located.banner)),
            );
        }
        symbols.insert(name.clone(), Value::Object(entry));
    }
    let ambiguous_names: std::collections::BTreeSet<&str> =
        ambiguous.iter().map(|(name, _)| name.as_str()).collect();
    ensure!(
        symbols.contains_key("linux_banner"),
        "linux_banner 地址有歧义"
    );
    let kallsyms_sha256 = {
        let mut hash = Sha256::new();
        for (i, s) in located.tables.symbols.iter().enumerate() {
            if i % 4096 == 0 {
                job.check()?;
            }
            hash.update(format!(
                "{:x} {} {} {}\n",
                s.runtime, s.relocated, s.kind, s.name
            ));
        }
        format!("{:x}", hash.finalize())
    };
    let untyped = addresses.len() - typed;
    let mut conflicts = types.conflicts.clone();
    conflicts.truncate(64);
    let metadata = json!({
        "format": "6.2.0",
        "producer": {"name": "zero", "version": env!("CARGO_PKG_VERSION")},
        "linux": {
            "symbols": [{"kind":"kallsyms","name":"memory image","hash_type":"sha256","hash_value":kallsyms_sha256}],
            "types": [{"kind":"btf","name":"vmlinux BTF","hash_type":"sha256","hash_value":btf_sha256}],
        },
        "zero": {
            "architecture": "x86_64",
            "page_shift": 12,
            "va_bits": if l5 == Some(1) { 57 } else { 48 },
            "source": "image",
            "generator": GENERATOR,
            "image_sha256": image.digest,
            "btf_sha256": btf_sha256,
            "kallsyms_sha256": kallsyms_sha256,
            "address_basis": if offset.is_some() { "link" } else { "runtime" },
            "kaslr_offset": offset,
            "symbol_types": "btf-variables-only",
            "measured_symbol_types": measured.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            "typed_symbols": typed,
            "untyped_symbols": untyped,
            "ambiguous_symbols": ambiguous_names.len(),
            // Reverse lookup only: [name, address] for names with several addresses.
            "duplicate_symbols": ambiguous.iter().map(|(name, address)| json!([name, address])).collect::<Vec<_>>(),
            "type_conflicts": types.conflicts.len(),
        },
    });
    // Move the large type/symbol trees, then release this tree before parsing
    // the engine ISF: generation should never keep two full JSON trees alive.
    let data = Value::Object(Map::from_iter([
        ("metadata".into(), metadata),
        ("base_types".into(), Value::Object(types.base_types)),
        ("user_types".into(), Value::Object(types.user_types)),
        ("enums".into(), Value::Object(types.enums)),
        ("symbols".into(), Value::Object(symbols)),
    ]));
    drop(types.variables);
    let bytes = artifact::json_bytes(&data, job)?;
    drop(data);
    let mut isf = Isf::parse(&bytes, "generated-from-image".into())?;
    ensure!(
        isf.banner == located.banner,
        "生成 ISF 的 banner 与镜像不一致"
    );
    job.report("用生成的 ISF 验证内核页表");
    let (root, slide) = validate(image, &mut isf, offset, job)?;
    job.report(format!(
        "生成符号：{} 个结构 · {} 个枚举 · {} 个符号（{typed} 个带类型，{} 个歧义已省略）",
        isf.data.key("user_types").as_object().map_or(0, Map::len),
        isf.data.key("enums").as_object().map_or(0, Map::len),
        addresses.len(),
        ambiguous_names.len()
    ));
    let path = cache
        .join("symbols/isf")
        .join(format!("{}.json.xz", isf.digest));
    let tables = &located.tables;
    let source = json!({
        "source": "image",
        "generator": GENERATOR,
        "image_sha256": image.digest,
        "banner": banner_text,
        "metadata": isf.data.key("metadata"),
        "provenance": {
            "kallsyms": {
                "symbols": tables.symbols.len(),
                "layout": tables.layout,
                "percpu": tables.percpu,
                "relative_base": format!("{:#x}", tables.relative_base),
                "physical": {
                    "num_syms": format!("{:#x}", tables.num_syms),
                    "names": format!("{:#x}", tables.names),
                    "markers": format!("{:#x}", tables.markers),
                    "token_table": format!("{:#x}", tables.token_table),
                    "token_index": format!("{:#x}", tables.token_index),
                    "offsets": format!("{:#x}", tables.offsets),
                    "relative_base": format!("{:#x}", tables.relative_base_at),
                },
            },
            "virtual_minus_physical": format!("{:#x}", located.delta),
            "banner_physical": format!("{:#x}", located.banner_physical),
            "btf": {"bytes": btf_length, "types": btf_types, "sha256": btf_sha256},
            "vmcoreinfo": vmcoreinfo,
            "page_table": {"root": format!("{root:#x}"), "slide": format!("{slide:#x}")},
            "ambiguous_symbols": ambiguous_names.iter().take(64).collect::<Vec<_>>(),
            "type_conflicts": conflicts,
        },
    });
    drop(isf);
    artifact::publish(image, &stamp, &path, &bytes, &source, job)?;
    artifact::index(image, &stamp, &build, &path, job)?;
    job.report(format!("已从镜像生成 ISF: {}", path.display()));
    Ok(path)
}

/// Both fresh and reused ISFs must identify the kernel through its actual page tables.
fn validate(image: &Image, isf: &mut Isf, offset: Option<u64>, job: &Job) -> Result<(u64, u64)> {
    job.check()?;
    isf.locations = image
        .banners(job)?
        .iter()
        .filter(|(_, b)| *b == isf.banner)
        .map(|(at, _)| *at)
        .collect();
    ensure!(!isf.locations.is_empty(), "ISF 完整 banner 与镜像不一致");
    let root = crate::linux::discover(image, isf, job).context("生成的 ISF 未通过页表验证")?;
    let slide = isf.slide.load(std::sync::atomic::Ordering::Relaxed);
    if let Some(offset) = offset {
        ensure!(
            slide == offset,
            "页表重定位 {slide:#x} 与预期 {offset:#x} 不一致"
        );
    }
    job.check()?;
    Ok((root, slide))
}

#[cfg(test)]
pub(crate) mod tests;
