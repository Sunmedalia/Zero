//! Exact module symbol queries. PDBs take precedence over mapped PE exports.
use super::*;
use crate::analysis::PESource;

const EXPORT_LIMIT: usize = 65536;
const INSTANCE_LIMIT: usize = 65536;
const NAME_LIMIT: usize = 4096;

#[derive(Clone, Copy)]
struct Instance {
    root: u64,
    base: u64,
    size: u64,
    kernel: bool,
}

/// Validate the mapped image before accepting its export directory. Section
/// metadata must be captured; missing bytes are never supplied as zeroes.
pub(super) fn export_header(bytes: &[u8]) -> Result<pe_info::Header> {
    let header = pe_info::parse_header(bytes)?;
    let nt = u32::from_le_bytes(bytes[60..64].try_into()?) as usize;
    let machine = u16::from_le_bytes(bytes[nt + 4..nt + 6].try_into()?);
    ensure!(
        (machine == 0x14c && !header.wide) || (matches!(machine, 0x8664 | 0xaa64) && header.wide),
        "模块 PE 架构与位宽冲突"
    );
    let sections = u16::from_le_bytes(bytes[nt + 6..nt + 8].try_into()?) as usize;
    ensure!(sections <= 96, "PE section 数量超限");
    let optional_size = u16::from_le_bytes(bytes[nt + 20..nt + 22].try_into()?) as usize;
    ensure!(
        optional_size >= if header.wide { 112 } else { 96 },
        "PE 可选头长度无效"
    );
    let start = nt + 24 + optional_size;
    let end = start
        .checked_add(sections * 40)
        .context("PE section 表溢出")?;
    ensure!(
        end as u64 <= u64::from(header.size),
        "PE section 表超出映像"
    );
    let table = bytes.get(start..end).context("PE section 表未完整捕获")?;
    for section in table.chunks_exact(40) {
        for offset in [8, 12, 16] {
            let value = u32::from_le_bytes(section[offset..offset + 4].try_into()?);
            ensure!(value <= header.size, "PE section 范围超出映像");
        }
    }
    Ok(header)
}

/// All reads are image-relative and bounded by SizeOfImage, including names.
pub(super) fn export_symbols(
    size: u32,
    directory: (u32, u32),
    mut read: impl FnMut(u32, &mut [u8]) -> Result<()>,
    job: &Job,
    diagnostics: &mut Vec<String>,
) -> Result<Vec<(String, u32)>> {
    job.check()?;
    let mut bounded = |rva: u32, out: &mut [u8]| -> Result<()> {
        ensure!(
            u64::from(rva) + out.len() as u64 <= u64::from(size),
            "PE 导出读取越界"
        );
        read(rva, out)
    };
    let (rva, length) = directory;
    if rva == 0 || length == 0 {
        return Ok(Vec::new());
    }
    ensure!(
        length >= 40 && rva.checked_add(length).is_some_and(|end| end <= size),
        "PE 导出目录越界"
    );
    let mut header = [0; 40];
    bounded(rva, &mut header)?;
    let word = |at| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    let functions = word(20) as usize;
    let names = word(24) as usize;
    ensure!(
        functions <= EXPORT_LIMIT && names <= EXPORT_LIMIT,
        "PE 导出数量超限"
    );
    let mut out = Vec::new();
    let mut text_bytes = 0usize;
    for index in 0..names {
        job.check()?;
        let entry = (|| -> Result<Option<(String, u32)>> {
            let mut pointer = [0; 4];
            let mut ordinal = [0; 2];
            bounded(
                word(32)
                    .checked_add(index as u32 * 4)
                    .context("PE 名称表溢出")?,
                &mut pointer,
            )?;
            bounded(
                word(36)
                    .checked_add(index as u32 * 2)
                    .context("PE ordinal 表溢出")?,
                &mut ordinal,
            )?;
            let ordinal = u16::from_le_bytes(ordinal) as usize;
            ensure!(ordinal < functions, "PE 导出 ordinal 越界");
            let mut address = [0; 4];
            bounded(
                word(28)
                    .checked_add(ordinal as u32 * 4)
                    .context("PE 地址表溢出")?,
                &mut address,
            )?;
            let address = u32::from_le_bytes(address);
            if address == 0 {
                return Ok(None);
            }
            ensure!(address < size, "PE 导出地址越界");
            let name_rva = u32::from_le_bytes(pointer);
            let mut name = Vec::new();
            for offset in 0..NAME_LIMIT {
                if offset % 256 == 0 {
                    job.check()?;
                }
                let mut byte = [0];
                bounded(
                    name_rva.checked_add(offset as u32).context("PE 名称溢出")?,
                    &mut byte,
                )?;
                if byte[0] == 0 {
                    break;
                }
                ensure!(byte[0].is_ascii(), "PE 导出名称不是 ASCII");
                name.push(byte[0]);
            }
            ensure!(name.len() < NAME_LIMIT, "PE 导出名称未终止");
            text_bytes += name.len();
            ensure!(text_bytes <= 16 * 1024 * 1024, "PE 导出文本超限");
            // Forwarders keep their directory RVA; never invent a resolved target.
            Ok(Some((String::from_utf8(name)?, address)))
        })();
        job.check()?;
        match entry {
            Ok(Some(symbol)) => out.push(symbol),
            Ok(None) => {}
            Err(error) => {
                if diagnostics.len() < 32 {
                    diagnostics.push(format!("export {index}: {error:#}"));
                }
                // Like the reference PE parser, stop at the first invalid
                // named entry; retain the decoded prefix without zero-padding.
                break;
            }
        }
        ensure!(text_bytes <= 16 * 1024 * 1024, "PE 导出文本超限");
    }
    Ok(out)
}

fn resolve_queries(
    symbols: &[(String, u64)],
    names: &[String],
    addresses: &[u64],
    resolved: &mut [bool],
    rows: &mut Vec<Vec<String>>,
    module: &str,
) {
    let mut by_name = BTreeMap::new();
    let mut by_address = BTreeMap::new();
    for symbol in symbols {
        by_name.entry(symbol.0.as_str()).or_insert(symbol);
        by_address.entry(symbol.1).or_insert(symbol);
    }
    for (index, done) in resolved.iter_mut().enumerate() {
        if *done {
            continue;
        }
        let found = if !names.is_empty() {
            by_name.get(names[index].as_str()).copied()
        } else {
            by_address.get(&addresses[index]).copied()
        };
        if let Some((name, address)) = found {
            rows.push(vec![module.to_owned(), name.clone(), hex(*address)]);
            *done = true;
        }
    }
}

impl Windows<'_> {
    pub(super) fn pe_symbols(
        &self,
        options: &Options,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<Results> {
        self.pe_symbols_with_reads(options, resources, job, false)
    }
    pub(super) fn pe_symbols_captured(
        &self,
        options: &Options,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
    ) -> Result<Results> {
        self.pe_symbols_with_reads(options, resources, job, true)
    }
    fn pe_symbols_with_reads(
        &self,
        options: &Options,
        resources: Option<(&std::path::Path, bool)>,
        job: &Job,
        captured: bool,
    ) -> Result<Results> {
        options.pe.validate(Plugin::WinPESymbols)?;
        let read = |vm: &Memory<'_>, address, bytes: &mut [u8]| {
            if captured {
                vm.read_captured(address, bytes)
            } else {
                vm.read(address, bytes)
            }
        };
        let query = &options.pe;
        let module = query.module.as_ref().unwrap().to_lowercase();
        let mut result = self.result(Plugin::WinPESymbols);
        let mut instances = Vec::new();
        if query.source == Some(PESource::Kernel) {
            let modules = self.module_entries(job, &mut result, false)?;
            let mut session_roots = None;
            for (index, loaded) in modules.into_iter().enumerate() {
                job.check()?;
                let kernel = index == 0 && module == concat!("nt", "oskrnl.exe");
                if !kernel && loaded.name.to_lowercase() != module {
                    continue;
                }
                let mut instance = Instance {
                    root: self.vm.root,
                    base: loaded.base,
                    size: loaded.size,
                    kernel,
                };
                let mut probe = [0; 2];
                if self.vm.read(loaded.base, &mut probe).is_err() {
                    if session_roots.is_none() {
                        let (processes, diagnostics) = self.processes_partial(job)?;
                        if !diagnostics.is_empty() {
                            result.complete = false;
                            result.diagnostics.extend(diagnostics);
                        }
                        session_roots = Some(
                            processes
                                .into_iter()
                                .filter_map(|p| self.process_memory(&p).ok().map(|vm| vm.root))
                                .collect::<Vec<_>>(),
                        );
                    }
                    let root = session_roots.as_ref().unwrap().iter().find(|root| {
                        Memory::new(self.vm.image, **root, self.vm.isf, self.vm.sources)
                            .read(loaded.base, &mut probe)
                            .is_ok()
                    });
                    if let Some(root) = root {
                        instance.root = *root;
                    } else {
                        Self::issue(&mut result, &module, "模块在可用地址空间中不可读");
                        continue;
                    }
                }
                instances.push(instance);
                ensure!(instances.len() <= INSTANCE_LIMIT, "PE 模块实例超过上限");
            }
        } else {
            let (processes, diagnostics) = self.processes_partial(job)?;
            if !diagnostics.is_empty() {
                result.complete = false;
                result.diagnostics.extend(diagnostics);
            }
            for process in processes {
                job.check()?;
                let vads = match self.vads_partial_order(&process, job, Some(&mut result), true) {
                    Ok(vads) => vads,
                    Err(error) => {
                        Self::issue(&mut result, format!("PID {} VAD", process.pid), error);
                        continue;
                    }
                };
                let matching = vads.into_iter().filter(|vad| {
                    vad.path
                        .rsplit_once('\\')
                        .is_some_and(|(_, name)| name.to_lowercase() == module)
                });
                for vad in matching {
                    job.check()?;
                    match self.process_memory(&process) {
                        Ok(vm) => instances.push(Instance {
                            root: vm.root,
                            base: vad.start,
                            size: vad.end - vad.start,
                            kernel: false,
                        }),
                        Err(error) => {
                            Self::issue(&mut result, format!("PID {}", process.pid), error)
                        }
                    }
                    ensure!(instances.len() <= INSTANCE_LIMIT, "PE 模块实例超过上限");
                }
            }
        }
        let count = if query.names.is_empty() {
            query.addresses.len()
        } else {
            query.names.len()
        };
        let mut resolved = vec![false; count];
        let mut evidence = Vec::new();
        let mut pdb_failures = Vec::new();
        let wanted_names: HashSet<_> = query.names.iter().map(String::as_str).collect();
        let wanted_addresses: HashSet<_> = query.addresses.iter().copied().collect();
        // Try PDBs for every instance before using exports from any instance.
        for instance in &instances {
            job.check()?;
            if resolved.iter().all(|done| *done) {
                break;
            }
            let vm = Memory::new(self.vm.image, instance.root, self.vm.isf, self.vm.sources);
            let found = (|| -> Result<Vec<(String, u64)>> {
                let acquired;
                let isf = if instance.kernel {
                    self.vm.isf
                } else {
                    let mut header = [0; 4096];
                    read(&vm, instance.base, &mut header)?;
                    ensure!(
                        u64::from(pe_info::parse_header(&header)?.size) == instance.size,
                        "模块范围与 PE SizeOfImage 不一致"
                    );
                    let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
                    let machine = u16::from_le_bytes(header[pe + 4..pe + 6].try_into()?);
                    let parsed = pe_info::parse_header(&header)?;
                    ensure!(
                        (machine == 0x14c && !parsed.wide)
                            || (matches!(machine, 0x8664 | 0xaa64) && parsed.wide),
                        "模块 PE 架构与位宽冲突"
                    );
                    let identity = network::pe_identity_for_machine(&vm, instance.base, machine)?;
                    let (cache, network) = resources.context("缺少外部模块符号资源上下文")?;
                    acquired = windows_symbols::acquire(&identity, cache, network, job)?;
                    ensure!(
                        PdbIdentity::from_isf(&acquired)? == identity,
                        "模块 PDB 身份不匹配"
                    );
                    ensure!(
                        Architecture::from_isf(&acquired)?.machine() == machine,
                        "模块 PDB 架构冲突"
                    );
                    &acquired
                };
                let mut symbols = Vec::new();
                let mut symbol_bytes = 0usize;
                let entries = isf.data["symbols"].as_object().context("缺少符号映射")?;
                ensure!(entries.len() <= 1_000_000, "模块符号数量超限");
                for (name, entry) in entries {
                    job.check()?;
                    if let Some(rva) = entry["address"].as_u64().filter(|rva| *rva < instance.size)
                    {
                        let address = add(instance.base, rva)?;
                        if (!query.names.is_empty() && wanted_names.contains(name.as_str()))
                            || (query.names.is_empty() && wanted_addresses.contains(&address))
                        {
                            symbol_bytes += name.len();
                            ensure!(symbol_bytes <= 128 * 1024 * 1024, "模块符号文本超限");
                            symbols.push((name.clone(), address));
                        }
                    }
                }
                evidence.push(serde_json::json!({"method":"pdb","base":hex(instance.base),"page_table":hex(instance.root),"isf_sha256":isf.digest}));
                Ok(symbols)
            })();
            match found {
                Ok(symbols) => resolve_queries(
                    &symbols,
                    &query.names,
                    &query.addresses,
                    &mut resolved,
                    &mut result.rows,
                    &module,
                ),
                Err(error) => pdb_failures.push(format!("{} PDB: {error:#}", hex(instance.base))),
            }
        }
        for instance in &instances {
            job.check()?;
            if resolved.iter().all(|done| *done) {
                break;
            }
            let vm = Memory::new(self.vm.image, instance.root, self.vm.isf, self.vm.sources);
            let mut export_diagnostics = Vec::new();
            let found = (|| -> Result<Vec<(String, u64)>> {
                let mut header = [0; 4096];
                read(&vm, instance.base, &mut header)?;
                let header = export_header(&header)?;
                ensure!(
                    u64::from(header.size) <= instance.size,
                    "PE SizeOfImage 超出模块范围"
                );
                let exports = export_symbols(
                    header.size,
                    header.exports,
                    |rva, bytes| read(&vm, add(instance.base, u64::from(rva))?, bytes),
                    job,
                    &mut export_diagnostics,
                )?;
                exports
                    .into_iter()
                    .map(|(name, rva)| Ok((name, add(instance.base, u64::from(rva))?)))
                    .collect()
            })();
            for error in export_diagnostics {
                Self::issue(
                    &mut result,
                    format!("{} exports", hex(instance.base)),
                    error,
                );
            }
            match found {
                Ok(symbols) => {
                    evidence
                        .push(serde_json::json!({"method":"exports","base":hex(instance.base),"page_table":hex(instance.root),"header_requires_recovery":vm.translate(instance.base).is_err()}));
                    resolve_queries(
                        &symbols,
                        &query.names,
                        &query.addresses,
                        &mut resolved,
                        &mut result.rows,
                        &module,
                    );
                }
                Err(error) => Self::issue(
                    &mut result,
                    format!("{} exports", hex(instance.base)),
                    error,
                ),
            }
        }
        job.check()?;
        if resolved.iter().any(|done| !done) && !pdb_failures.is_empty() {
            result.complete = false;
            result
                .diagnostics
                .extend(pdb_failures.iter().take(32).cloned());
        }
        result.kernel_identity["pe_symbols"] = serde_json::json!({"instances":instances.len(),"resolved":resolved.iter().filter(|done| **done).count(),"queries":count,"sources":evidence,"optional_pdb_failures":pdb_failures.iter().take(32).collect::<Vec<_>>()});
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapped_export_headers_validate_machine_sections_and_captured_bytes() {
        let mut bytes = vec![0u8; 4096];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x4000u32.to_le_bytes());
        let section = 0x178;
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        assert!(export_header(&bytes).is_ok());
        assert!(export_header(&bytes[..section + 39]).is_err());
        for offset in [8, 12, 16] {
            let mut broken = bytes.clone();
            broken[section + offset..section + offset + 4]
                .copy_from_slice(&0x4001u32.to_le_bytes());
            assert!(export_header(&broken).is_err());
        }
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        assert!(export_header(&bytes).is_err());
    }

    #[test]
    fn kernel_queries_use_selected_symbols_without_reading_optional_module_paths() {
        use super::super::tests::{K, fixture, image, put};
        use serde_json::json;
        let (mut bytes, mut isf) = fixture();
        bytes[0x8094..0x8096].copy_from_slice(&240u16.to_le_bytes());
        let pointer = |offset| json!({"offset":offset,"type":{"kind":"pointer"}});
        isf.data["user_types"]["_KLDR_DATA_TABLE_ENTRY"] = json!({"size":64,"fields":{
            "InLoadOrderLinks":{"offset":0,"type":{"kind":"struct","name":"_LIST_ENTRY"}},
            "DllBase":pointer(16),"SizeOfImage":pointer(24),
            "BaseDllName":{"offset":32,"type":{"kind":"struct","name":"_UNICODE_STRING"}}
        }});
        put(&mut bytes, 0x8700, K + 0x6000);
        put(&mut bytes, 0x8708, K + 0x6000);
        put(&mut bytes, 0xe000, K + 0x700);
        put(&mut bytes, 0xe008, K + 0x700);
        put(&mut bytes, 0xe010, K);
        put(&mut bytes, 0xe018, 0x8000);
        // Empty but valid BaseDllName. The first module still represents the kernel.
        let img = image(&bytes);
        let engine = Windows {
            vm: Memory::new(&img, 0x1000, &isf, None),
            base: K,
            pdb: PdbIdentity::from_isf(&isf).unwrap(),
        };
        let options = Options {
            pe: crate::analysis::PEQuery {
                source: Some(PESource::Kernel),
                module: Some(concat!("nt", "oskrnl.exe").into()),
                names: vec![
                    "PsActiveProcessHead".into(),
                    "PsActiveProcessHead".into(),
                    "AbsentSymbol".into(),
                ],
                addresses: vec![1],
            },
            ..Default::default()
        };
        let r = engine.pe_symbols(&options, None, &Job::default()).unwrap();
        assert!(r.complete, "{:?}", r.diagnostics);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0], r.rows[1]);
        assert_eq!(r.rows[0][2], hex(K + 0x400));
        assert_eq!(r.kernel_identity["pe_symbols"]["queries"], 3);
        assert_eq!(r.kernel_identity["pe_symbols"]["resolved"], 2);
    }
    #[test]
    fn unreadable_export_preserves_other_readable_entries() {
        let bytes = fixture();
        let mut diagnostics = Vec::new();
        let symbols = export_symbols(
            bytes.len() as u32,
            (0x100, 0x40),
            |rva, out| {
                ensure!(rva != 0x210, "missing name page");
                out.copy_from_slice(&bytes[rva as usize..rva as usize + out.len()]);
                Ok(())
            },
            &Job::default(),
            &mut diagnostics,
        )
        .unwrap();
        assert_eq!(symbols, [("Foo".into(), 0x250)]);
        assert_eq!(diagnostics.len(), 1);
    }
    #[test]
    fn exact_queries_preserve_duplicates_and_name_precedence() {
        let symbols = vec![("Alias".into(), 0x1010), ("Other".into(), 0x1010)];
        let mut rows = Vec::new();
        let mut resolved = vec![false; 3];
        resolve_queries(
            &symbols,
            &["Alias".into(), "Alias".into(), "alias".into()],
            &[0x1011],
            &mut resolved,
            &mut rows,
            "x.dll",
        );
        assert_eq!(resolved, [true, true, false]);
        assert_eq!(rows.len(), 2);
        rows.clear();
        resolve_queries(
            &symbols,
            &[],
            &[0x1010, 0x1011],
            &mut [false; 2],
            &mut rows,
            "x.dll",
        );
        assert_eq!(rows, vec![vec!["x.dll", "Alias", "0x0000000000001010"]]);
    }
    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 0x400];
        for (offset, value) in [(20, 3u32), (24, 2), (28, 0x140), (32, 0x160), (36, 0x180)] {
            bytes[0x100 + offset..0x104 + offset].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (0x140, 0x250u32),
            (0x144, 0x260),
            (0x148, 0x110),
            (0x160, 0x200),
            (0x164, 0x210),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x182..0x184].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x200..0x204].copy_from_slice(b"Foo\0");
        bytes[0x210..0x214].copy_from_slice(b"Bar\0");
        bytes
    }
    fn parse(bytes: &[u8]) -> Result<Vec<(String, u32)>> {
        let mut diagnostics = Vec::new();
        let symbols = export_symbols(
            bytes.len() as u32,
            (0x100, 0x40),
            |rva, out| {
                out.copy_from_slice(
                    bytes
                        .get(rva as usize..rva as usize + out.len())
                        .context("missing")?,
                );
                Ok(())
            },
            &Job::default(),
            &mut diagnostics,
        )?;
        ensure!(diagnostics.is_empty(), "{}", diagnostics.join("; "));
        Ok(symbols)
    }
    #[test]
    fn exports_keep_forwarder_rva_and_skip_ordinal_only() {
        assert_eq!(
            parse(&fixture()).unwrap(),
            [("Foo".into(), 0x250), ("Bar".into(), 0x110)]
        );
    }
    #[test]
    fn cancelled_exports_and_unterminated_names_fail() {
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let bytes = fixture();
        assert!(
            export_symbols(
                bytes.len() as u32,
                (0x100, 0x40),
                |rva, out| {
                    out.copy_from_slice(&bytes[rva as usize..rva as usize + out.len()]);
                    Ok(())
                },
                &job,
                &mut Vec::new()
            )
            .is_err()
        );
        let mut bytes = fixture();
        bytes[0x200..].fill(b'A');
        assert!(parse(&bytes).is_err());
        let mut bytes = fixture();
        bytes[0x182..0x184].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            parse(&bytes).unwrap(),
            [("Foo".into(), 0x250), ("Bar".into(), 0x250)]
        );
    }
    #[test]
    fn exports_reject_bad_ordinals_ranges_and_missing_bytes() {
        let mut bytes = fixture();
        bytes[0x180..0x182].copy_from_slice(&3u16.to_le_bytes());
        assert!(parse(&bytes).is_err());
        let mut bytes = fixture();
        bytes[0x160..0x164].copy_from_slice(&0x400u32.to_le_bytes());
        assert!(parse(&bytes).is_err());
        assert!(
            export_symbols(
                0x400,
                (0x100, 0x40),
                |_, _| anyhow::bail!("missing page"),
                &Job::default(),
                &mut Vec::new()
            )
            .is_err()
        );
    }
}
