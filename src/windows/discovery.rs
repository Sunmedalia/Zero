//! Kernel root discovery: self-referencing page tables validated against the exact PDB.
use super::*;

/// Discover self-referencing x64 roots and validate a mapped kernel against its PDB.
pub fn discover(image: &Image, isf: &Isf, job: &Job) -> Result<(u64, u64)> {
    job.check()?;
    let identity = PdbIdentity::from_isf(isf)?;
    let signatures: Vec<_> = image
        .windows_candidates(job)?
        .iter()
        .filter(|c| c.pdb == identity)
        .map(|c| c.offset)
        .collect();
    ensure!(!signatures.is_empty(), "ISF 与镜像 PDB 不匹配");
    if let Some(value) = image
        .windows_roots
        .lock()
        .map_err(|_| anyhow::anyhow!("Windows 准备缓存锁损坏"))?
        .get(&isf.digest)
    {
        return Ok(*value);
    }
    let geometry = Paging::new(isf)?;
    // A root found in an earlier session for the same verified content and
    // ISF skips the whole-image scans, but only after the same validation.
    if let Some(&(root, base)) = image.persisted_roots.get(&isf.digest) {
        match validate_kernel(image, isf, geometry, &identity, root, base) {
            Ok(()) => {
                job.report(format!(
                    "复用持久化 Windows 内核定位 DTB {root:#x} Base {base:#x}（PDB 身份、System 进程与链表已重新验证）"
                ));
                image
                    .windows_roots
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Windows 准备缓存锁损坏"))?
                    .insert(isf.digest.clone(), (root, base));
                return Ok((root, base));
            }
            Err(e) => job.report(format!("持久化 Windows 内核定位失效，重新扫描: {e:#}")),
        }
    }
    let mut headers = HashSet::new();
    let minimum = isf.raw_address("PsInitialSystemProcess")?;
    let mut roots = image
        .windows_container
        .as_ref()
        .and_then(|m| m.dtb)
        .into_iter()
        .collect::<Vec<_>>();
    let mut block = vec![0; 4 * 1024 * 1024];
    for segment in &image.segments {
        let mut start = segment.start.next_multiple_of(4096);
        while start < segment.end {
            job.check()?;
            let n = ((segment.end - start) as usize).min(block.len());
            image.read(start, &mut block[..n])?;
            for (i, page) in block[..n].chunks_exact(4096).enumerate() {
                let pa = start + i as u64 * 4096;
                if pe_header(page)
                    .is_ok_and(|(size, debug)| u64::from(size) > minimum && debug != 0)
                {
                    headers.insert(pa);
                }
                if geometry.arch == Architecture::X64
                    && page.as_chunks::<8>().0.iter().skip(256).any(|b| {
                        let e = u64::from_le_bytes(*b);
                        e & 1 != 0 && e & geometry.mask() == pa
                    })
                {
                    roots.push(pa);
                }
            }
            start += n as u64;
            job.report(format!(
                "Windows DTB 候选扫描 @ {start:#x} · {} 候选",
                roots.len()
            ));
        }
    }

    // A physical System EPROCESS gives a root candidate on every architecture.
    // Candidates still require mapped PE identity, PID, DTB and list validation.
    let name_offset = isf.offset("_EPROCESS", "ImageFileName")?;
    for hit in image.scan(b"System\0", job)? {
        job.check()?;
        let Some(address) = hit.checked_sub(name_offset) else {
            continue;
        };
        let read = |field: &str| -> Result<u64> {
            let mut b = [0; 8];
            image.read(
                add(address, isf.offset("_EPROCESS", field)?)?,
                &mut b[..isf.size("_EPROCESS", field)?],
            )?;
            Ok(u64::from_le_bytes(b))
        };
        if read("UniqueProcessId").is_ok_and(|pid| pid == 4)
            && let Ok(root) = read("Pcb.DirectoryTableBase")
            && root & geometry.root_mask() != 0
        {
            roots.push(root & geometry.root_mask());
        }
    }
    roots.sort_unstable();
    roots.dedup();

    ensure!(!headers.is_empty(), "找不到 Windows 内核 PE 头");
    job.report(format!(
        "Windows {} 个 PE 头，{} 个 DTB 候选",
        headers.len(),
        roots.len()
    ));
    for root in roots {
        job.check()?;
        let mut bases = Vec::new();
        let mut visited = HashSet::new();
        let mut budget = MAX_OBJECTS;
        find_mappings(
            image,
            root,
            geometry,
            0,
            0,
            &headers,
            &mut bases,
            &mut visited,
            &mut budget,
            job,
        )?;
        for base in bases {
            let test = validate_kernel(image, isf, geometry, &identity, root, base);
            if test.is_ok() {
                job.report(format!("Windows 内核已验证 DTB {root:#x} Base {base:#x}"));
                let vm = Memory::new(image, root, isf, None);
                let system = vm.pointer(add(base, isf.raw_address("PsInitialSystemProcess")?)?)?;
                let root = vm.number(system, "_EPROCESS", "Pcb.DirectoryTableBase")?
                    & geometry.root_mask();
                image
                    .windows_roots
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Windows 准备缓存锁损坏"))?
                    .insert(isf.digest.clone(), (root, base));
                image.remember_windows_root(&isf.digest, root, base);
                return Ok((root, base));
            } else if let Err(e) = test {
                job.report(format!(
                    "Windows 内核候选拒绝 DTB {root:#x} Base {base:#x}: {e:#}"
                ));
            }
        }
    }
    bail!("无法验证 Windows 内核/DTB/PDB/进程链表")
}

/// Full kernel validation for one (DTB, base) pair: mapped PE header and
/// architecture, exact PDB identity, the System process and both neighbours
/// of its process-list entry, and the System DTB mapping the kernel.
pub(super) fn validate_kernel(
    image: &Image,
    isf: &Isf,
    geometry: Paging,
    identity: &PdbIdentity,
    root: u64,
    base: u64,
) -> Result<()> {
    let vm = Memory::new(image, root, isf, None);
    let mut header = [0; 4096];
    vm.read(base, &mut header)?;
    let pe = u32::from_le_bytes(header[60..64].try_into()?) as usize;
    pe_header(&header)?;
    ensure!(
        u16::from_le_bytes(header[pe + 4..pe + 6].try_into()?) == geometry.arch.machine(),
        "内核 PE 与符号指针架构冲突"
    );
    ensure!(
        network::pe_identity(&vm, base)? == *identity,
        "内核 PE 身份不匹配"
    );
    let engine = Windows {
        vm,
        base,
        pdb: identity.clone(),
    };
    let system = engine
        .vm
        .pointer(engine.symbol("PsInitialSystemProcess")?)?;
    let process = engine.process(system)?;
    ensure!(
        process.pid == 4 && process.name == "System" && process.dtb != 0,
        "System 进程验证失败"
    );
    let head = engine.symbol("PsActiveProcessHead")?;
    let link = engine.field(system, "_EPROCESS", "ActiveProcessLinks")?;
    ensure!(
        engine.vm.pointer(head)? == link
            && engine
                .vm
                .pointer(add(link, engine.vm.pointer_size() as u64)?)?
                == head,
        "System 链表入口验证失败"
    );
    let next = engine.vm.pointer(link)?;
    ensure!(
        engine.vm.kernel(next)
            && engine
                .vm
                .pointer(add(next, engine.vm.pointer_size() as u64)?)?
                == link,
        "System 相邻链表验证失败"
    );
    let system_vm = Memory::new(image, process.dtb, isf, None);
    ensure!(system_vm.uint(base, 2)? == 0x5a4d, "System DTB 未映射内核");
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn find_mappings(
    image: &Image,
    table: u64,
    geometry: Paging,
    level: usize,
    prefix: u64,
    headers: &HashSet<u64>,
    out: &mut Vec<u64>,
    seen: &mut HashSet<(u64, u32)>,
    budget: &mut usize,
    job: &Job,
) -> Result<()> {
    job.check()?;
    let shift = geometry.shifts()[level];
    if !seen.insert((table, shift)) {
        return Ok(());
    }
    ensure!(*budget > 0, "Windows 页表搜索超限");
    *budget -= 1;
    let mut bytes = vec![0; geometry.entries(level) * geometry.width()];
    if image.read(table, &mut bytes).is_err() {
        return Ok(());
    }
    for (i, chunk) in bytes.chunks_exact(geometry.width()).enumerate() {
        if level == 0 && i < geometry.entries(level) / 2 {
            continue;
        }
        let mut raw = [0; 8];
        raw[..geometry.width()].copy_from_slice(chunk);
        let e = u64::from_le_bytes(raw);
        if e & 1 == 0 {
            continue;
        }
        let va = prefix | ((i as u64) << shift);
        let pa = e & geometry.mask();
        if shift == 12 || geometry.block(e, shift) {
            let mask = (1u64 << shift) - 1;
            let pa = pa & !mask;
            for &h in headers {
                if h >= pa && h - pa <= mask {
                    out.push(geometry.extend(va | (h - pa)));
                }
            }
        } else if level + 1 < geometry.shifts().len() {
            find_mappings(
                image,
                pa,
                geometry,
                level + 1,
                va,
                headers,
                out,
                seen,
                budget,
                job,
            )?;
        }
    }
    Ok(())
}
pub(crate) fn pe_header(b: &[u8]) -> Result<(u32, u32)> {
    ensure!(b.len() >= 64 && &b[..2] == b"MZ", "非 PE");
    let pe = u32::from_le_bytes(b[60..64].try_into()?) as usize;
    ensure!(
        pe >= 64 && pe + 24 + 168 <= b.len() && &b[pe..pe + 4] == b"PE\0\0",
        "PE 头越界"
    );
    let machine = u16::from_le_bytes(b[pe + 4..pe + 6].try_into()?);
    let magic = u16::from_le_bytes(b[pe + 24..pe + 26].try_into()?);
    ensure!(
        matches!((machine, magic), (0x14c, 0x10b) | (0x8664 | 0xaa64, 0x20b)),
        "未知 PE 机器类型/optional header"
    );
    let directories = if magic == 0x10b { 96 } else { 112 };
    let size = u32::from_le_bytes(b[pe + 80..pe + 84].try_into()?);
    let debug =
        u32::from_le_bytes(b[pe + 24 + directories + 48..pe + 24 + directories + 52].try_into()?);
    ensure!(
        (4096..=256 * 1024 * 1024).contains(&size),
        "PE SizeOfImage 无效"
    );
    Ok((size, debug))
}
