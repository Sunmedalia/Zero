//! Kernel page-table discovery and validation against the complete banner.
use super::*;
pub fn discover(image: &Image, isf: &Isf, job: &Job) -> Result<u64> {
    if isf.data["metadata"]["linux"]["architecture"].as_str() == Some("AArch64")
        || isf.data["metadata"]["zero"]["architecture"].as_str() == Some("aarch64")
        || String::from_utf8_lossy(&isf.banner).contains("aarch64-linux")
    {
        return discover_arm64(image, isf, job);
    }
    let banner = isf.address("linux_banner")?;
    let init = isf.address("init_task")?;
    let tasks = isf.offset("task_struct", "tasks")?;
    let next = isf.offset("list_head", "next")?;
    let prev = isf.offset("list_head", "prev")?;
    let pid = isf.offset("task_struct", "pid")?;
    let comm = isf.offset("task_struct", "comm")?;
    let mut valid = HashSet::new();
    let mut errors = Vec::new();
    for physical in &isf.locations {
        for name in ["init_top_pgt", "init_level4_pgt", "swapper_pg_dir"] {
            job.check()?;
            if let Ok(address) = isf.address(name) {
                let candidate = *physical as i128 + address as i128 - banner as i128;
                if candidate < 0 || candidate > u64::MAX as i128 || candidate & 4095 != 0 {
                    continue;
                }
                let root = candidate as u64;
                let vm = VirtualMemory::new(image, root);
                let checked = (|| -> Result<()> {
                    ensure!(vm.translate(banner)? == *physical, "banner 虚实地址不一致");
                    let mut b = vec![0; isf.banner.len()];
                    vm.read(banner, &mut b)?;
                    ensure!(b == isf.banner, "banner 内容不一致");
                    ensure!(
                        vm.uint(add(init, pid)?, isf.size("task_struct", "pid")?)? == 0,
                        "init_task PID 非 0"
                    );
                    ensure!(
                        vm.string(add(init, comm)?, isf.size("task_struct", "comm")?)?
                            .starts_with("swapper"),
                        "init_task 名称无效"
                    );
                    let head = add(init, tasks)?;
                    let n = vm.uint(add(head, next)?, 8)?;
                    let p = vm.uint(add(head, prev)?, 8)?;
                    ensure!(
                        vm.uint(add(n, prev)?, 8)? == head && vm.uint(add(p, next)?, 8)? == head,
                        "init_task 双向链表不一致"
                    );
                    Ok(())
                })();
                match checked {
                    Ok(()) => {
                        valid.insert(root);
                    }
                    Err(e) => errors.push(format!("{root:#x}: {e:#}")),
                }
            }
        }
    }
    ensure!(
        !valid.is_empty(),
        "无法验证页表；可能是错误符号、缺页或未支持的内核重定位。{}",
        errors.join("; ")
    );
    ensure!(valid.len() == 1, "多个有效页表候选，拒绝猜测: {valid:?}");
    Ok(*valid.iter().next().unwrap())
}
fn discover_arm64(image: &Image, isf: &Isf, job: &Job) -> Result<u64> {
    use std::sync::atomic::Ordering;
    let config = &isf.data["metadata"]["zero"];
    ensure!(
        config["page_shift"].as_u64() == Some(12),
        "ARM64 需要已核对的 4 KiB 内核配置；请通过符号生成入口附加配置"
    );
    let bits = u8::try_from(
        config["va_bits"]
            .as_u64()
            .context("缺少 ARM64 VA_BITS 配置")?,
    )
    .context("ARM64 VA_BITS 越界")?;
    ensure!(matches!(bits, 39 | 48), "尚未支持此 ARM64 VA_BITS");
    image.arm64_va_bits.store(bits, Ordering::Relaxed);
    let banner = isf.raw_address("linux_banner")?;
    let init = isf.raw_address("init_task")?;
    let pgd = isf.raw_address("swapper_pg_dir")?;
    let mut valid = Vec::new();
    let mut errors = Vec::new();
    for &physical in &isf.locations {
        job.check()?;
        let check = (|| -> Result<(u64, u64)> {
            let physical_at = |symbol: u64| -> Result<u64> {
                u64::try_from(physical as i128 + symbol as i128 - banner as i128)
                    .context("ARM64 内核物理地址溢出")
            };
            let init_phys = physical_at(init)?;
            let real_parent =
                image.u64(add(init_phys, isf.offset("task_struct", "real_parent")?)?)?;
            let slide = real_parent.wrapping_sub(init);
            ensure!(slide & 4095 == 0, "内核重定位未按页对齐");
            let root = physical_at(pgd)?;
            ensure!(root & 4095 == 0, "ARM64 页表未对齐");
            let vm = VirtualMemory::new(image, root);
            let runtime_banner = banner.wrapping_add(slide);
            ensure!(
                vm.translate(runtime_banner)? == physical,
                "ARM64 banner 虚实地址不一致"
            );
            let mut bytes = vec![0; isf.banner.len()];
            vm.read(runtime_banner, &mut bytes)?;
            ensure!(bytes == isf.banner, "ARM64 banner 不一致");
            ensure!(
                vm.uint(
                    add(real_parent, isf.offset("task_struct", "pid")?)?,
                    isf.size("task_struct", "pid")?
                )? == 0,
                "ARM64 init_task PID 非 0"
            );
            ensure!(
                vm.string(
                    add(real_parent, isf.offset("task_struct", "comm")?)?,
                    isf.size("task_struct", "comm")?
                )?
                .starts_with("swapper"),
                "ARM64 init_task 名称不一致"
            );
            let head = add(real_parent, isf.offset("task_struct", "tasks")?)?;
            let next = vm.uint(head, 8)?;
            let prev = vm.uint(add(head, 8)?, 8)?;
            ensure!(
                vm.uint(add(next, 8)?, 8)? == head && vm.uint(prev, 8)? == head,
                "ARM64 init_task 双向链表错误"
            );
            Ok((root, slide))
        })();
        match check {
            Ok(v) => valid.push(v),
            Err(e) => errors.push(format!("{physical:#x}: {e:#}")),
        }
    }
    valid.sort_unstable();
    valid.dedup();
    ensure!(
        valid.len() == 1,
        "无法唯一验证 ARM64 页表／重定位: {}",
        errors.join("; ")
    );
    isf.slide.store(valid[0].1, Ordering::Relaxed);
    job.report(format!(
        "ARM64 页表已验证 · DTB {:#x} · 重定位 {:#x}",
        valid[0].0, valid[0].1
    ));
    Ok(valid[0].0)
}
