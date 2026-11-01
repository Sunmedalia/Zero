//! Kernel page-table discovery and validation against the complete banner.
use super::*;
fn physical_field(image: &Image, isf: &Isf, at: u64, structure: &str, field: &str) -> Result<u64> {
    let width = isf.size(structure, field)?;
    ensure!(matches!(width, 1 | 2 | 4 | 8), "物理字段宽度无效");
    let mut bytes = [0u8; 8];
    image.read(at, &mut bytes[..width])?;
    Ok(u64::from_le_bytes(bytes))
}
pub(super) fn kernel_vm<'a>(image: &'a Image, isf: &Isf, root: u64) -> VirtualMemory<'a> {
    if isf.data["base_types"]["pointer"]["size"].as_u64() == Some(4) {
        let pae = isf.data["symbols"]["pkmap_count"]["type"]["count"]
            .as_u64()
            .is_some_and(|count| matches!(count, 512 | 2048));
        VirtualMemory::new_linux32(image, root, pae)
    } else {
        VirtualMemory::new(image, root)
    }
}
pub fn discover(image: &Image, isf: &Isf, job: &Job) -> Result<u64> {
    if isf.data["metadata"]["linux"]["architecture"].as_str() == Some("AArch64")
        || isf.data["metadata"]["zero"]["architecture"].as_str() == Some("aarch64")
        || String::from_utf8_lossy(&isf.banner).contains("aarch64-linux")
    {
        return discover_arm64(image, isf, job);
    }
    let linux32 = isf.data["base_types"]["pointer"]["size"].as_u64() == Some(4);
    // Physical placement and virtual KASLR are independent. Relative symbol
    // offsets locate the static objects, but their pointers use runtime VAs.
    let banner = isf.raw_address("linux_banner")?;
    let init = isf.raw_address("init_task")?;
    let tasks = isf.offset("task_struct", "tasks")?;
    let next = isf.offset("list_head", "next")?;
    let prev = isf.offset("list_head", "prev")?;
    let pid = isf.offset("task_struct", "pid")?;
    let comm = isf.offset("task_struct", "comm")?;
    let mut valid = std::collections::HashMap::new();
    let mut errors = Vec::new();
    let mut placements = isf.locations.clone();
    let mut index = 0;
    let mut scanned_swapper = false;
    loop {
        if index == placements.len() {
            if !valid.is_empty() || scanned_swapper {
                break;
            }
            scanned_swapper = true;
            for physical in swapper_banner_candidates(image, isf, job)? {
                if !placements.contains(&physical) {
                    placements.push(physical);
                }
            }
            if index == placements.len() {
                break;
            }
        }
        let physical = &placements[index];
        index += 1;
        job.check()?;
        let mut slides = vec![0];
        // Linux initializes init_task.real_parent to &init_task. Use it only
        // as a candidate: banner translation and the task links must validate.
        if let Ok(parent_offset) = isf.offset("task_struct", "real_parent") {
            let inferred = (|| -> Result<u64> {
                let init_phys = u64::try_from(*physical as i128 + init as i128 - banner as i128)
                    .context("init_task 物理地址溢出")?;
                let parent = physical_field(
                    image,
                    isf,
                    add(init_phys, parent_offset)?,
                    "task_struct",
                    "real_parent",
                )?;
                ensure!(
                    parent != 0 && (parent >> 47 == 0 || parent >> 47 == 0x1ffff),
                    "init_task.real_parent 非 canonical 地址: init_phys={init_phys:#x}, real_parent_offset={parent_offset:#x}, value={parent:#x}"
                );
                let slide = parent.wrapping_sub(init);
                ensure!(slide & 4095 == 0, "x86_64 内核重定位未按页对齐");
                Ok(slide)
            })();
            match inferred {
                Ok(slide) if slide != 0 => slides.push(slide),
                Ok(_) => (),
                Err(e) => errors.push(format!("{physical:#x} 重定位候选: {e:#}")),
            }
        }
        // init_files provides an independent runtime pointer when real_parent
        // or task links were captured during an update.
        if let (Ok(offset), Ok(files)) = (
            isf.offset("task_struct", "files"),
            isf.raw_address("init_files"),
        ) {
            let inferred = (|| -> Result<u64> {
                let init_phys = u64::try_from(*physical as i128 + init as i128 - banner as i128)?;
                let pointer =
                    physical_field(image, isf, add(init_phys, offset)?, "task_struct", "files")?;
                ensure!(
                    pointer != 0 && (pointer >> 47 == 0 || pointer >> 47 == 0x1ffff),
                    "init_task.files 指针无效"
                );
                let slide = pointer.wrapping_sub(files);
                ensure!(slide & 4095 == 0, "init_files 重定位未按页对齐");
                Ok(slide)
            })();
            if let Ok(slide) = inferred
                && !slides.contains(&slide)
            {
                slides.push(slide);
            }
        }
        let roots: &[&str] = if linux32 {
            &["swapper_pg_dir"]
        } else {
            &["init_top_pgt", "init_level4_pgt", "swapper_pg_dir"]
        };
        for &name in roots {
            job.check()?;
            if let Ok(address) = isf.raw_address(name) {
                let candidate = *physical as i128 + address as i128 - banner as i128;
                if candidate < 0 || candidate > u64::MAX as i128 || candidate & 4095 != 0 {
                    continue;
                }
                let root = candidate as u64;
                let vm = kernel_vm(image, isf, root);
                for &slide in &slides {
                    job.check()?;
                    let runtime_banner = banner.wrapping_add(slide);
                    let runtime_init = init.wrapping_add(slide);
                    let checked = (|| -> Result<Vec<String>> {
                        ensure!(
                            vm.translate(runtime_banner)? == *physical,
                            "banner 虚实地址不一致"
                        );
                        let mut b = vec![0; isf.banner.len()];
                        vm.read(runtime_banner, &mut b)?;
                        ensure!(b == isf.banner, "banner 内容不一致");
                        ensure!(
                            vm.uint(add(runtime_init, pid)?, isf.size("task_struct", "pid")?)? == 0,
                            "init_task PID 非 0"
                        );
                        ensure!(
                            matches!(
                                vm.string(
                                    add(runtime_init, comm)?,
                                    isf.size("task_struct", "comm")?
                                )?
                                .as_str(),
                                "swapper" | "swapper/0"
                            ),
                            "init_task 名称无效"
                        );
                        let head = add(runtime_init, tasks)?;
                        let n = vm.uint(add(head, next)?, isf.size("list_head", "next")?).with_context(|| {
                            format!("init_task.tasks.next 读取失败: init_task={runtime_init:#x}, head={head:#x}, next_offset={next:#x}")
                        });
                        let p = vm.uint(add(head, prev)?, isf.size("list_head", "prev")?).with_context(|| {
                            format!("init_task.tasks.prev 读取失败: init_task={runtime_init:#x}, head={head:#x}, prev_offset={prev:#x}")
                        });
                        let n_prev = n
                            .as_ref()
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .and_then(|n| add(*n, prev))
                            .and_then(|a| vm.uint(a, isf.size("list_head", "prev")?));
                        let p_next = p
                            .as_ref()
                            .map_err(|e| anyhow::anyhow!("{e:#}"))
                            .and_then(|p| add(*p, next))
                            .and_then(|a| vm.uint(a, isf.size("list_head", "next")?));
                        let describe = |value: &Result<u64>| match value {
                            Ok(value) => format!("{value:#x}"),
                            Err(error) => format!("读取失败({error:#})"),
                        };
                        let evidence = format!(
                            "init_task 双向链表不一致（完整 banner / PID 0 / swapper 已通过；init_task={runtime_init:#x}, tasks_offset={tasks:#x}, head={head:#x}, next={}, prev={}, next_offset={next:#x}, prev_offset={prev:#x}, next.prev={}, prev.next={}）",
                            describe(&n),
                            describe(&p),
                            describe(&n_prev),
                            describe(&p_next)
                        );
                        if n_prev.as_ref().is_ok_and(|value| *value == head)
                            && p_next.as_ref().is_ok_and(|value| *value == head)
                        {
                            return Ok(vec![]);
                        }
                        // Validate an independent static pointer through this
                        // address space. Task-list coherence is a plugin concern.
                        let files_proof = (|| -> Result<u64> {
                            let files = isf.raw_address("init_files")?.wrapping_add(slide);
                            ensure!(
                                vm.uint(
                                    add(runtime_init, isf.offset("task_struct", "files")?)?,
                                    isf.size("task_struct", "files")?
                                )? == files,
                                "init_files 运行时指针不匹配"
                            );
                            let expected = u64::try_from(
                                *physical as i128 + isf.raw_address("init_files")? as i128
                                    - banner as i128,
                            )?;
                            ensure!(
                                vm.translate(files)? == expected,
                                "init_files 虚实地址不一致"
                            );
                            let _ = vm.uint(files, 1)?;
                            Ok(files)
                        })();
                        if let Ok(files) = files_proof {
                            return Ok(vec![format!(
                                "内核校验部分恢复：{evidence}；独立 init_files 指针及虚实地址已验证 @ {files:#x}；任务链按方向逐对象恢复，结果保留异常"
                            )]);
                        }
                        ensure!(
                            n_prev.as_ref().is_ok_and(|value| *value == head) && p_next.is_ok(),
                            "{evidence}"
                        );
                        let count = p
                            .as_ref()
                            .ok()
                            .copied()
                            .context(evidence.clone())
                            .and_then(|first| validate_forward_tasks(&vm, isf, head, first, job))
                            .with_context(|| evidence.clone())?;
                        Ok(vec![format!(
                            "内核校验部分恢复：{evidence}；正向 {count} 个任务的 PID/TGID、名称及相邻回指均通过并闭环；表头 prev 指向链内非尾节点。可能为采集时状态不一致或链表异常，不能认定结果完整"
                        )])
                    })();
                    match checked {
                        Ok(diagnostics) => {
                            valid.insert((root, slide), diagnostics);
                        }
                        Err(e) => errors.push(format!("{root:#x} 重定位 {slide:#x}: {e:#}")),
                    }
                }
            }
        }
    }
    ensure!(
        !valid.is_empty(),
        "无法验证页表；可能是错误符号、缺页或未支持的内核重定位。{}",
        errors.join("; ")
    );
    ensure!(
        valid.len() == 1,
        "多个有效页表／重定位候选，拒绝猜测: {valid:?}"
    );
    let ((root, slide), diagnostics) = valid.into_iter().next().context("页表候选为空")?;
    isf.slide.store(slide, std::sync::atomic::Ordering::Relaxed);
    isf.set_diagnostics(diagnostics);
    let architecture = if linux32 { "x86 32 位" } else { "x86_64" };
    job.report(format!(
        "{architecture} 页表已验证 · DTB {root:#x} · 重定位 {slide:#x}{}",
        if isf.diagnostics().is_empty() {
            ""
        } else {
            " · 任务链异常，部分恢复"
        }
    ));
    Ok(root)
}

/// Recover kernel placement from idle-task objects rather than trusting a
/// banner hit's relative placement alone. Exact banner bytes still must match.
fn swapper_banner_candidates(image: &Image, isf: &Isf, job: &Job) -> Result<Vec<u64>> {
    let (Ok(comm), Ok(pid), Ok(files), Ok(_)) = (
        isf.offset("task_struct", "comm"),
        isf.offset("task_struct", "pid"),
        isf.offset("task_struct", "files"),
        isf.raw_address("init_files"),
    ) else {
        return Ok(vec![]);
    };
    let mut found = Vec::new();
    job.report("扫描 swapper 与独立 init_files 内核定位证据");
    for hit in image.scan(b"swapper", job)? {
        job.check()?;
        let check = (|| -> Result<u64> {
            let init = hit.checked_sub(comm).context("swapper 地址下溢")?;
            ensure!(
                physical_field(image, isf, add(init, pid)?, "task_struct", "pid")? == 0,
                "swapper PID 非 0"
            );
            let mut name = [0; 10];
            image.read(hit, &mut name)?;
            ensure!(
                name.starts_with(b"swapper\0") || name.starts_with(b"swapper/0\0"),
                "非 idle task 名称"
            );
            let pointer = physical_field(image, isf, add(init, files)?, "task_struct", "files")?;
            ensure!(
                pointer != 0 && (pointer >> 47 == 0 || pointer >> 47 == 0x1ffff),
                "init_files 非 canonical"
            );
            let banner = u64::try_from(
                init as i128 + isf.raw_address("linux_banner")? as i128
                    - isf.raw_address("init_task")? as i128,
            )?;
            let mut bytes = vec![0; isf.banner.len()];
            image.read(banner, &mut bytes)?;
            ensure!(bytes == isf.banner, "swapper 对应的完整 banner 不匹配");
            Ok(banner)
        })();
        if let Ok(banner) = check
            && !found.contains(&banner)
        {
            found.push(banner);
            ensure!(found.len() <= 4096, "swapper 定位候选超过上限");
        }
    }
    Ok(found)
}

/// Recover only a stale head.prev: every task and every interior backlink must
/// validate, the forward list must close, and the recorded prev must be in it.
/// Never bridge a missing page, infer a link, or accept an interior mismatch.
fn validate_forward_tasks(
    vm: &VirtualMemory<'_>,
    isf: &Isf,
    head: u64,
    recorded_tail: u64,
    job: &Job,
) -> Result<usize> {
    let tasks = isf.offset("task_struct", "tasks")?;
    let next = isf.offset("list_head", "next")?;
    let prev = isf.offset("list_head", "prev")?;
    let width = isf.size("list_head", "next")?;
    ensure!(matches!(width, 4 | 8), "任务链指针宽度无效");
    let mut node = vm.uint(add(head, next)?, width)?;
    let mut previous = head;
    let mut seen = HashSet::new();
    let mut pids = HashSet::new();
    let comm_size = isf.size("task_struct", "comm")?;
    ensure!((1..=256).contains(&comm_size), "任务名称长度无效");
    while node != head {
        job.check()?;
        ensure!(
            node != 0 && node & (width as u64 - 1) == 0,
            "任务链指针无效 @ {node:#x}"
        );
        ensure!(
            seen.insert(node) && seen.len() <= 65536,
            "任务链循环或超过恢复上限"
        );
        ensure!(
            vm.uint(add(node, prev)?, isf.size("list_head", "prev")?)? == previous,
            "任务链内部回指不一致 @ {node:#x}"
        );
        let task = node.checked_sub(tasks).context("任务对象地址下溢")?;
        let mut identity = Vec::new();
        for field in ["pid", "tgid"] {
            let value = vm.uint(
                add(task, isf.offset("task_struct", field)?)?,
                isf.size("task_struct", field)?,
            )?;
            ensure!(
                (1..=i32::MAX as u64).contains(&value),
                "任务 {field} 无效 @ {task:#x}"
            );
            identity.push(value);
        }
        ensure!(
            identity[0] == identity[1] && pids.insert(identity[0]),
            "任务 PID/TGID 不一致或重复 @ {task:#x}"
        );
        let mut name = vec![0; comm_size];
        vm.read(add(task, isf.offset("task_struct", "comm")?)?, &mut name)?;
        let end = name
            .iter()
            .position(|b| *b == 0)
            .context("任务名称未终止")?;
        ensure!(
            end > 0 && !name[..end].iter().any(|b| b.is_ascii_control()),
            "任务名称无效 @ {task:#x}"
        );
        previous = node;
        node = vm.uint(add(node, next)?, isf.size("list_head", "next")?)?;
    }
    ensure!(
        seen.len() >= 2 && seen.contains(&recorded_tail) && previous != recorded_tail,
        "表头 prev 不是链内旧尾节点"
    );
    Ok(seen.len())
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

#[cfg(test)]
mod linux32_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn discovers_four_byte_kernel_with_independent_physical_placement() {
        for pae in [false, true] {
            let (mut bytes, mut isf) = crate::linux::tests::fixture();
            bytes.fill(0);
            isf.data["base_types"]["pointer"]["size"] = json!(4);
            isf.data["user_types"]["list_head"] = json!({"size":8,"fields":{
                "next":{"offset":0,"type":{"kind":"pointer"}},
                "prev":{"offset":4,"type":{"kind":"pointer"}}
            }});
            isf.data["user_types"]["task_struct"] = json!({"size":64,"fields":{
                "tasks":{"offset":0,"type":{"kind":"struct","name":"list_head"}},
                "pid":{"offset":8,"type":{"kind":"base","name":"u32"}},
                "comm":{"offset":12,"type":{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}},
                "real_parent":{"offset":28,"type":{"kind":"pointer"}},
                "files":{"offset":32,"type":{"kind":"pointer"}}
            }});
            for (name, address) in [
                ("linux_banner", 0xc0000000u64),
                ("swapper_pg_dir", 0xc0001000),
                ("init_task", 0xc0002000),
                ("init_files", 0xc0003000),
            ] {
                isf.data["symbols"][name] = json!({"address":address});
            }
            isf.banner = b"Linux version synthetic-i386\0".to_vec();
            isf.locations = vec![0x1000];
            bytes[0x1000..0x1000 + isf.banner.len()].copy_from_slice(&isf.banner);
            if pae {
                isf.data["symbols"]["pkmap_count"] =
                    json!({"address":0xc0006000u64,"type":{"kind":"array","count":512}});
                bytes[0x2018..0x2020].copy_from_slice(&0x6003u64.to_le_bytes());
                bytes[0x6000..0x6008].copy_from_slice(&0x5003u64.to_le_bytes());
            } else {
                bytes[0x2c00..0x2c04].copy_from_slice(&0x5003u32.to_le_bytes());
            }
            for index in 0..4usize {
                let value = ((index as u64 + 1) * 4096) | 3;
                let width = if pae { 8 } else { 4 };
                let at = 0x5000 + index * width;
                bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
            }
            for (at, value) in [
                (0x3000, 0xc0002000u32),
                (0x3004, 0xc0002000),
                (0x301c, 0xc0002000),
                (0x3020, 0xc0003000),
            ] {
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            bytes[0x300c..0x3014].copy_from_slice(b"swapper\0");
            let image = crate::linux::tests::image(&bytes);
            assert_eq!(
                discover(&image, &isf, &Job::default()).unwrap(),
                0x2000,
                "PAE={pae}"
            );
            assert_eq!(isf.slide.load(std::sync::atomic::Ordering::Relaxed), 0);
            isf.data["user_types"]["task_struct"]["fields"]["tgid"] =
                json!({"offset":36,"type":{"kind":"base","name":"u32"}});
            for (at, value) in [
                (0x3000, 0xc0002104u32),
                (0x3004, 0xc0002104),
                (0x3104, 0xc0002184),
                (0x3108, 0xc0002000),
                (0x310c, 1),
                (0x3128, 1),
                (0x3184, 0xc0002000),
                (0x3188, 0xc0002104),
                (0x318c, 2),
                (0x31a8, 2),
            ] {
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            bytes[0x3110..0x3115].copy_from_slice(b"init\0");
            bytes[0x3190..0x3197].copy_from_slice(b"worker\0");
            let recovered_image = crate::linux::tests::image(&bytes);
            let vm = kernel_vm(&recovered_image, &isf, 0x2000);
            assert_eq!(
                validate_forward_tasks(&vm, &isf, 0xc0002000, 0xc0002104, &Job::default()).unwrap(),
                2
            );
            bytes[0x1000] ^= 1;
            assert!(discover(&crate::linux::tests::image(&bytes), &isf, &Job::default()).is_err());
        }
    }
}
