//! Kernel object walkers: lists, maple trees, VMAs and process address spaces.
use super::*;
impl Linux<'_> {
    pub(crate) fn modern_mount(&self) -> bool {
        self.isf.field("mount", "mnt").is_ok()
    }
    pub(crate) fn list_objects(&self, head: u64, offset: u64, job: &Job) -> Result<Vec<u64>> {
        let mut nodes = Vec::new();
        let mut seen = HashSet::new();
        let mut prev = head;
        let mut n = self.number(head, "list_head", "next")?;
        while n != head {
            job.check()?;
            ensure!(
                seen.insert(n) && seen.len() <= 1_000_000,
                "链表循环或达到上限"
            );
            ensure!(
                self.number(n, "list_head", "prev")? == prev,
                "链表反向引用错误"
            );
            nodes.push(n.checked_sub(offset).context("链表对象地址下溢")?);
            prev = n;
            n = self.number(n, "list_head", "next")?;
        }
        ensure!(
            self.number(head, "list_head", "prev")? == prev,
            "链表末尾错误"
        );
        Ok(nodes)
    }
    pub(crate) fn thread_nodes(&self, leader: u64, job: &Job) -> Result<Vec<u64>> {
        if self.isf.field("task_struct", "thread_group").is_ok() {
            let offset = self.isf.offset("task_struct", "thread_group")?;
            let mut nodes = self.list_objects(add(leader, offset)?, offset, job)?;
            nodes.insert(0, leader);
            Ok(nodes)
        } else {
            let signal = self.number(leader, "task_struct", "signal")?;
            self.list_objects(
                self.field_address(signal, "signal_struct", "thread_head")?,
                self.isf.offset("task_struct", "thread_node")?,
                job,
            )
        }
    }
    pub(crate) fn maple_vmas(&self, mm: u64, job: &Job, limit: u64) -> Result<Vec<u64>> {
        let tree = self.field_address(mm, "mm_struct", "mm_mt")?;
        let root = self.number(tree, "maple_tree", "ma_root")?;
        let mut stack = vec![(root, u64::MAX, root & 3 == 2)];
        let mut seen = HashSet::new();
        let mut leaves = Vec::new();
        while let Some((entry, max, is_node)) = stack.pop() {
            job.check()?;
            if entry == 0 {
                continue;
            }
            ensure!(seen.insert(entry), "maple tree 循环或重复指针 @ {entry:#x}");
            ensure!(seen.len() as u64 <= limit, "VMA 超过遍历上限");
            if !is_node {
                ensure!(entry & 7 == 0, "maple leaf 指针对齐错误");
                leaves.push(entry);
                continue;
            }
            ensure!(entry > 4096, "maple tree 包含保留节点");
            let kind = (entry >> 3) & 15;
            let node = entry & !255;
            let (structure, member, leaf) = match kind {
                0 => ("maple_node", "", true),
                1 => ("maple_range_64", "mr64", true),
                2 => ("maple_range_64", "mr64", false),
                3 => ("maple_arange_64", "ma64", false),
                _ => anyhow::bail!("不支持的 maple 节点类型 {kind}"),
            };
            let base = if member.is_empty() {
                node
            } else {
                self.field_address(node, "maple_node", member)?
            };
            let parent = self.number(base, structure, "parent")?;
            ensure!(parent & !255 != node, "maple 已删除节点");
            let slots = self.field_address(base, structure, "slot")?;
            let count = self.isf.field(structure, "slot")?["type"]["count"]
                .as_u64()
                .context("maple slot count 缺失")?;
            ensure!((1..=64).contains(&count), "maple slot count 异常");
            let end = if kind == 0 {
                count - 1
            } else if kind == 3 {
                self.number(base, structure, "meta.end")?
            } else {
                let last = self.vm.uint(
                    self.field_address(base, structure, "pivot")? + (count - 2) * 8,
                    8,
                )?;
                if last == 0 {
                    self.number(base, structure, "meta.end")?
                } else if last == max {
                    count - 2
                } else {
                    count - 1
                }
            };
            ensure!(end < count, "maple meta.end 越界");
            for i in 0..=end {
                let child = self.vm.uint(slots + i * 8, 8)?;
                let pivot = if kind == 0 || i == count - 1 {
                    max
                } else {
                    self.vm
                        .uint(self.field_address(base, structure, "pivot")? + i * 8, 8)?
                };
                if i > 0 && pivot == 0 {
                    break;
                }
                if child != 0 {
                    if leaf {
                        ensure!(child & 7 == 0, "maple VMA 指针对齐错误");
                        leaves.push(child);
                    } else {
                        stack.push((child, pivot, true));
                    }
                }
                if pivot >= max {
                    break;
                }
            }
        }
        leaves.sort_unstable();
        leaves.dedup();
        ensure!(leaves.len() as u64 <= limit, "VMA 超过遍历上限");
        let mut ordered = Vec::new();
        for node in leaves {
            ordered.push((self.number(node, "vm_area_struct", "vm_start")?, node));
        }
        ordered.sort_unstable();
        if self.isf.field("mm_struct", "map_count").is_ok() {
            ensure!(
                ordered.len() as u64 == self.number(mm, "mm_struct", "map_count")?,
                "maple VMA 数量与 map_count 不一致"
            );
        }
        Ok(ordered.into_iter().map(|(_, n)| n).collect())
    }
    pub(crate) fn vma_nodes(&self, mm: u64, job: &Job) -> Result<Vec<u64>> {
        if self.isf.field("mm_struct", "mmap").is_err() {
            return self.maple_vmas(mm, job, 1_000_000);
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut n = self.number(mm, "mm_struct", "mmap")?;
        while n != 0 {
            job.check()?;
            ensure!(
                seen.insert(n) && seen.len() <= 1_000_000,
                "VMA 循环或达到上限"
            );
            out.push(n);
            n = self.number(n, "vm_area_struct", "vm_next")?;
        }
        Ok(out)
    }
    pub(crate) fn process_vm(&self, task: u64) -> Result<Option<VirtualMemory<'_>>> {
        let mm = self.number(task, "task_struct", "mm")?;
        if mm == 0 {
            return Ok(None);
        }
        let pgd = self.number(mm, "mm_struct", "pgd")?;
        let root = self.vm.translate(pgd)?;
        ensure!(root & 4095 == 0, "用户页表未对齐");
        Ok(Some(VirtualMemory::new(self.vm.image, root)))
    }
    pub(super) fn user_region(&self, mm: u64, kind: &str, job: &Job) -> Result<Vec<u8>> {
        let start = self.number(mm, "mm_struct", &format!("{kind}_start"))?;
        let end = self.number(mm, "mm_struct", &format!("{kind}_end"))?;
        let length = end.checked_sub(start).context("用户区域地址倒置")?;
        ensure!(
            length <= REGION_LIMIT,
            "用户区域超过 1 MiB 上限 ({length} bytes)"
        );
        if length == 0 {
            return Ok(Vec::new());
        }
        let bits = self
            .vm
            .image
            .arm64_va_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        let ceiling = if bits == 0 { 1u64 << 47 } else { 1u64 << bits };
        ensure!(
            start < ceiling && end <= ceiling,
            "用户区域超出用户地址空间"
        );
        let pgd = self.number(mm, "mm_struct", "pgd")?;
        let root = self.vm.translate(pgd).context("mm.pgd 内核地址转换失败")?;
        ensure!(root & 4095 == 0, "进程页表未对齐");
        let vm = VirtualMemory::new(self.vm.image, root);
        let mut out = vec![0; length as usize];
        for (i, chunk) in out.chunks_mut(4096).enumerate() {
            job.check()?;
            vm.read(start + i as u64 * 4096, chunk)?;
        }
        Ok(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;
    fn put(b: &mut [u8], p: usize, v: u64) {
        b[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn ty(fields: &[(&str, u64, serde_json::Value)], size: u64) -> serde_json::Value {
        json!({"size":size,"kind":"struct","fields":fields.iter().map(|(name,offset,ty)|((*name).to_string(),json!({"offset":offset,"type":ty}))).collect::<serde_json::Map<_,_>>()})
    }
    fn base() -> serde_json::Value {
        json!({"kind":"base","name":"u64"})
    }
    #[test]
    fn maple_encoded_children_metadata_and_cycles() {
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["mm_struct"]["fields"]["mm_mt"] =
            json!({"offset":40,"type":{"kind":"struct","name":"maple_tree"}});
        isf.data["user_types"]["mm_struct"]["fields"]["map_count"] =
            json!({"offset":48,"type":{"kind":"base","name":"u64"}});
        isf.data["user_types"]["maple_tree"] = ty(&[("ma_root", 0, base())], 8);
        isf.data["user_types"]["maple_metadata"] =
            ty(&[("end", 0, json!({"kind":"base","name":"char"}))], 2);
        let slots = json!({"kind":"array","count":4,"subtype":{"kind":"base","name":"u64"}});
        let pivots = json!({"kind":"array","count":3,"subtype":{"kind":"base","name":"u64"}});
        let meta = json!({"kind":"struct","name":"maple_metadata"});
        isf.data["user_types"]["maple_range_64"] = ty(
            &[
                ("parent", 0, base()),
                ("pivot", 8, pivots.clone()),
                ("slot", 32, slots.clone()),
                ("meta", 56, meta.clone()),
            ],
            64,
        );
        isf.data["user_types"]["maple_arange_64"] = ty(
            &[
                ("parent", 0, base()),
                ("pivot", 8, pivots),
                ("slot", 32, slots),
                ("meta", 64, meta),
            ],
            72,
        );
        isf.data["user_types"]["maple_node"] = ty(
            &[
                ("mr64", 0, json!({"kind":"struct","name":"maple_range_64"})),
                ("ma64", 0, json!({"kind":"struct","name":"maple_arange_64"})),
            ],
            256,
        );
        put(&mut b, 0xb028, 0x1111e);
        put(&mut b, 0xb030, 2);
        put(&mut b, 0x11100, 0xb029);
        put(&mut b, 0x11108, u64::MAX);
        put(&mut b, 0x11120, 0x1100c);
        put(&mut b, 0x11000, 0x11106);
        put(&mut b, 0x11008, 0x200fff);
        put(&mut b, 0x11010, 0x201fff);
        put(&mut b, 0x11020, 0x12000);
        put(&mut b, 0x11028, 0x12100);
        b[0x11038] = 1;
        put(&mut b, 0x12008, 0x200000);
        put(&mut b, 0x12108, 0x201000);
        let img = image(&b);
        assert_eq!(
            engine(&img, &isf)
                .maple_vmas(0xb000, &Job::default(), 100)
                .unwrap(),
            vec![0x12000, 0x12100]
        );
        assert!(
            engine(&img, &isf)
                .maple_vmas(0xb000, &Job::default(), 1)
                .is_err()
        );
        b[0x11038] = 4;
        let img = image(&b);
        assert!(
            engine(&img, &isf)
                .maple_vmas(0xb000, &Job::default(), 100)
                .is_err()
        );
        b[0x11038] = 1;
        put(&mut b, 0x11120, 0x1111c);
        let img = image(&b);
        assert!(
            engine(&img, &isf)
                .maple_vmas(0xb000, &Job::default(), 100)
                .is_err()
        );
    }
    #[test]
    fn printk_descriptor_wrap_state_and_corruption() {
        let (mut b, mut isf) = fixture();
        isf.data["symbols"]["prb"] = json!({"address":0x15000});
        isf.data["user_types"]["atomic64_t"] = ty(&[("counter", 0, base())], 8);
        let atomic = json!({"kind":"struct","name":"atomic64_t"});
        isf.data["user_types"]["printk_ringbuffer"] = ty(
            &[
                (
                    "desc_ring",
                    0,
                    json!({"kind":"struct","name":"prb_desc_ring"}),
                ),
                (
                    "text_data_ring",
                    48,
                    json!({"kind":"struct","name":"prb_data_ring"}),
                ),
            ],
            80,
        );
        isf.data["user_types"]["prb_desc_ring"] = ty(
            &[
                ("count_bits", 0, base()),
                ("descs", 8, base()),
                ("infos", 16, base()),
                ("head_id", 24, atomic.clone()),
                ("tail_id", 32, atomic.clone()),
            ],
            48,
        );
        isf.data["user_types"]["prb_data_ring"] =
            ty(&[("size_bits", 0, base()), ("data", 8, base())], 32);
        isf.data["user_types"]["prb_data_blk_lpos"] =
            ty(&[("begin", 0, base()), ("next", 8, base())], 16);
        isf.data["user_types"]["prb_desc"] = ty(
            &[
                ("state_var", 0, atomic),
                (
                    "text_blk_lpos",
                    8,
                    json!({"kind":"struct","name":"prb_data_blk_lpos"}),
                ),
            ],
            24,
        );
        isf.data["user_types"]["printk_info"] =
            ty(&[("seq", 0, base()), ("text_len", 8, base())], 16);
        put(&mut b, 0x15000, 0x15100);
        put(&mut b, 0x15100, 1);
        put(&mut b, 0x15108, 0x15200);
        put(&mut b, 0x15110, 0x15300);
        put(&mut b, 0x15118, 10);
        put(&mut b, 0x15120, 9);
        put(&mut b, 0x15130, 6);
        put(&mut b, 0x15138, 0x15400);
        put(&mut b, 0x15200, (2 << 62) | 10);
        put(&mut b, 0x15208, 80);
        put(&mut b, 0x15210, 96);
        put(&mut b, 0x15218, (1 << 62) | 9);
        put(&mut b, 0x15220, 56);
        put(&mut b, 0x15228, 80);
        put(&mut b, 0x15300, 101);
        put(&mut b, 0x15308, 3);
        put(&mut b, 0x15310, 100);
        put(&mut b, 0x15318, 3);
        put(&mut b, 0x15400, 9);
        b[0x15408..0x1540b].copy_from_slice(b"abc");
        put(&mut b, 0x15410, 10);
        b[0x15418..0x1541b].copy_from_slice(b"xyz");
        let img = image(&b);
        let mut result = engine(&img, &isf)
            .run(crate::linux::Plugin::Dmesg, &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows, vec![vec!["100", "abc"], vec!["101", "xyz"]]);
        put(&mut b, 0x15410, 11);
        let img = image(&b);
        result = engine(&img, &isf)
            .run(crate::linux::Plugin::Dmesg, &Job::default())
            .unwrap();
        assert!(!result.complete);
        assert_eq!(result.rows, vec![vec!["100", "abc"]]);
        assert!(result.diagnostics.iter().any(|s| s.contains("descriptor")));
    }
}
