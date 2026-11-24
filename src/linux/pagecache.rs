//! Volatility-compatible Linux page cache listing and file extraction
//! (`linux.pagecache.Files`, `linux.pagecache.InodePages`, `linux.pagecache.RecoverFs`).
use super::*;
use crate::analysis::Options;
use crate::bytes::JsonKey as _;
use crate::dump::DumpOptions;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

struct MountPath {
    root: String,
    point: String,
}

impl MountPath {
    fn file_path(&self, path: &str) -> Option<String> {
        let relative = if self.root == "/" {
            path
        } else {
            let relative = path.strip_prefix(&self.root)?;
            if !relative.is_empty() && !relative.starts_with('/') {
                return None;
            }
            relative
        };
        if relative.is_empty() || relative == "/" {
            Some(self.point.clone())
        } else {
            Some(format!("{}{relative}", self.point.trim_end_matches('/')))
        }
    }
}

impl Linux<'_> {
    fn superblock_mount_points(
        &self,
        result: &mut Results,
        job: &Job,
    ) -> Result<HashMap<u64, Vec<MountPath>>> {
        let (tasks_result, tasks) = self.task_identities(Plugin::LinuxPagecacheFiles, job)?;
        result.complete &= tasks_result.complete;
        result.diagnostics.extend(tasks_result.diagnostics);
        let mut map = HashMap::<u64, Vec<MountPath>>::new();
        let mut namespaces = HashSet::new();
        let init = self.isf.address("init_task")?;
        for task in std::iter::once(init).chain(tasks.into_iter().map(|task| task.address)) {
            job.check()?;
            let read = (|| -> Result<()> {
                let proxy = self.number(task, "task_struct", "nsproxy")?;
                if proxy == 0 {
                    return Ok(());
                }
                let namespace = self.number(proxy, "nsproxy", "mnt_ns")?;
                if namespace == 0 || !namespaces.insert(namespace) {
                    return Ok(());
                }

                let modern = self.modern_mount();
                let mut mounts = if modern {
                    vec![self.number(namespace, "mnt_namespace", "root")?]
                } else {
                    self.list_objects(
                        self.field_address(namespace, "mnt_namespace", "list")?,
                        self.isf.offset("vfsmount", "mnt_list")?,
                        job,
                    )?
                };
                let mut seen_mounts = HashSet::new();
                while let Some(mount) = mounts.pop() {
                    job.check()?;
                    if mount == 0 || !seen_mounts.insert(mount) {
                        continue;
                    }
                    ensure!(seen_mounts.len() <= LIMIT, "挂载数量超过上限");
                    let read = (|| -> Result<()> {
                        let vfs = if modern {
                            let kids = self.list_objects(
                                self.field_address(mount, "mount", "mnt_mounts")?,
                                self.isf.offset("mount", "mnt_child")?,
                                job,
                            )?;
                            mounts.extend(kids.into_iter().rev());
                            add(mount, self.isf.offset("mount", "mnt")?)?
                        } else {
                            mount
                        };
                        let block = self.number(vfs, "vfsmount", "mnt_sb")?;
                        let dentry = self.number(vfs, "vfsmount", "mnt_root")?;
                        let point = self.resolve_path(dentry, vfs, None, job)?;
                        let root = self.dentry_path(dentry)?;
                        let paths = map.entry(block).or_default();
                        if !paths
                            .iter()
                            .any(|path| path.root == root && path.point == point)
                        {
                            paths.push(MountPath { root, point });
                        }
                        Ok(())
                    })();
                    if let Err(error) = read {
                        job.check()?;
                        partial(result, format!("mount {}", hex(mount)), error);
                    }
                }
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(result, format!("task {} 挂载命名空间", hex(task)), error);
            }
        }
        Ok(map)
    }

    pub(super) fn linux_pagecache_files(&self, options: &Options, job: &Job) -> Result<Results> {
        self.require(&[
            ("super_block", "s_list"),
            ("super_block", "s_inodes"),
            ("inode", "i_sb_list"),
            ("inode", "i_ino"),
            ("inode", "i_mode"),
            ("inode", "i_size"),
            ("inode", "i_mapping"),
            ("address_space", "nrpages"),
        ])?;

        let mut result = self.result(Plugin::LinuxPagecacheFiles);
        let type_filter: HashSet<String> = options
            .file_types
            .iter()
            .map(|t| t.trim().to_ascii_uppercase())
            .filter(|t| !t.is_empty())
            .collect();
        let find = options.find.as_deref().filter(|s| !s.is_empty());

        let mount_points = self.superblock_mount_points(&mut result, job)?;
        let blocks = self.list_objects(
            self.isf
                .address("super_blocks")
                .context("不支持: 缺少 super_blocks")?,
            self.isf.offset("super_block", "s_list")?,
            job,
        )?;
        let mut total = 0usize;

        for block in blocks {
            job.check()?;
            let read = (|| -> Result<()> {
                let device = self
                    .number(block, "super_block", "s_dev")
                    .ok()
                    .map(|dev| {
                        let (maj, min) = super::maps::decode_dev(dev);
                        format!("{maj}:{min}")
                    })
                    .unwrap_or_else(|| "0:0".into());

                let inodes = self.list_objects(
                    self.field_address(block, "super_block", "s_inodes")?,
                    self.isf.offset("inode", "i_sb_list")?,
                    job,
                )?;
                for inode in inodes {
                    job.check()?;
                    total += 1;
                    ensure!(total <= LIMIT, "inode 超过 {LIMIT} 项上限");
                    let row = (|| -> Result<Option<Vec<String>>> {
                        let mode = self.number(inode, "inode", "i_mode")?;
                        let file_type = super::lsof::vol3_inode_type(mode);
                        if !type_filter.is_empty() && !type_filter.contains(file_type) {
                            return Ok(None);
                        }
                        let rel_path = match self.inode_dentry(inode) {
                            Ok(Some(dentry)) => self
                                .dentry_path(dentry)
                                .unwrap_or_else(|_| "[unresolved]".into()),
                            _ => String::new(),
                        };
                        let mounted = mount_points
                            .get(&block)
                            .into_iter()
                            .flatten()
                            .filter(|_| rel_path.starts_with('/'))
                            .filter_map(|mount| {
                                mount.file_path(&rel_path).map(|path| (&mount.point, path))
                            })
                            .find(|(_, path)| find.is_none_or(|needle| path.contains(needle)));
                        let (mount_point, full_path) = match mounted {
                            Some((point, path)) => (point.clone(), path),
                            None if find.is_some() => return Ok(None),
                            None => ("N/A".into(), "[unresolved]".into()),
                        };
                        let ino = self.number(inode, "inode", "i_ino")?;
                        let size = self.signed_field(inode, "inode", "i_size")?;
                        let inode_pages = if size <= 0 {
                            0u64
                        } else {
                            u64::try_from(size)?.div_ceil(4096)
                        };
                        let mapping = self.number(inode, "inode", "i_mapping")?;
                        let cached_pages = if mapping == 0 {
                            0
                        } else {
                            self.number(mapping, "address_space", "nrpages")?
                        };
                        let atime = self
                            .inode_timestamp(inode, "atime")
                            .unwrap_or_else(|_| "N/A".into());
                        let mtime = self
                            .inode_timestamp(inode, "mtime")
                            .unwrap_or_else(|_| "N/A".into());
                        let ctime = self
                            .inode_timestamp(inode, "ctime")
                            .unwrap_or_else(|_| "N/A".into());
                        Ok(Some(vec![
                            hex(block),
                            mount_point,
                            device.clone(),
                            ino.to_string(),
                            hex(inode),
                            file_type.into(),
                            inode_pages.to_string(),
                            cached_pages.to_string(),
                            super::lsof::format_file_mode(mode),
                            atime,
                            mtime,
                            ctime,
                            full_path,
                            size.to_string(),
                        ]))
                    })();
                    match row {
                        Ok(Some(row)) => result.rows.push(row),
                        Ok(None) => {}
                        Err(error) => {
                            job.check()?;
                            partial(&mut result, format!("inode {}", hex(inode)), error);
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = read {
                job.check()?;
                partial(&mut result, format!("super_block {}", hex(block)), error);
            }
            job.report(format!("linux.pagecache.Files: {} 条", result.rows.len()));
        }
        Ok(result)
    }

    fn vmemmap_origin(&self) -> Result<(u64, u64)> {
        let page_struct_size = self
            .isf
            .data
            .key("user_types")
            .get("page")
            .and_then(|t| t.get("size"))
            .and_then(|s| s.as_u64())
            .context("不支持: 缺少 struct page 大小")?;
        ensure!(page_struct_size > 0, "struct page 大小无效");
        let read_ptr = |sym: u64| -> Option<u64> {
            let mut raw = [0u8; 8];
            self.vm.read(sym, &mut raw).ok()?;
            let val = u64::from_le_bytes(raw);
            (val != 0).then_some(val)
        };
        if let Ok(sym) = self.isf.address("vmemmap_base")
            && let Some(base) = read_ptr(sym)
        {
            return Ok((base, page_struct_size));
        }
        if let Ok(sym) = self.isf.address("mem_map")
            && let Some(base) = read_ptr(sym)
        {
            return Ok((base, page_struct_size));
        }
        Ok((0xffff_ea00_0000_0000, page_struct_size))
    }

    fn page_to_phys(&self, page_vaddr: u64, base: u64, page_struct_size: u64) -> Option<u64> {
        let delta = page_vaddr.checked_sub(base)?;
        if delta % page_struct_size != 0 {
            return None;
        }
        let pfn = delta / page_struct_size;
        pfn.checked_mul(4096)
    }

    fn address_space_pages(&self, mapping: u64, job: &Job) -> Result<Vec<u64>> {
        if self.isf.field("address_space", "i_pages").is_ok()
            && self.isf.field("xarray", "xa_head").is_ok()
            && self.isf.field("xa_node", "slots").is_ok()
        {
            let xa = self.field_address(mapping, "address_space", "i_pages")?;
            return self.pagecache_xarray_pages(xa, job);
        }
        if self.isf.field("address_space", "page_tree").is_ok()
            && self.isf.field("radix_tree_node", "slots").is_ok()
        {
            let tree = self.field_address(mapping, "address_space", "page_tree")?;
            return self.pagecache_radix_pages(tree, job);
        }
        bail!("不支持: 缺少 address_space.i_pages (xarray) 或 page_tree (radix_tree)")
    }

    fn pagecache_xarray_pages(&self, xa: u64, job: &Job) -> Result<Vec<u64>> {
        let head = self.number(xa, "xarray", "xa_head")?;
        if head == 0 {
            return Ok(Vec::new());
        }
        let slots_offset = self.isf.offset("xa_node", "slots")?;
        let count = usize::try_from(
            self.isf.field("xa_node", "slots")?["type"]
                .key("count")
                .as_u64()
                .context("xa_node.slots count")?,
        )?;
        ensure!(count <= 256, "xarray slot count 越界");
        let ptr_size = usize::try_from(
            self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .unwrap_or(8),
        )?;
        ensure!(matches!(ptr_size, 4 | 8), "不支持的指针宽度");
        let mut stack = vec![head];
        let mut seen = HashSet::new();
        let mut pages = Vec::new();
        let mut raw_slots = vec![0u8; count * ptr_size];
        while let Some(entry) = stack.pop() {
            job.check()?;
            if entry == 0 {
                continue;
            }
            ensure!(
                seen.insert(entry) && seen.len() <= 1_000_000,
                "pagecache xarray 循环或上限"
            );
            if entry & 3 == 2 {
                if entry <= 4096 {
                    // Sibling or reserved internal entry; skip.
                    continue;
                }
                let node = entry - 2;
                let slots = add(node, slots_offset)?;
                self.vm.read(slots, &mut raw_slots)?;
                for chunk in raw_slots.chunks_exact(ptr_size) {
                    let next = if ptr_size == 8 {
                        u64::from_le_bytes(chunk.try_into()?)
                    } else {
                        u64::from(u32::from_le_bytes(chunk.try_into()?))
                    };
                    if next != 0 {
                        stack.push(next);
                    }
                }
            } else if entry & 3 == 0 {
                pages.push(entry);
            }
        }
        Ok(pages)
    }

    fn pagecache_radix_pages(&self, tree: u64, job: &Job) -> Result<Vec<u64>> {
        let root = if self.isf.field("radix_tree_root", "rnode").is_ok() {
            self.number(tree, "radix_tree_root", "rnode")?
        } else {
            self.number(tree, "radix_tree_root", "xa_head")?
        };
        if root == 0 {
            return Ok(Vec::new());
        }
        let height = self
            .number(tree, "radix_tree_root", "height")
            .ok()
            .and_then(|h| usize::try_from(h).ok())
            .unwrap_or(0);
        let slots_offset = self.isf.offset("radix_tree_node", "slots")?;
        let count = usize::try_from(
            self.isf.field("radix_tree_node", "slots")?["type"]
                .key("count")
                .as_u64()
                .context("radix_tree_node.slots count")?,
        )?;
        ensure!(count <= 256, "radix_tree slot count 越界");
        let ptr_size = usize::try_from(
            self.isf.data.key("base_types")["pointer"]
                .key("size")
                .as_u64()
                .unwrap_or(8),
        )?;
        ensure!(matches!(ptr_size, 4 | 8), "不支持的指针宽度");
        let mut stack = vec![(root, height)];
        let mut seen = HashSet::new();
        let mut pages = Vec::new();
        let mut raw_slots = vec![0u8; count * ptr_size];
        while let Some((entry, remaining_height)) = stack.pop() {
            job.check()?;
            if entry == 0 {
                continue;
            }
            ensure!(
                seen.insert((entry, remaining_height)) && seen.len() <= 1_000_000,
                "pagecache radix_tree 循环或上限"
            );
            let is_internal = (entry & 1 == 1) || remaining_height > 0;
            if is_internal {
                let node = entry & !3;
                if node <= 4096 {
                    continue;
                }
                let slots = add(node, slots_offset)?;
                self.vm.read(slots, &mut raw_slots)?;
                let next_height = remaining_height.saturating_sub(1);
                for chunk in raw_slots.chunks_exact(ptr_size) {
                    let next = if ptr_size == 8 {
                        u64::from_le_bytes(chunk.try_into()?)
                    } else {
                        u64::from(u32::from_le_bytes(chunk.try_into()?))
                    };
                    if next != 0 {
                        stack.push((next, next_height));
                    }
                }
            } else if entry & 3 == 0 {
                pages.push(entry);
            }
        }
        Ok(pages)
    }

    fn dump_inode_pages_file(
        &self,
        inode: (u64, u64),                            // (inode_addr, inode_size)
        pages: &[(u64, u64)],                         // (index, page_paddr)
        target: (&std::path::Path, &std::path::Path), // (export root, relative file)
        total_dumped: &mut u64,
        result: &mut Results,
        job: &Job,
    ) -> Result<(u64, String, u64)> {
        let (inode, inode_size) = inode;
        ensure!(
            total_dumped
                .checked_add(inode_size)
                .is_some_and(|n| n <= crate::dump::MAX_DUMP_BYTES),
            "页缓存导出累计超过 256 MiB 上限"
        );
        let (root, relative) = target;
        let page_map: HashMap<u64, u64> = pages.iter().copied().collect();
        let (written, hash, missing_pages) =
            crate::dump::write_nested_artifact(root, relative, job, |out| {
                let mut hash = Sha256::new();
                let mut buf = [0u8; 4096];
                let mut written = 0u64;
                let mut missing_pages = 0u64;
                for index in 0..inode_size.div_ceil(4096) {
                    job.check()?;
                    let chunk = usize::try_from((inode_size - written).min(4096))?;
                    let bytes = buf.at_mut(..chunk)?;
                    if !page_map
                        .get(&index)
                        .copied()
                        .is_some_and(|paddr| self.vm.image.read(paddr, bytes).is_ok())
                    {
                        bytes.fill(0);
                        missing_pages += 1;
                    }
                    out.write_all(bytes)?;
                    hash.update(bytes);
                    written += chunk as u64;
                }
                Ok((written, hash, missing_pages))
            })?;
        if missing_pages > 0 {
            partial(
                result,
                format!("inode {}", hex(inode)),
                anyhow::anyhow!("导出有 {missing_pages} 个未驻留/不可读页已补零"),
            );
        }
        *total_dumped += written;
        Ok((written, format!("{:x}", hash.finalize()), missing_pages))
    }

    pub(super) fn linux_pagecache_inode_pages(
        &self,
        options: &Options,
        dump: Option<&DumpOptions>,
        job: &Job,
    ) -> Result<Results> {
        self.require(&[
            ("inode", "i_size"),
            ("inode", "i_mapping"),
            ("page", "index"),
            ("page", "flags"),
        ])?;
        let (vmemmap_base, page_struct_size) = self.vmemmap_origin()?;
        let mut result = self.result(Plugin::LinuxPagecacheInodePages);

        // Select target inodes either by explicit --base/--start address or via --find / all cached files.
        let targets: Vec<(u64, String)> = if let Some(inode) = dump.and_then(|d| d.start) {
            vec![(inode, format!("inode_{inode:#x}"))]
        } else {
            let files = self.linux_pagecache_files(options, job)?;
            result.complete &= files.complete;
            result.diagnostics.extend(files.diagnostics);
            files
                .rows
                .into_iter()
                .filter_map(|row| {
                    let cached = row.get(7)?.parse::<u64>().ok()?;
                    if cached == 0 {
                        return None;
                    }
                    let addr =
                        u64::from_str_radix(row.get(4)?.trim_start_matches("0x"), 16).ok()?;
                    let path = row.get(12)?.clone();
                    Some((addr, path))
                })
                .collect()
        };

        let mut total_dumped = 0u64;
        let mut dumped_manifest = Vec::new();
        for (inode, label) in targets {
            job.check()?;
            let read = (|| -> Result<()> {
                let mapping = self.number(inode, "inode", "i_mapping")?;
                if mapping == 0 {
                    return Ok(());
                }
                let size_signed = self.signed_field(inode, "inode", "i_size")?;
                let inode_size = u64::try_from(size_signed.max(0))?;
                let page_vaddrs = self.address_space_pages(mapping, job)?;
                let mut entries = Vec::new();
                for pv in page_vaddrs {
                    job.check()?;
                    let index = self.number(pv, "page", "index")?;
                    let flags = self.number(pv, "page", "flags")?;
                    let paddr = self.page_to_phys(pv, vmemmap_base, page_struct_size);
                    if paddr.is_none() {
                        partial(
                            &mut result,
                            format!("inode {} page {}", hex(inode), hex(pv)),
                            anyhow::anyhow!("无法转换为物理页地址"),
                        );
                    }
                    entries.push((index, pv, paddr, flags));
                }
                entries.sort_by_key(|&(index, _, _, _)| index);

                let output_label = if let Some(dump_opts) = dump {
                    if inode_size == 0 || entries.is_empty() {
                        "Skipped (empty)".into()
                    } else {
                        let base_name = label
                            .rsplit('/')
                            .next()
                            .filter(|s| !s.is_empty() && *s != "[unresolved]")
                            .unwrap_or("inode");
                        let safe: String = base_name
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                                    c
                                } else {
                                    '_'
                                }
                            })
                            .take(48)
                            .collect();
                        let filename = format!("inode.{inode:#x}.{safe}.dmp");
                        let dump_pages: Vec<(u64, u64)> = entries
                            .iter()
                            .filter_map(|&(idx, _, pa, _)| pa.map(|pa| (idx, pa)))
                            .collect();
                        match self.dump_inode_pages_file(
                            (inode, inode_size),
                            &dump_pages,
                            (&dump_opts.directory, std::path::Path::new(&filename)),
                            &mut total_dumped,
                            &mut result,
                            job,
                        ) {
                            Ok((written, sha256, missing)) => {
                                dumped_manifest.push(serde_json::json!({
                                    "inode": hex(inode),
                                    "path": label,
                                    "file": filename,
                                    "size": written,
                                    "sha256": sha256,
                                    "missing_pages": missing,
                                }));
                                filename
                            }
                            Err(e) => {
                                partial(&mut result, format!("inode {} 导出", hex(inode)), e);
                                "Error outputting file".into()
                            }
                        }
                    }
                } else {
                    "Disabled".into()
                };

                let mut probe = [0u8; 1];
                for (index, pv, paddr, flags) in entries {
                    let dump_safe = index.saturating_mul(4096) < inode_size
                        && paddr.is_some_and(|pa| self.vm.image.read(pa, &mut probe).is_ok());
                    result.rows.push(vec![
                        hex(pv),
                        paddr.map(hex).unwrap_or_default(),
                        hex(mapping),
                        index.to_string(),
                        dump_safe.to_string(),
                        format!("{flags:#x}"),
                        output_label.clone(),
                    ]);
                }
                Ok(())
            })();
            if let Err(e) = read {
                job.check()?;
                partial(&mut result, format!("inode {}", hex(inode)), e);
            }
        }
        if !dumped_manifest.is_empty() {
            if !result.kernel_identity.is_object() {
                result.kernel_identity = serde_json::json!({});
            }
            if let Some(identity) = result.kernel_identity.as_object_mut() {
                identity.insert(
                    "dumped_inodes".into(),
                    serde_json::Value::Array(dumped_manifest),
                );
            }
        }
        Ok(result)
    }

    pub(super) fn linux_pagecache_recover_fs(
        &self,
        options: &Options,
        dump: Option<&DumpOptions>,
        job: &Job,
    ) -> Result<Results> {
        self.require(&[
            ("inode", "i_size"),
            ("inode", "i_mapping"),
            ("page", "index"),
        ])?;
        let (vmemmap_base, page_struct_size) = self.vmemmap_origin()?;
        let files = self.linux_pagecache_files(options, job)?;
        let mut result = self.result(Plugin::LinuxPagecacheRecoverFs);
        result.complete = files.complete;
        result.diagnostics = files.diagnostics;

        let mut total_dumped = 0u64;
        let mut recovered_manifest = Vec::new();
        for mut row in files.rows {
            job.check()?;
            let file_type = row.get(5).cloned().unwrap_or_default();
            let cached = row.get(7).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let inode_size = row
                .get(13)
                .and_then(|s| s.parse::<i64>().ok())
                .and_then(|s| u64::try_from(s).ok())
                .unwrap_or(0);
            let mut recovered_size = 0u64;
            if file_type == "REG"
                && cached > 0
                && inode_size > 0
                && let Some(inode) = row
                    .get(4)
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            {
                let recover = (|| -> Result<u64> {
                    let mapping = self.number(inode, "inode", "i_mapping")?;
                    if mapping == 0 {
                        return Ok(0);
                    }
                    let page_vaddrs = self.address_space_pages(mapping, job)?;
                    let mut pages = Vec::new();
                    let mut probe = [0u8; 1];
                    let mut resident_bytes = 0u64;
                    for pv in page_vaddrs {
                        job.check()?;
                        let index = self.number(pv, "page", "index")?;
                        let Some(paddr) = self.page_to_phys(pv, vmemmap_base, page_struct_size)
                        else {
                            partial(
                                &mut result,
                                format!("RecoverFs inode {} page {}", hex(inode), hex(pv)),
                                anyhow::anyhow!("无法转换为物理页地址"),
                            );
                            continue;
                        };
                        let off = index.saturating_mul(4096);
                        if off < inode_size && self.vm.image.read(paddr, &mut probe).is_ok() {
                            resident_bytes += (inode_size - off).min(4096);
                            pages.push((index, paddr));
                        }
                    }
                    if let Some(dump_opts) = dump
                        && !pages.is_empty()
                    {
                        let raw_path = row.get(12).map(String::as_str).unwrap_or("");
                        let mut rel = std::path::PathBuf::new();
                        for part in raw_path.split('/') {
                            if part.is_empty() || part == "." || part == ".." {
                                continue;
                            }
                            let clean: String = part
                                .chars()
                                .map(|c| {
                                    if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                                        c
                                    } else {
                                        '_'
                                    }
                                })
                                .take(64)
                                .collect();
                            if !clean.is_empty() && clean != "." && clean != ".." {
                                rel.push(clean);
                            }
                        }
                        if rel.as_os_str().is_empty() {
                            rel.push(format!("inode_{inode:#x}.bin"));
                        }
                        let (written, sha256, missing) = self.dump_inode_pages_file(
                            (inode, inode_size),
                            &pages,
                            (&dump_opts.directory, &rel),
                            &mut total_dumped,
                            &mut result,
                            job,
                        )?;
                        recovered_manifest.push(serde_json::json!({
                            "inode": hex(inode),
                            "path": raw_path,
                            "file": rel.to_string_lossy(),
                            "size": written,
                            "sha256": sha256,
                            "missing_pages": missing,
                        }));
                    }
                    Ok(resident_bytes)
                })();
                match recover {
                    Ok(bytes) => recovered_size = bytes,
                    Err(e) => {
                        job.check()?;
                        partial(&mut result, format!("RecoverFs inode {}", hex(inode)), e);
                    }
                }
            }
            row.push(recovered_size.to_string());
            result.rows.push(row);
        }
        if !recovered_manifest.is_empty() {
            if !result.kernel_identity.is_object() {
                result.kernel_identity = serde_json::json!({});
            }
            if let Some(identity) = result.kernel_identity.as_object_mut() {
                identity.insert(
                    "recovered_files".into(),
                    serde_json::Value::Array(recovered_manifest),
                );
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::tests::{engine, fixture, image};
    use serde_json::json;

    fn put(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn linux_pagecache_files_emits_14_columns_and_filters_type_and_find() {
        let (mut b, mut isf) = fixture();
        isf.data["symbols"]["super_blocks"] = json!({"address": 0x10000});
        isf.data["user_types"]["super_block"] = json!({
            "size": 48,
            "fields": {
                "s_list": {"offset": 0, "type": {"kind": "struct", "name": "list_head"}},
                "s_inodes": {"offset": 16, "type": {"kind": "struct", "name": "list_head"}},
                "s_dev": {"offset": 32, "type": {"kind": "base", "name": "u32"}}
            }
        });
        isf.data["user_types"]["address_space"] = json!({
            "size": 16,
            "fields": {"nrpages": {"offset": 0, "type": {"kind": "base", "name": "u64"}}}
        });
        isf.data["user_types"]["timespec64"] = json!({
            "size": 16,
            "fields": {
                "tv_sec": {"offset": 0, "type": {"kind": "base", "name": "u64"}},
                "tv_nsec": {"offset": 8, "type": {"kind": "base", "name": "u64"}}
            }
        });
        isf.data["user_types"]["inode"] = json!({
            "size": 128,
            "fields": {
                "i_mode": {"offset": 0, "type": {"kind": "base", "name": "u32"}},
                "i_ino": {"offset": 8, "type": {"kind": "base", "name": "u64"}},
                "i_size": {"offset": 16, "type": {"kind": "base", "name": "u64"}},
                "i_mapping": {"offset": 24, "type": {"kind": "pointer"}},
                "i_sb_list": {"offset": 32, "type": {"kind": "struct", "name": "list_head"}},
                "i_dentry": {"offset": 48, "type": {"kind": "struct", "name": "list_head"}},
                "i_atime": {"offset": 64, "type": {"kind": "struct", "name": "timespec64"}},
                "i_mtime": {"offset": 80, "type": {"kind": "struct", "name": "timespec64"}},
                "i_ctime": {"offset": 96, "type": {"kind": "struct", "name": "timespec64"}}
            }
        });
        isf.data["user_types"]["dentry"]["fields"]["d_alias"] =
            json!({"offset": 32, "type": {"kind": "struct", "name": "list_head"}});
        isf.data["user_types"]["task_struct"]["fields"]["nsproxy"] =
            json!({"offset": 72, "type": {"kind": "pointer"}});

        // super_blocks head 0x10000 -> sb 0x11000
        put(&mut b, 0x10000, 0x11000);
        put(&mut b, 0x10008, 0x11000);
        put(&mut b, 0x11000, 0x10000);
        put(&mut b, 0x11008, 0x10000);
        // sb.s_inodes (0x11010) -> inode 0x12000 (i_sb_list at +32 = 0x12020)
        put(&mut b, 0x11010, 0x12020);
        put(&mut b, 0x11018, 0x12020);
        put(&mut b, 0x11020, (8u64 << 20) | 2); // s_dev = 8:2

        // inode at 0x12000: REG 0644, ino=404, size=5000 (2 pages), nrpages=1
        put(&mut b, 0x12000, 0o100644);
        put(&mut b, 0x12008, 404);
        put(&mut b, 0x12010, 5000);
        put(&mut b, 0x12018, 0x12500); // i_mapping
        put(&mut b, 0x12020, 0x11010); // i_sb_list.next
        put(&mut b, 0x12028, 0x11010); // i_sb_list.prev
        put(&mut b, 0x12030, 0x13020); // i_dentry.next -> dentry 0x13000 + d_alias(32)
        put(&mut b, 0x12038, 0x13020);
        put(&mut b, 0x12040, 1_700_000_000); // atime
        put(&mut b, 0x12050, 1_700_000_001); // mtime
        put(&mut b, 0x12060, 1_700_000_002); // ctime
        put(&mut b, 0x12500, 1); // nrpages

        // dentry at 0x13000 ("secret.conf") -> parent 0x13100 (root)
        put(&mut b, 0x13000, 0x13100);
        put(&mut b, 0x13008, 11);
        put(&mut b, 0x13010, 0x13200);
        put(&mut b, 0x13100, 0x13100);
        b[0x13200..0x1320c].copy_from_slice(b"secret.conf\0");

        // Only PID 1's mount namespace contains this superblock, at /container.
        isf.data["user_types"]["task_struct"]["fields"]["nsproxy"] = json!({
            "offset":72, "type":{"kind":"pointer","subtype":{"kind":"struct","name":"nsproxy"}}
        });
        isf.data["user_types"]["nsproxy"] = json!({
            "size":8, "fields":{"mnt_ns":{"offset":0,"type":{"kind":"pointer"}}}
        });
        isf.data["user_types"]["mnt_namespace"] = json!({
            "size":16, "fields":{"list":{"offset":0,"type":{"kind":"struct","name":"list_head"}}}
        });
        isf.data["user_types"]["vfsmount"]["fields"]["mnt_list"] =
            json!({"offset":24,"type":{"kind":"struct","name":"list_head"}});
        isf.data["user_types"]["vfsmount"]["fields"]["mnt_sb"] =
            json!({"offset":40,"type":{"kind":"pointer"}});
        isf.data["user_types"]["dentry"]["fields"]["d_sb"] =
            json!({"offset":40,"type":{"kind":"pointer"}});
        isf.data["user_types"]["super_block"]["fields"]["s_type"] =
            json!({"offset":40,"type":{"kind":"pointer"}});
        isf.data["user_types"]["file_system_type"] = json!({
            "size":8, "fields":{"name":{"offset":0,"type":{"kind":"pointer"}}}
        });
        put(&mut b, 0x9048, 0x15000);
        put(&mut b, 0x15000, 0x15100);
        put(&mut b, 0x15100, 0x15100);
        put(&mut b, 0x15108, 0x15100);
        put(&mut b, 0xa048, 0x15010);
        put(&mut b, 0x15010, 0x15200);
        put(&mut b, 0x15200, 0x16018);
        put(&mut b, 0x15208, 0x16018);
        put(&mut b, 0x16000, 0x13100);
        put(&mut b, 0x16008, 0x16100);
        put(&mut b, 0x16010, 0x16200);
        put(&mut b, 0x16018, 0x15200);
        put(&mut b, 0x16020, 0x15200);
        put(&mut b, 0x16028, 0x11000);
        put(&mut b, 0x16100, 0x16300);
        put(&mut b, 0x16108, 0x16100);
        put(&mut b, 0x16200, 0x16300);
        put(&mut b, 0x16208, 9);
        put(&mut b, 0x16210, 0x16400);
        b[0x16400..0x1640a].copy_from_slice(b"container\0");
        put(&mut b, 0x16300, 0x16300);
        put(&mut b, 0x16328, 0x16500);
        put(&mut b, 0x16528, 0x16600);
        put(&mut b, 0x16600, 0x16700);
        b[0x16700..0x16705].copy_from_slice(b"ext4\0");

        let img = image(&b);
        let linux = engine(&img, &isf);
        let result = linux
            .linux_pagecache_files(&Options::default(), &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0],
            vec![
                "0x0000000000011000",
                "/container",
                "8:2",
                "404",
                "0x0000000000012000",
                "REG",
                "2",
                "1",
                "-rw-r--r--",
                "2023-11-14T22:13:20.000000+00:00",
                "2023-11-14T22:13:21.000000+00:00",
                "2023-11-14T22:13:22.000000+00:00",
                "/container/secret.conf",
                "5000",
            ]
        );

        let dir_only = linux
            .linux_pagecache_files(
                &Options {
                    file_types: vec!["DIR".into()],
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(dir_only.rows.is_empty());

        let found = linux
            .linux_pagecache_files(
                &Options {
                    find: Some("/container/secret".into()),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(found.rows.len(), 1);

        // A known inode on an unmounted superblock has no verified absolute path.
        put(&mut b, 0x15200, 0x15200);
        put(&mut b, 0x15208, 0x15200);
        let img = image(&b);
        let unmounted = engine(&img, &isf)
            .linux_pagecache_files(&Options::default(), &Job::default())
            .unwrap();
        assert_eq!(unmounted.rows[0][1], "N/A");
        assert_eq!(unmounted.rows[0][12], "[unresolved]");
    }

    #[test]
    fn inode_pages_and_recover_fs_extract_xarray_cached_file_bytes() {
        let (mut b, mut isf) = fixture();
        b.resize(0x20000, 0);
        // Set up vmemmap_base symbol pointing to 0x18000 (so page struct at 0x18000 + pfn*64 -> phys pfn*4096).
        // Put file content "SECRET_DATA!" at physical page 0x1a000 (pfn = 0x1a).
        isf.data["symbols"]["vmemmap_base"] = json!({"address": 0x17000});
        isf.data["symbols"]["super_blocks"] = json!({"address": 0x10000});
        isf.data["user_types"]["super_block"] = json!({
            "size": 48,
            "fields": {
                "s_list": {"offset": 0, "type": {"kind": "struct", "name": "list_head"}},
                "s_inodes": {"offset": 16, "type": {"kind": "struct", "name": "list_head"}},
                "s_dev": {"offset": 32, "type": {"kind": "base", "name": "u32"}}
            }
        });
        isf.data["user_types"]["xarray"] = json!({
            "size": 8,
            "fields": {"xa_head": {"offset": 0, "type": {"kind": "pointer"}}}
        });
        isf.data["user_types"]["xa_node"] = json!({
            "size": 16,
            "fields": {"slots": {"offset": 0, "type": {"kind": "array", "count": 2, "subtype": {"kind": "pointer"}}}}
        });
        isf.data["user_types"]["address_space"] = json!({
            "size": 24,
            "fields": {
                "nrpages": {"offset": 0, "type": {"kind": "base", "name": "u64"}},
                "i_pages": {"offset": 8, "type": {"kind": "struct", "name": "xarray"}}
            }
        });
        isf.data["user_types"]["page"] = json!({
            "size": 64,
            "fields": {
                "flags": {"offset": 0, "type": {"kind": "base", "name": "u64"}},
                "index": {"offset": 8, "type": {"kind": "base", "name": "u64"}}
            }
        });
        isf.data["user_types"]["inode"] = json!({
            "size": 64,
            "fields": {
                "i_mode": {"offset": 0, "type": {"kind": "base", "name": "u32"}},
                "i_ino": {"offset": 8, "type": {"kind": "base", "name": "u64"}},
                "i_size": {"offset": 16, "type": {"kind": "base", "name": "u64"}},
                "i_mapping": {"offset": 24, "type": {"kind": "pointer"}},
                "i_sb_list": {"offset": 32, "type": {"kind": "struct", "name": "list_head"}},
                "i_dentry": {"offset": 48, "type": {"kind": "struct", "name": "list_head"}}
            }
        });
        isf.data["user_types"]["dentry"]["fields"]["d_alias"] =
            json!({"offset": 32, "type": {"kind": "struct", "name": "list_head"}});
        isf.data["user_types"]["task_struct"]["fields"]["nsproxy"] =
            json!({"offset": 72, "type": {"kind": "pointer"}});

        // vmemmap_base = 0x18000; page struct for pfn 0x1a is at 0x18000 + 0x1a * 64 = 0x18680
        let vmemmap: u64 = 0x18000;
        let page_vaddr: u64 = vmemmap + 0x1a * 64;
        put(&mut b, 0x17000, vmemmap);
        put(&mut b, page_vaddr as usize, 0x40); // flags
        put(&mut b, page_vaddr as usize + 8, 0); // index = 0
        b[0x1a000..0x1a00c].copy_from_slice(b"SECRET_DATA!");

        // super_blocks -> sb 0x11000 -> inode 0x12000
        put(&mut b, 0x10000, 0x11000);
        put(&mut b, 0x10008, 0x11000);
        put(&mut b, 0x11000, 0x10000);
        put(&mut b, 0x11008, 0x10000);
        put(&mut b, 0x11010, 0x12020);
        put(&mut b, 0x11018, 0x12020);
        put(&mut b, 0x11020, (8u64 << 20) | 1);

        // inode at 0x12000: REG, ino=77, size=12, i_mapping=0x12500
        put(&mut b, 0x12000, 0o100644);
        put(&mut b, 0x12008, 77);
        put(&mut b, 0x12010, 12);
        put(&mut b, 0x12018, 0x12500);
        put(&mut b, 0x12020, 0x11010);
        put(&mut b, 0x12028, 0x11010);
        put(&mut b, 0x12030, 0x13020);
        put(&mut b, 0x12038, 0x13020);
        // address_space at 0x12500: nrpages=1, i_pages.xa_head = page_vaddr
        put(&mut b, 0x12500, 1);
        put(&mut b, 0x12508, page_vaddr);
        // dentry at 0x13000 ("token.txt")
        put(&mut b, 0x13000, 0x13100);
        put(&mut b, 0x13008, 9);
        put(&mut b, 0x13010, 0x13200);
        put(&mut b, 0x13100, 0x13100);
        b[0x13200..0x1320a].copy_from_slice(b"token.txt\0");

        let img = image(&b);
        let linux = engine(&img, &isf);

        // 1. InodePages with explicit inode address and dump_dir extracts "SECRET_DATA!".
        let dir1 = tempfile::tempdir().unwrap();
        let pages = linux
            .linux_pagecache_inode_pages(
                &Options::default(),
                Some(&DumpOptions {
                    pid: 0,
                    directory: dir1.path().to_path_buf(),
                    start: Some(0x12000),
                    end: None,
                }),
                &Job::default(),
            )
            .unwrap();
        assert!(pages.complete, "{:?}", pages.diagnostics);
        assert_eq!(pages.rows.len(), 1);
        assert_eq!(pages.rows[0][1], hex(0x1a000));
        assert_eq!(pages.rows[0][4], "true");
        let out_file = dir1.path().join(&pages.rows[0][6]);
        assert_eq!(std::fs::read(&out_file).unwrap(), b"SECRET_DATA!");

        // 2. RecoverFs computes resident bytes and writes recovered file.
        let dir2 = tempfile::tempdir().unwrap();
        let rec = linux
            .linux_pagecache_recover_fs(
                &Options::default(),
                Some(&DumpOptions {
                    pid: 0,
                    directory: dir2.path().to_path_buf(),
                    start: None,
                    end: None,
                }),
                &Job::default(),
            )
            .unwrap();
        assert!(rec.complete, "{:?}", rec.diagnostics);
        assert_eq!(rec.rows.len(), 1);
        assert_eq!(rec.rows[0][14], "12");
        let entries = rec.kernel_identity["recovered_files"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let recovered = dir2.path().join(entries[0]["file"].as_str().unwrap());
        assert_eq!(std::fs::read(&recovered).unwrap(), b"SECRET_DATA!");

        // A readable struct page whose address is unaligned relative to vmemmap
        // must leave a hole, even when physical page zero is readable.
        put(&mut b, 0x17000, vmemmap + 4);
        b[..12].copy_from_slice(b"NOT_EVIDENCE");
        let img = image(&b);
        let dir3 = tempfile::tempdir().unwrap();
        let missing = engine(&img, &isf)
            .linux_pagecache_inode_pages(
                &Options::default(),
                Some(&DumpOptions {
                    pid: 0,
                    directory: dir3.path().to_path_buf(),
                    start: Some(0x12000),
                    end: None,
                }),
                &Job::default(),
            )
            .unwrap();
        assert!(!missing.complete);
        assert_eq!(missing.rows[0][1], "");
        assert_eq!(missing.rows[0][4], "false");
        assert_eq!(
            missing.kernel_identity["dumped_inodes"][0]["missing_pages"],
            1
        );
        assert_eq!(
            std::fs::read(dir3.path().join(&missing.rows[0][6])).unwrap(),
            [0; 12]
        );
    }
}
