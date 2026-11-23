//! Volatility-compatible Linux page cache file listing (`linux.pagecache.Files`).
use super::*;
use crate::analysis::Options;
use std::collections::{HashMap, HashSet};

fn join_mount_path(mount_point: &str, rel_path: &str) -> String {
    if mount_point.is_empty() || mount_point == "/" {
        if rel_path.starts_with('/') {
            rel_path.to_string()
        } else {
            format!("/{rel_path}")
        }
    } else if rel_path == "/" || rel_path.is_empty() {
        mount_point.to_string()
    } else {
        format!(
            "{}/{}",
            mount_point.trim_end_matches('/'),
            rel_path.trim_start_matches('/')
        )
    }
}

impl Linux<'_> {
    /// Best-effort map from `super_block` pointer to mount point path via `init_task`.
    fn superblock_mount_points(&self, job: &Job) -> HashMap<u64, String> {
        let mut map = HashMap::new();
        let Ok(init) = self.isf.address("init_task") else {
            return map;
        };
        let Ok(proxy) = self.number(init, "task_struct", "nsproxy") else {
            return map;
        };
        if proxy == 0 {
            return map;
        }
        let Ok(ns) = self.number(proxy, "nsproxy", "mnt_ns") else {
            return map;
        };
        if ns == 0 {
            return map;
        }
        if self.modern_mount() {
            let Ok(root) = self.number(ns, "mnt_namespace", "root") else {
                return map;
            };
            let Ok(offset) = self.isf.offset("mount", "mnt") else {
                return map;
            };
            let mut stack = vec![root];
            let mut seen = HashSet::new();
            while let Some(m) = stack.pop() {
                if m == 0 || !seen.insert(m) || seen.len() > 65536 {
                    continue;
                }
                if let Ok(head) = self.field_address(m, "mount", "mnt_mounts")
                    && let Ok(off) = self.isf.offset("mount", "mnt_child")
                    && let Ok(kids) = self.list_objects(head, off, job)
                {
                    stack.extend(kids);
                }
                if let Ok(vfs) = add(m, offset)
                    && let Ok(sb) = self.number(vfs, "vfsmount", "mnt_sb")
                    && let Ok(mnt_root) = self.number(vfs, "vfsmount", "mnt_root")
                    && let Ok(mp) = self.resolve_path(mnt_root, vfs, None, job)
                {
                    map.entry(sb).or_insert(mp);
                }
            }
        } else if let Ok(head) = self.field_address(ns, "mnt_namespace", "list")
            && let Ok(off) = self.isf.offset("vfsmount", "mnt_list")
            && let Ok(mounts) = self.list_objects(head, off, job)
        {
            for m in mounts {
                if let Ok(sb) = self.number(m, "vfsmount", "mnt_sb")
                    && let Ok(mnt_root) = self.number(m, "vfsmount", "mnt_root")
                    && let Ok(mp) = self.resolve_path(mnt_root, m, None, job)
                {
                    map.entry(sb).or_insert(mp);
                }
            }
        }
        map
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

        let mount_points = self.superblock_mount_points(job);
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
                let mount_point = mount_points
                    .get(&block)
                    .cloned()
                    .unwrap_or_else(|| "/".into());
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
                        let full_path = if rel_path.is_empty() || rel_path == "[unresolved]" {
                            rel_path
                        } else {
                            join_mount_path(&mount_point, &rel_path)
                        };
                        if let Some(needle) = find
                            && !full_path.contains(needle)
                        {
                            return Ok(None);
                        }
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
                            mount_point.clone(),
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
                "/",
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
                "/secret.conf",
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
                    find: Some("secret".into()),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(found.rows.len(), 1);
    }
}
