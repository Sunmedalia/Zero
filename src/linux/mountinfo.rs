//! Volatility-compatible Linux mount namespace listing (`linux.mountinfo.MountInfo`).
use super::*;
use crate::analysis::Options;
use std::collections::BTreeSet;

fn decode_mount_flags(flags: u64) -> String {
    let mut parts = vec![if flags & 0x40 != 0 { "ro" } else { "rw" }];
    if flags & 0x01 != 0 {
        parts.push("nosuid");
    }
    if flags & 0x02 != 0 {
        parts.push("nodev");
    }
    if flags & 0x04 != 0 {
        parts.push("noexec");
    }
    if flags & 0x08 != 0 {
        parts.push("noatime");
    }
    if flags & 0x10 != 0 {
        parts.push("nodiratime");
    }
    if flags & 0x20 != 0 {
        parts.push("relatime");
    }
    if flags & 0x80 != 0 {
        parts.push("nosymfollow");
    }
    parts.join(",")
}

fn decode_sb_flags(flags: u64) -> String {
    let mut parts = vec![if flags & 0x01 != 0 { "ro" } else { "rw" }];
    if flags & 0x10 != 0 {
        parts.push("sync");
    }
    if flags & 0x40 != 0 {
        parts.push("mand");
    }
    if flags & 0x80 != 0 {
        parts.push("dirsync");
    }
    if flags & 0x200_0000 != 0 {
        parts.push("lazytime");
    }
    parts.join(",")
}

struct MountEntry<'a> {
    ns_label: &'a str,
    mount_id: u64,
    parent_id: u64,
    sb: u64,
    vfs_mnt: u64,
    mnt_root: u64,
    dev_ptr: u64,
    mnt_flags: u64,
    group_id: Option<u64>,
    master_id: Option<u64>,
    mount_format: bool,
}

impl Linux<'_> {
    fn mnt_ns_id(&self, ns: u64) -> Option<u64> {
        if self.isf.field("mnt_namespace", "ns").is_ok()
            && self.isf.field("ns_common", "inum").is_ok()
        {
            self.number(ns, "mnt_namespace", "ns.inum").ok()
        } else if self.isf.field("mnt_namespace", "proc_inum").is_ok() {
            self.number(ns, "mnt_namespace", "proc_inum").ok()
        } else {
            None
        }
    }

    pub(super) fn linux_mountinfo(&self, options: &Options, job: &Job) -> Result<Results> {
        if self.modern_mount() {
            self.require(&[
                ("task_struct", "nsproxy"),
                ("nsproxy", "mnt_ns"),
                ("mnt_namespace", "root"),
                ("mount", "mnt_mounts"),
                ("mount", "mnt_child"),
                ("mount", "mnt"),
                ("mount", "mnt_id"),
                ("mount", "mnt_parent"),
                ("mount", "mnt_devname"),
                ("vfsmount", "mnt_root"),
                ("vfsmount", "mnt_sb"),
                ("vfsmount", "mnt_flags"),
                ("super_block", "s_type"),
                ("file_system_type", "name"),
            ])?;
        } else {
            self.require(&[
                ("task_struct", "nsproxy"),
                ("nsproxy", "mnt_ns"),
                ("mnt_namespace", "list"),
                ("vfsmount", "mnt_list"),
                ("vfsmount", "mnt_id"),
                ("vfsmount", "mnt_parent"),
                ("vfsmount", "mnt_root"),
                ("vfsmount", "mnt_sb"),
                ("vfsmount", "mnt_devname"),
                ("vfsmount", "mnt_flags"),
                ("super_block", "s_type"),
                ("file_system_type", "name"),
            ])?;
        }

        let pids: BTreeSet<u32> = options.pids.iter().copied().chain(options.pid).collect();
        let (mut result, tasks) = self.task_identities(Plugin::LinuxMountinfo, job)?;
        let filtered = !pids.is_empty();
        if options.mount_format {
            result.columns = ["MNT_NS_ID", "DEVNAME", "PATH", "FSTYPE", "MNT_OPTS"]
                .map(str::to_owned)
                .to_vec();
        }
        if filtered {
            result.columns.insert(1, "PID".into());
        }
        let mut seen_ns = HashSet::new();

        for task in tasks {
            job.check()?;
            if filtered && !task.pid.parse::<u32>().is_ok_and(|pid| pids.contains(&pid)) {
                continue;
            }
            let addr = task.address;
            let first_row = result.rows.len();
            let read = (|| -> Result<()> {
                let proxy = self.number(addr, "task_struct", "nsproxy")?;
                if proxy == 0 {
                    return Ok(());
                }
                let ns = self.number(proxy, "nsproxy", "mnt_ns")?;
                if ns == 0 || (!filtered && !seen_ns.insert(ns)) {
                    return Ok(());
                }
                let ns_id = self.mnt_ns_id(ns);
                if let Some(want) = options.mntns
                    && ns_id != Some(want)
                {
                    return Ok(());
                }
                let ns_label = ns_id.map(|v| v.to_string()).unwrap_or_else(|| "N/A".into());
                if self.modern_mount() {
                    self.mountinfo_modern(ns, &ns_label, options.mount_format, &mut result, job)
                } else {
                    self.mountinfo_legacy(ns, &ns_label, options.mount_format, &mut result, job)
                }
            })();
            if let Err(error) = read {
                job.check()?;
                partial(&mut result, format!("PID {} mountinfo", task.pid), error);
            }
            if filtered {
                for row in result.rows.at_mut(first_row..)? {
                    row.insert(1, task.pid.clone());
                }
            }
            job.report(format!(
                "linux.mountinfo.MountInfo: {} 条",
                result.rows.len()
            ));
        }
        Ok(result)
    }

    fn mountinfo_row(&self, entry: &MountEntry<'_>, job: &Job) -> Result<Vec<String>> {
        let dev = self
            .number(entry.sb, "super_block", "s_dev")
            .ok()
            .map(|d| {
                let (maj, min) = super::maps::decode_dev(d);
                format!("{maj}:{min}")
            })
            .unwrap_or_else(|| "0:0".into());
        let root_path = self
            .dentry_path(entry.mnt_root)
            .unwrap_or_else(|_| "/".into());
        let mount_point = self
            .resolve_path(entry.mnt_root, entry.vfs_mnt, None, job)
            .unwrap_or_else(|_| "[unresolved]".into());
        let ty = self.number(entry.sb, "super_block", "s_type")?;
        let fstype = self.kernel_text(self.number(ty, "file_system_type", "name")?, 128)?;
        let src = if entry.dev_ptr == 0 {
            "none".into()
        } else {
            self.kernel_text(entry.dev_ptr, 4096)?
        };
        let mnt_opts = decode_mount_flags(entry.mnt_flags);
        let sb_opts = self
            .number(entry.sb, "super_block", "s_flags")
            .ok()
            .map(decode_sb_flags)
            .unwrap_or_else(|| "rw".into());
        let mut field_parts = Vec::new();
        if entry.mnt_flags & 0x1000 != 0
            && let Some(g) = entry.group_id
            && g != 0
        {
            field_parts.push(format!("shared:{g}"));
        }
        if let Some(m) = entry.master_id
            && m != 0
        {
            field_parts.push(format!("master:{m}"));
        }
        if entry.mnt_flags & 0x2000 != 0 {
            field_parts.push("unbindable".into());
        }
        let fields = field_parts.join(" ");
        if entry.mount_format {
            let mut options = BTreeSet::new();
            for option in mnt_opts.split(',').chain(sb_opts.split(',')) {
                if option != "ro" && option != "rw" {
                    options.insert(option);
                }
            }
            let access = if mnt_opts.starts_with("ro") || sb_opts.starts_with("ro") {
                "ro"
            } else {
                "rw"
            };
            let options = std::iter::once(access)
                .chain(options)
                .collect::<Vec<_>>()
                .join(",");
            Ok(vec![
                entry.ns_label.to_string(),
                src,
                mount_point,
                fstype,
                options,
            ])
        } else {
            Ok(vec![
                entry.ns_label.to_string(),
                entry.mount_id.to_string(),
                entry.parent_id.to_string(),
                dev,
                root_path,
                mount_point,
                mnt_opts,
                fields,
                fstype,
                src,
                sb_opts,
            ])
        }
    }

    fn mountinfo_modern(
        &self,
        ns: u64,
        ns_label: &str,
        mount_format: bool,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let mut stack = vec![self.number(ns, "mnt_namespace", "root")?];
        let mut seen = HashSet::new();
        let offset = self.isf.offset("mount", "mnt")?;
        let has_group = self.isf.field("mount", "mnt_group_id").is_ok();
        let has_master = self.isf.field("mount", "mnt_master").is_ok();
        while let Some(m) = stack.pop() {
            job.check()?;
            ensure!(
                m != 0 && seen.insert(m) && seen.len() <= LIMIT,
                "挂载树循环或上限"
            );
            let kids = self.list_objects(
                self.field_address(m, "mount", "mnt_mounts")?,
                self.isf.offset("mount", "mnt_child")?,
                job,
            )?;
            stack.extend(kids.into_iter().rev());
            let read = (|| -> Result<Vec<String>> {
                let vfs = add(m, offset)?;
                let mount_id = self.number(m, "mount", "mnt_id")?;
                let parent = self.number(m, "mount", "mnt_parent")?;
                let parent_id = self.number(parent, "mount", "mnt_id")?;
                let dev_ptr = self.number(m, "mount", "mnt_devname")?;
                let sb = self.number(vfs, "vfsmount", "mnt_sb")?;
                let mnt_root = self.number(vfs, "vfsmount", "mnt_root")?;
                let mnt_flags = self.number(vfs, "vfsmount", "mnt_flags")?;
                let group = if has_group {
                    self.number(m, "mount", "mnt_group_id").ok()
                } else {
                    None
                };
                let master = if has_group && has_master {
                    self.number(m, "mount", "mnt_master")
                        .ok()
                        .filter(|&ptr| ptr != 0)
                        .and_then(|ptr| self.number(ptr, "mount", "mnt_group_id").ok())
                } else {
                    None
                };
                self.mountinfo_row(
                    &MountEntry {
                        ns_label,
                        mount_id,
                        parent_id,
                        sb,
                        vfs_mnt: vfs,
                        mnt_root,
                        dev_ptr,
                        mnt_flags,
                        group_id: group,
                        master_id: master,
                        mount_format,
                    },
                    job,
                )
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(error) => {
                    job.check()?;
                    partial(result, format!("mntns {ns_label} mount {}", hex(m)), error);
                }
            }
        }
        Ok(())
    }

    fn mountinfo_legacy(
        &self,
        ns: u64,
        ns_label: &str,
        mount_format: bool,
        result: &mut Results,
        job: &Job,
    ) -> Result<()> {
        let head = self.field_address(ns, "mnt_namespace", "list")?;
        let offset = self.isf.offset("vfsmount", "mnt_list")?;
        let has_group = self.isf.field("vfsmount", "mnt_group_id").is_ok();
        let has_master = self.isf.field("vfsmount", "mnt_master").is_ok();
        let mounts = self.list_objects(head, offset, job)?;
        for m in mounts {
            job.check()?;
            let read = (|| -> Result<Vec<String>> {
                let mount_id = self.number(m, "vfsmount", "mnt_id")?;
                let parent = self.number(m, "vfsmount", "mnt_parent")?;
                let parent_id = self.number(parent, "vfsmount", "mnt_id")?;
                let dev_ptr = self.number(m, "vfsmount", "mnt_devname")?;
                let sb = self.number(m, "vfsmount", "mnt_sb")?;
                let mnt_root = self.number(m, "vfsmount", "mnt_root")?;
                let mnt_flags = self.number(m, "vfsmount", "mnt_flags")?;
                let group = if has_group {
                    self.number(m, "vfsmount", "mnt_group_id").ok()
                } else {
                    None
                };
                let master = if has_group && has_master {
                    self.number(m, "vfsmount", "mnt_master")
                        .ok()
                        .filter(|&ptr| ptr != 0)
                        .and_then(|ptr| self.number(ptr, "vfsmount", "mnt_group_id").ok())
                } else {
                    None
                };
                self.mountinfo_row(
                    &MountEntry {
                        ns_label,
                        mount_id,
                        parent_id,
                        sb,
                        vfs_mnt: m,
                        mnt_root,
                        dev_ptr,
                        mnt_flags,
                        group_id: group,
                        master_id: master,
                        mount_format,
                    },
                    job,
                )
            })();
            match read {
                Ok(row) => result.rows.push(row),
                Err(error) => {
                    job.check()?;
                    partial(result, format!("mntns {ns_label} mount {}", hex(m)), error);
                }
            }
        }
        Ok(())
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
    fn linux_mountinfo_deduplicates_namespaces_and_decodes_options() {
        let (mut b, mut isf) = fixture();
        isf.data["user_types"]["task_struct"]["fields"]["nsproxy"] = json!({
            "offset": 72,
            "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "nsproxy"}}
        });
        isf.data["user_types"]["nsproxy"] = json!({
            "size": 16,
            "fields": {"mnt_ns": {"offset": 0, "type": {"kind": "pointer"}}}
        });
        isf.data["user_types"]["ns_common"] = json!({
            "size": 16,
            "fields": {"inum": {"offset": 0, "type": {"kind": "base", "name": "u32"}}}
        });
        isf.data["user_types"]["mnt_namespace"] = json!({
            "size": 48,
            "fields": {
                "ns": {"offset": 0, "type": {"kind": "struct", "name": "ns_common"}},
                "list": {"offset": 16, "type": {"kind": "struct", "name": "list_head"}}
            }
        });
        isf.data["user_types"]["vfsmount"] = json!({
            "size": 96,
            "fields": {
                "mnt_root": {"offset": 0, "type": {"kind": "pointer"}},
                "mnt_parent": {"offset": 8, "type": {"kind": "pointer"}},
                "mnt_mountpoint": {"offset": 16, "type": {"kind": "pointer"}},
                "mnt_list": {"offset": 24, "type": {"kind": "struct", "name": "list_head"}},
                "mnt_id": {"offset": 40, "type": {"kind": "base", "name": "u32"}},
                "mnt_sb": {"offset": 48, "type": {"kind": "pointer"}},
                "mnt_devname": {"offset": 56, "type": {"kind": "pointer"}},
                "mnt_flags": {"offset": 64, "type": {"kind": "base", "name": "u64"}},
                "mnt_group_id": {"offset": 72, "type": {"kind": "base", "name": "u32"}}
            }
        });
        isf.data["user_types"]["super_block"] = json!({
            "size": 32,
            "fields": {
                "s_dev": {"offset": 0, "type": {"kind": "base", "name": "u32"}},
                "s_flags": {"offset": 8, "type": {"kind": "base", "name": "u64"}},
                "s_type": {"offset": 16, "type": {"kind": "pointer"}}
            }
        });
        isf.data["user_types"]["file_system_type"] = json!({
            "size": 16,
            "fields": {"name": {"offset": 0, "type": {"kind": "pointer"}}}
        });
        isf.data["user_types"]["dentry"]["fields"]["d_sb"] =
            json!({"offset": 32, "type": {"kind": "pointer"}});

        // Two tasks sharing the same mnt_ns (4026531840) => emitted only once!
        put(&mut b, 0xa048, 0xc000);
        put(&mut b, 0xa148, 0xc000);
        put(&mut b, 0xc000, 0xc100); // nsproxy.mnt_ns
        put(&mut b, 0xc100, 4_026_531_840); // mnt_namespace.ns.inum
        put(&mut b, 0xc110, 0xd018); // list.next -> vfsmount.mnt_list
        put(&mut b, 0xc118, 0xd018); // list.prev

        // vfsmount at 0xd000
        put(&mut b, 0xd000, 0xd200); // mnt_root
        put(&mut b, 0xd008, 0xd000); // mnt_parent (self)
        put(&mut b, 0xd010, 0xd200); // mnt_mountpoint
        put(&mut b, 0xd018, 0xc110); // mnt_list.next -> head
        put(&mut b, 0xd020, 0xc110); // mnt_list.prev -> head
        put(&mut b, 0xd028, 22); // mnt_id
        put(&mut b, 0xd030, 0xd300); // mnt_sb
        put(&mut b, 0xd038, 0xd400); // mnt_devname
        put(&mut b, 0xd040, 0x20 | 0x01 | 0x1000); // relatime + nosuid + MNT_SHARED
        put(&mut b, 0xd048, 1); // shared:1

        // root dentry at 0xd200
        put(&mut b, 0xd200, 0xd200);
        put(&mut b, 0xd220, 0xd300);
        // super_block at 0xd300: s_dev = 8:1, s_flags = 0 (rw), s_type = 0xd500
        put(&mut b, 0xd300, (8u64 << 20) | 1);
        put(&mut b, 0xd308, 0);
        put(&mut b, 0xd310, 0xd500);
        b[0xd400..0xd40a].copy_from_slice(b"/dev/sda1\0");
        put(&mut b, 0xd500, 0xd520);
        b[0xd520..0xd525].copy_from_slice(b"ext4\0");

        let img = image(&b);
        let linux = engine(&img, &isf);
        let result = linux
            .linux_mountinfo(&Options::default(), &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0],
            vec![
                "4026531840",
                "22",
                "22",
                "8:1",
                "/",
                "/",
                "rw,nosuid,relatime",
                "shared:1",
                "ext4",
                "/dev/sda1",
                "rw",
            ]
        );

        let by_pid = linux
            .linux_mountinfo(
                &Options {
                    pids: vec![1, 2],
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(by_pid.columns.len(), 12);
        assert_eq!(by_pid.columns[1], "PID");
        assert_eq!(
            by_pid
                .rows
                .iter()
                .map(|row| row[1].as_str())
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
        assert!(
            by_pid
                .rows
                .iter()
                .all(|row| row.len() == by_pid.columns.len())
        );

        let compact = linux
            .linux_mountinfo(
                &Options {
                    pid: Some(2),
                    mount_format: true,
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert_eq!(
            compact.columns,
            ["MNT_NS_ID", "PID", "DEVNAME", "PATH", "FSTYPE", "MNT_OPTS"]
        );
        assert_eq!(
            compact.rows,
            [[
                "4026531840",
                "2",
                "/dev/sda1",
                "/",
                "ext4",
                "rw,nosuid,relatime"
            ]]
        );

        let filtered = linux
            .linux_mountinfo(
                &Options {
                    mntns: Some(999),
                    ..Default::default()
                },
                &Job::default(),
            )
            .unwrap();
        assert!(filtered.rows.is_empty());
        assert_eq!(decode_mount_flags(0x80), "rw,nosymfollow");
        assert_eq!(decode_mount_flags(0x800), "rw");
    }
}
