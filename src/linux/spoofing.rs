//! Compare independently captured process identity sources (Volatility ProcessSpoofing).
use super::*;

// PurePosixPath.name semantics: ignore trailing separators and dot components.
fn basename(path: &str) -> Option<&str> {
    path.rsplit('/').find(|s| !s.is_empty() && *s != ".")
}
fn mismatch(executable: Option<&str>, argv: Option<&str>, comm: &str) -> (bool, bool) {
    let Some(executable) = executable else {
        return (false, false);
    };
    (
        argv.is_some_and(|argv| argv != executable),
        !comm.is_empty() && executable.chars().take(15).collect::<String>() != comm,
    )
}
impl Linux<'_> {
    pub(super) fn process_spoofing(&self, job: &Job) -> Result<Results> {
        let (mut result, tasks) = self.tasks(Plugin::ProcessSpoofing, job)?;
        for task in tasks {
            job.check()?;
            let parent = (|| -> Result<String> {
                let parent = self.number(task.address, "task_struct", "real_parent")?;
                Ok(self.number(parent, "task_struct", "tgid")?.to_string())
            })();
            let ppid = match parent {
                Ok(parent) => parent,
                Err(error) => {
                    partial(&mut result, format!("PID {} parent", task.pid), error);
                    String::new()
                }
            };
            let mm = match self.number(task.address, "task_struct", "mm") {
                Ok(mm) => mm,
                Err(error) => {
                    partial(&mut result, format!("PID {} mm", task.pid), error);
                    // Preserve the task; unavailable identity sources must not imply absence.
                    result.rows.push(vec![
                        task.pid,
                        ppid,
                        "N/A".into(),
                        "N/A".into(),
                        task.name,
                        "false".into(),
                        "false".into(),
                        "false".into(),
                    ]);
                    continue;
                }
            };
            let exe = if mm == 0 {
                None
            } else {
                let read = (|| -> Result<Option<String>> {
                    let file = self.number(mm, "mm_struct", "exe_file")?;
                    if file == 0 {
                        return Ok(None);
                    }
                    let dentry = self.number(file, "file", "f_path.dentry")?;
                    let mut path = match self.file_path(task.address, file, job) {
                        Ok(path) => path,
                        Err(error) if error.to_string().starts_with("路径不在进程根目录内") =>
                        {
                            // An executable can lie outside a chroot entered after exec.
                            // The reference walks to the global root in this case.
                            let mount = self.number(file, "file", "f_path.mnt")?;
                            self.resolve_path(dentry, mount, None, job)?
                        }
                        Err(error) => return Err(error),
                    };
                    let inode = self.number(dentry, "dentry", "d_inode")?;
                    if inode != 0 && self.number(inode, "inode", "i_nlink")? == 0 {
                        // Preserve the reference's leading space on deleted paths.
                        path = format!(" {path} (deleted)");
                    }
                    Ok(Some(path))
                })();
                match read {
                    Ok(path) => path,
                    Err(error) => {
                        job.check()?;
                        partial(&mut result, format!("PID {} exe", task.pid), error);
                        None
                    }
                }
            };
            let argv = if mm == 0 {
                None
            } else {
                let read = (|| -> Result<Option<String>> {
                    let start = self.number(mm, "mm_struct", "arg_start")?;
                    let end = self.number(mm, "mm_struct", "arg_end")?;
                    let length = end
                        .checked_sub(start)
                        .context("argv 地址倒置")?
                        .min(32 * 4096);
                    if length == 0 {
                        return Ok(None);
                    }
                    let vm = self.process_vm(task.address)?.context("用户地址空间为空")?;
                    let mut bytes = vec![0; length as usize];
                    for (index, chunk) in bytes.chunks_mut(4096).enumerate() {
                        job.check()?;
                        vm.read(
                            start
                                .checked_add(index as u64 * 4096)
                                .context("argv 地址溢出")?,
                            chunk,
                        )?;
                    }
                    let end = bytes
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(bytes.len());
                    let text = String::from_utf8_lossy(&bytes[..end]);
                    Ok(basename(&text).map(str::to_owned))
                })();
                match read {
                    Ok(argv) => argv,
                    Err(error) => {
                        job.check()?;
                        partial(&mut result, format!("PID {} argv[0]", task.pid), error);
                        None
                    }
                }
            };
            let deleted = exe
                .as_deref()
                .is_some_and(|path| path.ends_with(" (deleted)"));
            let exe_name = exe
                .as_deref()
                .and_then(basename)
                .map(|name| name.strip_suffix(" (deleted)").unwrap_or(name));
            let (argv_spoofed, comm_spoofed) = mismatch(exe_name, argv.as_deref(), &task.name);
            result.rows.push(vec![
                task.pid,
                ppid,
                exe.unwrap_or_else(|| "N/A".into()),
                argv.unwrap_or_else(|| "N/A".into()),
                if task.name.is_empty() {
                    "N/A".into()
                } else {
                    task.name
                },
                argv_spoofed.to_string(),
                comm_spoofed.to_string(),
                deleted.to_string(),
            ]);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_follow_reference_truncation_and_posix_rules() {
        assert_eq!(basename("/usr/bin/tool/./"), Some("tool"));
        assert_eq!(basename("/"), None);
        assert_eq!(
            mismatch(
                Some("long-process-name"),
                Some("long-process-name"),
                "long-process-na"
            ),
            (false, false)
        );
        assert_eq!(
            mismatch(Some("long-process-name"), Some("forged"), "long-process-na"),
            (true, false)
        );
        assert_eq!(
            mismatch(Some("long-process-name"), None, "long-process-na"),
            (false, false)
        );
        assert_eq!(mismatch(None, Some("forged"), "other"), (false, false));
        assert_eq!(
            mismatch(Some("actual"), Some("forged"), "other"),
            (true, true)
        );
        assert_eq!(
            mismatch(
                Some("123456789012345678"),
                Some("123456789012345678"),
                "123456789012345"
            ),
            (false, false)
        );
    }
    #[test]
    fn independent_sources_deleted_files_and_bounded_nonterminated_argv() {
        use serde_json::json;
        let (mut bytes, mut isf) = crate::linux::tests::fixture();
        crate::linux::tests::path_fixture(&mut bytes);
        isf.data["user_types"]["mm_struct"]["fields"]["exe_file"] =
            json!({"offset":64,"type":{"kind":"pointer"}});
        isf.data["user_types"]["inode"]["fields"]["i_nlink"] =
            json!({"offset":16,"type":{"kind":"base","name":"u64"}});
        bytes[0xb040..0xb048].copy_from_slice(&0xc600u64.to_le_bytes());
        bytes[0xca10..0xca18].copy_from_slice(&1u64.to_le_bytes());
        // A non-NUL-terminated argv bounded by arg_end is accepted by the reference.
        bytes[0xb008..0xb010].copy_from_slice(&0x201000u64.to_le_bytes());
        bytes[0xb010..0xb018].copy_from_slice(&0x201004u64.to_le_bytes());
        bytes[0x25000..0x25004].copy_from_slice(b"file");
        bytes[0xa028..0xa030].copy_from_slice(b"file\0\0\0\0");
        let image = crate::linux::tests::image(&bytes);
        let result = crate::linux::tests::engine(&image, &isf)
            .run(Plugin::ProcessSpoofing, &Job::default())
            .unwrap();
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(
            result.rows[0],
            [
                "1",
                "0",
                "/mnt/file",
                "file",
                "file",
                "false",
                "false",
                "false"
            ]
        );
        drop(image);
        bytes[0xca10..0xca18].fill(0);
        let image = crate::linux::tests::image(&bytes);
        let result = crate::linux::tests::engine(&image, &isf)
            .run(Plugin::ProcessSpoofing, &Job::default())
            .unwrap();
        assert_eq!(result.rows[0][2], " /mnt/file (deleted)");
        assert_eq!(&result.rows[0][5..], ["false", "false", "true"]);
    }
    #[test]
    fn unreadable_identity_preserves_task_and_cancellation() {
        let (bytes, isf) = crate::linux::tests::fixture();
        let image = crate::linux::tests::image(&bytes);
        let linux = crate::linux::tests::engine(&image, &isf);
        let job = Job::default();
        let result = linux.run(Plugin::ProcessSpoofing, &job).unwrap();
        assert_eq!(result.rows.len(), 2);
        assert!(!result.complete);
        assert_eq!(result.rows[0][2], "N/A");
        assert_eq!(result.rows[1][2], "N/A"); // kernel thread is an expected absent source
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(linux.run(Plugin::ProcessSpoofing, &job).is_err());
    }
}
