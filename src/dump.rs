//! Targeted, atomic exports of bytes from a process address space.
use crate::{
    Job,
    image::VirtualMemory,
    linux::{Linux, Plugin},
    store::Results,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub enum Mode {
    Process,
    Range,
    Elf,
}
impl Mode {
    pub fn plugin(self) -> Plugin {
        match self {
            Self::Process => Plugin::Procdump,
            Self::Range => Plugin::Memdump,
            Self::Elf => Plugin::Elfdump,
        }
    }
}
pub const MAX_DUMP_BYTES: u64 = 256 * 1024 * 1024;
#[derive(Clone, Debug)]
pub struct DumpOptions {
    pub pid: u32,
    pub directory: PathBuf,
    pub start: Option<u64>,
    pub end: Option<u64>,
}
pub fn parse_address(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    }
    .map_err(|_| format!("无效地址 {text}；使用十进制或 0x 十六进制"))
}
impl DumpOptions {
    pub fn validate(&self, plugin: Plugin) -> Result<()> {
        ensure!(plugin.is_dump(), "非 Dump 插件");
        ensure!(self.pid > 0, "必须指定非零 PID");
        ensure!(!self.directory.as_os_str().is_empty(), "必须指定转储目录");
        match (self.start, self.end) {
            (Some(start), Some(end)) => {
                ensure!(start < end, "Start 必须小于 End（End 不包含在范围内）");
                ensure!(end - start <= MAX_DUMP_BYTES, "转储范围超过 256 MiB 上限");
            }
            (None, None) => ensure!(
                plugin != Plugin::Memdump,
                "memdump 必须指定 --start 和 --end"
            ),
            _ => anyhow::bail!("Start 和 End 必须同时填写"),
        }
        ensure!(
            plugin != Plugin::Elfdump || self.start.is_none(),
            "elfdump 不接受地址范围；使用 memdump 精确导出范围"
        );
        Ok(())
    }
}
fn directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "转储目录不能是符号链接或普通文件: {}",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(path)?,
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn write_region(
    vm: &VirtualMemory<'_>,
    start: u64,
    end: u64,
    target: &Path,
    job: &Job,
) -> Result<String> {
    let mut temp = tempfile::NamedTempFile::new_in(target.parent().context("输出文件缺少目录")?)?;
    let mut hash = Sha256::new();
    let size = end - start;
    let mut buffer = vec![0; (1024 * 1024).min(size as usize)];
    let mut offset = 0;
    while offset < size {
        job.check()?;
        let count = (size - offset).min(buffer.len() as u64) as usize;
        vm.read(start + offset, &mut buffer[..count])?;
        temp.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
        offset += count as u64;
        job.report(format!("dump {start:#x}: {offset}/{size} bytes"));
    }
    job.check()?;
    temp.as_file().sync_all()?;
    // Never overwrite a previous evidence file, including a symlink at the final target.
    temp.persist_noclobber(target).map_err(|e| e.error)?;
    Ok(format!("{:x}", hash.finalize()))
}
impl Linux<'_> {
    pub fn run_dump(&self, plugin: Plugin, options: &DumpOptions, job: &Job) -> Result<Results> {
        options.validate(plugin)?;
        job.check()?;
        let tasks = self.run(Plugin::Pslist, job)?;
        let pid = options.pid.to_string();
        let task = tasks
            .rows
            .iter()
            .find(|row| row[0] == pid)
            .with_context(|| format!("未找到 PID {pid}；请使用 pslist 确认"))?;
        let address = parse_address(&task[4]).map_err(anyhow::Error::msg)?;
        let vm = self
            .process_vm(address)?
            .context("目标为内核线程，没有用户地址空间")?;
        let mut result = self.inspect_result(plugin);
        // A damaged process list does not disappear merely because the target was found.
        result.complete = tasks.complete;
        result.diagnostics = tasks.diagnostics;
        let mut regions = Vec::new();
        if plugin == Plugin::Memdump {
            regions.push((options.start.unwrap(), options.end.unwrap()));
        } else {
            let mm = self.number(address, "task_struct", "mm")?;
            for node in self.vma_nodes(mm, job)? {
                job.check()?;
                let read = (|| -> Result<Option<(u64, u64)>> {
                    let start = self.number(node, "vm_area_struct", "vm_start")?;
                    let end = self.number(node, "vm_area_struct", "vm_end")?;
                    ensure!(start < end, "VMA 地址倒置");
                    if self.number(node, "vm_area_struct", "vm_flags")? & 1 == 0 {
                        return Ok(None);
                    }
                    if plugin == Plugin::Elfdump {
                        if end - start < 64 {
                            return Ok(None);
                        }
                        let mut head = [0; 64];
                        vm.read(start, &mut head)?;
                        if &head[..4] != b"\x7fELF" {
                            return Ok(None);
                        }
                        ensure!(
                            matches!(head[4], 1 | 2) && matches!(head[5], 1 | 2) && head[6] == 1,
                            "ELF 头无效"
                        );
                    }
                    let start = options.start.map_or(start, |lo| start.max(lo));
                    let end = options.end.map_or(end, |hi| end.min(hi));
                    Ok((start < end).then_some((start, end)))
                })();
                match read {
                    Ok(Some(region)) => regions.push(region),
                    Ok(None) => (),
                    Err(e) => {
                        result.complete = false;
                        result
                            .diagnostics
                            .push(format!("PID {pid} VMA {node:#018x}: {e:#}"));
                    }
                }
            }
        }
        ensure!(
            !regions.is_empty() || !result.complete,
            "目标范围没有可转储的映射"
        );
        let base = if options.directory.is_absolute() {
            options.directory.clone()
        } else {
            std::env::current_dir()?.join(&options.directory)
        };
        directory(&base)?;
        let run = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let output = base.join(format!(
            "{}-{}-{pid}-{run}",
            plugin.name(),
            self.vm.image.digest
        ));
        directory(&output)?;
        let mut total = 0;
        for (start, end) in regions {
            job.check()?;
            let size = end - start;
            if size > MAX_DUMP_BYTES - total {
                result.complete = false;
                result.diagnostics.push(format!(
                    "PID {pid} {start:#018x}: 达到 256 MiB 转储上限，未导出此映射"
                ));
                continue;
            }
            let target = output.join(format!("{start:016x}-{end:016x}.bin"));
            match write_region(&vm, start, end, &target, job) {
                Ok(hash) => {
                    total += size;
                    result.rows.push(vec![
                        pid.clone(),
                        task[3].clone(),
                        format!("{start:#018x}"),
                        format!("{end:#018x}"),
                        size.to_string(),
                        hash,
                        target.display().to_string(),
                    ]);
                }
                Err(e) => {
                    job.check()?;
                    result.complete = false;
                    result
                        .diagnostics
                        .push(format!("PID {pid} {start:#018x}..{end:#018x}: {e:#}"));
                }
            }
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_target_and_range_are_required() {
        let mut opts = DumpOptions {
            pid: 0,
            directory: "exports".into(),
            start: None,
            end: None,
        };
        assert!(opts.validate(Plugin::Procdump).is_err());
        opts.pid = 12;
        assert!(opts.validate(Plugin::Procdump).is_ok());
        assert!(opts.validate(Plugin::Memdump).is_err());
        opts.start = Some(0x1000);
        opts.end = Some(0x2000);
        assert!(opts.validate(Plugin::Memdump).is_ok());
        assert!(opts.validate(Plugin::Elfdump).is_err());
        opts.end = Some(0x1000);
        assert!(opts.validate(Plugin::Memdump).is_err());
        opts.end = Some(MAX_DUMP_BYTES + 0x1001);
        assert!(opts.validate(Plugin::Memdump).is_err());
        assert_eq!(parse_address("0X2000"), Ok(8192));
        assert_eq!(parse_address("8192"), Ok(8192));
        assert!(parse_address("all").is_err());
    }
    #[test]
    fn parameters_fail_before_image_access() {
        let tmp = tempfile::tempdir().unwrap();
        let error = crate::linux::Session::default()
            .analyze(
                &crate::linux::Request {
                    image: Path::new("missing-image"),
                    symbols: Path::new("missing-symbols"),
                    choice: None,
                    plugin: Plugin::Procdump,
                    cache: tmp.path(),
                    use_cache: true,
                    network: false,
                },
                &Job::new(|_| {}),
            )
            .err()
            .unwrap();
        assert!(error.to_string().contains("--pid"));
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }
}
