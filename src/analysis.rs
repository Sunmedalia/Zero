//! Platform-neutral requests. Existing Linux APIs remain compatibility entry points.
use crate::bytes::Row as _;
pub use crate::linux::{Descriptor, Outcome, Plugin, Request, Session};
use crate::{Job, dump::DumpOptions};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    #[default]
    Auto,
    Linux,
    Windows,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct KallsymsOptions {
    pub core: bool,
    pub modules: bool,
    pub ftrace: bool,
    pub bpf: bool,
}
impl KallsymsOptions {
    pub fn any(self) -> bool {
        self.core || self.modules || self.ftrace || self.bpf
    }
    pub fn selected(self) -> [bool; 4] {
        if self.any() {
            [self.core, self.modules, self.ftrace, self.bpf]
        } else {
            [true; 4]
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PESource {
    Kernel,
    Processes,
}
#[derive(Clone, Debug, Default)]
pub struct PEQuery {
    pub source: Option<PESource>,
    pub module: Option<String>,
    pub names: Vec<String>,
    pub addresses: Vec<u64>,
}
impl PEQuery {
    pub fn any(&self) -> bool {
        self.source.is_some()
            || self.module.is_some()
            || !self.names.is_empty()
            || !self.addresses.is_empty()
    }
    pub fn validate(&self, plugin: Plugin) -> Result<()> {
        if plugin != Plugin::WinPESymbols {
            ensure!(
                !self.any(),
                "source/module/symbol-name/address 仅用于 windows.pe_symbols.PESymbols"
            );
            return Ok(());
        }
        self.source
            .context("PESymbols 需要 --source kernel|processes")?;
        let module = self
            .module
            .as_deref()
            .context("PESymbols 需要 --module 文件名")?;
        ensure!(
            !module.is_empty() && module.len() <= 1024 && !module.contains(['\\', '/', '\0']),
            "PESymbols module 必须是文件名"
        );
        ensure!(
            !self.names.is_empty() || !self.addresses.is_empty(),
            "PESymbols 需要 --symbol-name 或 --address"
        );
        ensure!(
            self.names.len() <= 4096 && self.addresses.len() <= 4096,
            "PESymbols 查询超过上限"
        );
        ensure!(
            self.names
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 4096 && !s.contains('\0')),
            "PESymbols 符号名无效"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub pe: PEQuery,
    pub os: Os,
    pub arch: crate::windows::Architecture,
    pub pid: Option<u32>,
    pub pids: Vec<u32>,
    pub maxsize: Option<i64>,
    pub unresolved: bool,
    pub include_threads: bool,
    pub decorate_comm: bool,
    pub plain_taints: bool,
    pub files_only: bool,
    pub netns: Option<u64>,
    pub vma_addresses: Vec<u64>,
    pub hexdump_size: Option<usize>,
    pub show_all_dirty_pages: bool,
    pub mntns: Option<u64>,
    pub mount_format: bool,
    pub file_types: Vec<String>,
    pub find: Option<String>,
    pub kallsyms: KallsymsOptions,
    pub hive: Option<u64>,
    pub key: String,
    /// Recursively walk subkeys in `windows.printkey`.
    pub recurse: bool,
    /// Byte pattern for vmayarascan / windows.vadyarascan.
    pub pattern: Option<String>,
    /// Local decimal-offset strings output consumed by windows.strings.Strings.
    pub strings_file: Option<std::path::PathBuf>,
    /// Signed lower bound for windows.truecrypt.Passphrase lengths.
    pub min_length: Option<i64>,
    pub pagefiles: Vec<crate::windows::paging::Attachment>,
    pub swapfile: Option<std::path::PathBuf>,
}
/// Scan plugins need a pattern and no other plugin accepts one.
pub fn validate_pattern(plugin: crate::linux::Plugin, options: &Options) -> Result<()> {
    if plugin.is_regex_scan() {
        let text = options
            .pattern
            .as_deref()
            .context("此插件需要 --pattern 字节正则")?;
        crate::byte_regex::ByteRegex::compile(text, true)?;
        crate::byte_regex::ByteRegex::compile(text, false)?;
    } else if plugin.is_pattern_scan() {
        let text = options.pattern.as_deref().context("此插件需要 --pattern")?;
        crate::pattern::Pattern::parse(text)?;
    } else {
        ensure!(
            options.pattern.is_none(),
            "--pattern 仅用于字节模式或正则扫描插件"
        );
    }
    Ok(())
}
pub fn analyze(
    session: &mut Session,
    request: &Request<'_>,
    dump: Option<&DumpOptions>,
    options: &Options,
    job: &Job,
) -> Result<Outcome> {
    options.pe.validate(request.plugin)?;
    ensure!(
        options.min_length.is_none() || request.plugin == Plugin::WinTruecryptPassphrase,
        "min-length 仅用于 windows.truecrypt.Passphrase"
    );
    ensure!(
        options.pid.is_none()
            || !matches!(
                request.plugin,
                Plugin::WinDirectSystemCalls
                    | Plugin::WinIndirectSystemCalls
                    | Plugin::WinSkeletonKeyCheck
                    | Plugin::WinTruecryptPassphrase
            ),
        "此检测插件按参考自行选择进程，不接受 PID 筛选"
    );
    ensure!(
        options.strings_file.is_some() == (request.plugin == Plugin::WinStrings),
        "windows.strings.Strings 需要 strings-file；其他插件不接受该参数"
    );
    validate_pattern(request.plugin, options)?;
    ensure!(options.pids.len() <= 4096, "PID 列表超过 4096 项");
    ensure!(
        options.pids.is_empty() || request.plugin.accepts_pid_list(),
        "此插件不支持 PID 列表"
    );
    ensure!(
        options.maxsize.is_none()
            || request.plugin.is_regex_scan()
            || matches!(request.plugin, Plugin::LinuxMaps | Plugin::LinuxMalfind),
        "maxsize 仅用于 VmaRegExScan / VadRegExScan / linux.proc.Maps / linux.malware.malfind.Malfind"
    );
    ensure!(
        !matches!(request.plugin, Plugin::LinuxMaps | Plugin::LinuxMalfind)
            || options.maxsize.is_none_or(|v| v > 0),
        "linux.proc.Maps / linux.malware.malfind.Malfind 的 maxsize 必须大于 0"
    );
    ensure!(
        !options.unresolved || request.plugin == Plugin::PsCallStack,
        "unresolved 仅用于 PsCallStack"
    );

    ensure!(
        !(options.include_threads || options.decorate_comm)
            || matches!(request.plugin, Plugin::LinuxPslist | Plugin::LinuxPstree),
        "threads/decorate_comm 当前仅支持 linux.pslist.PsList / linux.pstree.PsTree"
    );
    ensure!(
        !options.files_only || request.plugin == Plugin::LinuxLsof,
        "files_only 仅支持 linux.lsof.Lsof"
    );
    ensure!(
        options.netns.is_none() || request.plugin == Plugin::LinuxSockstat,
        "netns 仅支持 linux.sockstat.Sockstat"
    );
    ensure!(
        options.vma_addresses.len() <= 4096,
        "VMA 地址列表超过 4096 项"
    );
    ensure!(
        options.vma_addresses.is_empty() || request.plugin == Plugin::LinuxMaps,
        "vma_addresses 仅支持 linux.proc.Maps"
    );
    ensure!(
        (options.hexdump_size.is_none() && !options.show_all_dirty_pages)
            || request.plugin == Plugin::LinuxMalfind,
        "hexdump_size / show_all_dirty_pages 仅支持 linux.malware.malfind.Malfind"
    );
    ensure!(
        options.hexdump_size.is_none_or(|v| v <= 4096),
        "hexdump_size 超过 4096 字节上限"
    );
    ensure!(
        (options.mntns.is_none() && !options.mount_format)
            || request.plugin == Plugin::LinuxMountinfo,
        "mntns / mount_format 仅支持 linux.mountinfo.MountInfo"
    );
    ensure!(
        options.file_types.is_empty()
            || matches!(
                request.plugin,
                Plugin::LinuxPagecacheFiles | Plugin::LinuxPagecacheRecoverFs
            ),
        "file_types 仅支持 linux.pagecache.Files / linux.pagecache.RecoverFs"
    );
    ensure!(
        options.find.is_none()
            || matches!(
                request.plugin,
                Plugin::LinuxPagecacheFiles
                    | Plugin::LinuxPagecacheInodePages
                    | Plugin::LinuxPagecacheRecoverFs
            ),
        "find 仅支持 linux.pagecache.Files / InodePages / RecoverFs"
    );
    ensure!(
        !options.plain_taints || request.plugin == Plugin::Modxview,
        "plain_taints 仅支持 linux.malware.modxview.Modxview"
    );
    ensure!(
        !options.kallsyms.any() || request.plugin == Plugin::Kallsyms,
        "core/modules/ftrace/bpf 参数仅支持 linux.kallsyms.Kallsyms"
    );
    ensure!(
        !options.recurse || request.plugin == Plugin::WinPrintkey,
        "recurse 仅支持 windows.printkey"
    );
    if let Some(dump) = dump {
        dump.validate(request.plugin)?;
    } else {
        ensure!(!request.plugin.is_dump(), "Dump 插件需要转储参数");
    }
    let image = if request.plugin == crate::linux::Plugin::Banners && request.use_cache {
        session.identify_image(request.image, request.cache, job)?
    } else {
        session.prepare_image(request.image, request.cache, job)?
    };
    let linux = !image.banners(job)?.is_empty();
    let windows = image.windows_container.is_some()
        || request.plugin.is_windows()
        || options.os == Os::Windows
        || (!linux && !image.windows_candidates(job)?.is_empty());
    ensure!(
        options.os != Os::Linux || !windows,
        "指定 Linux 与 Windows 镜像/插件不一致"
    );
    ensure!(
        options.os != Os::Windows || windows,
        "指定 Windows 与镜像不一致"
    );
    if windows {
        ensure!(
            !linux || options.os == Os::Windows,
            "镜像同时包含 Linux 与 Windows 身份；使用 --os 明确选择"
        );
        let mapped = if !request.plugin.is_windows() && request.plugin.is_dump() {
            use crate::linux::Plugin;
            let plugin = match request.plugin {
                Plugin::Procdump => Plugin::WinProcdump,
                Plugin::Memdump => Plugin::WinMemdump,
                _ => anyhow::bail!("Windows 转储使用 process/range/pe 模式"),
            };
            Some(Request { plugin, ..*request })
        } else {
            None
        };
        let request = mapped.as_ref().unwrap_or(request);
        ensure!(
            request.plugin.is_windows(),
            "Windows 镜像请使用 windows.* 插件"
        );
        return session.analyze_windows(&image, request, dump, options, job);
    }
    ensure!(
        !request.plugin.is_windows(),
        "Windows 插件不能分析 Linux 镜像"
    );
    ensure!(
        options.hive.is_none() && options.key.is_empty(),
        "hive/key 参数仅用于 windows.printkey"
    );
    let pattern = options
        .pattern
        .as_deref()
        .filter(|_| !request.plugin.is_regex_scan())
        .map(crate::pattern::Pattern::parse)
        .transpose()?;
    ensure!(
        options.pagefiles.is_empty() && options.swapfile.is_none(),
        "分页附件仅用于 Windows 镜像"
    );
    let outcome = session.analyze_linux_options(request, dump, pattern.as_ref(), options, job)?;
    Ok(match outcome {
        Outcome::Ready(mut r) => {
            if let Some(pid) = options.pid
                && !request.plugin.accepts_pid_list()
            {
                let col = r
                    .columns
                    .iter()
                    .position(|c| c == "PID")
                    .ok_or_else(|| anyhow::anyhow!("此插件不支持 PID 筛选"))?;
                let pid = pid.to_string();
                r.rows.retain(|row| row.cell(col) == pid);
            }
            Outcome::Ready(r)
        }
        other => other,
    })
}

pub fn plugins(os: Os) -> impl Iterator<Item = &'static Descriptor> {
    crate::linux::PLUGINS.iter().filter(move |d| match os {
        Os::Auto => true,
        Os::Linux => !d.plugin.is_windows(),
        Os::Windows => d.plugin.is_windows(),
    })
}

#[cfg(test)]
mod pe_query_tests {
    use super::*;
    #[test]
    fn strings_file_is_required_and_rejected_for_other_plugins_before_image_io() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.raw");
        let mut request = Request {
            image: &missing,
            symbols: dir.path(),
            choice: None,
            plugin: Plugin::WinStrings,
            cache: dir.path(),
            use_cache: false,
            network: false,
        };
        let mut session = Session::default();
        let error = analyze(
            &mut session,
            &request,
            None,
            &Options::default(),
            &crate::Job::default(),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("strings-file"));
        request.plugin = Plugin::WinPslist;
        let options = Options {
            strings_file: Some(dir.path().join("input.txt")),
            ..Default::default()
        };
        let error = analyze(
            &mut session,
            &request,
            None,
            &options,
            &crate::Job::default(),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("其他插件"));
    }
    #[test]
    fn validates_required_parameters_and_rejects_cross_plugin_options() {
        let mut query = PEQuery::default();
        assert!(query.validate(Plugin::WinPESymbols).is_err());
        assert!(query.validate(Plugin::WinPslist).is_ok());
        query.source = Some(PESource::Processes);
        query.module = Some("ntdll.dll".into());
        query.names = vec!["NtClose".into()];
        assert!(query.validate(Plugin::WinPESymbols).is_ok());
        assert!(query.validate(Plugin::WinPslist).is_err());
        query.module = Some("C:\\Windows\\ntdll.dll".into());
        assert!(query.validate(Plugin::WinPESymbols).is_err());
        query.module = Some("ntdll.dll".into());
        query.names = vec!["bad\0name".into()];
        assert!(query.validate(Plugin::WinPESymbols).is_err());
        query.names.clear();
        query.addresses = vec![u64::MAX];
        assert!(query.validate(Plugin::WinPESymbols).is_ok());
        query.addresses.resize(4097, 0);
        assert!(query.validate(Plugin::WinPESymbols).is_err());
    }
}
