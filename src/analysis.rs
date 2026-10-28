//! Platform-neutral requests. Existing Linux APIs remain compatibility entry points.
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
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub os: Os,
    pub arch: crate::windows::Architecture,
    pub pid: Option<u32>,
    pub pids: Vec<u32>,
    pub maxsize: Option<usize>,
    pub include_threads: bool,
    pub decorate_comm: bool,
    pub plain_taints: bool,
    pub kallsyms: KallsymsOptions,
    pub hive: Option<u64>,
    pub key: String,
    /// Byte pattern for vmayarascan / windows.vadyarascan.
    pub pattern: Option<String>,
    pub pagefiles: Vec<crate::windows::paging::Attachment>,
    pub swapfile: Option<std::path::PathBuf>,
}
/// Scan plugins need a pattern and no other plugin accepts one.
pub fn validate_pattern(plugin: crate::linux::Plugin, options: &Options) -> Result<()> {
    if plugin == Plugin::VmaRegExScan {
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
    validate_pattern(request.plugin, options)?;
    ensure!(options.pids.len() <= 4096, "PID 列表超过 4096 项");
    ensure!(
        (options.pids.is_empty() && options.maxsize.is_none())
            || request.plugin == Plugin::VmaRegExScan,
        "pids/maxsize 当前仅用于 linux.vmaregexscan.VmaRegExScan"
    );
    if let Some(size) = options.maxsize {
        ensure!((1..=4096).contains(&size), "maxsize 必须为 1..4096");
    }

    ensure!(
        !(options.include_threads || options.decorate_comm)
            || request.plugin == Plugin::LinuxPslist,
        "threads/decorate_comm 当前仅支持 linux.pslist.PsList"
    );
    ensure!(
        !options.plain_taints || request.plugin == Plugin::Modxview,
        "plain_taints 仅支持 linux.malware.modxview.Modxview"
    );
    ensure!(
        !options.kallsyms.any() || request.plugin == Plugin::Kallsyms,
        "core/modules/ftrace/bpf 参数仅支持 linux.kallsyms.Kallsyms"
    );
    if request.plugin.is_dump() {
        dump.context("Dump 插件需要转储参数")?
            .validate(request.plugin)?;
    } else {
        ensure!(dump.is_none(), "非 Dump 插件不接受转储参数");
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
        .filter(|_| request.plugin != Plugin::VmaRegExScan)
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
                && request.plugin != Plugin::VmaRegExScan
            {
                let col = r
                    .columns
                    .iter()
                    .position(|c| c == "PID")
                    .ok_or_else(|| anyhow::anyhow!("此插件不支持 PID 筛选"))?;
                r.rows.retain(|row| row[col] == pid.to_string());
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
