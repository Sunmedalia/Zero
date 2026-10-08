//! Platform-neutral requests. Existing Linux APIs remain compatibility entry points.
pub use crate::linux::{Descriptor, Outcome, Plugin, Request, Session};
use crate::{Job, dump::DumpOptions};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    #[default]
    Auto,
    Linux,
    Windows,
}
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub os: Os,
    pub arch: crate::windows::Architecture,
    pub pid: Option<u32>,
    pub hive: Option<u64>,
    pub key: String,
    pub pagefiles: Vec<crate::windows::paging::Attachment>,
    pub swapfile: Option<std::path::PathBuf>,
}
pub fn analyze(
    session: &mut Session,
    request: &Request<'_>,
    dump: Option<&DumpOptions>,
    options: &Options,
    job: &Job,
) -> Result<Outcome> {
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
    ensure!(
        options.pagefiles.is_empty() && options.swapfile.is_none(),
        "分页附件仅用于 Windows 镜像"
    );
    let outcome = session.analyze_with_dump(request, dump, job)?;
    Ok(match outcome {
        Outcome::Ready(mut r) => {
            if let Some(pid) = options.pid {
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
