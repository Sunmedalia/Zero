//! Offline kernel validation reports, independent of plugin results and caches.
use crate::{Job, analysis::Os, linux::Session, store, symbols};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

fn hex_address<S: serde::Serializer>(
    value: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{value:#x}"))
}
fn optional_hex_address<S: serde::Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(&format!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Segment {
    #[serde(serialize_with = "hex_address")]
    pub start: u64,
    #[serde(serialize_with = "hex_address")]
    pub end_exclusive: u64,
    #[serde(serialize_with = "hex_address")]
    pub file_offset: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub symbol: String,
    pub sha256: String,
    pub passed: bool,
    #[serde(serialize_with = "optional_hex_address")]
    pub page_table: Option<u64>,
    #[serde(serialize_with = "optional_hex_address")]
    pub relocation_or_kernel_base: Option<u64>,
    pub evidence: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub engine_version: String,
    pub created_unix_ms: u128,
    pub image: PathBuf,
    pub symbol_source: PathBuf,
    pub symbol_choice: Option<String>,
    pub system: String,
    pub image_format: Option<String>,
    pub image_sha256: Option<String>,
    pub segments: Vec<Segment>,
    pub identities: Vec<String>,
    pub stages: Vec<String>,
    pub candidates: Vec<Candidate>,
    pub failure: Option<String>,
    pub previous_analysis_error: Option<String>,
    pub elapsed_seconds: f64,
}
pub struct Request<'a> {
    pub image: &'a Path,
    pub symbols: &'a Path,
    pub cache: &'a Path,
    pub choice: Option<&'a str>,
    pub os: Os,
    pub previous_error: Option<String>,
}

// A scan hit may be source code or a cached document, not linux_banner.
// This is a report filter only; discovery still checks the original bytes.
fn linux_banner_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes)
        .ok()?
        .trim_end_matches(['\0', '\n']);
    if text.len() > 1024
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, '\'' | '"' | '`' | '{' | '}' | ';'))
    {
        return None;
    }
    let rest = text.strip_prefix("Linux version ")?;
    let (release, build) = rest.split_once(' ')?;
    let mut version = release.split('.');
    for _ in 0..2 {
        let part = version.next()?;
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    if !release
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b".-_+".contains(&c))
    {
        return None;
    }
    if !build.starts_with('(')
        || !build.split_whitespace().any(|word| {
            word.strip_prefix('#')
                .is_some_and(|s| s.starts_with(|c: char| c.is_ascii_digit()))
        })
    {
        return None;
    }
    let mut depth = 0usize;
    for c in build.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.checked_sub(1)?,
            _ => (),
        }
    }
    (depth == 0).then_some(text)
}
impl Report {
    pub fn passed(&self) -> usize {
        self.candidates.iter().filter(|c| c.passed).count()
    }
    pub fn summary(&self) -> String {
        if self.failure.is_some() {
            "诊断未完成；查看失败阶段".into()
        } else {
            format!(
                "{} / {} 个符号候选通过内核校验",
                self.passed(),
                self.candidates.len()
            )
        }
    }
    pub fn text(&self) -> String {
        let mut out = format!(
            "内核诊断报告 · {}\n{}\n\n镜像: {}\n符号来源: {}\n系统: {}\n格式: {}\nSHA256: {}\n耗时: {:.1} s\n\n准备阶段\n{}\n\n内核身份候选（需结合页表校验）\n{}\n\n物理区段（结束地址不包含在内）\n",
            self.engine_version,
            self.summary(),
            self.image.display(),
            self.symbol_source.display(),
            self.system,
            self.image_format.as_deref().unwrap_or("未识别"),
            self.image_sha256.as_deref().unwrap_or("未完成校验"),
            self.elapsed_seconds,
            self.stages.join("\n"),
            self.identities.join("\n")
        );
        for s in &self.segments {
            out.push_str(&format!(
                "{:#x}–{:#x} · 文件偏移 {:#x}\n",
                s.start, s.end_exclusive, s.file_offset
            ));
        }
        for (i, c) in self.candidates.iter().enumerate() {
            out.push_str(&format!(
                "\n符号候选 {} · {}\n{}\nSHA256: {}\n",
                i + 1,
                if c.passed { "通过" } else { "未通过" },
                c.symbol,
                c.sha256
            ));
            if let Some(root) = c.page_table {
                out.push_str(&format!("页表 DTB: {root:#x}\n"));
            }
            if let Some(value) = c.relocation_or_kernel_base {
                out.push_str(&format!("重定位／内核基址: {value:#x}\n"));
            }
            out.push_str(&c.evidence.replace("; ", "\n").replace(", ", "\n"));
            out.push('\n');
        }
        if let Some(error) = &self.failure {
            out.push_str(&format!("\n未完成原因\n{error}\n"));
        }
        if let Some(error) = &self.previous_analysis_error {
            out.push_str(&format!("\n此前分析错误（供对照）\n{error}\n"));
        }
        if self.passed() == 0 {
            out.push_str("\n下一步：核对精确符号、报告中的读取错误及链表回指；保留原始镜像，尚不能仅据此判断内核版本不受支持。\n");
        }
        let mut safe = String::with_capacity(out.len());
        for c in out.chars() {
            if c.is_control() && c != '\n' {
                safe.extend(c.escape_default());
            } else {
                safe.push(c);
            }
        }
        safe
    }
    pub fn export(&self, path: &Path, job: &Job) -> Result<()> {
        job.check()?;
        let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        for source in std::iter::once(self.image.as_path())
            .chain(std::iter::once(self.symbol_source.as_path()))
            .chain(
                self.candidates
                    .iter()
                    .map(|c| Path::new(c.symbol.split("::").next().unwrap_or(&c.symbol))),
            )
        {
            let source = source
                .canonicalize()
                .unwrap_or_else(|_| source.to_path_buf());
            ensure!(target != source, "诊断报告不能覆盖镜像或符号文件");
        }
        let bytes = match path.extension().and_then(|s| s.to_str()) {
            Some("json") => serde_json::to_vec_pretty(self)?,
            Some("txt") => self.text().into_bytes(),
            _ => anyhow::bail!("诊断报告格式应为 .json 或 .txt"),
        };
        job.check()?;
        store::atomic_write(path, &bytes)
    }
}
pub fn run(session: &mut Session, request: Request<'_>, job: &Job) -> Result<Report> {
    let started = Instant::now();
    let mut report = Report {
        schema_version: 1,
        engine_version: crate::ENGINE_VERSION.into(),
        created_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        image: request.image.into(),
        symbol_source: request.symbols.into(),
        symbol_choice: request.choice.map(str::to_owned),
        system: "未识别".into(),
        image_format: None,
        image_sha256: None,
        segments: vec![],
        identities: vec![],
        stages: vec![],
        candidates: vec![],
        failure: None,
        previous_analysis_error: request.previous_error,
        elapsed_seconds: 0.0,
    };
    let check = (|| -> Result<()> {
        job.report("内核诊断：校验并读取镜像");
        let image = session
            .prepare_image(request.image, request.cache, job)
            .context("镜像读取／校验失败")?;
        report.image_format = Some(image.format.into());
        report.image_sha256 = Some(image.digest.clone());
        report.segments = image
            .segments
            .iter()
            .map(|s| Segment {
                start: s.start,
                end_exclusive: s.end,
                file_offset: s.file_offset,
            })
            .collect();
        report
            .stages
            .push("通过 · 镜像格式、物理区段及 SHA256".into());
        let banners = image.banners(job)?;
        let windows = match request.os {
            Os::Linux => false,
            Os::Windows => true,
            Os::Auto => {
                image.windows_container.is_some()
                    || (banners.is_empty() && !image.windows_candidates(job)?.is_empty())
            }
        };
        report.system = if windows { "Windows" } else { "Linux" }.into();
        report.identities = if windows {
            image
                .windows_candidates(job)?
                .iter()
                .map(|c| format!("{:#x}: Windows PDB {}", c.offset, c.pdb.key()))
                .collect()
        } else {
            banners
                .iter()
                .filter_map(|(at, b)| linux_banner_text(b).map(|text| format!("{at:#x}: {text}")))
                .collect()
        };
        ensure!(
            if windows {
                !report.identities.is_empty()
            } else {
                !banners.is_empty()
            },
            "系统识别失败：镜像中没有所选系统的内核身份"
        );
        if windows {
            report.stages.push("通过 · 内核身份识别".into());
        } else {
            report.stages.push(format!(
                "banner 扫描 · 保留 {} 个格式完整候选，过滤 {} 个噪声命中（不影响符号匹配及页表校验）",
                report.identities.len(), banners.len() - report.identities.len()
            ));
        }
        job.report("内核诊断：匹配本地精确符号（离线）");
        let mut candidates = if windows {
            crate::windows_symbols::resolve(request.symbols, &image, request.cache, false, job)
        } else {
            symbols::resolve(request.symbols, &image, request.cache, false, job)
        }
        .context("本地符号匹配失败；请先导入或下载精确符号")?;
        if let Some(choice) = request.choice {
            candidates.retain(|c| c.label == choice);
        }
        ensure!(!candidates.is_empty(), "没有匹配当前选择的符号候选");
        report
            .stages
            .push(format!("通过 · {} 个本地精确符号候选", candidates.len()));
        for isf in candidates {
            job.check()?;
            job.report(format!("内核诊断：验证 {}", isf.label));
            let result = if windows {
                crate::windows::discover(&image, &isf, job)
            } else {
                crate::linux::discover(&image, &isf, job)
                    .map(|root| (root, isf.slide.load(Ordering::Relaxed)))
            };
            job.check()?;
            let mut candidate = Candidate {
                symbol: isf.label.clone(),
                sha256: isf.digest.clone(),
                passed: false,
                page_table: None,
                relocation_or_kernel_base: None,
                evidence: String::new(),
            };
            match result {
                Ok((root, value)) => {
                    candidate.passed = true;
                    candidate.page_table = Some(root);
                    candidate.relocation_or_kernel_base = Some(value);
                    candidate.evidence = "通过引擎的完整内核页表校验".into();
                }
                Err(error) => candidate.evidence = format!("{error:#}"),
            }
            report.candidates.push(candidate);
        }
        Ok(())
    })();
    job.check()?;
    if let Err(error) = check {
        report.failure = Some(format!("{error:#}"));
    }
    report.elapsed_seconds = started.elapsed().as_secs_f64();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::linux_banner_text;

    #[test]
    fn report_filters_source_code_and_partial_hits_but_keeps_complete_banners() {
        let banner = "Linux version 6.12.105+deb13-amd64 (debian-kernel@lists.debian.org) (x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) #1 SMP PREEMPT_DYNAMIC Debian 6.12.105-1 (2026-08-24)";
        assert_eq!(
            linux_banner_text(format!("{banner}\n\0").as_bytes()),
            Some(banner)
        );
        for noise in [
            format!("{banner}',\n  path: 'releases/download/test.json.xz';"),
            format!("{banner}4)"),
            banner.replace("#1", "#"),
            "Linux version ".into(),
            "Linux version ')) { return []; }".into(),
            "Linux version 5.15.0-${index}-generic`".into(),
            "Linux version 3.2 Debian', path: 'Debian/test.json.xz'".into(),
            "Linux version 6.8.11-arm646.8.11-1kali2symbol_sizes".into(),
            format!("{banner}\nconst SAVED = 1"),
            format!("{banner}{}", "x".repeat(1024)),
        ] {
            assert_eq!(linux_banner_text(noise.as_bytes()), None, "{noise}");
        }
    }
}
