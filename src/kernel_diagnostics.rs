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
            "内核诊断报告 · {}\n{}\n\n镜像: {}\n符号来源: {}\n系统: {}\n格式: {}\nSHA256: {}\n耗时: {:.1} s\n\n准备阶段\n{}\n\n内核身份\n{}\n\n物理区段（结束地址不包含在内）\n",
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
                .map(|(at, b)| {
                    format!(
                        "{at:#x}: {}",
                        String::from_utf8_lossy(b).trim_end_matches(['\0', '\n'])
                    )
                })
                .collect()
        };
        ensure!(
            !report.identities.is_empty(),
            "系统识别失败：镜像中没有所选系统的内核身份"
        );
        report.stages.push("通过 · 内核身份识别".into());
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
