//! Bounded, cancellable YARA-X rule engine for physical and virtual memory scans.
//!
//! Supports full YARA rules (`.yar`/`.yara` files, directories of rule files, and
//! inline rule source via pure-Rust `yara-x`) as well as legacy literal byte
//! patterns (`text:`, `wide:`, `hex:`).
use crate::{
    Job,
    bytes::Checked as _,
    image::Image,
    pattern::{HIT_LIMIT, Pattern},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const PAGE_SIZE: usize = 4096;
const PAGE: u64 = PAGE_SIZE as u64;
const CHUNK: usize = 16 * 1024 * 1024;
const OVERLAP: usize = 4096;
const CONTEXT: usize = 32;
const MAX_RULE_FILES: usize = 1024;
const MAX_RULE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_RULE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RULE_DIR_DEPTH: usize = 16;
const CHUNK_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_MATCHES_PER_PATTERN: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraHit {
    pub address: u64,
    pub rule: String,
    pub component: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    HitLimit,
    ByteLimit,
    Timeout,
}
impl StopReason {
    pub fn diagnostic(self) -> String {
        match self {
            Self::HitLimit => format!("命中数达到 {HIT_LIMIT} 上限"),
            Self::ByteLimit => "扫描读取达到上限".into(),
            Self::Timeout => format!(
                "YARA 规则单块扫描超过 {} 秒超时上限",
                CHUNK_TIMEOUT.as_secs()
            ),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RegionScan {
    pub hits: Vec<YaraHit>,
    pub unreadable: u64,
    pub stop_reason: Option<StopReason>,
}

#[derive(Debug, Default, Serialize)]
pub struct PhysicalCoverage {
    pub scope: &'static str,
    pub captured_segments: usize,
    pub captured_bytes: u64,
    pub scanned_bytes: u64,
    pub gap_count: usize,
    pub gap_bytes: u64,
    pub read_failures: u64,
    pub first_read_failure: Option<String>,
    pub stop_reason: Option<String>,
    pub hits: usize,
}
impl PhysicalCoverage {
    pub fn complete(&self) -> bool {
        self.read_failures == 0
            && self.stop_reason.is_none()
            && self.scanned_bytes == self.captured_bytes
    }
}

#[derive(Debug)]
pub struct PhysicalScan {
    pub hits: Vec<YaraHit>,
    pub coverage: PhysicalCoverage,
}

#[derive(Clone)]
pub struct CompiledRules {
    rules: Arc<yara_x::Rules>,
    source: String,
    digest: String,
    file_count: usize,
}
impl std::fmt::Debug for CompiledRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRules")
            .field("source", &self.source)
            .field("digest", &self.digest)
            .field("file_count", &self.file_count)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub enum YaraSpec {
    Pattern(Pattern),
    Rules(CompiledRules),
}

impl YaraSpec {
    pub fn from_pattern(text: &str) -> Result<Self> {
        Ok(Self::Pattern(Pattern::parse(text)?))
    }

    pub fn from_rules_source(source: &str) -> Result<Self> {
        ensure!(!source.trim().is_empty(), "YARA 规则源码不能为空");
        ensure!(
            source.len() as u64 <= MAX_RULE_FILE_BYTES,
            "内联 YARA 规则超过 {} MiB 上限",
            MAX_RULE_FILE_BYTES >> 20
        );
        let mut compiler = yara_x::Compiler::new();
        compiler.relaxed_re_syntax(true);
        compiler.enable_includes(false);
        compiler
            .add_source(yara_x::SourceCode::from(source).with_origin("<inline>"))
            .map_err(|e| anyhow::anyhow!("YARA 规则编译失败: {e}"))?;
        let rules = compiler.build();
        let mut hasher = Sha256::new();
        hasher.update(b"inline\0");
        hasher.update(source.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        Ok(Self::Rules(CompiledRules {
            rules: Arc::new(rules),
            source: "inline".into(),
            digest,
            file_count: 1,
        }))
    }

    pub fn from_rules_path(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("无法读取 YARA 规则路径 {}", path.display()))?;
        let mut files = Vec::new();
        let include_dir = if metadata.is_dir() {
            collect_rule_files(path, 0, &mut files)?;
            files.sort();
            ensure!(
                !files.is_empty(),
                "YARA 规则目录 {} 中未找到 .yar / .yara 文件",
                path.display()
            );
            Some(path.to_path_buf())
        } else {
            ensure!(
                metadata.is_file(),
                "YARA 规则路径 {} 不是普通文件或目录",
                path.display()
            );
            files.push(path.to_path_buf());
            path.parent().map(Path::to_path_buf)
        };

        let mut compiler = yara_x::Compiler::new();
        compiler.relaxed_re_syntax(true);
        if let Some(dir) = include_dir {
            compiler.enable_includes(true);
            compiler.add_include_dir(dir);
        } else {
            compiler.enable_includes(false);
        }

        let mut total_bytes = 0u64;
        let mut hasher = Sha256::new();
        hasher.update(b"files\0");
        for file in &files {
            let meta = std::fs::metadata(file)
                .with_context(|| format!("无法读取 YARA 规则文件 {}", file.display()))?;
            ensure!(
                meta.len() <= MAX_RULE_FILE_BYTES,
                "YARA 规则文件 {} 超过 {} MiB 上限",
                file.display(),
                MAX_RULE_FILE_BYTES >> 20
            );
            total_bytes = total_bytes
                .checked_add(meta.len())
                .context("YARA 规则文件总大小溢出")?;
            ensure!(
                total_bytes <= MAX_TOTAL_RULE_BYTES,
                "YARA 规则总大小超过 {} MiB 上限",
                MAX_TOTAL_RULE_BYTES >> 20
            );
            let bytes = std::fs::read(file)
                .with_context(|| format!("读取 YARA 规则文件 {} 失败", file.display()))?;
            let origin = file.display().to_string();
            hasher.update(origin.as_bytes());
            hasher.update(b"\0");
            hasher.update(&bytes);
            hasher.update(b"\0");
            compiler
                .add_source(yara_x::SourceCode::from(bytes.as_slice()).with_origin(origin))
                .with_context(|| format!("YARA 规则文件 {} 编译失败", file.display()))?;
        }
        let rules = compiler.build();
        let digest = format!("{:x}", hasher.finalize());
        Ok(Self::Rules(CompiledRules {
            rules: Arc::new(rules),
            source: format!("file:{}", path.display()),
            digest,
            file_count: files.len(),
        }))
    }

    pub fn from_inputs(
        pattern: Option<&str>,
        yara_file: Option<&Path>,
        yara_rules: Option<&str>,
    ) -> Result<Self> {
        let count = usize::from(pattern.is_some())
            + usize::from(yara_file.is_some())
            + usize::from(yara_rules.is_some());
        ensure!(
            count == 1,
            "YARA 扫描插件必须且只能指定 --pattern、--yara-file 或 --yara-rules 之一"
        );
        if let Some(path) = yara_file {
            Self::from_rules_path(path)
        } else if let Some(source) = yara_rules {
            Self::from_rules_source(source)
        } else if let Some(text) = pattern {
            Self::from_pattern(text)
        } else {
            bail!("缺少 YARA 规则或字节模式")
        }
    }

    pub fn cache_identity(&self) -> String {
        match self {
            Self::Pattern(p) => format!("pattern:{}", p.source()),
            Self::Rules(r) => format!("yara:{}", r.digest),
        }
    }

    pub fn source_summary(&self) -> String {
        match self {
            Self::Pattern(p) => p.source().to_owned(),
            Self::Rules(r) => format!(
                "{} ({} files, sha256:{})",
                r.source,
                r.file_count,
                r.digest.get(..12).unwrap_or(&r.digest)
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_buffer(
        &self,
        buffer: &[u8],
        base: u64,
        accept_start_below: Option<usize>,
        limit: usize,
        job: &Job,
        seen: &mut HashSet<(u64, String, String)>,
        out: &mut Vec<YaraHit>,
    ) -> Result<Option<StopReason>> {
        job.check()?;
        if buffer.is_empty() {
            return Ok(None);
        }
        if out.len() >= limit {
            return Ok(Some(StopReason::HitLimit));
        }
        match self {
            Self::Pattern(pattern) => {
                for offset in pattern.find_all(buffer) {
                    if accept_start_below.is_some_and(|bound| offset >= bound) {
                        continue;
                    }
                    let address = base
                        .checked_add(offset as u64)
                        .context("模式命中地址溢出")?;
                    let rule = "pattern".to_owned();
                    let component = "$pattern".to_owned();
                    if !seen.insert((address, rule.clone(), component.clone())) {
                        continue;
                    }
                    if out.len() >= limit {
                        return Ok(Some(StopReason::HitLimit));
                    }
                    let stop = buffer.len().min(offset + CONTEXT);
                    out.push(YaraHit {
                        address,
                        rule,
                        component,
                        bytes: buffer.at(offset..stop)?.to_vec(),
                    });
                }
                Ok(None)
            }
            Self::Rules(compiled) => {
                let mut scanner = yara_x::Scanner::new(&compiled.rules);
                scanner.set_timeout(CHUNK_TIMEOUT);
                scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);
                let results = match scanner.scan(buffer) {
                    Ok(results) => results,
                    Err(yara_x::ScanError::Timeout) => return Ok(Some(StopReason::Timeout)),
                    Err(error) => return Err(anyhow::anyhow!("YARA 扫描失败: {error}")),
                };
                for matched_rule in results.matching_rules() {
                    job.check()?;
                    let rule_name = if matched_rule.namespace() == "default" {
                        matched_rule.identifier().to_owned()
                    } else {
                        format!("{}:{}", matched_rule.namespace(), matched_rule.identifier())
                    };
                    let mut emitted_pattern = false;
                    for pattern in matched_rule.patterns() {
                        let component = pattern.identifier().to_owned();
                        for m in pattern.matches() {
                            emitted_pattern = true;
                            let offset = m.range().start;
                            if accept_start_below.is_some_and(|bound| offset >= bound) {
                                continue;
                            }
                            let address = base
                                .checked_add(offset as u64)
                                .context("YARA 命中地址溢出")?;
                            if !seen.insert((address, rule_name.clone(), component.clone())) {
                                continue;
                            }
                            if out.len() >= limit {
                                return Ok(Some(StopReason::HitLimit));
                            }
                            let stop = buffer.len().min(offset + CONTEXT);
                            out.push(YaraHit {
                                address,
                                rule: rule_name.clone(),
                                component: component.clone(),
                                bytes: buffer.at(offset..stop)?.to_vec(),
                            });
                        }
                    }
                    if !emitted_pattern {
                        let component = "(condition)".to_owned();
                        if seen.insert((base, rule_name.clone(), component.clone())) {
                            if out.len() >= limit {
                                return Ok(Some(StopReason::HitLimit));
                            }
                            let stop = buffer.len().min(CONTEXT);
                            out.push(YaraHit {
                                address: base,
                                rule: rule_name,
                                component,
                                bytes: buffer.at(..stop)?.to_vec(),
                            });
                        }
                    }
                }
                Ok(None)
            }
        }
    }
}

fn collect_rule_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<()> {
    ensure!(
        depth <= MAX_RULE_DIR_DEPTH,
        "YARA 规则目录深度超过 {MAX_RULE_DIR_DEPTH} 层"
    );
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("无法读取目录 {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("遍历目录 {} 失败", dir.display()))?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("读取文件类型 {} 失败", path.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_rule_files(&path, depth + 1, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara")
                })
        {
            ensure!(
                out.len() < MAX_RULE_FILES,
                "YARA 规则文件数量超过 {MAX_RULE_FILES} 上限"
            );
            out.push(path);
        }
    }
    Ok(())
}

/// Scan a virtual address range `[start, end)` with `spec`.
pub fn scan_region(
    spec: &YaraSpec,
    start: u64,
    end: u64,
    budget: &mut u64,
    limit: usize,
    job: &Job,
    read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<RegionScan> {
    scan_region_sparse(spec, start, end, budget, limit, job, read, |_, _| None)
}

/// Like `scan_region`, with an optional `skip_absent(page, end)` callback for
/// sparse page-table skipping.
#[allow(clippy::too_many_arguments)]
pub fn scan_region_sparse(
    spec: &YaraSpec,
    start: u64,
    end: u64,
    budget: &mut u64,
    limit: usize,
    job: &Job,
    read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    skip_absent: impl FnMut(u64, u64) -> Option<u64>,
) -> Result<RegionScan> {
    match spec {
        YaraSpec::Pattern(pattern) => {
            let scan = crate::pattern::scan_region_sparse(
                pattern,
                start,
                end,
                budget,
                limit,
                job,
                read,
                skip_absent,
            )?;
            Ok(RegionScan {
                hits: scan
                    .hits
                    .into_iter()
                    .map(|(address, bytes)| YaraHit {
                        address,
                        rule: "pattern".into(),
                        component: "$pattern".into(),
                        bytes,
                    })
                    .collect(),
                unreadable: scan.unreadable,
                stop_reason: scan.stop_reason.map(|r| match r {
                    crate::pattern::StopReason::HitLimit => StopReason::HitLimit,
                    crate::pattern::StopReason::ByteLimit => StopReason::ByteLimit,
                }),
            })
        }
        YaraSpec::Rules(_) => scan_region_rules::<CHUNK, OVERLAP>(
            spec,
            start,
            end,
            budget,
            limit,
            job,
            read,
            skip_absent,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_region_rules<const CHUNK_LEN: usize, const OVERLAP_LEN: usize>(
    spec: &YaraSpec,
    start: u64,
    end: u64,
    budget: &mut u64,
    limit: usize,
    job: &Job,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    mut skip_absent: impl FnMut(u64, u64) -> Option<u64>,
) -> Result<RegionScan> {
    let mut out = RegionScan::default();
    job.check()?;
    if start >= end {
        return Ok(out);
    }
    if limit == 0 {
        out.stop_reason = Some(StopReason::HitLimit);
        return Ok(out);
    }

    let mut buffer = Vec::new();
    let mut base = start;
    let mut page = start & !(PAGE - 1);
    let mut page_buf = [0u8; PAGE_SIZE];
    let mut seen = HashSet::new();

    let flush_tail = |buffer: &mut Vec<u8>,
                      base: &mut u64,
                      seen: &mut HashSet<(u64, String, String)>,
                      out: &mut RegionScan|
     -> Result<bool> {
        if buffer.is_empty() {
            return Ok(true);
        }
        if let Some(reason) =
            spec.scan_buffer(buffer, *base, None, limit, job, seen, &mut out.hits)?
        {
            out.stop_reason = Some(reason);
            return Ok(false);
        }
        buffer.clear();
        Ok(true)
    };

    while page < end {
        job.check()?;
        if *budget < PAGE {
            flush_tail(&mut buffer, &mut base, &mut seen, &mut out)?;
            out.stop_reason.get_or_insert(StopReason::ByteLimit);
            return Ok(out);
        }
        let result = read(page, &mut page_buf);
        job.check()?;
        let next_page = page.saturating_add(PAGE);
        if result.is_err() {
            if !flush_tail(&mut buffer, &mut base, &mut seen, &mut out)? {
                return Ok(out);
            }
            if let Some(skip_to) = skip_absent(page, end).filter(|&skip_to| skip_to > next_page) {
                let target = skip_to.min(end);
                out.unreadable += target.saturating_sub(page).div_ceil(PAGE);
                page = target;
            } else {
                out.unreadable += 1;
                page = next_page;
            }
            base = page.max(start);
            continue;
        }
        *budget -= PAGE;
        let slice_start = usize::try_from(start.saturating_sub(page))?;
        let slice_end = usize::try_from(end.min(next_page).saturating_sub(page))?;
        if buffer.is_empty() {
            base = page + slice_start as u64;
        }
        buffer.extend_from_slice(page_buf.at(slice_start..slice_end)?);

        while buffer.len() >= CHUNK_LEN + OVERLAP_LEN {
            let window = buffer.at(..CHUNK_LEN + OVERLAP_LEN)?;
            if let Some(reason) = spec.scan_buffer(
                window,
                base,
                Some(CHUNK_LEN),
                limit,
                job,
                &mut seen,
                &mut out.hits,
            )? {
                out.stop_reason = Some(reason);
                return Ok(out);
            }
            buffer.drain(..CHUNK_LEN);
            base = base.checked_add(CHUNK_LEN as u64).context("扫描地址溢出")?;
        }
        page = next_page;
    }

    flush_tail(&mut buffer, &mut base, &mut seen, &mut out)?;
    job.check()?;
    Ok(out)
}

/// Scan every captured physical segment of `image` with `spec`.
pub fn scan_physical(image: &Image, spec: &YaraSpec, job: &Job) -> Result<PhysicalScan> {
    scan_physical_impl::<CHUNK, OVERLAP>(image, spec, HIT_LIMIT, job)
}

fn scan_physical_impl<const CHUNK_LEN: usize, const OVERLAP_LEN: usize>(
    image: &Image,
    spec: &YaraSpec,
    limit: usize,
    job: &Job,
) -> Result<PhysicalScan> {
    job.check()?;
    ensure!(
        !image.segments.is_empty(),
        "此镜像不包含可扫描的物理内存区段"
    );
    let mut coverage = PhysicalCoverage {
        scope: "captured physical segments",
        captured_segments: image.segments.len(),
        ..Default::default()
    };
    for segment in &image.segments {
        coverage.captured_bytes = coverage
            .captured_bytes
            .checked_add(
                segment
                    .end
                    .checked_sub(segment.start)
                    .context("物理区段倒置")?,
            )
            .context("物理覆盖总量溢出")?;
    }
    for pair in image.segments.windows(2) {
        let gap = pair
            .at(1)?
            .start
            .checked_sub(pair.at(0)?.end)
            .context("物理区段重叠或未排序")?;
        if gap > 0 {
            coverage.gap_count += 1;
            coverage.gap_bytes = coverage
                .gap_bytes
                .checked_add(gap)
                .context("空洞范围溢出")?;
        }
    }

    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    let mut buffer = Vec::new();
    let mut base = 0u64;
    let mut previous_end = None;
    let mut reported = 0u64;

    let flush_tail = |buffer: &mut Vec<u8>,
                      base: u64,
                      seen: &mut HashSet<(u64, String, String)>,
                      hits: &mut Vec<YaraHit>,
                      coverage: &mut PhysicalCoverage|
     -> Result<bool> {
        if buffer.is_empty() {
            return Ok(true);
        }
        if let Some(reason) = spec.scan_buffer(buffer, base, None, limit, job, seen, hits)? {
            coverage.stop_reason = Some(reason.diagnostic());
            return Ok(false);
        }
        buffer.clear();
        Ok(true)
    };

    'scan: for segment in &image.segments {
        if previous_end != Some(segment.start) {
            if !flush_tail(&mut buffer, base, &mut seen, &mut hits, &mut coverage)? {
                break 'scan;
            }
            base = segment.start;
        }
        let mut position = segment.start;
        while position < segment.end {
            job.check()?;
            let want = (CHUNK_LEN + OVERLAP_LEN)
                .saturating_sub(buffer.len())
                .max(1);
            let count = usize::try_from((segment.end - position).min(want as u64))?;
            if buffer.is_empty() {
                base = position;
            }
            let prev_len = buffer.len();
            buffer.resize(prev_len + count, 0);
            if let Err(error) = image.read(position, buffer.at_mut(prev_len..)?) {
                job.check()?;
                buffer.truncate(prev_len);
                coverage.read_failures += 1;
                if coverage.first_read_failure.is_none() {
                    coverage.first_read_failure = Some(format!(
                        "{position:#x}..{:#x}: {error:#}",
                        position + count as u64
                    ));
                }
                if !flush_tail(&mut buffer, base, &mut seen, &mut hits, &mut coverage)? {
                    break 'scan;
                }
                position += count as u64;
                base = position;
                continue;
            }
            coverage.scanned_bytes += count as u64;
            position += count as u64;

            while buffer.len() >= CHUNK_LEN + OVERLAP_LEN {
                let window = buffer.at(..CHUNK_LEN + OVERLAP_LEN)?;
                if let Some(reason) = spec.scan_buffer(
                    window,
                    base,
                    Some(CHUNK_LEN),
                    limit,
                    job,
                    &mut seen,
                    &mut hits,
                )? {
                    coverage.stop_reason = Some(reason.diagnostic());
                    break 'scan;
                }
                buffer.drain(..CHUNK_LEN);
                base = base
                    .checked_add(CHUNK_LEN as u64)
                    .context("物理扫描地址溢出")?;
            }

            if coverage.scanned_bytes.saturating_sub(reported) >= 64 * 1024 * 1024 {
                reported = coverage.scanned_bytes;
                job.report(format!(
                    "物理 YARA 扫描: {} / {} MiB (命中 {})",
                    coverage.scanned_bytes >> 20,
                    coverage.captured_bytes >> 20,
                    hits.len()
                ));
            }
        }
        previous_end = Some(segment.end);
    }

    if coverage.stop_reason.is_none() {
        flush_tail(&mut buffer, base, &mut seen, &mut hits, &mut coverage)?;
    }
    coverage.hits = hits.len();
    job.check()?;
    Ok(PhysicalScan { hits, coverage })
}

/// Run a physical memory YARA scan and format it as a `store::Results` table.
pub fn physical_results(
    image: &Image,
    plugin: crate::plugin::Plugin,
    spec: &YaraSpec,
    job: &Job,
) -> Result<crate::store::Results> {
    let scan = scan_physical(image, spec, job)?;
    let mut diagnostics = Vec::new();
    if scan.coverage.read_failures > 0 {
        diagnostics.push(format!(
            "物理内存读取失败 {} 次{}",
            scan.coverage.read_failures,
            scan.coverage
                .first_read_failure
                .as_deref()
                .map_or_else(String::new, |first| format!("（首次: {first}）"))
        ));
    }
    if let Some(reason) = &scan.coverage.stop_reason {
        diagnostics.push(format!("物理 YARA 扫描提前停止: {reason}"));
    }
    let rows = scan
        .hits
        .into_iter()
        .map(|hit| {
            vec![
                format!("{:#x}", hit.address),
                hit.rule,
                hit.component,
                crate::pattern::context(&hit.bytes),
            ]
        })
        .collect();
    Ok(crate::store::Results {
        plugin: plugin.name().into(),
        columns: plugin
            .descriptor()
            .columns
            .iter()
            .map(|c| (*c).into())
            .collect(),
        rows,
        complete: scan.coverage.complete(),
        diagnostics,
        banner: String::new(),
        symbol: String::new(),
        page_table: 0,
        historical: false,
        system: if plugin.is_windows() {
            "windows".into()
        } else {
            "linux".into()
        },
        kernel_identity: serde_json::json!({
            "image_digest": image.digest,
            "yara": spec.source_summary(),
            "coverage": scan.coverage,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Segment;
    use std::io::Write;

    fn make_image(bytes: &[u8]) -> Image {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        Image::from_file(file, "yara-fixture".into()).unwrap()
    }

    #[test]
    fn multi_string_condition_hex_and_modules_match() {
        let rule = r#"
            import "math"
            rule beacon_like {
                strings:
                    $mz = { 4D 5A ?? 00 }
                    $s1 = "ReflectiveLoader" ascii
                    $s2 = "beacon.dll" wide
                condition:
                    $mz and ($s1 or $s2) and math.entropy(0, filesize) >= 0.0
            }
        "#;
        let spec = YaraSpec::from_rules_source(rule).unwrap();
        let mut payload = vec![0u8; 4096];
        payload[0..4].copy_from_slice(&[0x4d, 0x5a, 0x90, 0x00]);
        payload[200..216].copy_from_slice(b"ReflectiveLoader");
        let image = make_image(&payload);
        let scan = scan_physical(&image, &spec, &Job::default()).unwrap();
        assert!(scan.coverage.complete());
        assert_eq!(scan.hits.len(), 2);
        assert_eq!(scan.hits[0].rule, "beacon_like");
        assert_eq!(scan.hits[0].component, "$mz");
        assert_eq!(scan.hits[0].address, 0);
        assert_eq!(scan.hits[1].component, "$s1");
        assert_eq!(scan.hits[1].address, 200);

        // Missing $mz means the boolean condition fails completely.
        payload[0] = 0;
        let image2 = make_image(&payload);
        let scan2 = scan_physical(&image2, &spec, &Job::default()).unwrap();
        assert!(scan2.hits.is_empty());
    }

    #[test]
    fn loads_single_file_and_directory_of_yar_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.yar"),
            r#"rule r_alpha { strings: $a = "ALPHA_MARKER" condition: $a }"#,
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(
            dir.path().join("sub/b.yara"),
            r#"rule r_beta { strings: $b = "BETA_MARKER" condition: $b }"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("ignored.txt"), "not yara syntax {{{").unwrap();

        let single = YaraSpec::from_rules_path(&dir.path().join("a.yar")).unwrap();
        let dir_spec = YaraSpec::from_rules_path(dir.path()).unwrap();
        assert_ne!(single.cache_identity(), dir_spec.cache_identity());

        let image = make_image(b"..ALPHA_MARKER..BETA_MARKER..");
        let scan = scan_physical(&image, &dir_spec, &Job::default()).unwrap();
        let rules: Vec<&str> = scan.hits.iter().map(|h| h.rule.as_str()).collect();
        assert_eq!(rules, ["r_alpha", "r_beta"]);
    }

    #[test]
    fn invalid_rule_and_missing_inputs_fail_explicitly() {
        assert!(YaraSpec::from_rules_source("rule broken { condition: ").is_err());
        assert!(YaraSpec::from_inputs(None, None, None).is_err());
        assert!(
            YaraSpec::from_inputs(Some("abc"), None, Some("rule r { condition: true }")).is_err()
        );
    }

    #[test]
    fn physical_scan_crosses_chunk_boundary_without_bridging_holes() {
        let spec =
            YaraSpec::from_rules_source(r#"rule cross { strings: $a = "NEEDLE" condition: $a }"#)
                .unwrap();
        let mut bytes = vec![0u8; 40];
        bytes[14..20].copy_from_slice(b"NEEDLE");
        let image = make_image(&bytes);
        let scan = scan_physical_impl::<16, 8>(&image, &spec, 100, &Job::default()).unwrap();
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].address, 14);
        assert!(scan.coverage.complete());

        // Physical hole between 0x1000..0x1003 and 0x1004..0x1008 must never bridge "NEE" + "DLE".
        let mut hole_img = make_image(b"NEE_DLE_");
        hole_img.segments = vec![
            Segment {
                start: 0x1000,
                end: 0x1003,
                file_offset: 0,
            },
            Segment {
                start: 0x1004,
                end: 0x1007,
                file_offset: 4,
            },
        ];
        let hole_scan = scan_physical(&hole_img, &spec, &Job::default()).unwrap();
        assert!(hole_scan.hits.is_empty());
        assert_eq!(hole_scan.coverage.gap_count, 1);
        assert_eq!(hole_scan.coverage.gap_bytes, 1);
    }

    #[test]
    fn virtual_region_rules_scan_handles_holes_budget_and_cancellation() {
        let spec =
            YaraSpec::from_rules_source(r#"rule virt { strings: $a = "NEEDLE" condition: $a }"#)
                .unwrap();
        let mut memory = vec![0u8; 4 * PAGE_SIZE];
        memory[4093..4096].copy_from_slice(b"NEE");
        memory[4096..4099].copy_from_slice(b"DLE");
        memory[3 * PAGE_SIZE + 10..3 * PAGE_SIZE + 16].copy_from_slice(b"NEEDLE");

        let mut budget = 1 << 20;
        let scan = scan_region(
            &spec,
            0,
            4 * PAGE,
            &mut budget,
            100,
            &Job::default(),
            |at, out| {
                ensure!(at != 2 * PAGE, "absent");
                out.copy_from_slice(&memory[at as usize..at as usize + PAGE_SIZE]);
                Ok(())
            },
        )
        .unwrap();
        let addrs: Vec<u64> = scan.hits.iter().map(|h| h.address).collect();
        assert_eq!(addrs, [4093, 3 * PAGE + 10]);
        assert_eq!(scan.unreadable, 1);

        // Cancellation stops immediately.
        let job = Job::default();
        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut budget2 = 1 << 20;
        assert!(scan_region(&spec, 0, PAGE, &mut budget2, 10, &job, |_, _| Ok(())).is_err());
    }

    #[test]
    fn analysis_entry_runs_physical_yarascan_without_symbols_and_invalidates_cache_on_rule_edit() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("raw.mem");
        let rule_path = dir.path().join("detect.yar");
        let cache_dir = dir.path().join("cache");
        let symbols_dir = dir.path().join("symbols");
        std::fs::create_dir_all(&symbols_dir).unwrap();
        std::fs::write(&img_path, b"header..SLIVER_IMPLANT_V1..trailer").unwrap();
        std::fs::write(
            &rule_path,
            r#"rule sliver_v1 { strings: $s = "SLIVER_IMPLANT_V1" condition: $s }"#,
        )
        .unwrap();

        let mut session = crate::analysis::Session::default();
        let request = crate::analysis::Request {
            image: &img_path,
            symbols: &symbols_dir,
            choice: None,
            plugin: crate::plugin::Plugin::LinuxYarascan,
            cache: &cache_dir,
            use_cache: true,
            network: false,
        };
        let options = crate::analysis::Options {
            yara_file: Some(rule_path.clone()),
            ..Default::default()
        };
        let crate::analysis::Outcome::Ready(first) =
            crate::analysis::analyze(&mut session, &request, None, &options, &Job::default())
                .unwrap()
        else {
            panic!("expected ready outcome");
        };
        assert!(first.complete);
        assert_eq!(first.rows.len(), 1);
        assert_eq!(first.rows[0][0], "0x8");
        assert_eq!(first.rows[0][1], "sliver_v1");
        assert_eq!(first.rows[0][2], "$s");

        // Editing the .yar file changes its digest and must invalidate the cache.
        std::fs::write(
            &rule_path,
            r#"rule sliver_v2 { strings: $s = "SLIVER_IMPLANT_V1" condition: $s }"#,
        )
        .unwrap();
        let crate::analysis::Outcome::Ready(second) =
            crate::analysis::analyze(&mut session, &request, None, &options, &Job::default())
                .unwrap()
        else {
            panic!("expected ready outcome");
        };
        assert_eq!(second.rows.len(), 1);
        assert_eq!(second.rows[0][1], "sliver_v2");
    }
}
