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
    collections::{HashMap, HashSet},
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
    Pattern(Box<Pattern>),
    Rules(CompiledRules),
}

impl YaraSpec {
    pub fn from_pattern(text: &str) -> Result<Self> {
        Ok(Self::Pattern(Box::new(Pattern::parse(text)?)))
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
        let digest = rules_digest(&rules)?;
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
            compiler
                .add_source(yara_x::SourceCode::from(bytes.as_slice()).with_origin(origin))
                .with_context(|| format!("YARA 规则文件 {} 编译失败", file.display()))?;
        }
        let rules = compiler.build();
        let digest = rules_digest(&rules)?;
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
        Self::validate_inputs(pattern, yara_file, yara_rules)?;
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

    pub(crate) fn validate_inputs(
        pattern: Option<&str>,
        yara_file: Option<&Path>,
        yara_rules: Option<&str>,
    ) -> Result<()> {
        let count = usize::from(pattern.is_some())
            + usize::from(yara_file.is_some())
            + usize::from(yara_rules.is_some());
        ensure!(
            count == 1,
            "YARA 扫描插件必须且只能指定 --pattern、--yara-file 或 --yara-rules 之一"
        );
        Ok(())
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

    pub fn scanner(&self) -> YaraScanner<'_> {
        match self {
            Self::Pattern(pattern) => YaraScanner::Pattern(pattern),
            Self::Rules(compiled) => {
                let mut scanner = yara_x::Scanner::new(&compiled.rules);
                scanner.set_timeout(CHUNK_TIMEOUT);
                scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);
                YaraScanner::Rules {
                    scanner,
                    scratch: Vec::new(),
                }
            }
        }
    }
}

fn rules_digest(rules: &yara_x::Rules) -> Result<String> {
    let serialized = rules
        .serialize()
        .map_err(|e| anyhow::anyhow!("序列化编译后的 YARA 规则失败: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"yara-x-rules\0");
    hasher.update(&serialized);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Reusable scanner state so a single `yara_x::Scanner` instance and scratch
/// buffer are shared across all chunks, segments, VMAs, and VADs in one run.
pub enum YaraScanner<'a> {
    Pattern(&'a Pattern),
    Rules {
        scanner: yara_x::Scanner<'a>,
        scratch: Vec<u8>,
    },
}

impl<'r> YaraScanner<'r> {
    #[allow(clippy::too_many_arguments)]
    fn scan_buffer(
        &mut self,
        buffer: &[u8],
        base: u64,
        accept_start_below: Option<usize>,
        limit: usize,
        job: &Job,
        seen: &mut SeenHits<'r>,
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
                let mut ids: Option<(u32, u32)> = None;
                for offset in pattern.find_all(buffer) {
                    if accept_start_below.is_some_and(|bound| offset >= bound) {
                        continue;
                    }
                    let address = base
                        .checked_add(offset as u64)
                        .context("模式命中地址溢出")?;
                    let (rule_id, comp_id) = match ids {
                        Some(pair) => pair,
                        None => {
                            let pair = (
                                seen.intern_rule("default", "pattern")?,
                                seen.intern_component("$pattern")?,
                            );
                            ids = Some(pair);
                            pair
                        }
                    };
                    if !seen.insert(address, rule_id, comp_id) {
                        continue;
                    }
                    if out.len() >= limit {
                        return Ok(Some(StopReason::HitLimit));
                    }
                    let stop = buffer.len().min(offset + CONTEXT);
                    out.push(YaraHit {
                        address,
                        rule: "pattern".to_owned(),
                        component: "$pattern".to_owned(),
                        bytes: buffer.at(offset..stop)?.to_vec(),
                    });
                }
                Ok(None)
            }
            Self::Rules { scanner, .. } => {
                let results = match scanner.scan(buffer) {
                    Ok(results) => results,
                    Err(yara_x::ScanError::Timeout) => return Ok(Some(StopReason::Timeout)),
                    Err(error) => return Err(anyhow::anyhow!("YARA 扫描失败: {error}")),
                };
                for matched_rule in results.matching_rules() {
                    job.check()?;
                    let namespace = matched_rule.namespace();
                    let identifier = matched_rule.identifier();
                    let rule_id = seen.intern_rule(namespace, identifier)?;
                    let mut formatted_rule: Option<String> = None;
                    let mut emitted_pattern = false;
                    for pattern in matched_rule.patterns() {
                        let component_str = pattern.identifier();
                        let mut comp_id: Option<u32> = None;
                        for m in pattern.matches() {
                            emitted_pattern = true;
                            let offset = m.range().start;
                            if accept_start_below.is_some_and(|bound| offset >= bound) {
                                continue;
                            }
                            let address = base
                                .checked_add(offset as u64)
                                .context("YARA 命中地址溢出")?;
                            let cid = match comp_id {
                                Some(id) => id,
                                None => {
                                    let id = seen.intern_component(component_str)?;
                                    comp_id = Some(id);
                                    id
                                }
                            };
                            if !seen.insert(address, rule_id, cid) {
                                continue;
                            }
                            if out.len() >= limit {
                                return Ok(Some(StopReason::HitLimit));
                            }
                            let rule = if namespace == "default" {
                                identifier.to_owned()
                            } else {
                                formatted_rule
                                    .get_or_insert_with(|| format!("{namespace}:{identifier}"))
                                    .clone()
                            };
                            let stop = buffer.len().min(offset + CONTEXT);
                            out.push(YaraHit {
                                address,
                                rule,
                                component: component_str.to_owned(),
                                bytes: buffer.at(offset..stop)?.to_vec(),
                            });
                        }
                    }
                    if !emitted_pattern {
                        let cid = seen.intern_component("(condition)")?;
                        if seen.insert(base, rule_id, cid) {
                            if out.len() >= limit {
                                return Ok(Some(StopReason::HitLimit));
                            }
                            let rule = if namespace == "default" {
                                identifier.to_owned()
                            } else {
                                formatted_rule
                                    .unwrap_or_else(|| format!("{namespace}:{identifier}"))
                            };
                            let stop = buffer.len().min(CONTEXT);
                            out.push(YaraHit {
                                address: base,
                                rule,
                                component: "(condition)".to_owned(),
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
    let mut scanner = spec.scanner();
    scan_region_sparse_with_scanner(
        &mut scanner,
        start,
        end,
        budget,
        limit,
        job,
        read,
        |_, _| None,
    )
}

/// Like `scan_region`, reusing an existing `YaraScanner` across regions.
pub fn scan_region_with_scanner(
    scanner: &mut YaraScanner<'_>,
    start: u64,
    end: u64,
    budget: &mut u64,
    limit: usize,
    job: &Job,
    read: impl FnMut(u64, &mut [u8]) -> Result<()>,
) -> Result<RegionScan> {
    scan_region_sparse_with_scanner(scanner, start, end, budget, limit, job, read, |_, _| None)
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
    let mut scanner = spec.scanner();
    scan_region_sparse_with_scanner(
        &mut scanner,
        start,
        end,
        budget,
        limit,
        job,
        read,
        skip_absent,
    )
}

/// Like `scan_region_sparse`, reusing an existing `YaraScanner` across regions.
#[allow(clippy::too_many_arguments)]
pub fn scan_region_sparse_with_scanner(
    scanner: &mut YaraScanner<'_>,
    start: u64,
    end: u64,
    budget: &mut u64,
    limit: usize,
    job: &Job,
    read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    skip_absent: impl FnMut(u64, u64) -> Option<u64>,
) -> Result<RegionScan> {
    match scanner {
        YaraScanner::Pattern(pattern) => {
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
        YaraScanner::Rules { .. } => scan_region_rules::<CHUNK, OVERLAP>(
            scanner,
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

const MAX_REGION_BATCH_PAGES: usize = 128;

#[allow(clippy::too_many_arguments)]
fn scan_region_rules<'r, const CHUNK_LEN: usize, const OVERLAP_LEN: usize>(
    scanner: &mut YaraScanner<'r>,
    start: u64,
    end: u64,
    budget: &mut u64,
    limit: usize,
    job: &Job,
    read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    skip_absent: impl FnMut(u64, u64) -> Option<u64>,
) -> Result<RegionScan> {
    let mut buffer = match scanner {
        YaraScanner::Rules { scratch, .. } => std::mem::take(scratch),
        YaraScanner::Pattern(_) => Vec::new(),
    };
    let result = scan_region_rules_inner::<CHUNK_LEN, OVERLAP_LEN>(
        scanner,
        &mut buffer,
        start,
        end,
        budget,
        limit,
        job,
        read,
        skip_absent,
    );
    if let YaraScanner::Rules { scratch, .. } = scanner {
        *scratch = buffer;
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn scan_region_rules_inner<'r, const CHUNK_LEN: usize, const OVERLAP_LEN: usize>(
    scanner: &mut YaraScanner<'r>,
    buffer: &mut Vec<u8>,
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

    let window_len = CHUNK_LEN + OVERLAP_LEN;
    let mut valid_len = 0usize;
    let mut base = start;
    let mut page = start & !(PAGE - 1);
    let mut page_buf = [0u8; PAGE_SIZE];
    let mut seen = SeenHits::<'r>::default();
    let mut fallback_remaining = 0usize;

    let flush_tail = |scanner: &mut YaraScanner<'r>,
                      buffer: &[u8],
                      valid_len: &mut usize,
                      base: u64,
                      seen: &mut SeenHits<'r>,
                      out: &mut RegionScan|
     -> Result<bool> {
        if *valid_len == 0 {
            return Ok(true);
        }
        let slice = buffer.at(..*valid_len)?;
        if let Some(reason) =
            scanner.scan_buffer(slice, base, None, limit, job, seen, &mut out.hits)?
        {
            out.stop_reason = Some(reason);
            return Ok(false);
        }
        *valid_len = 0;
        Ok(true)
    };

    while page < end {
        job.check()?;
        if *budget < PAGE {
            flush_tail(scanner, buffer, &mut valid_len, base, &mut seen, &mut out)?;
            out.stop_reason.get_or_insert(StopReason::ByteLimit);
            return Ok(out);
        }

        if fallback_remaining == 0 && page >= start {
            let full_pages_left =
                usize::try_from(end.saturating_sub(page) / PAGE).unwrap_or(usize::MAX);
            let budget_pages = usize::try_from(*budget / PAGE).unwrap_or(usize::MAX);
            let space_pages = window_len.saturating_sub(valid_len) / PAGE_SIZE;
            let batch_pages = full_pages_left
                .min(budget_pages)
                .min(space_pages)
                .min(MAX_REGION_BATCH_PAGES);
            if batch_pages > 1 {
                let batch_bytes = batch_pages
                    .checked_mul(PAGE_SIZE)
                    .context("批量读取长度溢出")?;
                let new_len = valid_len
                    .checked_add(batch_bytes)
                    .context("扫描缓冲大小溢出")?;
                if buffer.len() < new_len {
                    buffer.resize(new_len, 0);
                }
                let batch_result = read(page, buffer.at_mut(valid_len..new_len)?);
                job.check()?;
                if batch_result.is_ok() {
                    let batch_u64 = batch_bytes as u64;
                    *budget -= batch_u64;
                    if valid_len == 0 {
                        base = page;
                    }
                    valid_len = new_len;
                    while valid_len >= window_len {
                        let window = buffer.at(..window_len)?;
                        if let Some(reason) = scanner.scan_buffer(
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
                        buffer.copy_within(CHUNK_LEN..valid_len, 0);
                        valid_len -= CHUNK_LEN;
                        base = base.checked_add(CHUNK_LEN as u64).context("扫描地址溢出")?;
                    }
                    page = page.saturating_add(batch_u64);
                    continue;
                }
                fallback_remaining = batch_pages;
            }
        }

        let result = read(page, &mut page_buf);
        job.check()?;
        let next_page = page.saturating_add(PAGE);
        if result.is_err() {
            fallback_remaining = 0;
            if !flush_tail(scanner, buffer, &mut valid_len, base, &mut seen, &mut out)? {
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
        fallback_remaining = fallback_remaining.saturating_sub(1);
        *budget -= PAGE;
        let slice_start = usize::try_from(start.saturating_sub(page))?;
        let slice_end = usize::try_from(end.min(next_page).saturating_sub(page))?;
        let slice = page_buf.at(slice_start..slice_end)?;
        if valid_len == 0 {
            base = page + slice_start as u64;
        }
        let new_len = valid_len
            .checked_add(slice.len())
            .context("扫描缓冲大小溢出")?;
        if buffer.len() < new_len {
            buffer.resize(new_len, 0);
        }
        buffer.at_mut(valid_len..new_len)?.copy_from_slice(slice);
        valid_len = new_len;

        while valid_len >= window_len {
            let window = buffer.at(..window_len)?;
            if let Some(reason) = scanner.scan_buffer(
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
            buffer.copy_within(CHUNK_LEN..valid_len, 0);
            valid_len -= CHUNK_LEN;
            base = base.checked_add(CHUNK_LEN as u64).context("扫描地址溢出")?;
        }
        page = next_page;
    }

    flush_tail(scanner, buffer, &mut valid_len, base, &mut seen, &mut out)?;
    job.check()?;
    Ok(out)
}

#[derive(Default)]
struct SeenHits<'r> {
    rules: HashMap<(&'r str, &'r str), u32>,
    components: HashMap<&'r str, u32>,
    entries: HashSet<(u64, u32, u32)>,
}

impl<'r> SeenHits<'r> {
    fn intern_rule(&mut self, namespace: &'r str, identifier: &'r str) -> Result<u32> {
        if let Some(&id) = self.rules.get(&(namespace, identifier)) {
            return Ok(id);
        }
        let id = u32::try_from(self.rules.len()).context("YARA 规则索引溢出")?;
        self.rules.insert((namespace, identifier), id);
        Ok(id)
    }

    fn intern_component(&mut self, component: &'r str) -> Result<u32> {
        if let Some(&id) = self.components.get(component) {
            return Ok(id);
        }
        let id = u32::try_from(self.components.len()).context("YARA 模式索引溢出")?;
        self.components.insert(component, id);
        Ok(id)
    }

    fn insert(&mut self, address: u64, rule_id: u32, component_id: u32) -> bool {
        self.entries.insert((address, rule_id, component_id))
    }
}

/// Scan every captured physical segment of `image` with `spec`.
pub fn scan_physical(image: &Image, spec: &YaraSpec, job: &Job) -> Result<PhysicalScan> {
    scan_physical_impl::<CHUNK, OVERLAP>(image, spec, HIT_LIMIT, job)
}

fn scan_physical_impl<'r, const CHUNK_LEN: usize, const OVERLAP_LEN: usize>(
    image: &Image,
    spec: &'r YaraSpec,
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

    let window_len = CHUNK_LEN + OVERLAP_LEN;
    let mut hits = Vec::new();
    let mut scanner = spec.scanner();
    let mut seen = SeenHits::default();
    let mut buffer = Vec::new();
    let mut valid_len = 0usize;
    let mut base = 0u64;
    let mut previous_end = None;
    let mut reported = 0u64;

    let flush_tail = |scanner: &mut YaraScanner<'r>,
                      buffer: &[u8],
                      valid_len: &mut usize,
                      base: u64,
                      seen: &mut SeenHits<'r>,
                      hits: &mut Vec<YaraHit>,
                      coverage: &mut PhysicalCoverage|
     -> Result<bool> {
        if *valid_len == 0 {
            return Ok(true);
        }
        let slice = buffer.at(..*valid_len)?;
        if let Some(reason) = scanner.scan_buffer(slice, base, None, limit, job, seen, hits)? {
            coverage.stop_reason = Some(reason.diagnostic());
            return Ok(false);
        }
        *valid_len = 0;
        Ok(true)
    };

    'scan: for segment in &image.segments {
        if previous_end != Some(segment.start) {
            if !flush_tail(
                &mut scanner,
                &buffer,
                &mut valid_len,
                base,
                &mut seen,
                &mut hits,
                &mut coverage,
            )? {
                break 'scan;
            }
            base = segment.start;
        }
        let mut position = segment.start;
        while position < segment.end {
            job.check()?;
            let want = window_len.saturating_sub(valid_len).max(1);
            let count = usize::try_from((segment.end - position).min(want as u64))?;
            if valid_len == 0 {
                base = position;
            }
            let new_len = valid_len.checked_add(count).context("物理扫描缓冲溢出")?;
            if buffer.len() < new_len {
                buffer.resize(new_len, 0);
            }
            if let Err(error) = image.read(position, buffer.at_mut(valid_len..new_len)?) {
                job.check()?;
                coverage.read_failures += 1;
                if coverage.first_read_failure.is_none() {
                    coverage.first_read_failure = Some(format!(
                        "{position:#x}..{:#x}: {error:#}",
                        position + count as u64
                    ));
                }
                if !flush_tail(
                    &mut scanner,
                    &buffer,
                    &mut valid_len,
                    base,
                    &mut seen,
                    &mut hits,
                    &mut coverage,
                )? {
                    break 'scan;
                }
                position += count as u64;
                base = position;
                continue;
            }
            valid_len = new_len;
            coverage.scanned_bytes += count as u64;
            position += count as u64;

            while valid_len >= window_len {
                let window = buffer.at(..window_len)?;
                if let Some(reason) = scanner.scan_buffer(
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
                buffer.copy_within(CHUNK_LEN..valid_len, 0);
                valid_len -= CHUNK_LEN;
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
        flush_tail(
            &mut scanner,
            &buffer,
            &mut valid_len,
            base,
            &mut seen,
            &mut hits,
            &mut coverage,
        )?;
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
    fn included_rule_edit_changes_cache_identity() {
        let dir = tempfile::tempdir().unwrap();
        let common = dir.path().join("common.yar");
        let main = dir.path().join("main.yar");
        std::fs::write(
            &common,
            r#"rule inc_v1 { strings: $a = "INC_TOKEN" condition: $a }"#,
        )
        .unwrap();
        std::fs::write(&main, "include \"common.yar\"\n").unwrap();

        let first = YaraSpec::from_rules_path(&main).unwrap();
        std::fs::write(
            &common,
            r#"rule inc_v2 { strings: $a = "INC_TOKEN" condition: $a }"#,
        )
        .unwrap();
        let second = YaraSpec::from_rules_path(&main).unwrap();
        assert_ne!(first.cache_identity(), second.cache_identity());
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
                let mut cur = at;
                let mut dst = out;
                while !dst.is_empty() {
                    ensure!(cur != 2 * PAGE, "absent");
                    let step = dst.len().min(PAGE_SIZE);
                    dst[..step].copy_from_slice(&memory[cur as usize..cur as usize + step]);
                    cur += step as u64;
                    dst = &mut dst[step..];
                }
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

    // Reference baseline implementations (pre-optimization Vec::drain +
    // HashSet<(u64, String, String)> + single-page VMA reads) for equivalence tests.
    fn ref_scan_buffer(
        scanner: &mut yara_x::Scanner<'_>,
        buffer: &[u8],
        base: u64,
        accept_start_below: Option<usize>,
        limit: usize,
        seen: &mut HashSet<(u64, String, String)>,
        out: &mut Vec<YaraHit>,
    ) -> Option<StopReason> {
        if buffer.is_empty() {
            return None;
        }
        if out.len() >= limit {
            return Some(StopReason::HitLimit);
        }
        let results = scanner.scan(buffer).unwrap();
        for matched_rule in results.matching_rules() {
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
                    let address = base + offset as u64;
                    if !seen.insert((address, rule_name.clone(), component.clone())) {
                        continue;
                    }
                    if out.len() >= limit {
                        return Some(StopReason::HitLimit);
                    }
                    let stop = buffer.len().min(offset + CONTEXT);
                    out.push(YaraHit {
                        address,
                        rule: rule_name.clone(),
                        component: component.clone(),
                        bytes: buffer[offset..stop].to_vec(),
                    });
                }
            }
            if !emitted_pattern {
                let component = "(condition)".to_owned();
                if seen.insert((base, rule_name.clone(), component.clone())) {
                    if out.len() >= limit {
                        return Some(StopReason::HitLimit);
                    }
                    let stop = buffer.len().min(CONTEXT);
                    out.push(YaraHit {
                        address: base,
                        rule: rule_name,
                        component,
                        bytes: buffer[..stop].to_vec(),
                    });
                }
            }
        }
        None
    }

    fn ref_scan_physical<const CHUNK_LEN: usize, const OVERLAP_LEN: usize>(
        image: &Image,
        spec: &YaraSpec,
        limit: usize,
    ) -> PhysicalScan {
        let YaraSpec::Rules(compiled) = spec else {
            panic!("expected rules spec");
        };
        let mut scanner = yara_x::Scanner::new(&compiled.rules);
        scanner.set_timeout(CHUNK_TIMEOUT);
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);

        let mut coverage = PhysicalCoverage {
            scope: "captured physical segments",
            captured_segments: image.segments.len(),
            ..Default::default()
        };
        for segment in &image.segments {
            coverage.captured_bytes += segment.end - segment.start;
        }
        for pair in image.segments.windows(2) {
            let gap = pair[1].start - pair[0].end;
            if gap > 0 {
                coverage.gap_count += 1;
                coverage.gap_bytes += gap;
            }
        }
        let mut hits = Vec::new();
        let mut seen = HashSet::new();
        let mut buffer = Vec::new();
        let mut base = 0u64;
        let mut previous_end = None;

        'scan: for segment in &image.segments {
            if previous_end != Some(segment.start) {
                if !buffer.is_empty() {
                    if let Some(reason) = ref_scan_buffer(
                        &mut scanner,
                        &buffer,
                        base,
                        None,
                        limit,
                        &mut seen,
                        &mut hits,
                    ) {
                        coverage.stop_reason = Some(reason.diagnostic());
                        break 'scan;
                    }
                    buffer.clear();
                }
                base = segment.start;
            }
            let mut position = segment.start;
            while position < segment.end {
                let want = (CHUNK_LEN + OVERLAP_LEN)
                    .saturating_sub(buffer.len())
                    .max(1);
                let count = usize::try_from((segment.end - position).min(want as u64)).unwrap();
                if buffer.is_empty() {
                    base = position;
                }
                let prev_len = buffer.len();
                buffer.resize(prev_len + count, 0);
                if let Err(error) = image.read(position, &mut buffer[prev_len..]) {
                    buffer.truncate(prev_len);
                    coverage.read_failures += 1;
                    if coverage.first_read_failure.is_none() {
                        coverage.first_read_failure = Some(format!(
                            "{position:#x}..{:#x}: {error:#}",
                            position + count as u64
                        ));
                    }
                    if !buffer.is_empty() {
                        if let Some(reason) = ref_scan_buffer(
                            &mut scanner,
                            &buffer,
                            base,
                            None,
                            limit,
                            &mut seen,
                            &mut hits,
                        ) {
                            coverage.stop_reason = Some(reason.diagnostic());
                            break 'scan;
                        }
                        buffer.clear();
                    }
                    position += count as u64;
                    base = position;
                    continue;
                }
                coverage.scanned_bytes += count as u64;
                position += count as u64;
                while buffer.len() >= CHUNK_LEN + OVERLAP_LEN {
                    if let Some(reason) = ref_scan_buffer(
                        &mut scanner,
                        &buffer[..CHUNK_LEN + OVERLAP_LEN],
                        base,
                        Some(CHUNK_LEN),
                        limit,
                        &mut seen,
                        &mut hits,
                    ) {
                        coverage.stop_reason = Some(reason.diagnostic());
                        break 'scan;
                    }
                    buffer.drain(..CHUNK_LEN);
                    base += CHUNK_LEN as u64;
                }
            }
            previous_end = Some(segment.end);
        }
        if coverage.stop_reason.is_none()
            && !buffer.is_empty()
            && let Some(reason) = ref_scan_buffer(
                &mut scanner,
                &buffer,
                base,
                None,
                limit,
                &mut seen,
                &mut hits,
            )
        {
            coverage.stop_reason = Some(reason.diagnostic());
        }
        coverage.hits = hits.len();
        PhysicalScan { hits, coverage }
    }

    #[allow(clippy::too_many_arguments)]
    fn ref_scan_region<const CHUNK_LEN: usize, const OVERLAP_LEN: usize>(
        spec: &YaraSpec,
        start: u64,
        end: u64,
        budget: &mut u64,
        limit: usize,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
        mut skip_absent: impl FnMut(u64, u64) -> Option<u64>,
    ) -> RegionScan {
        let YaraSpec::Rules(compiled) = spec else {
            panic!("expected rules spec");
        };
        let mut scanner = yara_x::Scanner::new(&compiled.rules);
        scanner.set_timeout(CHUNK_TIMEOUT);
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);

        let mut out = RegionScan::default();
        if start >= end {
            return out;
        }
        if limit == 0 {
            out.stop_reason = Some(StopReason::HitLimit);
            return out;
        }
        let mut buffer = Vec::new();
        let mut base = start;
        let mut page = start & !(PAGE - 1);
        let mut page_buf = [0u8; PAGE_SIZE];
        let mut seen = HashSet::new();

        while page < end {
            if *budget < PAGE {
                if !buffer.is_empty() {
                    if let Some(reason) = ref_scan_buffer(
                        &mut scanner,
                        &buffer,
                        base,
                        None,
                        limit,
                        &mut seen,
                        &mut out.hits,
                    ) {
                        out.stop_reason = Some(reason);
                    }
                    buffer.clear();
                }
                out.stop_reason.get_or_insert(StopReason::ByteLimit);
                return out;
            }
            let result = read(page, &mut page_buf);
            let next_page = page.saturating_add(PAGE);
            if result.is_err() {
                if !buffer.is_empty() {
                    if let Some(reason) = ref_scan_buffer(
                        &mut scanner,
                        &buffer,
                        base,
                        None,
                        limit,
                        &mut seen,
                        &mut out.hits,
                    ) {
                        out.stop_reason = Some(reason);
                        return out;
                    }
                    buffer.clear();
                }
                if let Some(skip_to) = skip_absent(page, end).filter(|&s| s > next_page) {
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
            let slice_start = usize::try_from(start.saturating_sub(page)).unwrap();
            let slice_end = usize::try_from(end.min(next_page).saturating_sub(page)).unwrap();
            if buffer.is_empty() {
                base = page + slice_start as u64;
            }
            buffer.extend_from_slice(&page_buf[slice_start..slice_end]);
            while buffer.len() >= CHUNK_LEN + OVERLAP_LEN {
                if let Some(reason) = ref_scan_buffer(
                    &mut scanner,
                    &buffer[..CHUNK_LEN + OVERLAP_LEN],
                    base,
                    Some(CHUNK_LEN),
                    limit,
                    &mut seen,
                    &mut out.hits,
                ) {
                    out.stop_reason = Some(reason);
                    return out;
                }
                buffer.drain(..CHUNK_LEN);
                base += CHUNK_LEN as u64;
            }
            page = next_page;
        }
        if !buffer.is_empty()
            && let Some(reason) = ref_scan_buffer(
                &mut scanner,
                &buffer,
                base,
                None,
                limit,
                &mut seen,
                &mut out.hits,
            )
        {
            out.stop_reason = Some(reason);
        }
        out
    }

    fn assert_physical_eq(actual: &PhysicalScan, expected: &PhysicalScan) {
        assert_eq!(actual.hits, expected.hits);
        assert_eq!(actual.coverage.scope, expected.coverage.scope);
        assert_eq!(
            actual.coverage.captured_segments,
            expected.coverage.captured_segments
        );
        assert_eq!(
            actual.coverage.captured_bytes,
            expected.coverage.captured_bytes
        );
        assert_eq!(
            actual.coverage.scanned_bytes,
            expected.coverage.scanned_bytes
        );
        assert_eq!(actual.coverage.gap_count, expected.coverage.gap_count);
        assert_eq!(actual.coverage.gap_bytes, expected.coverage.gap_bytes);
        assert_eq!(
            actual.coverage.read_failures,
            expected.coverage.read_failures
        );
        assert_eq!(
            actual.coverage.first_read_failure,
            expected.coverage.first_read_failure
        );
        assert_eq!(actual.coverage.stop_reason, expected.coverage.stop_reason);
        assert_eq!(actual.coverage.hits, expected.coverage.hits);
    }

    #[test]
    fn physical_equivalence_cross_chunk_overlap_holes_read_failures_and_hit_limit() {
        let rules = r#"
            rule r_multi {
                strings:
                    $a = "NEEDLE"
                    $b = "XY"
                condition:
                    any of them
            }
            rule r_cond_only {
                condition:
                    filesize >= 8
            }
        "#;
        let spec = YaraSpec::from_rules_source(rules).unwrap();

        // 1. Cross-chunk boundary + overlap-zone hits (must appear exactly once).
        let mut bytes = vec![b'.'; 64];
        bytes[0..6].copy_from_slice(b"NEEDLE"); // chunk 0 start
        bytes[14..20].copy_from_slice(b"NEEDLE"); // crosses CHUNK=16 boundary
        bytes[17..19].copy_from_slice(b"XY"); // inside overlap [16..24), emitted in chunk 1
        bytes[22..28].copy_from_slice(b"NEEDLE"); // starts in overlap, crosses into chunk 1
        bytes[30..36].copy_from_slice(b"NEEDLE"); // crosses CHUNK=32 boundary
        bytes[58..64].copy_from_slice(b"NEEDLE"); // tail flush
        let img = make_image(&bytes);
        for limit in [0, 1, 3, 5, 100] {
            let actual = scan_physical_impl::<16, 8>(&img, &spec, limit, &Job::default()).unwrap();
            let expected = ref_scan_physical::<16, 8>(&img, &spec, limit);
            assert_physical_eq(&actual, &expected);
        }

        // 2. Contiguous segments (must bridge) + hole segments (must flush, no bridge).
        let mut seg_bytes = vec![b'.'; 48];
        seg_bytes[13..19].copy_from_slice(b"NEEDLE"); // bridges seg 0 [0..16) and seg 1 [16..32)
        seg_bytes[29..35].copy_from_slice(b"NEEDLE"); // split across hole between seg 1 and seg 2
        seg_bytes[38..44].copy_from_slice(b"NEEDLE"); // inside seg 2
        let mut seg_img = make_image(&seg_bytes);
        seg_img.segments = vec![
            Segment {
                start: 0x1000,
                end: 0x1010,
                file_offset: 0,
            },
            Segment {
                start: 0x1010,
                end: 0x1020,
                file_offset: 16,
            },
            Segment {
                start: 0x1030,
                end: 0x1040,
                file_offset: 32,
            },
        ];
        let actual = scan_physical_impl::<16, 8>(&seg_img, &spec, 100, &Job::default()).unwrap();
        let expected = ref_scan_physical::<16, 8>(&seg_img, &spec, 100);
        assert_physical_eq(&actual, &expected);
        assert!(actual.hits.iter().any(|h| h.address == 0x100d));
        assert!(!actual.hits.iter().any(|h| h.address == 0x101d));

        // 3. Read failure mid-segment (file shorter than segment claims).
        let mut short_img = make_image(b"__NEEDLE________");
        short_img.segments = vec![Segment {
            start: 0x2000,
            end: 0x2040,
            file_offset: 0,
        }];
        let actual = scan_physical_impl::<16, 8>(&short_img, &spec, 100, &Job::default()).unwrap();
        let expected = ref_scan_physical::<16, 8>(&short_img, &spec, 100);
        assert_physical_eq(&actual, &expected);
        assert!(actual.coverage.read_failures > 0);
        assert!(!actual.coverage.complete());
    }

    #[test]
    fn region_equivalence_batch_fallback_skip_absent_budget_and_unaligned() {
        let spec = YaraSpec::from_rules_source(
            r#"
            rule vma_rule {
                strings:
                    $a = "NEEDLE"
                    $b = "OVERLAP_HIT"
                condition:
                    any of them
            }
            "#,
        )
        .unwrap();

        // 16 pages (64 KiB) with hits across chunk/page boundaries and overlap zones.
        let total_pages = 16usize;
        let mut mem = vec![b'.'; total_pages * PAGE_SIZE];
        // Cross page 0 -> 1
        mem[PAGE_SIZE - 3..PAGE_SIZE + 3].copy_from_slice(b"NEEDLE");
        // Cross CHUNK=8192 boundary (page 1 -> 2) and overlap zone [8192..12288)
        mem[2 * PAGE_SIZE - 2..2 * PAGE_SIZE + 4].copy_from_slice(b"NEEDLE");
        mem[2 * PAGE_SIZE + 100..2 * PAGE_SIZE + 111].copy_from_slice(b"OVERLAP_HIT");
        // Hit right before middle-of-batch absent page 5
        mem[4 * PAGE_SIZE + 4080..4 * PAGE_SIZE + 4086].copy_from_slice(b"NEEDLE");
        // Split across absent page 5 (must not bridge)
        mem[5 * PAGE_SIZE - 3..5 * PAGE_SIZE].copy_from_slice(b"NEE");
        mem[6 * PAGE_SIZE..6 * PAGE_SIZE + 3].copy_from_slice(b"DLE");
        // Hit in page 9, cross page 10 -> 11, and tail page 15
        mem[9 * PAGE_SIZE + 50..9 * PAGE_SIZE + 56].copy_from_slice(b"NEEDLE");
        mem[11 * PAGE_SIZE - 4..11 * PAGE_SIZE + 2].copy_from_slice(b"NEEDLE");
        mem[15 * PAGE_SIZE + 4000..15 * PAGE_SIZE + 4006].copy_from_slice(b"NEEDLE");

        // Absent pages: 5, 6, 7 (middle of a multi-page batch!) and 13 (single absent page).
        let is_absent = |p: u64| matches!(p, 5 | 6 | 7 | 13);
        let read_pages = |at: u64, out: &mut [u8]| -> Result<()> {
            let mut cur = at;
            let mut dst = out;
            while !dst.is_empty() {
                ensure!(!is_absent(cur / PAGE), "absent page");
                let step = dst.len().min(PAGE_SIZE - (cur as usize % PAGE_SIZE));
                let off = usize::try_from(cur)?;
                dst[..step].copy_from_slice(&mem[off..off + step]);
                cur += step as u64;
                dst = &mut dst[step..];
            }
            Ok(())
        };
        let skip_fn = |at: u64, end: u64| -> Option<u64> {
            if at == 5 * PAGE {
                Some((8 * PAGE).min(end))
            } else {
                None
            }
        };

        // Test combinations of aligned/unaligned ranges, budgets, limits, and skip_absent.
        let cases = [
            (0u64, (total_pages as u64) * PAGE, 1 << 20, 100usize, false),
            (0, (total_pages as u64) * PAGE, 1 << 20, 100, true),
            (0, (total_pages as u64) * PAGE, 6 * PAGE, 100, true), // ByteLimit mid-region
            (0, (total_pages as u64) * PAGE, 3 * PAGE, 100, false), // ByteLimit smaller than batch
            (0, (total_pages as u64) * PAGE, 1 << 20, 3, true),    // HitLimit
            (0, (total_pages as u64) * PAGE, 1 << 20, 0, false),   // HitLimit = 0
            (137, (total_pages as u64) * PAGE - 211, 1 << 20, 100, true), // unaligned start & end
        ];
        let mut scanner = spec.scanner();
        for (start, end, init_budget, limit, use_skip) in cases {
            let mut b_new = init_budget;
            let mut b_old = init_budget;
            let actual = if use_skip {
                scan_region_rules::<8192, 4096>(
                    &mut scanner,
                    start,
                    end,
                    &mut b_new,
                    limit,
                    &Job::default(),
                    read_pages,
                    skip_fn,
                )
                .unwrap()
            } else {
                scan_region_rules::<8192, 4096>(
                    &mut scanner,
                    start,
                    end,
                    &mut b_new,
                    limit,
                    &Job::default(),
                    read_pages,
                    |_, _| None,
                )
                .unwrap()
            };
            let expected = if use_skip {
                ref_scan_region::<8192, 4096>(
                    &spec, start, end, &mut b_old, limit, read_pages, skip_fn,
                )
            } else {
                ref_scan_region::<8192, 4096>(
                    &spec,
                    start,
                    end,
                    &mut b_old,
                    limit,
                    read_pages,
                    |_, _| None,
                )
            };
            assert_eq!(
                actual, expected,
                "mismatch for case ({start}, {end}, {init_budget}, {limit}, {use_skip})"
            );
            assert_eq!(
                b_new, b_old,
                "budget mismatch for case ({start}, {end}, {init_budget}, {limit}, {use_skip})"
            );
        }

        // Also verify fallback when a reader rejects multi-page slices (only accepts PAGE_SIZE).
        let mut b_strict = 1 << 20;
        let mut b_ref = 1 << 20;
        let strict = scan_region_rules::<8192, 4096>(
            &mut scanner,
            0,
            (total_pages as u64) * PAGE,
            &mut b_strict,
            100,
            &Job::default(),
            |at, out| {
                ensure!(out.len() == PAGE_SIZE, "single-page only");
                ensure!(!is_absent(at / PAGE), "absent page");
                let off = usize::try_from(at)?;
                out.copy_from_slice(&mem[off..off + PAGE_SIZE]);
                Ok(())
            },
            skip_fn,
        )
        .unwrap();
        let expected = ref_scan_region::<8192, 4096>(
            &spec,
            0,
            (total_pages as u64) * PAGE,
            &mut b_ref,
            100,
            read_pages,
            skip_fn,
        );
        assert_eq!(strict, expected);
        assert_eq!(b_strict, b_ref);
    }
}
