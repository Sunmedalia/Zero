//! Cross-plugin entity correlation (Process Dossier) and multi-plugin Triage Playbooks.
//!
//! All findings are strictly factual structural clues linked back to their source
//! plugin and coverage boundary (complete vs. partial/missing-page diagnostics).
use crate::{
    Job,
    analysis::{self, Options, Os},
    linux::{Outcome, Plugin, Request, Session},
    store::Results,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

const MAX_DOSSIER_ROWS_PER_SECTION: usize = 200;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TriagePlaybook {
    #[default]
    Auto,
    LinuxQuick,
    WindowsQuick,
}

impl TriagePlaybook {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::LinuxQuick => "linux-quick",
            Self::WindowsQuick => "windows-quick",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessLink {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub offset: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceSignal {
    pub level: String,
    pub category: String,
    pub plugin: String,
    pub summary: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionSummary {
    pub plugin: String,
    pub label: String,
    pub complete: bool,
    pub cached: bool,
    pub total_rows: usize,
    pub matched_rows: usize,
    pub truncated: bool,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub diagnostics: Vec<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DossierReport {
    pub pid: u32,
    pub os: String,
    pub process_name: String,
    pub ppid: Option<u32>,
    pub offset: String,
    pub banner: String,
    pub symbol: String,
    pub complete: bool,
    pub ancestors: Vec<ProcessLink>,
    pub children: Vec<ProcessLink>,
    pub signals: Vec<EvidenceSignal>,
    pub sections: Vec<SectionSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaybookPluginStatus {
    pub plugin: String,
    pub label: String,
    pub complete: bool,
    pub cached: bool,
    pub rows: usize,
    pub diagnostics: Vec<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntitySignalGroup {
    pub entity_type: String,
    pub entity_id: String,
    pub name: String,
    pub signal_count: usize,
    pub signals: Vec<EvidenceSignal>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriageReport {
    pub playbook: String,
    pub os: String,
    pub banner: String,
    pub symbol: String,
    pub complete: bool,
    pub plugins: Vec<PlaybookPluginStatus>,
    pub entities: Vec<EntitySignalGroup>,
    pub kernel_signals: Vec<EvidenceSignal>,
}

pub enum DossierOutcome {
    Ready(Box<DossierReport>),
    Choose(Vec<String>),
}

pub enum TriageOutcome {
    Ready(Box<TriageReport>),
    Choose(Vec<String>),
}

/// Request parameters shared by `correlate_pid` and `run_triage`.
pub struct DossierRequest<'a> {
    pub image: &'a Path,
    pub symbols: &'a Path,
    pub choice: Option<&'a str>,
    pub cache: &'a Path,
    pub use_cache: bool,
    pub network: bool,
    pub options: &'a Options,
}

/// Find a column index matching any candidate header name (case-insensitive).
pub fn find_column(columns: &[String], candidates: &[&str]) -> Option<usize> {
    columns.iter().position(|col| {
        let lower = col.trim().to_ascii_lowercase();
        candidates.iter().any(|c| lower == *c)
    })
}

/// Extract a PID from a plugin result row, if the table exposes a PID column.
pub fn extract_pid_from_row(columns: &[String], row: &[String]) -> Option<u32> {
    let idx = find_column(columns, &["pid", "tgid", "process_id", "owner_pid"])?;
    parse_pid(row.get(idx)?)
}

/// Extract an inspectable address (and an optional suggested ISF struct type) from a result row.
pub fn extract_address_from_row(
    plugin_name: &str,
    columns: &[String],
    row: &[String],
) -> Option<(u64, Option<String>)> {
    extract_inspect_target(plugin_name, columns, row)
        .map(|(address, _, structure)| (address, structure))
}

pub(crate) fn extract_inspect_target(
    plugin_name: &str,
    columns: &[String],
    row: &[String],
) -> Option<(u64, bool, Option<String>)> {
    let is_windows = plugin_name.starts_with("windows.");
    let priority: &[&str] = &[
        "offset",
        "offset(v)",
        "offset (v)",
        "offset(p)",
        "offset (p)",
        "start",
        "base",
        "address",
        "addr",
        "va",
        "task",
        "eprocess",
        "module_base",
        "handler",
        "entry",
        "ptr",
        "object",
        "target",
        "hive offset",
        "sock offset",
        "credaddress",
        "physical",
        "virtual",
    ];
    for name in priority {
        if let Some(idx) = find_column(columns, &[name])
            && let Some(raw) = row.get(idx)
            && let Some((addr, physical)) = parse_row_address(raw)
        {
            let suggested = suggest_struct(plugin_name, name, is_windows);
            return Some((
                addr,
                physical
                    || matches!(*name, "offset(p)" | "offset (p)" | "physical")
                    || (plugin_name == Plugin::Banners.name() && *name == "offset"),
                suggested,
            ));
        }
    }
    // Other columns need an explicit address prefix to distinguish offsets from scalar values.
    for (idx, cell) in row.iter().enumerate() {
        if let Some((addr, physical)) = parse_row_address(cell)
            && (physical || cell.trim_start().starts_with("virtual:"))
        {
            let col = columns.get(idx).map(String::as_str).unwrap_or("");
            return Some((addr, physical, suggest_struct(plugin_name, col, is_windows)));
        }
    }
    None
}

fn suggest_struct(plugin_name: &str, col_name: &str, is_windows: bool) -> Option<String> {
    let col = col_name.trim().to_ascii_lowercase();
    let plugin = plugin_name.to_ascii_lowercase();
    if is_windows {
        if (plugin.contains("pslist") || plugin.contains("pstree") || plugin.contains("psscan"))
            && col.contains("offset")
        {
            return Some("_EPROCESS".into());
        }
        if plugin.contains("thread") && col.contains("offset") {
            return Some("_ETHREAD".into());
        }
        if plugin.contains("vad") && col.contains("offset") {
            return Some("_MMVAD".into());
        }
        if (plugin.contains("modules") || plugin.contains("dlllist")) && col.contains("offset") {
            return Some("_LDR_DATA_TABLE_ENTRY".into());
        }
        if plugin.contains("hivelist") && col.contains("offset") {
            return Some("_CMHIVE".into());
        }
        if plugin.contains("driver") && col.contains("offset") {
            return Some("_DRIVER_OBJECT".into());
        }
    } else {
        if (plugin.contains("pslist") || plugin.contains("pstree") || plugin.contains("psscan"))
            && (col.contains("offset") || col == "task")
        {
            return Some("task_struct".into());
        }
        if (plugin.contains("lsmod") || plugin.contains("module")) && col.contains("offset") {
            return Some("module".into());
        }
        if plugin.contains("lsof") && col.contains("offset") {
            return Some("file".into());
        }
        if plugin.contains("maps") && col.contains("offset") {
            return Some("vm_area_struct".into());
        }
    }
    None
}

fn parse_pid(raw: &str) -> Option<u32> {
    let trimmed = raw
        .trim()
        .trim_start_matches(['*', ' ', '|', '-', '+', '\\', '/']);
    let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u32>().ok()
}

fn parse_row_address(raw: &str) -> Option<(u64, bool)> {
    let trimmed = raw.trim();
    let physical = trimmed.starts_with("physical:");
    let trimmed = trimmed
        .strip_prefix("physical:")
        .or_else(|| trimmed.strip_prefix("virtual:"))
        .unwrap_or(trimmed);
    let token = trimmed.split_whitespace().next()?;
    let hex = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))?;
    if hex.is_empty() || hex.len() > 16 {
        return None;
    }
    Some((u64::from_str_radix(hex, 16).ok()?, physical))
}

/// Detect whether the image/options target Windows or Linux.
pub fn resolve_target_os(
    session: &mut Session,
    image: &Path,
    symbols: &Path,
    cache: &Path,
    requested: Os,
    job: &Job,
) -> Result<Os> {
    match requested {
        Os::Linux | Os::Windows => Ok(requested),
        Os::Auto => {
            let prepared = session.identify_image(image, cache, job)?;
            if prepared.windows_container.is_some() {
                return Ok(Os::Windows);
            }
            if !prepared.banners(job)?.is_empty() {
                return Ok(Os::Linux);
            }
            if symbols.is_file()
                && let Ok(bytes) = std::fs::read(symbols)
                && crate::symbols::Isf::probe_windows_identity(&bytes).is_some()
            {
                return Ok(Os::Windows);
            }
            if !prepared.windows_candidates(job)?.is_empty() {
                return Ok(Os::Windows);
            }
            Ok(Os::Linux)
        }
    }
}

fn run_single_plugin(
    session: &mut Session,
    req: &DossierRequest<'_>,
    plugin: Plugin,
    pid_filter: Option<u32>,
    job: &Job,
) -> Result<std::result::Result<(Results, bool), Vec<String>>> {
    let mut opts = req.options.clone();
    opts.pid = None;
    opts.pids.clear();
    if let Some(pid) = pid_filter {
        if plugin.accepts_pid_list() {
            opts.pids = vec![pid];
        } else if plugin_accepts_single_pid(plugin) {
            opts.pid = Some(pid);
        }
    }
    let child_job = Job {
        cancel: job.cancel.clone(),
        ..Job::default()
    };
    // Propagate parent cancellation cleanly.
    job.check()?;
    let outcome = analysis::analyze(
        session,
        &Request {
            image: req.image,
            symbols: req.symbols,
            choice: req.choice,
            plugin,
            cache: req.cache,
            use_cache: req.use_cache,
            network: req.network,
        },
        None,
        &opts,
        &child_job,
    );
    job.check()?;
    match outcome? {
        Outcome::Ready(results) => Ok(Ok((results, child_job.served_from_cache()))),
        Outcome::Choose(labels) => Ok(Err(labels)),
    }
}

fn plugin_accepts_single_pid(plugin: Plugin) -> bool {
    matches!(
        plugin,
        Plugin::LinuxPslist
            | Plugin::LinuxPsaux
            | Plugin::LinuxEnvars
            | Plugin::LinuxCapabilities
            | Plugin::LinuxLsof
            | Plugin::LinuxSockstat
            | Plugin::LinuxMaps
            | Plugin::LinuxMalfind
            | Plugin::LinuxBash
            | Plugin::WinPslist
            | Plugin::WinCmdline
            | Plugin::WinEnvars
            | Plugin::WinPrivileges
            | Plugin::WinHandles
            | Plugin::WinDlllist
            | Plugin::WinVadinfo
            | Plugin::WinMalfind
            | Plugin::WinLdrmodules
    )
}

fn filter_rows_for_pid(results: &Results, pid: u32) -> Vec<Vec<String>> {
    let Some(pid_col) = find_column(
        &results.columns,
        &["pid", "tgid", "process_id", "owner_pid"],
    ) else {
        return Vec::new();
    };
    results
        .rows
        .iter()
        .filter(|row| row.get(pid_col).and_then(|v| parse_pid(v)) == Some(pid))
        .cloned()
        .collect()
}

fn build_process_links(
    pslist: &Results,
    target_pid: u32,
) -> (
    String,
    Option<u32>,
    String,
    Vec<ProcessLink>,
    Vec<ProcessLink>,
) {
    let pid_col = find_column(&pslist.columns, &["pid", "tgid"]);
    let ppid_col = find_column(&pslist.columns, &["ppid"]);
    let name_col = find_column(
        &pslist.columns,
        &["comm", "name", "imagefilename", "process", "command"],
    );
    let offset_col = find_column(
        &pslist.columns,
        &["offset", "offset(v)", "task", "eprocess"],
    );

    let mut by_pid: HashMap<u32, ProcessLink> = HashMap::new();
    let mut children = Vec::new();
    for row in &pslist.rows {
        let Some(pid) = pid_col.and_then(|i| row.get(i)).and_then(|v| parse_pid(v)) else {
            continue;
        };
        let ppid = ppid_col.and_then(|i| row.get(i)).and_then(|v| parse_pid(v));
        let name = name_col
            .and_then(|i| row.get(i))
            .cloned()
            .unwrap_or_default();
        let offset = offset_col
            .and_then(|i| row.get(i))
            .cloned()
            .unwrap_or_default();
        let link = ProcessLink {
            pid,
            ppid,
            name,
            offset,
        };
        if ppid == Some(target_pid) && pid != target_pid {
            children.push(link.clone());
        }
        by_pid.entry(pid).or_insert(link);
    }

    let (process_name, ppid, offset) = by_pid
        .get(&target_pid)
        .map(|p| (p.name.clone(), p.ppid, p.offset.clone()))
        .unwrap_or_else(|| (String::from("<未在 pslist 中找到>"), None, String::new()));

    // Walk ancestor chain with cycle guard.
    let mut ancestors = Vec::new();
    let mut seen = HashSet::new();
    seen.insert(target_pid);
    let mut cursor = ppid;
    while let Some(parent_pid) = cursor {
        if !seen.insert(parent_pid) {
            break;
        }
        if let Some(parent) = by_pid.get(&parent_pid) {
            ancestors.push(parent.clone());
            cursor = parent.ppid;
        } else {
            ancestors.push(ProcessLink {
                pid: parent_pid,
                ppid: None,
                name: String::from("<已退出或未见于 pslist>"),
                offset: String::new(),
            });
            break;
        }
        if ancestors.len() >= 32 {
            break;
        }
    }
    children.sort_by_key(|c| c.pid);
    (process_name, ppid, offset, ancestors, children)
}

/// Correlate all relevant plugins for a single PID into a unified Process Dossier.
pub fn correlate_pid(
    session: &mut Session,
    req: &DossierRequest<'_>,
    pid: u32,
    job: &Job,
) -> Result<DossierOutcome> {
    job.check()?;
    job.report(format!("识别目标系统并准备 PID {pid} 全景档案"));
    let target_os = resolve_target_os(
        session,
        req.image,
        req.symbols,
        req.cache,
        req.options.os,
        job,
    )?;
    let is_windows = target_os == Os::Windows;

    // 1. Run full pslist (unfiltered) so we can reconstruct parent chain and children.
    let pslist_plugin = if is_windows {
        Plugin::WinPslist
    } else {
        Plugin::LinuxPslist
    };
    job.report(format!("收集进程表 ({})", pslist_plugin.name()));
    let pslist_res = match run_single_plugin(session, req, pslist_plugin, None, job)? {
        Ok(res) => res,
        Err(choices) => return Ok(DossierOutcome::Choose(choices)),
    };
    let (pslist, pslist_cached) = pslist_res;
    let banner = pslist.banner.clone();
    let symbol = pslist.symbol.clone();
    let (process_name, ppid, offset, ancestors, children) = build_process_links(&pslist, pid);

    let mut sections = Vec::new();
    let mut signals = Vec::new();
    let mut all_complete = pslist.complete;

    let pslist_matched = filter_rows_for_pid(&pslist, pid);
    if !pslist.complete {
        signals.push(EvidenceSignal {
            level: "覆盖受限".into(),
            category: "完整性".into(),
            plugin: pslist_plugin.name().into(),
            summary: "pslist 为部分结果，父子链或进程存在性可能不完整".into(),
            detail: pslist.diagnostics.join("; "),
        });
    }
    sections.push(build_section(
        pslist_plugin,
        "进程信息",
        &pslist,
        pslist_matched,
        pslist_cached,
    ));

    // 2. Run process-centric plugins.
    let plan: &[(Plugin, &str, bool)] = if is_windows {
        &[
            (Plugin::WinCmdline, "命令行", true),
            (Plugin::WinEnvars, "环境变量", true),
            (Plugin::WinPrivileges, "权限令牌", true),
            (Plugin::WinDlllist, "加载 DLL", true),
            (Plugin::WinLdrmodules, "隐藏/脱链模块 (ldrmodules)", true),
            (Plugin::WinNetscan, "网络连接 (netscan)", false),
            (Plugin::WinHandles, "打开句柄", true),
            (Plugin::WinVadinfo, "虚拟内存段 (vadinfo)", true),
            (Plugin::WinMalfind, "注入线索 (malfind)", true),
        ]
    } else {
        &[
            (Plugin::LinuxPsaux, "命令行 (psaux)", true),
            (Plugin::LinuxEnvars, "环境变量 (envars)", true),
            (Plugin::LinuxCapabilities, "能力位 (capabilities)", true),
            (Plugin::LinuxLsof, "打开文件 (lsof)", true),
            (Plugin::LinuxSockstat, "网络 Socket (sockstat)", true),
            (Plugin::LinuxMaps, "内存映射 (maps)", true),
            (Plugin::LinuxMalfind, "注入线索 (malfind)", true),
            (Plugin::LinuxBash, "Bash 命令历史", true),
        ]
    };

    for (index, &(plugin, label, filter_at_source)) in plan.iter().enumerate() {
        job.check()?;
        job.report(format!(
            "关联 PID {pid} [{}/{}]: {}",
            index + 1,
            plan.len(),
            plugin.name()
        ));
        let pid_arg = filter_at_source.then_some(pid);
        match run_single_plugin(session, req, plugin, pid_arg, job) {
            Ok(Ok((results, cached))) => {
                let matched = if filter_at_source
                    && find_column(&results.columns, &["pid", "tgid", "process_id"]).is_none()
                {
                    results.rows.clone()
                } else {
                    filter_rows_for_pid(&results, pid)
                };
                if !results.complete {
                    all_complete = false;
                    signals.push(EvidenceSignal {
                        level: "覆盖受限".into(),
                        category: "完整性".into(),
                        plugin: plugin.name().into(),
                        summary: format!("{label} 为部分结果，未命中不能作为排除依据"),
                        detail: results.diagnostics.join("; "),
                    });
                }
                collect_dossier_signals(plugin, &results.columns, &matched, &mut signals);
                sections.push(build_section(plugin, label, &results, matched, cached));
            }
            Ok(Err(choices)) => return Ok(DossierOutcome::Choose(choices)),
            Err(err) => {
                job.check()?;
                all_complete = false;
                sections.push(SectionSummary {
                    plugin: plugin.name().into(),
                    label: label.into(),
                    complete: false,
                    cached: false,
                    total_rows: 0,
                    matched_rows: 0,
                    truncated: false,
                    columns: Vec::new(),
                    rows: Vec::new(),
                    diagnostics: Vec::new(),
                    error: Some(format!("{err:#}")),
                });
            }
        }
    }

    Ok(DossierOutcome::Ready(Box::new(DossierReport {
        pid,
        os: if is_windows { "windows" } else { "linux" }.into(),
        process_name,
        ppid,
        offset,
        banner,
        symbol,
        complete: all_complete,
        ancestors,
        children,
        signals,
        sections,
    })))
}

fn build_section(
    plugin: Plugin,
    label: &str,
    results: &Results,
    matched: Vec<Vec<String>>,
    cached: bool,
) -> SectionSummary {
    let matched_rows = matched.len();
    let truncated = matched_rows > MAX_DOSSIER_ROWS_PER_SECTION;
    let rows = matched
        .into_iter()
        .take(MAX_DOSSIER_ROWS_PER_SECTION)
        .collect();
    SectionSummary {
        plugin: plugin.name().into(),
        label: label.into(),
        complete: results.complete,
        cached,
        total_rows: results.rows.len(),
        matched_rows,
        truncated,
        columns: results.columns.clone(),
        rows,
        diagnostics: results.diagnostics.clone(),
        error: None,
    }
}

fn collect_dossier_signals(
    plugin: Plugin,
    columns: &[String],
    rows: &[Vec<String>],
    signals: &mut Vec<EvidenceSignal>,
) {
    if rows.is_empty() {
        return;
    }
    match plugin {
        Plugin::LinuxMalfind | Plugin::WinMalfind => {
            signals.push(EvidenceSignal {
                level: "高关注".into(),
                category: "内存注入线索".into(),
                plugin: plugin.name().into(),
                summary: format!("malfind 发现 {} 处可疑可执行/脏页区域", rows.len()),
                detail: rows
                    .iter()
                    .take(3)
                    .map(|r| r.join(" | "))
                    .collect::<Vec<_>>()
                    .join(" ; "),
            });
        }
        Plugin::LinuxMaps => {
            let mut rwx = 0usize;
            let mut memfd_or_deleted = 0usize;
            for row in rows {
                let joined = row.join(" ");
                let lower = joined.to_ascii_lowercase();
                if lower.contains("rwx") {
                    rwx += 1;
                }
                if lower.contains("memfd:") || lower.contains("(deleted)") {
                    memfd_or_deleted += 1;
                }
            }
            if rwx > 0 {
                signals.push(EvidenceSignal {
                    level: "高关注".into(),
                    category: "可执行可写映射".into(),
                    plugin: plugin.name().into(),
                    summary: format!("发现 {rwx} 个 RWX 内存映射"),
                    detail: "请结合 malfind 与内存检查器核查该映射内容".into(),
                });
            }
            if memfd_or_deleted > 0 {
                signals.push(EvidenceSignal {
                    level: "高关注".into(),
                    category: "无文件/已删除映射".into(),
                    plugin: plugin.name().into(),
                    summary: format!("发现 {memfd_or_deleted} 个 memfd 或 (deleted) 映射"),
                    detail: "可能为内存执行或磁盘文件被删除后的残留映射".into(),
                });
            }
        }
        Plugin::WinVadinfo => {
            let rwx = rows
                .iter()
                .filter(|r| {
                    r.iter()
                        .any(|c| c.to_ascii_uppercase().contains("EXECUTE_READWRITE"))
                })
                .count();
            if rwx > 0 {
                signals.push(EvidenceSignal {
                    level: "高关注".into(),
                    category: "可执行可写 VAD".into(),
                    plugin: plugin.name().into(),
                    summary: format!("发现 {rwx} 个 PAGE_EXECUTE_READWRITE VAD"),
                    detail: "建议对起始地址打开内存检查器反汇编核查".into(),
                });
            }
        }
        Plugin::WinLdrmodules => {
            let in_load = find_column(columns, &["inload"]);
            let in_init = find_column(columns, &["ininit"]);
            let in_mem = find_column(columns, &["inmem"]);
            let unlinked = rows
                .iter()
                .filter(|r| {
                    let check = |idx: Option<usize>| {
                        idx.and_then(|i| r.get(i))
                            .is_some_and(|v| v.eq_ignore_ascii_case("false"))
                    };
                    check(in_load) || check(in_init) || check(in_mem)
                })
                .count();
            if unlinked > 0 {
                signals.push(EvidenceSignal {
                    level: "中关注".into(),
                    category: "脱链模块线索".into(),
                    plugin: plugin.name().into(),
                    summary: format!("ldrmodules 发现 {unlinked} 项未出现在全部 PEB 链表中"),
                    detail: "需结合模块路径核查是否为正常映射或脱链隐藏 DLL".into(),
                });
            }
        }
        Plugin::LinuxSockstat | Plugin::WinNetscan => {
            signals.push(EvidenceSignal {
                level: "信息".into(),
                category: "网络活动".into(),
                plugin: plugin.name().into(),
                summary: format!("关联到 {} 条网络 Socket/连接记录", rows.len()),
                detail: rows
                    .iter()
                    .take(3)
                    .map(|r| r.join(" | "))
                    .collect::<Vec<_>>()
                    .join(" ; "),
            });
        }
        Plugin::LinuxBash => {
            signals.push(EvidenceSignal {
                level: "信息".into(),
                category: "命令历史".into(),
                plugin: plugin.name().into(),
                summary: format!("恢复 {} 条 Bash 历史记录", rows.len()),
                detail: rows
                    .iter()
                    .take(3)
                    .map(|r| r.join(" | "))
                    .collect::<Vec<_>>()
                    .join(" ; "),
            });
        }
        _ => {}
    }
}

/// Run an automated multi-plugin triage playbook and aggregate signals by entity.
pub fn run_triage(
    session: &mut Session,
    req: &DossierRequest<'_>,
    playbook: TriagePlaybook,
    job: &Job,
) -> Result<TriageOutcome> {
    job.check()?;
    let target_os = match playbook {
        TriagePlaybook::LinuxQuick => Os::Linux,
        TriagePlaybook::WindowsQuick => Os::Windows,
        TriagePlaybook::Auto => resolve_target_os(
            session,
            req.image,
            req.symbols,
            req.cache,
            req.options.os,
            job,
        )?,
    };
    let is_windows = target_os == Os::Windows;
    let effective_playbook = if is_windows {
        TriagePlaybook::WindowsQuick
    } else {
        TriagePlaybook::LinuxQuick
    };

    let plan: &[(Plugin, &str)] = if is_windows {
        &[
            (Plugin::WinPslist, "进程列表 (pslist)"),
            (Plugin::WinCmdline, "命令行 (cmdline)"),
            (Plugin::WinNetscan, "网络连接 (netscan)"),
            (Plugin::WinMalfind, "内存注入线索 (malfind)"),
            (Plugin::WinLdrmodules, "模块脱链检查 (ldrmodules)"),
            (Plugin::WinPsxview, "隐藏进程交叉验证 (psxview)"),
            (Plugin::WinModules, "内核模块 (modules)"),
        ]
    } else {
        &[
            (Plugin::LinuxPslist, "进程列表 (pslist)"),
            (Plugin::LinuxPsaux, "命令行 (psaux)"),
            (Plugin::LinuxSockstat, "网络 Socket (sockstat)"),
            (Plugin::LinuxMalfind, "内存注入线索 (malfind)"),
            (Plugin::Lsmod, "内核模块 (lsmod)"),
            (Plugin::HiddenModules, "隐藏内核模块 (hidden_modules)"),
            (Plugin::CheckSyscall, "系统调用表检查 (check_syscall)"),
            (Plugin::LinuxBash, "Bash 命令历史 (bash)"),
        ]
    };

    let mut statuses = Vec::new();
    let mut pid_names: HashMap<u32, String> = HashMap::new();
    let mut entity_map: BTreeMap<u32, Vec<EvidenceSignal>> = BTreeMap::new();
    let mut kernel_signals = Vec::new();
    let mut banner = String::new();
    let mut symbol = String::new();
    let mut all_complete = true;

    for (index, &(plugin, label)) in plan.iter().enumerate() {
        job.check()?;
        job.report(format!(
            "应急初筛 [{}/{}]: {}",
            index + 1,
            plan.len(),
            plugin.name()
        ));
        match run_single_plugin(session, req, plugin, None, job) {
            Ok(Ok((results, cached))) => {
                if banner.is_empty() && !results.banner.is_empty() {
                    banner = results.banner.clone();
                }
                if symbol.is_empty() && !results.symbol.is_empty() {
                    symbol = results.symbol.clone();
                }
                if !results.complete {
                    all_complete = false;
                }
                // Record PID -> Name from pslist.
                if matches!(plugin, Plugin::LinuxPslist | Plugin::WinPslist) {
                    let pid_col = find_column(&results.columns, &["pid", "tgid"]);
                    let name_col = find_column(
                        &results.columns,
                        &["comm", "name", "imagefilename", "process"],
                    );
                    for row in &results.rows {
                        if let Some(pid) =
                            pid_col.and_then(|i| row.get(i)).and_then(|v| parse_pid(v))
                        {
                            let name = name_col
                                .and_then(|i| row.get(i))
                                .cloned()
                                .unwrap_or_default();
                            pid_names.entry(pid).or_insert(name);
                        }
                    }
                }
                aggregate_triage_signals(plugin, &results, &mut entity_map, &mut kernel_signals);
                statuses.push(PlaybookPluginStatus {
                    plugin: plugin.name().into(),
                    label: label.into(),
                    complete: results.complete,
                    cached,
                    rows: results.rows.len(),
                    diagnostics: results.diagnostics,
                    error: None,
                });
            }
            Ok(Err(choices)) => return Ok(TriageOutcome::Choose(choices)),
            Err(err) => {
                job.check()?;
                all_complete = false;
                statuses.push(PlaybookPluginStatus {
                    plugin: plugin.name().into(),
                    label: label.into(),
                    complete: false,
                    cached: false,
                    rows: 0,
                    diagnostics: Vec::new(),
                    error: Some(format!("{err:#}")),
                });
            }
        }
    }

    let mut entities: Vec<EntitySignalGroup> = entity_map
        .into_iter()
        .map(|(pid, signals)| EntitySignalGroup {
            entity_type: "process".into(),
            entity_id: pid.to_string(),
            name: pid_names
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| String::from("<未知>")),
            signal_count: signals.len(),
            signals,
        })
        .collect();
    // Sort entities with most signals first, then by PID.
    entities.sort_by(|a, b| {
        b.signal_count
            .cmp(&a.signal_count)
            .then_with(|| a.entity_id.cmp(&b.entity_id))
    });

    Ok(TriageOutcome::Ready(Box::new(TriageReport {
        playbook: effective_playbook.label().into(),
        os: if is_windows { "windows" } else { "linux" }.into(),
        banner,
        symbol,
        complete: all_complete,
        plugins: statuses,
        entities,
        kernel_signals,
    })))
}

fn aggregate_triage_signals(
    plugin: Plugin,
    results: &Results,
    entity_map: &mut BTreeMap<u32, Vec<EvidenceSignal>>,
    kernel_signals: &mut Vec<EvidenceSignal>,
) {
    match plugin {
        Plugin::LinuxMalfind | Plugin::WinMalfind => {
            let mut per_pid: BTreeMap<u32, usize> = BTreeMap::new();
            for row in &results.rows {
                if let Some(pid) = extract_pid_from_row(&results.columns, row) {
                    *per_pid.entry(pid).or_insert(0) += 1;
                }
            }
            for (pid, count) in per_pid {
                entity_map.entry(pid).or_default().push(EvidenceSignal {
                    level: "高关注".into(),
                    category: "内存注入线索".into(),
                    plugin: plugin.name().into(),
                    summary: format!("malfind 命中 {count} 处"),
                    detail: format!("可使用 zero dossier --pid {pid} 或 TUI 按 x 检查地址"),
                });
            }
        }
        Plugin::LinuxSockstat | Plugin::WinNetscan => {
            let mut per_pid: BTreeMap<u32, usize> = BTreeMap::new();
            for row in &results.rows {
                if let Some(pid) = extract_pid_from_row(&results.columns, row) {
                    *per_pid.entry(pid).or_insert(0) += 1;
                }
            }
            for (pid, count) in per_pid {
                entity_map.entry(pid).or_default().push(EvidenceSignal {
                    level: "信息".into(),
                    category: "网络活动".into(),
                    plugin: plugin.name().into(),
                    summary: format!("持有 {count} 条网络连接/Socket"),
                    detail: String::new(),
                });
            }
        }
        Plugin::WinLdrmodules => {
            let in_load = find_column(&results.columns, &["inload"]);
            let in_init = find_column(&results.columns, &["ininit"]);
            let in_mem = find_column(&results.columns, &["inmem"]);
            let mut per_pid: BTreeMap<u32, usize> = BTreeMap::new();
            for row in &results.rows {
                let unlinked = |idx: Option<usize>| {
                    idx.and_then(|i| row.get(i))
                        .is_some_and(|v| v.eq_ignore_ascii_case("false"))
                };
                if (unlinked(in_load) || unlinked(in_init) || unlinked(in_mem))
                    && let Some(pid) = extract_pid_from_row(&results.columns, row)
                {
                    *per_pid.entry(pid).or_insert(0) += 1;
                }
            }
            for (pid, count) in per_pid {
                entity_map.entry(pid).or_default().push(EvidenceSignal {
                    level: "中关注".into(),
                    category: "脱链模块".into(),
                    plugin: plugin.name().into(),
                    summary: format!("{count} 个模块在 PEB 链表中缺失"),
                    detail: String::new(),
                });
            }
        }
        Plugin::WinPsxview => {
            let pslist_col = find_column(&results.columns, &["pslist"]);
            for row in &results.rows {
                if let Some(col) = pslist_col
                    && row
                        .get(col)
                        .is_some_and(|v| v.eq_ignore_ascii_case("false"))
                    && let Some(pid) = extract_pid_from_row(&results.columns, row)
                {
                    entity_map.entry(pid).or_default().push(EvidenceSignal {
                        level: "高关注".into(),
                        category: "隐藏进程线索".into(),
                        plugin: plugin.name().into(),
                        summary: "psxview 显示该进程不在 pslist 中".into(),
                        detail: row.join(" | "),
                    });
                }
            }
        }
        Plugin::HiddenModules if !results.rows.is_empty() => {
            kernel_signals.push(EvidenceSignal {
                level: "高关注".into(),
                category: "内核隐藏模块".into(),
                plugin: plugin.name().into(),
                summary: format!("hidden_modules 发现 {} 个异常模块线索", results.rows.len()),
                detail: results
                    .rows
                    .iter()
                    .take(5)
                    .map(|r| r.join(" | "))
                    .collect::<Vec<_>>()
                    .join(" ; "),
            });
        }
        Plugin::CheckSyscall => {
            let Some(reason_col) = find_column(&results.columns, &["reason"]) else {
                return;
            };
            let hooked: Vec<&Vec<String>> = results
                .rows
                .iter()
                .filter(|row| {
                    row.get(reason_col).is_some_and(|reason| {
                        matches!(
                            reason.as_str(),
                            "ModuleTarget; inspect hook" | "OutsideKnownExecutableRanges"
                        )
                    })
                })
                .collect();
            if !hooked.is_empty() {
                kernel_signals.push(EvidenceSignal {
                    level: "高关注".into(),
                    category: "系统调用表线索".into(),
                    plugin: plugin.name().into(),
                    summary: format!("check_syscall 发现 {} 条待核查表项", hooked.len()),
                    detail: hooked
                        .iter()
                        .take(5)
                        .map(|r| r.join(" | "))
                        .collect::<Vec<_>>()
                        .join(" ; "),
                });
            }
        }
        _ => {}
    }
}

impl DossierReport {
    /// Render a human-readable Chinese forensic dossier report for TUI/CLI display.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "进程全景档案 · PID {} ({})\n",
            self.pid, self.process_name
        ));
        out.push_str(&format!(
            "系统: {} | PPID: {} | 地址: {}\n",
            self.os,
            self.ppid.map_or_else(|| "-".into(), |p| p.to_string()),
            if self.offset.is_empty() {
                "-"
            } else {
                &self.offset
            }
        ));
        if !self.banner.is_empty() {
            out.push_str(&format!("内核: {}\n", self.banner));
        }
        if !self.symbol.is_empty() {
            out.push_str(&format!("符号: {}\n", self.symbol));
        }
        out.push_str(&format!(
            "完整性: {}\n",
            if self.complete {
                "全部关联插件完整完成"
            } else {
                "部分插件不完整或执行失败（未命中不能作为排除依据）"
            }
        ));

        out.push_str("\n=== 进程血缘 ===\n");
        if self.ancestors.is_empty() {
            out.push_str("  父链: (无或根进程)\n");
        } else {
            let chain = self
                .ancestors
                .iter()
                .map(|a| format!("{}({})", a.name, a.pid))
                .collect::<Vec<_>>()
                .join(" <- ");
            out.push_str(&format!(
                "  父链: {}({}) <- {chain}\n",
                self.process_name, self.pid
            ));
        }
        if self.children.is_empty() {
            out.push_str("  子进程: (无)\n");
        } else {
            let kids = self
                .children
                .iter()
                .map(|c| format!("{}({})", c.name, c.pid))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("  子进程 ({}): {kids}\n", self.children.len()));
        }

        out.push_str("\n=== 聚合线索摘要 ===\n");
        if self.signals.is_empty() {
            out.push_str("  未触发预设结构线索（请仍结合下方各插件明细核查）。\n");
        } else {
            for sig in &self.signals {
                out.push_str(&format!(
                    "  [{}] [{}] {}: {}\n",
                    sig.level, sig.category, sig.plugin, sig.summary
                ));
                if !sig.detail.is_empty() {
                    out.push_str(&format!("      明细: {}\n", sig.detail));
                }
            }
        }

        for section in &self.sections {
            let status = if let Some(err) = &section.error {
                format!("失败: {err}")
            } else if section.complete {
                format!(
                    "命中 {} 行{}",
                    section.matched_rows,
                    if section.cached { " · 缓存" } else { "" }
                )
            } else {
                format!("部分结果 · 命中 {} 行", section.matched_rows)
            };
            out.push_str(&format!(
                "\n=== {} [{}] ({}) ===\n",
                section.label, section.plugin, status
            ));
            if !section.diagnostics.is_empty() {
                out.push_str(&format!("  诊断: {}\n", section.diagnostics.join("; ")));
            }
            if section.rows.is_empty() {
                if section.error.is_none() {
                    out.push_str("  (无匹配行)\n");
                }
                continue;
            }
            if !section.columns.is_empty() {
                out.push_str(&format!("  {}\n", section.columns.join(" | ")));
            }
            for row in &section.rows {
                out.push_str(&format!("  {}\n", row.join(" | ")));
            }
            if section.truncated {
                out.push_str(&format!(
                    "  ... 仅展示前 {} 行，共 {} 行\n",
                    section.rows.len(),
                    section.matched_rows
                ));
            }
        }
        out
    }
}

impl TriageReport {
    /// Render a human-readable Chinese triage board for TUI/CLI display.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "一键应急初筛看板 · 剧本 {} ({})\n",
            self.playbook, self.os
        ));
        if !self.banner.is_empty() {
            out.push_str(&format!("内核: {}\n", self.banner));
        }
        if !self.symbol.is_empty() {
            out.push_str(&format!("符号: {}\n", self.symbol));
        }
        out.push_str(&format!(
            "覆盖状态: {}\n",
            if self.complete {
                "全部剧本插件完整完成"
            } else {
                "存在部分结果或失败插件（未命中不能作为排除依据）"
            }
        ));

        out.push_str("\n=== 内核与系统线索 ===\n");
        if self.kernel_signals.is_empty() {
            out.push_str("  未发现预设内核异常线索。\n");
        } else {
            for sig in &self.kernel_signals {
                out.push_str(&format!(
                    "  [{}] [{}] {}: {}\n",
                    sig.level, sig.category, sig.plugin, sig.summary
                ));
                if !sig.detail.is_empty() {
                    out.push_str(&format!("      明细: {}\n", sig.detail));
                }
            }
        }

        out.push_str("\n=== 按实体聚合线索 (Top 进程) ===\n");
        if self.entities.is_empty() {
            out.push_str("  暂无聚合到单个进程的线索。\n");
        } else {
            for entity in self.entities.iter().take(30) {
                out.push_str(&format!(
                    "  PID {} ({}) · {} 条线索:\n",
                    entity.entity_id, entity.name, entity.signal_count
                ));
                for sig in &entity.signals {
                    out.push_str(&format!(
                        "    - [{}] [{}] {}: {}\n",
                        sig.level, sig.category, sig.plugin, sig.summary
                    ));
                }
            }
        }

        out.push_str("\n=== 剧本插件执行明细 ===\n");
        for plugin in &self.plugins {
            let state = if let Some(err) = &plugin.error {
                format!("失败: {err}")
            } else if plugin.complete {
                format!(
                    "完整 · {} 行{}",
                    plugin.rows,
                    if plugin.cached { " · 缓存" } else { "" }
                )
            } else {
                format!("部分 · {} 行", plugin.rows)
            };
            out.push_str(&format!(
                "  {} [{}] -> {}\n",
                plugin.label, plugin.plugin, state
            ));
            if !plugin.diagnostics.is_empty() {
                out.push_str(&format!("    诊断: {}\n", plugin.diagnostics.join("; ")));
            }
        }
        out
    }
}

/// Keep report exports separate from the memory image, symbols, and paging attachments.
pub fn validate_report_destination(
    path: &Path,
    image: &Path,
    symbols: &Path,
    options: &Options,
) -> Result<()> {
    let destination = match path.canonicalize() {
        Ok(destination) => destination,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let inputs = [image, symbols]
        .into_iter()
        .chain(options.pagefiles.iter().map(|file| file.path.as_path()))
        .chain(options.swapfile.as_deref());
    anyhow::ensure!(
        !inputs
            .filter_map(|input| input.canonicalize().ok())
            .any(|input| input == destination),
        "报告输出不能覆盖输入镜像、符号或分页附件"
    );
    Ok(())
}

/// Export a report as pretty JSON.
pub fn export_report_json<T: Serialize>(path: &Path, report: &T, job: &Job) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report).context("序列化报告 JSON 失败")?;
    crate::store::atomic_stream(path, job, |writer| {
        writer.write_all(&bytes)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Results;

    fn sample_results(plugin: &str, columns: &[&str], rows: Vec<Vec<&str>>) -> Results {
        Results {
            plugin: plugin.into(),
            columns: columns.iter().map(|s| (*s).to_owned()).collect(),
            rows: rows
                .into_iter()
                .map(|r| r.into_iter().map(str::to_owned).collect())
                .collect(),
            complete: true,
            diagnostics: Vec::new(),
            banner: "Linux version 6.1.0".into(),
            symbol: "test.isf.json".into(),
            page_table: 0x1000,
            historical: false,
            system: "linux".into(),
            kernel_identity: serde_json::Value::Null,
        }
    }

    #[test]
    fn extracts_pid_and_suggested_struct_from_rows() {
        let cols = vec!["PID".into(), "PPID".into(), "COMM".into(), "OFFSET".into()];
        let row = vec![
            "|-- 42".into(),
            "1".into(),
            "sshd".into(),
            "0xffff888001234000".into(),
        ];
        assert_eq!(extract_pid_from_row(&cols, &row), Some(42));
        assert_eq!(
            extract_address_from_row("linux.pslist.full", &cols, &row),
            Some((0xffff_8880_0123_4000, Some("task_struct".into())))
        );
        assert_eq!(
            extract_address_from_row("windows.pslist", &cols, &row),
            Some((0xffff_8880_0123_4000, Some("_EPROCESS".into())))
        );
    }

    #[test]
    fn inspect_target_preserves_physical_offsets() {
        for (column, value) in [
            ("Offset", "physical:0x220"),
            ("OFFSET (P)", "0x220"),
            ("Physical", "0x220"),
            ("Other", "physical:0x220"),
        ] {
            assert_eq!(
                extract_inspect_target("windows.netscan", &[column.into()], &[value.into()]),
                Some((0x220, true, None))
            );
        }
    }

    #[test]
    fn inspector_does_not_treat_handle_values_as_addresses() {
        let row = ["0x1234".into(), "0xffff800000001000".into()];
        assert_eq!(
            extract_inspect_target("windows.handles", &["Handle".into()], &row[..1]),
            None
        );
        assert_eq!(
            extract_inspect_target("windows.handles", &["Handle".into(), "Object".into()], &row),
            Some((0xffff_8000_0000_1000, false, None))
        );
    }

    #[test]
    fn auto_detects_windows_raw_with_a_symbol_directory() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let image = dir.path().join("image.raw");
        let mut raw = Vec::from(b"RSDS");
        raw.extend([1; 16]);
        raw.extend(1u32.to_le_bytes());
        raw.extend(b"ntkrnlmp.pdb\0");
        raw.resize(4096, 0);
        std::fs::write(&image, raw)?;

        assert_eq!(
            resolve_target_os(
                &mut Session::default(),
                &image,
                dir.path(),
                dir.path(),
                Os::Auto,
                &Job::default(),
            )?,
            Os::Windows
        );
        Ok(())
    }

    #[test]
    fn syscall_triage_uses_the_verdict_instead_of_the_symbol_name() {
        let results = sample_results(
            "linux.check_syscall",
            &["Symbol", "Reason"],
            vec![
                vec!["__x64_sys_init_module", "KernelText"],
                vec!["__x64_sys_delete_module", "KernelText"],
                vec!["target", "OutsideKnownExecutableRanges"],
                vec!["another_target", "ModuleTarget; inspect hook"],
            ],
        );
        let mut signals = Vec::new();
        aggregate_triage_signals(
            Plugin::CheckSyscall,
            &results,
            &mut BTreeMap::new(),
            &mut signals,
        );
        assert_eq!(signals.len(), 1);
        assert!(signals[0].summary.contains("2 条"));
    }

    #[test]
    fn builds_process_lineage_and_children_with_cycle_guard() {
        let pslist = sample_results(
            "linux.pslist.full",
            &["PID", "PPID", "COMM", "OFFSET"],
            vec![
                vec!["1", "0", "systemd", "0xffff888000010000"],
                vec!["100", "1", "sshd", "0xffff888000020000"],
                vec!["200", "100", "bash", "0xffff888000030000"],
                vec!["201", "200", "curl", "0xffff888000040000"],
                vec!["202", "200", "python3", "0xffff888000050000"],
            ],
        );
        let (name, ppid, offset, ancestors, children) = build_process_links(&pslist, 200);
        assert_eq!(name, "bash");
        assert_eq!(ppid, Some(100));
        assert_eq!(offset, "0xffff888000030000");
        assert_eq!(ancestors.len(), 3); // 100 -> 1 -> 0(exited/missing)
        assert_eq!(ancestors[0].pid, 100);
        assert_eq!(ancestors[1].pid, 1);
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].pid, 201);
        assert_eq!(children[1].pid, 202);
    }

    #[test]
    fn collects_signals_and_renders_chinese_dossier_and_triage() {
        let mut signals = Vec::new();
        let cols = vec!["PID".into(), "PERMS".into(), "PATH".into()];
        let rows = vec![vec![
            "42".into(),
            "rwxp".into(),
            "/memfd:payload (deleted)".into(),
        ]];
        collect_dossier_signals(Plugin::LinuxMaps, &cols, &rows, &mut signals);
        assert_eq!(signals.len(), 2);
        assert!(signals.iter().any(|s| s.category == "可执行可写映射"));
        assert!(signals.iter().any(|s| s.category == "无文件/已删除映射"));

        let report = DossierReport {
            pid: 42,
            os: "linux".into(),
            process_name: "payload".into(),
            ppid: Some(1),
            offset: "0xffff888000020000".into(),
            banner: "Linux version 6.1.0".into(),
            symbol: "test.isf".into(),
            complete: false,
            ancestors: vec![ProcessLink {
                pid: 1,
                ppid: Some(0),
                name: "systemd".into(),
                offset: "0xffff888000010000".into(),
            }],
            children: Vec::new(),
            signals,
            sections: Vec::new(),
        };
        let text = report.render_text();
        assert!(text.contains("进程全景档案 · PID 42 (payload)"));
        assert!(text.contains("未命中不能作为排除依据"));
        assert!(text.contains("systemd(1)"));

        let mut entity_map = BTreeMap::new();
        let mut kernel_signals = Vec::new();
        let malfind = sample_results(
            "linux.malfind.full",
            &["PID", "START"],
            vec![vec!["42", "0x7f0000001000"], vec!["42", "0x7f0000002000"]],
        );
        aggregate_triage_signals(
            Plugin::LinuxMalfind,
            &malfind,
            &mut entity_map,
            &mut kernel_signals,
        );
        assert_eq!(entity_map.get(&42).map(Vec::len), Some(1));
        assert!(entity_map[&42][0].summary.contains("2 处"));
    }
}
