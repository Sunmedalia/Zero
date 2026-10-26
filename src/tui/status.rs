//! Status vocabulary shared by results, the footer and diagnostic details.
use super::*;
const FAMILIES: &[(&str, &[&str], &str)] = &[
    (
        "页面不在镜像中",
        &["缺页", "不驻留", "PEB 不存在", "越界", "空洞"],
        "对象所在的页在采集时已换出到 pagefile、未提交或不在镜像范围内；附加 pagefile／swapfile 后可读到更多。",
    ),
    (
        "布局未验收",
        &["布局", "验收", "尚未验证"],
        "这些结构的布局尚未与此精确符号身份的真实样本对照；结果可用，但需要核查。",
    ),
    (
        "达到上限",
        &["上限", "超限"],
        "读取到的计数超过安全上限，按无效数据处理并停止该对象。",
    ),
    (
        "对象前后矛盾",
        &[
            "不一致",
            "无效链表",
            "无效 EPROCESS",
            "无效对象",
            "未闭合",
            "循环",
            "NUL",
            "无效 UNICODE_STRING",
            "签名无效",
            "非 canonical",
            "未分配",
            "无效",
        ],
        "链表指针、父指针或对象头与相邻对象矛盾；运行中采集时，对象可能正在创建或释放。",
    ),
    ("其他", &[], "未归类的诊断，需要逐项核查。"),
];
fn family(text: &str) -> usize {
    FAMILIES
        .iter()
        .position(|(_, patterns, _)| patterns.iter().any(|p| text.contains(p)))
        .unwrap_or(FAMILIES.len() - 1)
}
pub(super) fn diagnostic_summary(diagnostics: &[String]) -> String {
    let mut counts = [0; 5];
    for text in diagnostics {
        counts[family(text)] += 1;
    }
    FAMILIES
        .iter()
        .enumerate()
        .filter(|(i, _)| counts[*i] > 0)
        .map(|(i, (label, _, _))| format!("{label} {}", counts[i]))
        .collect::<Vec<_>>()
        .join(" · ")
}
pub(super) fn diagnostics_text(result: &Results) -> String {
    if result.diagnostics.is_empty() {
        return "没有诊断；结果完整。".into();
    }
    let mut lines = vec![format!("{} 条诊断。", result.diagnostics.len())];
    for (index, (label, _, explanation)) in FAMILIES.iter().enumerate() {
        let entries = result
            .diagnostics
            .iter()
            .filter(|s| family(s) == index)
            .collect::<Vec<_>>();
        if entries.is_empty() {
            continue;
        }
        lines.push(format!("\n· {label} {}：{explanation}", entries.len()));
        lines.push(format!("\n── {label} {} ──", entries.len()));
        lines.extend(entries.into_iter().map(|s| escaped(s)));
    }
    lines.join("\n")
}
pub(super) fn format_duration(seconds: f64) -> String {
    if seconds < 10.0 {
        format!("{:.1} s", (seconds * 10.0).round() / 10.0)
    } else if seconds < 60.0 {
        format!("{:.0} s", seconds)
    } else {
        let whole = seconds.round() as u64;
        format!("{}m{:02}s", whole / 60, whole % 60)
    }
}
impl App {
    pub(super) fn current_origin(&self) -> Option<&str> {
        if self.history.is_some() {
            None
        } else {
            self.result_origins
                .get(&self.request_key())
                .or_else(|| self.result_origins.get(self.plugin.name()))
                .map(String::as_str)
        }
    }
}
