//! Interactive TUI Workbench features:
//! - #1: Process Dossier pivoting (`K`) and Triage Playbook (`T`)
//! - #3: Live Memory, ISF/PDB Struct & Capstone Disassembly Inspector (`x`)
use super::*;
use crate::{
    bytes::Cells,
    dossier::{TriagePlaybook, extract_address_from_row, extract_pid_from_row},
    inspector::{DEFAULT_INSPECT_BYTES, InspectView, SpaceKind},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum InspectorTab {
    #[default]
    Hex,
    Struct,
    Disasm,
}

impl InspectorTab {
    pub(super) fn next(self) -> Self {
        match self {
            Self::Hex => Self::Struct,
            Self::Struct => Self::Disasm,
            Self::Disasm => Self::Hex,
        }
    }
    pub(super) fn view(self) -> InspectView {
        match self {
            Self::Hex => InspectView::Hex,
            Self::Struct => InspectView::Struct,
            Self::Disasm => InspectView::Disasm,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InspectorQuery {
    pub space: SpaceKind,
    pub pid: Option<u32>,
    pub address: Option<u64>,
    pub symbol_name: Option<String>,
    pub length: usize,
    pub struct_name: Option<String>,
}

impl Default for InspectorQuery {
    fn default() -> Self {
        Self {
            space: SpaceKind::Kernel,
            pid: None,
            address: None,
            symbol_name: None,
            length: DEFAULT_INSPECT_BYTES,
            struct_name: None,
        }
    }
}

impl App {
    /// Selected result row (columns + cells) on the Analysis page, if any.
    fn current_result_row(&self) -> Option<(String, Vec<String>, Vec<String>)> {
        let result = self.result()?;
        let row = self.visible().get(self.row)?;
        Some((result.plugin.clone(), result.columns.clone(), row))
    }

    /// Pivot from the currently selected result row's PID into a full Process Dossier tab.
    pub(super) fn open_dossier_from_row(&mut self) {
        if self.job.is_some() {
            self.status = "任务执行中；等待完成或按 Esc 取消后再生成档案".into();
            return;
        }
        let pid = self
            .current_result_row()
            .and_then(|(_, cols, row)| extract_pid_from_row(&cols, &row))
            .or(self.analysis_options.pid);
        let Some(pid) = pid else {
            self.status =
                "当前行未包含 PID；请在进程/网络/映射等结果行按 E，或先在参数中设置 PID".into();
            return;
        };
        self.status = format!("正在生成 PID {pid} 进程全景档案…");
        self.start_work(Work::Dossier(pid));
    }

    /// Run the automated forensic triage playbook and open the entity-aggregated board.
    pub(super) fn open_triage(&mut self) {
        if self.job.is_some() {
            self.status = "任务执行中；等待完成或按 Esc 取消后再执行初筛".into();
            return;
        }
        let playbook = match self.shown_os() {
            crate::analysis::Os::Windows => TriagePlaybook::WindowsQuick,
            crate::analysis::Os::Linux => TriagePlaybook::LinuxQuick,
            crate::analysis::Os::Auto => TriagePlaybook::Auto,
        };
        self.status = "正在执行一键应急初筛剧本…".into();
        self.start_work(Work::Triage(playbook));
    }

    /// Open the interactive Memory/Struct/Disasm Inspector from the selected row,
    /// or prompt for an address/symbol if no address is present.
    pub(super) fn open_memory_inspector_from_row(&mut self) {
        if self.job.is_some() {
            self.status = "任务执行中；等待完成或按 Esc 取消后再打开内存检查器".into();
            return;
        }
        if let Some((plugin_name, cols, row)) = self.current_result_row()
            && let Some((address, suggested_struct)) =
                extract_address_from_row(&plugin_name, &cols, &row)
        {
            let pid = extract_pid_from_row(&cols, &row);
            let is_user_va = address < 0x0000_8000_0000_0000
                && pid.is_some()
                && (plugin_name.contains("maps")
                    || plugin_name.contains("malfind")
                    || plugin_name.contains("vad")
                    || plugin_name.contains("dll")
                    || plugin_name.contains("elfs"));
            let query = InspectorQuery {
                space: if is_user_va {
                    SpaceKind::Pid
                } else {
                    SpaceKind::Kernel
                },
                pid: if is_user_va { pid } else { None },
                address: Some(address),
                symbol_name: None,
                length: DEFAULT_INSPECT_BYTES,
                struct_name: suggested_struct.clone(),
            };
            let initial_tab = if suggested_struct.is_some() {
                InspectorTab::Struct
            } else if plugin_name.contains("malfind") {
                InspectorTab::Disasm
            } else {
                InspectorTab::Hex
            };
            self.inspector_history.clear();
            self.launch_inspector_query(query, initial_tab);
            return;
        }
        if self.inspector_report.is_some() {
            self.dialog = Some(Dialog::MemoryInspector {
                tab: InspectorTab::Hex,
                scroll: 0,
                selected_field: 0,
            });
        } else {
            self.open_input(InputKind::InspectAddress);
        }
    }

    pub(super) fn launch_inspector_query(&mut self, query: InspectorQuery, tab: InspectorTab) {
        self.inspector_query = Some(query.clone());
        self.inspector_report = None;
        self.inspector_running = true;
        self.dialog = Some(Dialog::MemoryInspector {
            tab,
            scroll: 0,
            selected_field: 0,
        });
        self.start_work(Work::Inspect(query));
    }

    pub(super) fn draw_memory_inspector(
        &self,
        frame: &mut Frame,
        popup: Rect,
        tab: InspectorTab,
        scroll: usize,
        selected_field: usize,
    ) {
        let mut lines: Vec<Line<'static>> = Vec::new();
        let tab_bar = format!(
            "  {}  {}  {}   |  历史深度: {}",
            if tab == InspectorTab::Hex {
                "[1 Hex]"
            } else {
                " 1 Hex "
            },
            if tab == InspectorTab::Struct {
                "[2 结构体]"
            } else {
                " 2 结构体 "
            },
            if tab == InspectorTab::Disasm {
                "[3 反汇编]"
            } else {
                " 3 反汇编 "
            },
            self.inspector_history.len()
        );
        lines.push(Line::styled(
            tab_bar,
            Style::default()
                .fg(color_focus())
                .add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::raw(""));

        if self.inspector_running {
            lines.push(Line::styled(
                format!("正在读取内存并解析… {}", escaped(&self.status)),
                Style::default().fg(color_accent()),
            ));
        } else if let Some(report) = &self.inspector_report {
            let sym_tag = report
                .resolved_symbol
                .as_deref()
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            lines.push(Line::styled(
                format!(
                    "地址: {:#x}{sym_tag} | 空间: {} | 架构: {} | {} B",
                    report.address, report.space, report.arch, report.length
                ),
                Style::default().fg(color_accent()),
            ));
            if let Some(first) = report.translations.first() {
                let map_line = match first.pa {
                    Some(pa) => format!("映射: VA {:#x} -> PA {:#x}", first.va, pa),
                    None => format!(
                        "映射: VA {:#x} -> 不可转换 ({})",
                        first.va,
                        first.error.as_deref().unwrap_or("缺页")
                    ),
                };
                lines.push(Line::styled(map_line, Style::default().fg(color_muted())));
            }
            if !report.diagnostics.is_empty() {
                lines.push(Line::styled(
                    format!("诊断: {}", report.diagnostics.join("; ")),
                    Style::default().fg(color_warn()),
                ));
            }
            lines.push(Line::raw(""));

            let body_height = popup.height.saturating_sub(7) as usize;
            match tab {
                InspectorTab::Hex => {
                    for line in report.hex_lines.iter().skip(scroll).take(body_height) {
                        lines.push(Line::raw(line.clone()));
                    }
                }
                InspectorTab::Struct => {
                    if let Some(st) = &report.structure {
                        lines.push(Line::styled(
                            format!(
                                "结构体: {} ({} B, {} 字段) · ↑↓ 选字段 · Enter 跟随指针",
                                st.type_name,
                                st.size,
                                st.fields.len()
                            ),
                            Style::default().fg(color_muted()),
                        ));
                        let list_height = body_height.saturating_sub(1).max(1);
                        let start = if selected_field >= scroll + list_height {
                            selected_field + 1 - list_height
                        } else if selected_field < scroll {
                            selected_field
                        } else {
                            scroll
                        };
                        for (idx, f) in st.fields.iter().enumerate().skip(start).take(list_height) {
                            let marker = if idx == selected_field { "› " } else { "  " };
                            let follow = if f.follow_address.is_some() {
                                " → [Enter]"
                            } else {
                                ""
                            };
                            let text = format!(
                                "{marker}+{:#05x} {:<22} {:<20} = {}{follow}",
                                f.offset, f.name, f.type_desc, f.value
                            );
                            let style = if idx == selected_field {
                                Style::default()
                                    .fg(color_focus())
                                    .bg(color_selected_bg())
                                    .add_modifier(Modifier::BOLD)
                            } else if f.follow_address.is_some() {
                                Style::default().fg(color_accent())
                            } else if !f.valid {
                                Style::default().fg(color_muted())
                            } else {
                                Style::default().fg(color_text())
                            };
                            lines.push(Line::styled(text, style));
                        }
                    } else {
                        lines.push(Line::styled(
                            "未指定结构体类型。按 s 输入 ISF/PDB 结构体名（如 task_struct / _EPROCESS / mm_struct）。",
                            Style::default().fg(color_muted()),
                        ));
                    }
                }
                InspectorTab::Disasm => {
                    if report.disasm.is_empty() {
                        lines.push(Line::styled(
                            "无可反汇编指令（当前区域缺页或架构暂不支持 Capstone 反汇编）。",
                            Style::default().fg(color_muted()),
                        ));
                    } else {
                        for insn in report.disasm.iter().skip(scroll).take(body_height) {
                            let note = insn
                                .annotation
                                .as_deref()
                                .map(|a| format!("  ; {a}"))
                                .unwrap_or_default();
                            let text = format!(
                                "{:016x}  {:<22} {:<8} {}{note}",
                                insn.address, insn.bytes, insn.mnemonic, insn.op_str
                            );
                            let style = if insn.annotation.is_some() {
                                Style::default().fg(color_accent())
                            } else {
                                Style::default().fg(color_text())
                            };
                            lines.push(Line::styled(text, style));
                        }
                    }
                }
            }
        } else {
            lines.push(Line::styled(
                format!(
                    "内存检查未完成: {}",
                    escaped(self.last_error.as_deref().unwrap_or("按 g 输入地址或符号"))
                ),
                Style::default().fg(color_warn()),
            ));
        }

        frame.render_widget(
            Paragraph::new(lines)
                .style(Style::default().fg(color_text()).bg(color_surface()))
                .block(panel().title(Line::from(vec![
                    Span::styled(
                        " 内存检查器 ",
                        Style::default()
                            .fg(color_focus())
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "· Hex / 结构体 / Capstone 反汇编 ",
                        Style::default().fg(color_muted()),
                    ),
                ]))),
            popup,
        );

        let mut x = popup.x + 1;
        for (label, key, enabled) in [
            ("[g 跳转]", KeyCode::Char('g'), self.job.is_none()),
            ("[s 结构体]", KeyCode::Char('s'), self.job.is_none()),
            (
                "[← 返回]",
                KeyCode::Backspace,
                !self.inspector_history.is_empty() && self.job.is_none(),
            ),
            (
                "[t 标签页]",
                KeyCode::Char('t'),
                self.inspector_report.is_some(),
            ),
            (
                "[c 复制]",
                KeyCode::Char('c'),
                self.inspector_report.is_some(),
            ),
        ] {
            let width = Span::raw(label).width().cells();
            if x + width + 2 >= popup.right() {
                break;
            }
            let rect = Rect::new(x, popup.bottom().saturating_sub(1), width, 1);
            frame.render_widget(
                Paragraph::new(label).style(Style::default().fg(if enabled {
                    color_accent()
                } else {
                    color_muted()
                })),
                rect,
            );
            if enabled {
                self.hits.borrow_mut().buttons.push((rect, key));
            }
            x += width + 1;
        }
    }

    pub(super) fn memory_inspector_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        let Dialog::MemoryInspector {
            tab,
            scroll,
            selected_field,
        } = &mut dialog
        else {
            self.dialog = Some(dialog);
            return;
        };

        match key.code {
            KeyCode::Char('1') => {
                *tab = InspectorTab::Hex;
                *scroll = 0;
            }
            KeyCode::Char('2') => {
                *tab = InspectorTab::Struct;
                *scroll = 0;
            }
            KeyCode::Char('3') => {
                *tab = InspectorTab::Disasm;
                *scroll = 0;
            }
            KeyCode::Tab => {
                *tab = tab.next();
                *scroll = 0;
            }
            KeyCode::Char('g') if self.job.is_none() => {
                self.back_dialog = Some(Box::new(dialog));
                self.open_input(InputKind::InspectAddress);
                return;
            }
            KeyCode::Char('s') if self.job.is_none() => {
                self.back_dialog = Some(Box::new(dialog));
                self.open_input(InputKind::InspectStruct);
                return;
            }
            KeyCode::Char('c') => {
                if let Some(report) = &self.inspector_report {
                    let text = report.render_text(tab.view());
                    self.copy_detail(&text);
                }
            }
            KeyCode::Char('t') => {
                if let Some(report) = self.inspector_report.clone() {
                    let title = format!("内存 {:#x}", report.address);
                    let text = report.render_text(InspectView::All);
                    self.open_titled_detail_tab(title, text);
                    return;
                }
            }
            KeyCode::Backspace | KeyCode::Left if self.job.is_none() => {
                if let Some((prev_query, prev_tab)) = self.inspector_history.pop() {
                    self.launch_inspector_query(prev_query, prev_tab);
                    return;
                }
            }
            KeyCode::Char('[') if self.job.is_none() => {
                if let Some(mut q) = self.inspector_query.clone()
                    && let Some(addr) = q.address
                {
                    let step = q.length.max(64) as u64;
                    q.address = Some(addr.saturating_sub(step));
                    q.symbol_name = None;
                    let cur_tab = *tab;
                    self.launch_inspector_query(q, cur_tab);
                    return;
                }
            }
            KeyCode::Char(']') if self.job.is_none() => {
                if let Some(mut q) = self.inspector_query.clone()
                    && let Some(addr) = q.address
                {
                    let step = q.length.max(64) as u64;
                    q.address = Some(addr.saturating_add(step));
                    q.symbol_name = None;
                    let cur_tab = *tab;
                    self.launch_inspector_query(q, cur_tab);
                    return;
                }
            }
            KeyCode::Enter if *tab == InspectorTab::Struct && self.job.is_none() => {
                let target = self
                    .inspector_report
                    .as_ref()
                    .and_then(|r| r.structure.as_ref())
                    .and_then(|st| st.fields.get(*selected_field))
                    .and_then(|f| f.follow_address.map(|addr| (addr, f.follow_type.clone())));
                if let Some((addr, follow_type)) = target {
                    if let Some(cur) = self.inspector_query.clone() {
                        self.inspector_history.push((cur, *tab));
                        if self.inspector_history.len() > 64 {
                            self.inspector_history.remove(0);
                        }
                    }
                    let mut next = self.inspector_query.clone().unwrap_or_default();
                    next.address = Some(addr);
                    next.symbol_name = None;
                    next.struct_name = follow_type.clone();
                    let next_tab = if follow_type.is_some() {
                        InspectorTab::Struct
                    } else {
                        InspectorTab::Hex
                    };
                    self.launch_inspector_query(next, next_tab);
                    return;
                }
            }
            KeyCode::Up => {
                if *tab == InspectorTab::Struct {
                    *selected_field = selected_field.saturating_sub(1);
                } else {
                    *scroll = scroll.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if *tab == InspectorTab::Struct {
                    let max = self
                        .inspector_report
                        .as_ref()
                        .and_then(|r| r.structure.as_ref())
                        .map_or(0, |s| s.fields.len().saturating_sub(1));
                    *selected_field = selected_field.saturating_add(1).min(max);
                } else {
                    let max = self.inspector_max_scroll(*tab);
                    *scroll = scroll.saturating_add(1).min(max);
                }
            }
            KeyCode::PageUp => {
                if *tab == InspectorTab::Struct {
                    *selected_field = selected_field.saturating_sub(10);
                } else {
                    *scroll = scroll.saturating_sub(10);
                }
            }
            KeyCode::PageDown => {
                if *tab == InspectorTab::Struct {
                    let max = self
                        .inspector_report
                        .as_ref()
                        .and_then(|r| r.structure.as_ref())
                        .map_or(0, |s| s.fields.len().saturating_sub(1));
                    *selected_field = selected_field.saturating_add(10).min(max);
                } else {
                    let max = self.inspector_max_scroll(*tab);
                    *scroll = scroll.saturating_add(10).min(max);
                }
            }
            KeyCode::Home => {
                *scroll = 0;
                *selected_field = 0;
            }
            KeyCode::End => {
                if *tab == InspectorTab::Struct {
                    *selected_field = self
                        .inspector_report
                        .as_ref()
                        .and_then(|r| r.structure.as_ref())
                        .map_or(0, |s| s.fields.len().saturating_sub(1));
                } else {
                    *scroll = self.inspector_max_scroll(*tab);
                }
            }
            _ => {}
        }
        self.dialog = Some(dialog);
    }

    fn inspector_max_scroll(&self, tab: InspectorTab) -> usize {
        let Some(report) = &self.inspector_report else {
            return 0;
        };
        let popup = self.hits.borrow().popup;
        let visible = popup.height.saturating_sub(7) as usize;
        let total = match tab {
            InspectorTab::Hex => report.hex_lines.len(),
            InspectorTab::Struct => report.structure.as_ref().map_or(0, |s| s.fields.len()),
            InspectorTab::Disasm => report.disasm.len(),
        };
        total.saturating_sub(visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::{
        DisasmLine, InspectReport, PageTranslation, StructFieldView, StructInspection,
    };
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn memory_inspector_renders_tabs_and_expands_to_detail_tab() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            None,
            dir.path().to_path_buf(),
            dir.path().join("cache"),
            Settings::default(),
        );
        app.inspector_report = Some(Arc::new(InspectReport {
            os: "linux".into(),
            arch: "x64".into(),
            space: "kernel".into(),
            pid: None,
            address: 0xffff_8880_0000_1000,
            resolved_symbol: Some("init_task".into()),
            length: 16,
            complete: true,
            banner: "Linux version 6.1.0".into(),
            symbol_label: "test.isf".into(),
            bytes: vec![0x90; 16],
            valid_mask: vec![true; 16],
            translations: vec![PageTranslation {
                va: 0xffff_8880_0000_1000,
                pa: Some(0x1000),
                error: None,
            }],
            hex_lines: vec!["ffff888000001000  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|".into()],
            structure: Some(StructInspection {
                type_name: "task_struct".into(),
                size: 16,
                fields: vec![StructFieldView {
                    offset: 0,
                    size: 8,
                    name: "parent".into(),
                    type_desc: "*struct task_struct".into(),
                    value: "0xffffffff81200000 (init_task)".into(),
                    valid: true,
                    follow_address: Some(0xffff_ffff_8120_0000),
                    follow_type: Some("task_struct".into()),
                }],
                diagnostics: Vec::new(),
            }),
            disasm: vec![DisasmLine {
                address: 0xffff_8880_0000_1000,
                bytes: "90".into(),
                mnemonic: "nop".into(),
                op_str: String::new(),
                annotation: None,
            }],
            diagnostics: Vec::new(),
        }));
        app.dialog = Some(Dialog::MemoryInspector {
            tab: InspectorTab::Struct,
            scroll: 0,
            selected_field: 0,
        });

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        let compact: String = buffer
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .filter(|s| *s != " ")
            .collect();
        assert!(compact.contains("内存检查器"));
        assert!(compact.contains("task_struct"));
        assert!(compact.contains("parent"));

        // Switch to Disasm with '3', then expand to Detail tab with 't'.
        app.dialog_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
        assert!(matches!(
            app.dialog,
            Some(Dialog::MemoryInspector {
                tab: InspectorTab::Disasm,
                ..
            })
        ));
        app.dialog_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert!(app.dialog.is_none());
        assert!(app.active_detail().is_some());
    }
}
