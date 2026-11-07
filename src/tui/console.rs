//! Symbol-generation console on the resource page: a guided, one-key path from
//! the selected image to saved, selected symbols.
//!
//! The console only decides what to offer; every method runs through the same
//! `Work` items and generation service as the dialog and the command line, so
//! validation, provenance and caching are identical. It checks the image, the
//! identified kernel and the environment, recommends the most complete method
//! that can work, and keeps a readable log and result of the last run.
use super::*;
use crate::bytes::Cells;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Method {
    /// Official distribution debug package converted by dwarf2json.
    Official,
    /// The image's own BTF types and kallsyms addresses.
    FromImage,
    /// Debug ELF and config the user already has.
    LocalFiles,
}
impl Method {
    pub(super) const ALL: [Self; 3] = [Self::Official, Self::FromImage, Self::LocalFiles];
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Official => "官方调试包",
            Self::FromImage => "从镜像生成",
            Self::LocalFiles => "本地调试文件",
        }
    }
    fn summary(self) -> &'static str {
        match self {
            Self::Official => "从 Ubuntu / Debian / Kali 官方源下载调试包并转换；类型与符号最完整",
            Self::FromImage => "用镜像自带的 BTF 类型与 kallsyms 地址生成；无需网络和工具",
            Self::LocalFiles => "已有 vmlinux 调试 ELF 与内核 config 时使用；填写路径后转换",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Readiness {
    Ready,
    /// Can run, but something limits it (offline, kernel not yet identified).
    Limited,
    Blocked,
}

pub(super) struct MethodState {
    pub(super) method: Method,
    pub(super) readiness: Readiness,
    pub(super) notes: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) enum ConsoleResult {
    Saved(Method, PathBuf),
    Failed(Method, String),
    Cancelled(Method),
}

#[derive(Default)]
pub(super) struct Console {
    pub(super) selected: usize,
    /// Method whose work is in flight (or waiting in its follow-up dialog).
    pub(super) running: Option<Method>,
    pub(super) log: Vec<String>,
    pub(super) result: Option<ConsoleResult>,
    /// `missing_build_tools()` at the last check; `None` before the first.
    pub(super) missing_tools: Option<Vec<&'static str>>,
}

const LOG_LIMIT: usize = 400;

/// Generation work the console follows from start to result.
pub(super) fn generation_work(work: &Work) -> bool {
    matches!(
        work,
        Work::GenerateFromImage
            | Work::FindKernelPackages(_)
            | Work::PrepareKernel(_)
            | Work::GenerateSymbols(_)
    )
}

/// Message prefix that repeats while a long step reports progress.
fn progress_key(line: &str) -> &str {
    line.split([':', '：']).next().unwrap_or(line)
}

impl App {
    fn console_banner(&self) -> Option<String> {
        self.results.get("banners").and_then(|r| {
            banner_candidates(r)
                .first()
                .and_then(|row| row.get(1))
                .cloned()
        })
    }

    fn dwarf2json_prepared(&self) -> bool {
        self.cache
            .join("symbols/build/dwarf2json")
            .join(format!("dwarf2json{}", std::env::consts::EXE_SUFFIX))
            .is_file()
    }

    pub(super) fn console_methods(&self) -> Vec<MethodState> {
        let banner = self.console_banner();
        let arm64 = banner
            .as_deref()
            .is_some_and(|b| b.contains("aarch64") || b.contains("arm64"));
        let common = if self.image.is_none() {
            Some("请先选用镜像（i 导入，或在“镜像”标签 Space 选用）")
        } else if self.windows {
            Some("Windows 镜像无需生成：按 M 获取精确 PDB 符号")
        } else {
            None
        };
        Method::ALL
            .iter()
            .map(|&method| {
                let mut notes = Vec::new();
                let readiness = if let Some(reason) = common {
                    notes.push(reason.to_owned());
                    Readiness::Blocked
                } else {
                    match method {
                        Method::Official => {
                            let tools = self.console.missing_tools.clone().unwrap_or_default();
                            if !self.supports_automatic_symbols() {
                                notes.push(if banner.is_some() {
                                    "无法从 banner 确定 Ubuntu / Debian / Kali 发行版与架构".into()
                                } else {
                                    "内核尚未识别；识别完成后再检查".into()
                                });
                                Readiness::Blocked
                            } else if !self.dwarf2json_prepared() && !tools.is_empty() {
                                notes.push(format!(
                                    "缺少 {}，无法编译 dwarf2json；安装后按 r 重新检查",
                                    tools.join("、")
                                ));
                                Readiness::Blocked
                            } else if !self.settings.remote_symbols {
                                notes.push("离线：只能复用已下载的调试包；o 切换在线".into());
                                Readiness::Limited
                            } else {
                                notes.push("需联网下载数百 MB 调试包；官方源可能已下架旧版本".into());
                                Readiness::Ready
                            }
                        }
                        Method::FromImage => {
                            if arm64 {
                                notes.push("ARM64 无法独立生成；可验证并复用精确本地 ISF，无需网络或编译工具".into());
                                Readiness::Limited
                            } else {
                                notes.push(
                                    "需内核启用 BTF 与 KALLSYMS_ALL；少数依赖全局变量类型的插件会提示不支持"
                                        .into(),
                                );
                                if banner.is_none() {
                                    notes.push("内核尚未识别；生成时会自动校验".into());
                                    Readiness::Limited
                                } else {
                                    Readiness::Ready
                                }
                            }
                        }
                        Method::LocalFiles => Readiness::Ready,
                    }
                };
                MethodState {
                    method,
                    readiness,
                    notes,
                }
            })
            .collect()
    }

    /// The most complete method that can run: an official package when it is
    /// fully available, otherwise the image itself, otherwise local files.
    pub(super) fn console_recommended(&self, states: &[MethodState]) -> Option<usize> {
        let find = |method: Method, accept: &[Readiness]| {
            states
                .iter()
                .position(|s| s.method == method && accept.contains(&s.readiness))
        };
        find(Method::Official, &[Readiness::Ready])
            .or_else(|| find(Method::FromImage, &[Readiness::Ready, Readiness::Limited]))
            .or_else(|| find(Method::Official, &[Readiness::Limited]))
            .or_else(|| find(Method::LocalFiles, &[Readiness::Ready]))
    }

    pub(super) fn console_refresh(&mut self) {
        self.console.missing_tools = Some(crate::prepare::missing_build_tools());
        if self.console.running.is_none() || self.job.is_none() {
            let states = self.console_methods();
            if let Some(index) = self.console_recommended(&states) {
                self.console.selected = index;
            }
        }
    }

    pub(super) fn open_generation_console(&mut self) {
        self.dialog = None;
        self.page = Page::Assets;
        self.asset_console = true;
        self.focus = Focus::Navigation;
        self.console_refresh();
        self.status = if self.image.is_none() {
            "符号表生成控制台：请先选用镜像（i 导入，或在“镜像”标签 Space 选用）".into()
        } else {
            "符号表生成控制台：↑↓ 选择方式，Enter 开始".into()
        };
    }

    pub(super) fn console_start(&mut self) {
        if self.job.is_some() {
            self.status = "已有任务运行；等待完成或 Esc 取消".into();
            return;
        }
        let states = self.console_methods();
        let Some(state) = states.get(self.console.selected) else {
            return;
        };
        if state.readiness == Readiness::Blocked {
            self.status = state.notes.first().cloned().unwrap_or_default();
            return;
        }
        let method = state.method;
        self.console.log.clear();
        self.console.result = None;
        self.console.running = Some(method);
        match method {
            Method::FromImage => self.start_work(Work::GenerateFromImage),
            Method::Official => self.start_work(Work::FindKernelPackages(false)),
            Method::LocalFiles => {
                self.open_symbol_generation();
                if let Some(Dialog::GenerateSymbols {
                    automatic, field, ..
                }) = self.dialog.as_mut()
                {
                    *automatic = false;
                    *field = 0;
                }
            }
        }
    }

    /// Progress from a console-started task; repeated step messages replace
    /// the previous line so the log stays readable.
    pub(super) fn console_progress(&mut self, line: &str) {
        if self.console.running.is_none() {
            return;
        }
        let line = line.to_owned();
        match self.console.log.last_mut() {
            Some(last) if progress_key(last) == progress_key(&line) && last.contains(':') => {
                *last = line;
            }
            _ => self.console.log.push(line),
        }
        if self.console.log.len() > LOG_LIMIT {
            self.console.log.remove(0);
        }
    }

    pub(super) fn console_saved(&mut self, path: &std::path::Path) -> bool {
        let Some(method) = self.console.running.take() else {
            return false;
        };
        self.console.result = Some(ConsoleResult::Saved(method, path.to_path_buf()));
        true
    }

    pub(super) fn console_failed(&mut self, error: &str) {
        let Some(method) = self.console.running.take() else {
            return;
        };
        self.console.result = Some(ConsoleResult::Failed(method, error.to_owned()));
        if method == Method::Official {
            // The image path needs nothing that just failed; offer it next.
            let states = self.console_methods();
            if let Some(index) = states
                .iter()
                .position(|s| s.method == Method::FromImage && s.readiness != Readiness::Blocked)
            {
                self.console.selected = index;
            }
        }
    }

    pub(super) fn console_cancelled(&mut self) {
        if let Some(method) = self.console.running.take() {
            self.console.result = Some(ConsoleResult::Cancelled(method));
        }
    }

    /// Keys while the console is shown. Row actions of the hidden lists are not
    /// reachable; global commands keep working.
    pub(super) fn console_key(&mut self, key: KeyEvent) -> bool {
        let count = Method::ALL.len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.console.selected = self.console.selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.console.selected = (self.console.selected + 1).min(count - 1);
            }
            KeyCode::Enter => self.console_start(),
            KeyCode::Char('r') => {
                self.refresh_assets();
                self.console_refresh();
                self.status = "已重新检查镜像、内核与环境".into();
            }
            KeyCode::Tab => self.switch_section(AssetSection::Images),
            KeyCode::BackTab => self.switch_section(AssetSection::Remote),
            code => {
                if let Some(command) = Command::from_key(Page::Assets, code) {
                    if matches!(
                        command,
                        Command::Select
                            | Command::SelectAndEnter
                            | Command::AssetDetail
                            | Command::DeleteAsset
                            | Command::SearchAssets
                            | Command::ToggleSource
                            | Command::FetchIndex
                            | Command::Download
                            | Command::ToggleMatchFilter
                            | Command::ImportCurrent
                    ) {
                        self.status = "该操作作用于资源列表；Tab 切换到列表标签".into();
                        return false;
                    }
                    return self.run_command(command);
                }
            }
        }
        false
    }

    /// Actions for the footer strip while the console is shown.
    pub(super) fn console_actions(&self) -> Vec<(&'static str, KeyCode)> {
        let mut actions = Vec::new();
        if self.job.is_some() {
            actions.push(("取消任务 Esc", KeyCode::Esc));
        } else {
            actions.push(("开始生成 Enter", KeyCode::Enter));
        }
        actions.push(("重新检查 r", KeyCode::Char('r')));
        if self.image.is_none() {
            actions.push(("导入镜像 i", KeyCode::Char('i')));
        }
        if self.preparation == Preparation::Ready {
            actions.push(("进入分析 x", KeyCode::Char('x')));
        }
        actions.push(("切换列表 Tab", KeyCode::Tab));
        actions.push(("更多 ?", KeyCode::Char('?')));
        actions
    }

    pub(super) fn draw_console_actions(&self, frame: &mut Frame, area: Rect) {
        if area.height == 0 {
            return;
        }
        let mut x = area.x;
        for (label, key) in self.console_actions() {
            let text = format!(" {label} ");
            let width = Span::raw(&text).width().cells();
            if x + width > area.right() {
                break;
            }
            let rect = Rect::new(x, area.y, width, 1);
            let primary = matches!(key, KeyCode::Enter | KeyCode::Esc);
            frame.render_widget(
                Paragraph::new(text).style(if primary {
                    Style::default()
                        .fg(color_focus())
                        .bg(color_selected_bg())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(color_text()).bg(color_raised())
                }),
                rect,
            );
            self.hits.borrow_mut().buttons.push((rect, key));
            x += width + 1;
        }
    }

    fn console_check_lines(&self, width: u16) -> Vec<Line<'static>> {
        let ok = Style::default().fg(color_success());
        let warn = Style::default().fg(color_warn());
        let bad = Style::default().fg(color_danger());
        let value = Style::default().fg(color_text());
        let width = usize::from(width);
        let step = |n: &str, mark: (&'static str, Style), label: &str, text: String| {
            let head = format!("{n} {label}  ");
            let budget = width.saturating_sub(Span::raw(&head).width() + 2);
            Line::from(vec![
                Span::styled(mark.0, mark.1),
                Span::raw(" "),
                Span::styled(head, Style::default().fg(color_accent())),
                Span::styled(truncate_with_ellipsis(&escaped(&text), budget), value),
            ])
        };
        let image = match &self.image {
            Some(path) => step("①", ("✓", ok), "镜像", self.display_path(path)),
            None => step(
                "①",
                ("✗", bad),
                "镜像",
                "尚未选用；按 i 导入或在“镜像”标签 Space 选用".into(),
            ),
        };
        let kernel = if self.windows {
            step(
                "②",
                ("•", warn),
                "内核",
                "Windows 镜像：使用 M 获取 PDB 符号".into(),
            )
        } else if let Some(banner) = self.console_banner() {
            step("②", ("✓", ok), "内核", summarise_banner(&banner))
        } else if self.preparation == Preparation::Matching {
            step("②", ("…", warn), "内核", "正在识别".into())
        } else {
            step(
                "②",
                ("•", warn),
                "内核",
                "尚未识别；选用镜像后自动识别".into(),
            )
        };
        let symbols = match self.preparation {
            Preparation::Ready => step(
                "③",
                ("✓", ok),
                "符号",
                format!(
                    "已选用 {}；可直接分析，也可重新生成",
                    self.display_path(&self.symbols)
                ),
            ),
            Preparation::ChooseSymbols => step(
                "③",
                ("•", warn),
                "符号",
                "有多个精确候选；在“本地库”选择即可".into(),
            ),
            _ if self.image.is_some() && !self.windows => step(
                "③",
                ("✗", bad),
                "符号",
                "缺少精确符号；在下方选择生成方式".into(),
            ),
            _ => step("③", ("•", warn), "符号", "等待镜像".into()),
        };
        vec![image, kernel, symbols]
    }

    fn console_result_lines(&self, width: u16) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        let wrap = |text: &str, style: Style, lines: &mut Vec<Line<'static>>| {
            lines.extend(
                detail_lines(text, width)
                    .into_iter()
                    .map(|line| Line::styled(line, style)),
            );
        };
        if self.job.is_some()
            && let Some(method) = self.console.running
        {
            let elapsed = self.started.map_or(0.0, |s| s.elapsed().as_secs_f64());
            wrap(
                &format!(
                    "● 正在用“{}”生成 · 已用 {} · Esc 取消",
                    method.title(),
                    status::format_duration(elapsed)
                ),
                Style::default()
                    .fg(color_accent())
                    .add_modifier(Modifier::BOLD),
                &mut lines,
            );
            return lines;
        }
        match &self.console.result {
            Some(ConsoleResult::Saved(method, path)) => {
                let reused = self
                    .console
                    .log
                    .iter()
                    .any(|line| line.contains("复用本地精确符号："));
                let title = if reused {
                    "✓ 已验证并复用本地精确符号表，已选用".into()
                } else {
                    format!("✓ 已通过“{}”生成并选用符号表", method.title())
                };
                wrap(
                    &title,
                    Style::default()
                        .fg(color_success())
                        .add_modifier(Modifier::BOLD),
                    &mut lines,
                );
                wrap(
                    &escaped(&self.display_path(path)),
                    Style::default().fg(color_text()),
                    &mut lines,
                );
                if *method == Method::FromImage && !reused {
                    wrap(
                        "提示：BTF 不记录多数全局变量类型，check_syscall、check_afinfo、boottime 与模块 taint 列会明确提示不支持。",
                        Style::default().fg(color_muted()),
                        &mut lines,
                    );
                }
                wrap(
                    "按 x 进入分析。",
                    Style::default().fg(color_focus()),
                    &mut lines,
                );
            }
            Some(ConsoleResult::Failed(method, error)) => {
                wrap(
                    &format!("✗ “{}”未完成", method.title()),
                    Style::default()
                        .fg(color_danger())
                        .add_modifier(Modifier::BOLD),
                    &mut lines,
                );
                wrap(
                    &escaped(error),
                    Style::default().fg(color_text()),
                    &mut lines,
                );
                let next = match method {
                    Method::Official => {
                        "建议：已切换到“从镜像生成”，按 Enter 重试；或使用本地调试文件。"
                    }
                    Method::FromImage => {
                        "建议：缺少 BTF / 必需全局符号或架构不支持时，将尝试验证并复用精确本地 ISF；没有本地 ISF 时可用官方调试包或本地调试文件。"
                    }
                    Method::LocalFiles => {
                        "建议：确认 ELF 含 DWARF 调试信息，且与镜像内核完全一致。"
                    }
                };
                wrap(next, Style::default().fg(color_warn()), &mut lines);
            }
            Some(ConsoleResult::Cancelled(method)) => wrap(
                &format!("“{}”已取消；按 Enter 重新开始", method.title()),
                Style::default().fg(color_warn()),
                &mut lines,
            ),
            None if self.console.running.is_some() => wrap(
                "等待在弹出窗口中确认（调试包候选或调试文件路径）。",
                Style::default().fg(color_accent()),
                &mut lines,
            ),
            None => {}
        }
        lines
    }

    pub(super) fn draw_generation_console(&self, frame: &mut Frame, area: Rect) {
        if area.height < 3 || area.width < 10 {
            return;
        }
        frame.render_widget(panel().title("符号表生成控制台"), area);
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        let states = self.console_methods();
        let recommended = self.console_recommended(&states);
        let checks = self.console_check_lines(inner.width);
        let result = self.console_result_lines(inner.width);
        // Steps, methods (three lines each), result, then the log takes the rest.
        let method_height = (states.len() * 3 + 1).cells();
        let parts = Layout::vertical([
            Constraint::Length(checks.len().cells() + 1),
            Constraint::Length(method_height),
            Constraint::Length(result.len().cells()),
            Constraint::Min(0),
        ])
        .split(inner);
        frame.render_widget(Paragraph::new(checks), parts.rect(0));
        let methods = parts.rect(1);
        frame.render_widget(
            Paragraph::new(Line::styled(
                "选择生成方式 · ↑↓ 或点击选择 · Enter 开始",
                Style::default().fg(color_muted()),
            )),
            Rect::new(methods.x, methods.y, methods.width, 1.min(methods.height)),
        );
        let busy = self.job.is_some();
        for (index, state) in states.iter().enumerate() {
            let y = methods.y + 1 + (index * 3).cells();
            if y >= methods.bottom() {
                break;
            }
            let rect = Rect::new(methods.x, y, methods.width, (methods.bottom() - y).min(3));
            let selected = index == self.console.selected;
            let (mark, color) = match state.readiness {
                Readiness::Ready => ("可用", color_success()),
                Readiness::Limited => ("受限", color_warn()),
                Readiness::Blocked => ("不可用", color_danger()),
            };
            let mut title = vec![
                Span::styled(
                    if selected { "› " } else { "  " },
                    Style::default().fg(color_focus()),
                ),
                Span::styled(
                    state.method.title(),
                    Style::default()
                        .fg(if selected {
                            color_focus()
                        } else {
                            color_text()
                        })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(format!("[{mark}]"), Style::default().fg(color)),
            ];
            if recommended == Some(index) {
                title.push(Span::styled(
                    " 推荐",
                    Style::default()
                        .fg(color_accent())
                        .add_modifier(Modifier::BOLD),
                ));
            }
            let budget = usize::from(rect.width.saturating_sub(4));
            let detail = Style::default().fg(if state.readiness == Readiness::Blocked {
                color_muted()
            } else {
                color_text()
            });
            let lines = vec![
                Line::from(title),
                Line::styled(
                    format!(
                        "    {}",
                        truncate_with_ellipsis(state.method.summary(), budget)
                    ),
                    detail,
                ),
                Line::styled(
                    format!(
                        "    {}",
                        truncate_with_ellipsis(&state.notes.join("；"), budget)
                    ),
                    Style::default().fg(color),
                ),
            ];
            let style = if selected {
                Style::default().bg(color_selected_bg())
            } else {
                Style::default()
            };
            frame.render_widget(Paragraph::new(lines).style(style), rect);
            if !busy {
                self.hits.borrow_mut().console_methods.push((rect, index));
            }
        }
        frame.render_widget(Paragraph::new(result), parts.rect(2));
        let log_area = parts.rect(3);
        if log_area.height >= 3 {
            let visible = usize::from(log_area.height.saturating_sub(2));
            let start = self.console.log.len().saturating_sub(visible);
            let budget = usize::from(log_area.width.saturating_sub(2));
            let lines: Vec<Line> = if self.console.log.is_empty() {
                vec![Line::styled(
                    "开始后在此显示每一步：定位、下载、校验、转换与保存。",
                    Style::default().fg(color_muted()),
                )]
            } else {
                self.console
                    .log
                    .iter()
                    .skip(start)
                    .map(|line| {
                        Line::styled(
                            truncate_with_ellipsis(&escaped(line), budget),
                            Style::default().fg(color_muted()),
                        )
                    })
                    .collect()
            };
            frame.render_widget(
                Paragraph::new(lines).block(panel().title("运行日志")),
                log_area,
            );
        }
    }
}
