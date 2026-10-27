use super::*;
impl App {
    pub(super) fn open_kernel_diagnostics(&mut self) {
        let symbols = if self.symbols.as_os_str().is_empty() {
            self.directory(&self.settings.symbols)
        } else {
            self.symbols.clone()
        };
        let stale = self.kernel_report.as_ref().is_some_and(|report| {
            self.image
                .as_ref()
                .is_none_or(|image| !same_path(&report.image, image))
                || !same_path(&report.symbol_source, &symbols)
                || report.symbol_choice.as_deref() != self.choice.as_deref()
        });
        if stale {
            if self.job.is_some() {
                self.status = "对象选择已变化；等待当前任务完成后重新诊断".into();
                return;
            }
            self.kernel_report = None;
        }
        self.dialog = Some(Dialog::KernelDiagnostics { scroll: 0 });
        if self.kernel_report.is_none() && self.job.is_none() {
            self.start_work(Work::KernelDiagnostic);
        }
    }
    pub(super) fn kernel_diagnostic_text(&self) -> String {
        if let Some(report) = &self.kernel_report {
            let mut text = report.text();
            for root in [
                self.root
                    .canonicalize()
                    .unwrap_or_else(|_| self.root.clone()),
                self.root.clone(),
            ] {
                if root != std::path::Path::new("/") {
                    text = text.replace(&format!("{}/", root.display()), "");
                }
            }
            return text;
        }
        if self.diagnosis_running {
            format!(
                "正在生成内核诊断报告\n\n{}\n\n镜像和本地符号校验在后台执行。\nEsc 取消诊断并关闭。",
                escaped(&self.status)
            )
        } else {
            format!(
                "诊断未完成\n{}\n\nr 重新诊断",
                escaped(self.last_error.as_deref().unwrap_or("尚无报告"))
            )
        }
    }
    pub(super) fn draw_kernel_diagnostics(&self, frame: &mut Frame, popup: Rect, scroll: usize) {
        let text = self.kernel_diagnostic_text();
        let lines = detail_lines(&text, popup.width.saturating_sub(2));
        frame.render_widget(
            Paragraph::new(
                lines
                    .into_iter()
                    .skip(scroll)
                    .map(Line::raw)
                    .collect::<Vec<_>>(),
            )
            .style(Style::default().fg(color_text()).bg(color_surface()))
            .block(panel().title("内核诊断 · ↑↓ / PgUp PgDn 滚动")),
            popup,
        );
        let mut x = popup.x + 1;
        for (label, key, enabled) in [
            ("[重新诊断 r]", KeyCode::Char('r'), self.job.is_none()),
            (
                "[导出 e]",
                KeyCode::Char('e'),
                self.kernel_report.is_some() && self.job.is_none(),
            ),
        ] {
            let width = Span::raw(label).width() as u16;
            if x + width + 8 >= popup.right() {
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
    pub(super) fn kernel_diagnostics_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        if key.code == KeyCode::Char('r') && self.job.is_none() {
            self.kernel_report = None;
            self.start_work(Work::KernelDiagnostic);
            self.dialog = Some(Dialog::KernelDiagnostics { scroll: 0 });
            return;
        }
        if key.code == KeyCode::Char('e') && self.kernel_report.is_some() && self.job.is_none() {
            self.open_input(InputKind::DiagnosticExport);
            return;
        }
        if let Dialog::KernelDiagnostics { scroll } = &mut dialog {
            let popup = self.hits.borrow().popup;
            let maximum = detail_lines(
                &self.kernel_diagnostic_text(),
                popup.width.saturating_sub(2),
            )
            .len()
            .saturating_sub(popup.height.saturating_sub(2) as usize);
            *scroll = match key.code {
                KeyCode::Up => scroll.saturating_sub(1),
                KeyCode::Down => scroll.saturating_add(1).min(maximum),
                KeyCode::PageUp => scroll.saturating_sub(10),
                KeyCode::PageDown => scroll.saturating_add(10).min(maximum),
                KeyCode::Home => 0,
                KeyCode::End => maximum,
                _ => *scroll,
            };
        }
        self.dialog = Some(dialog);
    }
}
