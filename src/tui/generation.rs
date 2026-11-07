use super::*;
use crate::bytes::Cells;

impl App {
    pub(super) fn open_symbol_generation(&mut self) {
        if self.image.is_none() {
            self.status = "请先在资源库用 Space 选用镜像".into();
            return;
        }
        if self.windows {
            self.status = "Windows 使用 M 获取当前镜像的精确 PDB 符号".into();
            return;
        }
        self.back_dialog = None;
        let automatic = self.supports_automatic_symbols();
        let prepared_tool = self.cache.join("symbols/build/dwarf2json/dwarf2json");
        self.dialog = Some(Dialog::GenerateSymbols {
            automatic,
            fields: [
                String::new(),
                String::new(),
                if prepared_tool.is_file() {
                    prepared_tool.display().to_string()
                } else {
                    "dwarf2json".into()
                },
            ],
            field: if automatic { 3 } else { 0 },
            cursor: 0,
            selected: true,
            error: String::new(),
        });
    }

    pub(super) fn generation_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        let Dialog::GenerateSymbols {
            automatic,
            fields,
            field,
            cursor,
            selected,
            error,
        } = &mut dialog
        else {
            return;
        };
        if key.code == KeyCode::F(8) {
            self.start_work(Work::GenerateFromImage);
            return;
        }
        if key.code == KeyCode::F(7) {
            if self.supports_automatic_symbols() {
                *automatic = !*automatic;
                *field = if *automatic { 3 } else { 0 };
                *cursor = 0;
                *selected = true;
                error.clear();
            } else {
                *error = "该内核尚不支持自动获取调试资料；请填写匹配的 ELF 和配置".into();
            }
        } else if key.code == KeyCode::Enter
            && (*field == 3 || key.modifiers.contains(KeyModifiers::CONTROL))
        {
            if *automatic {
                self.start_work(Work::FindKernelPackages(false));
                return;
            }
            let paths = fields.clone().map(|text| store::expand_home(text.trim()));
            let [elf, config, mut tool] = paths;
            if !tool.is_file()
                && tool.components().count() == 1
                && let Some(found) = std::env::var_os("PATH").and_then(|value| {
                    std::env::split_paths(&value)
                        .map(|dir| dir.join(&tool))
                        .find(|path| path.is_file())
                })
            {
                tool = found;
            }
            if let Some((label, _)) = [
                ("调试 ELF", &elf),
                ("内核配置", &config),
                ("dwarf2json", &tool),
            ]
            .into_iter()
            .find(|(_, path)| !path.is_file())
            {
                *error = format!("{label} 文件不存在；请填写有效路径");
            } else {
                self.start_work(Work::GenerateSymbols([elf, config, tool]));
                return;
            }
        } else if matches!(
            key.code,
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Down | KeyCode::Up | KeyCode::Enter
        ) {
            if !*automatic {
                let back = matches!(key.code, KeyCode::BackTab | KeyCode::Up);
                *field = (*field + if back { 3 } else { 1 }) % 4;
                *cursor = if *field < 3 {
                    fields.get(*field).map_or(0, String::len)
                } else {
                    0
                };
                *selected = true;
            }
        } else if *field < 3
            && !*automatic
            && let Some(text) = fields.get_mut(*field)
        {
            edit_input(text, cursor, selected, key);
        }
        self.dialog = Some(dialog);
    }

    pub(super) fn draw_generation(&self, frame: &mut Frame, area: Rect, dialog: &Dialog) {
        let Dialog::GenerateSymbols {
            automatic,
            fields,
            field,
            error,
            ..
        } = dialog
        else {
            return;
        };
        frame.render_widget(panel().title("生成当前镜像符号表"), area);
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        let image = self
            .image
            .as_ref()
            .map(|path| self.display_path(path))
            .unwrap_or_default();
        let mode = if *automatic {
            "自动查找 Ubuntu / Debian / Kali 官方调试包；F7 手动输入"
        } else {
            "使用当前内核的调试 ELF 和配置；F7 切换自动获取（支持的构建）"
        };
        let mut lines = vec![
            Line::raw(format!("当前镜像：{image}")),
            Line::raw("符号表用于解析内核结构；生成后校验完整 banner，保存到本地库并选用。"),
            Line::raw(mode),
        ];
        if *automatic {
            lines.push(Line::raw(if self.settings.remote_symbols {
                "将复用精确本地符号；缺少时先查找并展示来源，选择后下载生成。"
            } else {
                "离线：仅复用已有精确符号、调试包和生成工具。"
            }));
        } else {
            for (index, label) in ["调试 ELF", "内核配置", "dwarf2json 路径"]
                .into_iter()
                .enumerate()
            {
                let y = inner.y.saturating_add(lines.len().cells());
                lines.push(Line::styled(
                    format!(
                        "{} {label}: {}",
                        if *field == index { "›" } else { " " },
                        escaped(fields.get(index).map_or("", String::as_str))
                    ),
                    Style::default().fg(if *field == index {
                        color_focus()
                    } else {
                        color_accent()
                    }),
                ));
                if y < inner.bottom() {
                    self.hits
                        .borrow_mut()
                        .dump_fields
                        .push((Rect::new(inner.x, y, inner.width, 1), index));
                }
            }
        }
        lines.push(Line::raw(
            "F8 无需调试包：从镜像自带 BTF 与 kallsyms 生成（x86_64；全局变量仅 BTF 记录的有类型）。",
        ));
        let y = inner.y.saturating_add(lines.len().cells());
        lines.push(Line::styled(
            "[生成并选用 Enter]  [切换方式 F7]  [从镜像生成 F8]  [取消 Esc]",
            Style::default().fg(color_focus()),
        ));
        lines.push(Line::raw(
            "Tab 切换字段；Ctrl+Enter 执行。内存镜像保持只读。",
        ));
        lines.push(Line::styled(
            escaped(error),
            Style::default().fg(color_danger()),
        ));
        if y < inner.bottom() {
            let mut x = inner.x;
            for (label, key) in [
                ("[生成并选用 Enter]  ", KeyCode::Enter),
                ("[切换方式 F7]  ", KeyCode::F(7)),
                ("[从镜像生成 F8]  ", KeyCode::F(8)),
                ("[取消 Esc]", KeyCode::Esc),
            ] {
                let width = (Span::raw(label).width().cells()).min(inner.right().saturating_sub(x));
                self.hits
                    .borrow_mut()
                    .buttons
                    .push((Rect::new(x, y, width, 1), key));
                x += width;
            }
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

impl App {
    pub(super) fn kernel_packages_key(&mut self, mut dialog: Dialog, key: KeyEvent) {
        let Dialog::KernelPackages { packages, selected } = &mut dialog else {
            return;
        };
        match key.code {
            KeyCode::F(5) => {
                if !self.settings.remote_symbols {
                    self.status = "离线模式不能刷新官方索引；可直接选用已有候选".into();
                    self.dialog = Some(dialog);
                    return;
                }
                self.start_work(Work::FindKernelPackages(true));
                return;
            }
            KeyCode::Up => *selected = selected.saturating_sub(1),
            KeyCode::Down => *selected = (*selected + 1).min(packages.len().saturating_sub(1)),
            KeyCode::Enter => {
                if let Some(package) = packages.get(*selected) {
                    self.start_work(Work::PrepareKernel(package.clone()));
                    return;
                }
            }
            _ => {}
        }
        self.dialog = Some(dialog);
    }

    pub(super) fn draw_kernel_packages(
        &self,
        frame: &mut Frame,
        area: Rect,
        packages: &[crate::prepare::KernelPackage],
        selected: usize,
    ) {
        frame.render_widget(
            panel().title("官方调试包 · ↑↓ 选择 · Enter 生成 · F5 刷新 · Esc 返回"),
            area,
        );
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        let Some(package) = packages.get(selected) else {
            return;
        };
        let text = format!(
            "候选 {}/{} · {} · {}\n内核：{} · 包版本：{}\n调试包大小：{}\n调试包：{}\n配置来源：{}\n\n生成后校验完整 banner，保存到本地符号库并选用。\n当前 banner：{}",
            selected + 1,
            packages.len(),
            package.distribution,
            package.architecture,
            package.release,
            package.version,
            package.download_size.as_deref().unwrap_or("索引未提供"),
            package.debug_url,
            package.kernel_url,
            package.banner
        );
        frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
    }
}
