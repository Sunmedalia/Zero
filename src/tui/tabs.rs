//! Open result pages retain their own selection and filter state.
use super::*;

#[derive(Clone)]
pub(super) enum OpenTab {
    Plugin(Plugin),
    History(PathBuf, Arc<Results>),
}
impl App {
    pub(super) fn ensure_plugin_tab(&mut self, plugin: Plugin) {
        if let Some(index) = self
            .open_tabs
            .iter()
            .position(|t| matches!(t, OpenTab::Plugin(p) if *p == plugin))
        {
            self.active_tab = Some(index);
            return;
        }
        if let Some(index) = self.active_tab.filter(|&i| matches!(self.open_tabs.get(i), Some(OpenTab::Plugin(p)) if !self.results.contains_key(p.name()) && self.job.is_none())) {
            self.open_tabs[index] = OpenTab::Plugin(plugin); self.active_tab = Some(index); return;
        }
        self.open_tabs.push(OpenTab::Plugin(plugin));
        self.active_tab = Some(self.open_tabs.len() - 1);
    }
    pub(super) fn open_history_tab(&mut self, path: PathBuf, result: Results) {
        self.save_view();
        let result = Arc::new(result);
        let index = self
            .open_tabs
            .iter()
            .position(|t| matches!(t, OpenTab::History(p, _) if *p == path))
            .unwrap_or_else(|| {
                self.open_tabs.push(OpenTab::History(path, result.clone()));
                self.open_tabs.len() - 1
            });
        self.history_source = match &self.open_tabs[index] {
            OpenTab::History(path, _) => Some(path.clone()),
            _ => None,
        };
        if let OpenTab::History(source, _) = &self.open_tabs[index] {
            self.open_tabs[index] = OpenTab::History(source.clone(), result.clone());
        }
        self.active_tab = Some(index);
        self.history = Some(result);
        self.history_revision += 1;
        self.page = Page::Analysis;
        self.query.clear();
        self.sort = None;
        self.row = 0;
        self.focus = Focus::Content;
        self.status = "导出记录：历史内容，未重新验证镜像".into();
    }
    pub(super) fn switch_result_tab(&mut self, index: usize) {
        let Some(tab) = self.open_tabs.get(index).cloned() else {
            return;
        };
        self.save_view();
        match tab {
            OpenTab::Plugin(plugin) => {
                self.select_plugin(plugin);
                self.history = None;
            }
            OpenTab::History(path, result) => {
                self.history_source = Some(path);
                self.history = Some(result);
                self.history_revision += 1;
                self.query.clear();
                self.sort = None;
                self.row = 0;
                self.restore_view();
            }
        }
        self.active_tab = Some(index);
        self.page = Page::Analysis;
        self.focus = Focus::Content;
    }
    pub(super) fn next_result_tab(&mut self, back: bool) {
        if self.open_tabs.is_empty() {
            return;
        }
        let count = self.open_tabs.len();
        let index = (self.active_tab.unwrap_or(0) + if back { count - 1 } else { 1 }) % count;
        self.switch_result_tab(index);
    }
    pub(super) fn close_result_tab(&mut self, index: usize) {
        if index >= self.open_tabs.len() {
            return;
        }
        if let OpenTab::Plugin(plugin) = &self.open_tabs[index] {
            if self.job.is_some()
                && self
                    .active_request
                    .as_ref()
                    .is_some_and(|r| r.plugin == *plugin)
            {
                self.status = "请先取消正在运行的插件".into();
                return;
            }
            let name = plugin.name();
            self.results
                .retain(|key, _| key != name && !key.starts_with(&format!("{name}:")));
            self.views
                .retain(|key, _| !key.starts_with(&format!("{name}:")));
        }
        let current = self.active_tab.unwrap_or(0);
        self.open_tabs.remove(index);
        if self.open_tabs.is_empty() {
            self.active_tab = None;
            self.history = None;
            self.history_source = None;
            self.history_revision += 1;
            self.focus = if self.plugins_collapsed {
                Focus::Content
            } else {
                Focus::Navigation
            };
            self.status = "已关闭全部页面 · 选择插件后 R 运行".into();
        } else if current == index {
            self.switch_result_tab(index.min(self.open_tabs.len() - 1));
        } else {
            self.active_tab = Some(if current > index {
                current - 1
            } else {
                current
            });
        }
    }
    pub(super) fn clear_plugin_tabs(&mut self) {
        self.open_tabs.retain(|t| matches!(t, OpenTab::History(..)));
        self.active_tab = None;
    }
    pub(super) fn draw_result_tabs(&self, frame: &mut Frame, area: Rect) {
        if self.open_tabs.is_empty() || area.width < 8 {
            return;
        }
        frame.render_widget(
            Paragraph::new("─".repeat(area.width as usize))
                .style(Style::default().fg(color_border()).bg(color_surface())),
            area,
        );
        let active = self.active_tab.unwrap_or(0);
        let count = self.open_tabs.len();
        let overflow = count.saturating_mul(24) > area.width as usize;
        let available = area.width.saturating_sub(if overflow { 6 } else { 0 });
        let width = 24.min(available).max(1);
        let capacity = (available / width).max(1) as usize;
        let maximum = count.saturating_sub(capacity);
        let mut start = self.tab_offset.get().min(maximum);
        let layout = (self.active_tab, area.width);
        if self.tab_layout.get() != Some(layout) {
            if active < start {
                start = active;
            }
            if active >= start + capacity {
                start = active + 1 - capacity;
            }
            self.tab_layout.set(Some(layout));
        }
        self.tab_offset.set(start);
        if overflow {
            for (column, label, offset) in [
                (area.right() - 6, " < ", start.checked_sub(1)),
                (
                    area.right() - 3,
                    " > ",
                    (start < maximum).then_some(start + 1),
                ),
            ] {
                let rect = Rect::new(column, area.y, 3, 1);
                frame.render_widget(
                    Paragraph::new(label).style(Style::default().fg(if offset.is_some() {
                        color_accent()
                    } else {
                        color_muted()
                    })),
                    rect,
                );
                if let Some(offset) = offset {
                    self.hits.borrow_mut().result_tab_steps.push((rect, offset));
                }
            }
        }
        let mut x = area.x;
        for (index, tab) in self.open_tabs.iter().enumerate().skip(start).take(capacity) {
            let name = match tab {
                OpenTab::Plugin(p) => {
                    if self.active_tab == Some(index) {
                        format!(
                            "{} · {}",
                            plugin_label(*p),
                            self.results
                                .get(p.name())
                                .map_or("待运行", |r| if r.complete {
                                    "完整"
                                } else {
                                    "部分"
                                })
                        )
                    } else {
                        plugin_label(*p).to_owned()
                    }
                }
                OpenTab::History(_, r) => format!("{} 历史", r.plugin),
            };
            let label = truncate_with_ellipsis(&name, width.saturating_sub(2) as usize);
            let label = format!(
                "{}{}",
                label,
                " ".repeat((width as usize).saturating_sub(Span::raw(&label).width()))
            );
            let rect = Rect::new(x, area.y, width.min(area.right().saturating_sub(x)), 1);
            if rect.width < 2 {
                break;
            }
            frame.render_widget(
                Paragraph::new(label).style(
                    Style::default()
                        .fg(if self.active_tab == Some(index) {
                            color_focus()
                        } else {
                            color_text()
                        })
                        .bg(if self.active_tab == Some(index) {
                            color_selected_bg()
                        } else {
                            color_surface()
                        }),
                ),
                rect,
            );
            let close = Rect::new(rect.right() - 1, rect.y, 1, 1);
            // Draw the close glyph at its hit target, independent of label width.
            frame.render_widget(
                Paragraph::new("×").style(Style::default().fg(color_muted())),
                close,
            );
            self.hits
                .borrow_mut()
                .result_tabs
                .push((rect, close, index));
            x += rect.width;
        }
    }
}
