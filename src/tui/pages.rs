//! Page composition. `draw` owns the frame skeleton — tabs, system row, header,
//! body and footer — and delegates each region to its module:
//! [`chrome`](super::chrome) for shared widgets, [`assets`](super::assets) for
//! the resource library, [`results`](super::results) for the analysis
//! workbench, [`footer`](super::footer) for status and actions, and
//! [`dialogs`](super::dialogs) for modals.
use super::*;

impl App {
    /// Height the footer needs: a status line, then either the resource
    /// toolbar or the wrapped action strip.
    ///
    /// The resource toolbar carries the page's actions, so it gets the toolbar
    /// budget; it never takes more than a third of the screen, so a short
    /// terminal keeps its list and `更多 ?` covers whatever does not fit.
    fn footer_height(&self, width: u16, height: u16) -> u16 {
        if self.page == Page::Assets {
            let wanted = 2 + action_rows(&toolbar_actions(self.section, self.job.is_some()), width);
            wanted.min((height / 3).max(3))
        } else {
            2
        }
    }
    pub fn draw(&self, frame: &mut Frame) {
        *self.hits.borrow_mut() = HitMap::default();
        frame.render_widget(
            Block::default().style(Style::default().bg(SURFACE)),
            frame.area(),
        );
        let [tabs, systems, area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .areas(frame.area());
        self.draw_tabs(frame, tabs);
        self.draw_system_row(frame, systems);
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if self.page == Page::Analysis { 1 } else { 0 }),
                Constraint::Min(3),
                Constraint::Length(self.footer_height(frame.area().width, frame.area().height)),
            ])
            .split(area);
        self.hits.borrow_mut().header = parts[0];
        self.hits.borrow_mut().header_image = Rect::new(
            parts[0].x,
            parts[0].y,
            parts[0].width,
            parts[0].height.min(1),
        );
        self.hits.borrow_mut().header_symbol = if parts[0].height > 1 {
            Rect::new(parts[0].x, parts[0].y + 1, parts[0].width, 1)
        } else {
            // A single-line header cannot separate the two fields, so the whole
            // line opens the image picker and `y` remains the way to symbols.
            Rect::default()
        };
        self.draw_header(frame, parts[0]);
        if self.page == Page::Assets {
            self.draw_assets(frame, parts[1]);
        } else {
            self.draw_workbench(frame, area, parts[1]);
        }
        self.draw_footer(frame, parts[2]);
        self.draw_dialog(frame, area);
    }
    /// Narrow analysis layouts replace the system picker with region tabs, so
    /// the only visible control stays reachable.
    fn draw_system_row(&self, frame: &mut Frame, systems: Rect) {
        let layout = Space::new(frame.area().width, frame.area().height);
        if self.page == Page::Analysis && !layout.system_row() {
            let mut x = systems.x;
            for (label, focus) in [(" 插件 ", Focus::Navigation), (" 内容 ", Focus::Content)] {
                let width =
                    (Span::raw(label).width() as u16).min(systems.right().saturating_sub(x));
                let rect = Rect::new(x, systems.y, width, systems.height);
                frame.render_widget(
                    Paragraph::new(label).style(Style::default().fg(if self.focus == focus {
                        FOCUS
                    } else {
                        ACCENT
                    })),
                    rect,
                );
                self.hits.borrow_mut().regions.push((rect, focus));
                x += width;
            }
        } else {
            self.draw_system_buttons(frame, systems);
        }
    }
    /// The two-line analysis header: system and image, then page-table and
    /// symbol verification state.
    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let image = self
            .image
            .as_ref()
            .map(|p| self.display_path(p))
            .unwrap_or_else(|| "未加载；按 i 输入路径".into());
        let verified = self
            .results
            .values()
            .find(|r| !r.historical && r.page_table > 0)
            .map(|r| r.page_table);
        let (kernel, kernel_style) = match verified {
            Some(table) => (
                format!("页表已验证 {table:#x}"),
                Style::default().fg(SUCCESS),
            ),
            None if self.preparation == Preparation::Ready => {
                ("运行时验证页表".into(), Style::default().fg(TEXT))
            }
            None => ("尚未验证页表".into(), Style::default().fg(WARN)),
        };
        let symbol = self
            .result()
            .filter(|r| !r.historical && !r.symbol.is_empty())
            .map(|r| r.symbol.clone());
        let (symbol, symbol_style) = match symbol {
            Some(symbol) => (symbol, Style::default().fg(TEXT)),
            None if self.symbols.as_os_str().is_empty() => {
                ("未选择 · F2 资源库".into(), Style::default().fg(WARN))
            }
            None => (self.display_path(&self.symbols), Style::default().fg(TEXT)),
        };
        let value = Style::default().fg(TEXT);
        let separator = || Span::styled(" · ", Style::default().fg(BORDER));
        // One line, filled by priority: what changes, then what identifies the
        // input. Narrow windows drop the tail instead of truncating it
        // mid-word, so a field is either fully readable or not shown.
        let platform = if self.windows { "Windows" } else { "Linux" };
        let mut line = field("", platform.into(), value.add_modifier(Modifier::BOLD)).to_vec();
        let mut used = Span::raw(platform).width();
        for (label, text, style) in [
            ("验证: ", kernel, kernel_style),
            ("符号: ", symbol, symbol_style),
            ("镜像: ", image, value),
        ] {
            let width = 3 + Span::raw(label).width() + Span::raw(&text).width();
            if used + width > area.width as usize {
                break;
            }
            used += width;
            line.push(separator());
            line.extend(field(label, escaped(&text), style));
        }
        frame.render_widget(Paragraph::new(Line::from(line)), area);
    }
}
