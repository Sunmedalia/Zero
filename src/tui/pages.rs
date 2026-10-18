//! Page composition. `draw` owns the frame skeleton — tabs, system row, header,
//! body and footer — and delegates each region to its module:
//! [`chrome`](super::chrome) for shared widgets, [`assets`](super::assets) for
//! the resource library, [`results`](super::results) for the analysis
//! workbench, [`footer`](super::footer) for status and actions, and
//! [`dialogs`](super::dialogs) for modals.
use super::*;

impl App {
    /// Height the footer needs: a status line, the resource toolbar when the
    /// assets page is showing, and the wrapped action strip.
    fn footer_height(&self, width: u16) -> u16 {
        if self.page == Page::Assets {
            2 + action_rows(&toolbar_actions(self.section, self.job.is_some()), width)
        } else {
            3
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
                Constraint::Length(if self.page == Page::Analysis { 2 } else { 0 }),
                Constraint::Min(3),
                Constraint::Length(self.footer_height(frame.area().width)),
            ])
            .split(area);
        self.hits.borrow_mut().header = parts[0];
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
        if self.page == Page::Analysis && (frame.area().width < 100 || frame.area().height < 20) {
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
        frame.render_widget(
            Paragraph::new(vec![
                Line::from_iter(
                    field(
                        "系统: ",
                        if self.windows { "Windows" } else { "Linux" }.into(),
                        value.add_modifier(Modifier::BOLD),
                    )
                    .into_iter()
                    .chain([separator()])
                    .chain(field("镜像: ", escaped(&image), value)),
                ),
                Line::from_iter(
                    field("验证: ", escaped(&kernel), kernel_style)
                        .into_iter()
                        .chain([separator()])
                        .chain(field("符号: ", escaped(&symbol), symbol_style)),
                ),
            ]),
            area,
        );
    }
}
