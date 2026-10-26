//! Inventory and export records use the engine allowlist for every removal.
use super::*;

pub(super) struct CachePage {
    pub(super) entries: Vec<cache::Entry>,
    pub(super) records: Vec<store::ExportRecord>,
    pub(super) scope: usize,
    pub(super) row: usize,
    pub(super) content: bool,
    pub(super) confirm: bool,
    confirm_key: Option<KeyCode>,
    pub(super) summaries: HashMap<PathBuf, store::Summary>,
    collapsed: HashSet<String>,
    checked: Vec<cache::Scope>,
    state: RefCell<ListState>,
    query_rx: Option<mpsc::Receiver<Result<crate::engine_service::Inventory, String>>>,
    query_worker: Option<thread::JoinHandle<()>>,
}
impl Default for CachePage {
    fn default() -> Self {
        Self {
            entries: vec![],
            records: vec![],
            scope: 0,
            row: 0,
            content: false,
            confirm: false,
            confirm_key: None,
            summaries: HashMap::new(),
            collapsed: HashSet::new(),
            checked: vec![cache::Scope::Results, cache::Scope::Identification],
            state: RefCell::new(ListState::default()),
            query_rx: None,
            query_worker: None,
        }
    }
}
#[derive(Clone)]
struct CacheItem {
    paths: Vec<PathBuf>,
    bytes: u64,
    label: String,
    record: Option<String>,
    group: Option<String>,
}
impl App {
    pub(super) fn refresh_cache_page(&mut self) {
        if self.job.is_none() {
            self.start_work(Work::Inventory);
            return;
        }
        if self.cache_page.query_rx.is_some() {
            return;
        }
        let context = self.engine_context();
        let (sender, receiver) = mpsc::channel();
        self.cache_page.query_rx = Some(receiver);
        self.cache_page.query_worker = Some(thread::spawn(move || {
            let result = context
                .inventory(&Job::default())
                .map_err(|error| format!("{error:#}"));
            let _ = sender.send(result);
        }));
    }
    pub(super) fn drain_cache_query(&mut self) -> bool {
        let Some(receiver) = &self.cache_page.query_rx else {
            return false;
        };
        let result = match receiver.try_recv() {
            Ok(value) => value,
            Err(mpsc::TryRecvError::Empty) => return false,
            Err(mpsc::TryRecvError::Disconnected) => Err("缓存查询线程已结束".into()),
        };
        self.cache_page.query_rx = None;
        if let Some(worker) = self.cache_page.query_worker.take() {
            let _ = worker.join();
        }
        match result {
            Ok(inventory) => self.apply_inventory(inventory),
            Err(error) => {
                if self.job.is_none() {
                    self.status = format!("缓存查询失败: {error}");
                }
            }
        }
        true
    }
    pub(super) fn apply_inventory(&mut self, inventory: crate::engine_service::Inventory) {
        self.cache_page.confirm = false;
        self.cache_page.entries = inventory.entries;
        self.cache_page.records = inventory.records;
        self.cache_page.summaries = inventory.summaries;
        self.cache_page.row = self
            .cache_page
            .row
            .min(self.cache_items().len().saturating_sub(1));
    }
    fn cache_items(&self) -> Vec<CacheItem> {
        let scope = cache::SCOPES.get(self.cache_page.scope).copied();
        let mut items = Vec::new();
        let mut record_files = HashSet::new();
        if scope.is_none_or(|s| s == cache::Scope::Exports) {
            for record in &self.cache_page.records {
                record_files.insert(format!("{}.export.json", record.key));
                record_files.insert(format!("{}.{}", record.key, record.format));
                items.push(CacheItem {
                    paths: vec![
                        self.cache
                            .join("exports")
                            .join(format!("{}.export.json", record.key)),
                    ],
                    bytes: self
                        .cache_page
                        .entries
                        .iter()
                        .filter(|e| {
                            e.path
                                .file_name()
                                .is_some_and(|n| n.to_string_lossy().starts_with(&record.key))
                        })
                        .map(|e| e.bytes)
                        .sum(),
                    label: format!(
                        "{} · {} 条 · {} · {} · {}",
                        record.plugin,
                        record.rows,
                        record.format.to_uppercase(),
                        if record.complete { "完整" } else { "部分" },
                        self.display_path(&record.destination)
                    ),
                    record: Some(record.key.clone()),
                    group: None,
                });
            }
        }
        let mut groups: std::collections::BTreeMap<String, Vec<CacheItem>> = Default::default();
        for entry in &self.cache_page.entries {
            if !scope.is_none_or(|s| s == entry.scope) {
                continue;
            }
            if entry
                .path
                .file_name()
                .is_some_and(|n| record_files.contains(&n.to_string_lossy().into_owned()))
            {
                continue;
            }
            let summary = self.cache_page.summaries.get(&entry.path);
            let label = summary.map_or_else(
                || {
                    format!(
                        "{} · {} bytes",
                        entry.path.file_name().unwrap_or_default().to_string_lossy(),
                        entry.bytes
                    )
                },
                |s| {
                    format!(
                        "  {} · {} 行 · {} · {} 条诊断",
                        s.plugin,
                        s.rows,
                        if s.complete { "完整" } else { "部分" },
                        s.diagnostics
                    )
                },
            );
            let item = CacheItem {
                paths: vec![entry.path.clone()],
                bytes: entry.bytes,
                label,
                record: None,
                group: None,
            };
            if entry.scope == cache::Scope::Results {
                groups
                    .entry(
                        summary
                            .map(|s| s.image.clone())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| "未记录镜像".into()),
                    )
                    .or_default()
                    .push(item);
            } else {
                items.push(item);
            }
        }
        for (image, children) in groups {
            let name = children
                .first()
                .and_then(|item| self.cache_page.summaries.get(&item.paths[0]))
                .map(|s| self.display_path(&s.source))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| image.clone());
            let closed = self.cache_page.collapsed.contains(&image);
            items.push(CacheItem {
                paths: children.iter().flat_map(|c| c.paths.clone()).collect(),
                bytes: children.iter().map(|c| c.bytes).sum(),
                label: format!(
                    "{} {} · {} 个结果 · {}",
                    if closed { "▸" } else { "▾" },
                    name,
                    children.len(),
                    image.chars().take(12).collect::<String>()
                ),
                record: None,
                group: Some(image),
            });
            if !closed {
                items.extend(children);
            }
        }
        items
    }
    pub(super) fn draw_cache_page(&self, frame: &mut Frame, area: Rect) {
        let panes = Layout::horizontal([
            Constraint::Length(if area.width >= 100 { 28 } else { 22 }),
            Constraint::Min(20),
        ])
        .split(area);
        let scope_items = cache::SCOPES.iter().map(|scope| {
            let entries: Vec<_> = self
                .cache_page
                .entries
                .iter()
                .filter(|e| e.scope == *scope)
                .collect();
            ListItem::new(format!(
                "[{}] {} · {} 项",
                if self.cache_page.checked.contains(scope) {
                    "x"
                } else {
                    " "
                },
                scope.label(),
                entries.len()
            ))
        });
        frame.render_stateful_widget(
            List::new(scope_items)
                .block(panel().title("缓存范围"))
                .highlight_style(Style::default().fg(color_focus()).bg(color_selected_bg())),
            panes[0],
            &mut ListState::default().with_selected(Some(self.cache_page.scope)),
        );
        let items = self.cache_items();
        let mut state = self.cache_page.state.borrow_mut();
        state.select(Some(self.cache_page.row));
        frame.render_stateful_widget(
            List::new(items.iter().map(|item| ListItem::new(escaped(&item.label))))
                .block(panel().title(if self.cache_page.confirm {
                    "再次按同一清理键确认 · Esc 撤销"
                } else {
                    "缓存条目 / 导出记录 · Enter 打开 · Delete 删除 · x 清理已勾选"
                }))
                .highlight_style(Style::default().fg(color_focus()).bg(color_selected_bg())),
            panes[1],
            &mut state,
        );
        let mut hits = self.hits.borrow_mut();
        hits.cache_scopes = panes[0];
        hits.cache_items = panes[1];
        hits.cache_offset = state.offset();
        let offset = hits.cache_offset;
        drop(hits);
        self.draw_scrollbar(
            frame,
            panes[1],
            items.len(),
            panes[1].height.saturating_sub(2) as usize,
            offset,
            ScrollTarget::CacheItems,
        );
        self.draw_scrollbar(
            frame,
            panes[0],
            cache::SCOPES.len(),
            panes[0].height.saturating_sub(2) as usize,
            self.cache_page
                .scope
                .saturating_sub(panes[0].height.saturating_sub(3) as usize),
            ScrollTarget::CacheScopes,
        );
    }
    pub(super) fn cache_page_key(&mut self, mut key: KeyEvent) -> bool {
        if key.code == KeyCode::Char('C') {
            key.code = KeyCode::Char('x');
        }
        if key.code == KeyCode::Esc && self.cache_page.confirm {
            self.cache_page.confirm = false;
            return false;
        }
        if !matches!(key.code, KeyCode::Delete | KeyCode::Char('x')) {
            self.cache_page.confirm = false;
        }
        if self.job.is_some()
            && (matches!(
                key.code,
                KeyCode::Delete | KeyCode::Char('x') | KeyCode::Char('r')
            ) || (key.code == KeyCode::Enter && self.cache_page.content))
        {
            self.status = "任务执行中，请等待或取消".into();
            return false;
        }
        let old_scope = self.cache_page.scope;
        let count = if self.cache_page.content {
            self.cache_items().len()
        } else {
            cache::SCOPES.len()
        };
        let row = if self.cache_page.content {
            &mut self.cache_page.row
        } else {
            &mut self.cache_page.scope
        };
        match key.code {
            KeyCode::Left => self.cache_page.content = false,
            KeyCode::Right => self.cache_page.content = true,
            KeyCode::Tab | KeyCode::BackTab => self.cache_page.content = !self.cache_page.content,
            KeyCode::Up | KeyCode::Char('k') => *row = row.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => *row = (*row + 1).min(count.saturating_sub(1)),
            KeyCode::PageUp => *row = row.saturating_sub(10),
            KeyCode::PageDown => *row = (*row + 10).min(count.saturating_sub(1)),
            KeyCode::Home => *row = 0,
            KeyCode::End => *row = count.saturating_sub(1),
            KeyCode::Char('r') => self.refresh_cache_page(),
            KeyCode::Char(' ') | KeyCode::Enter if !self.cache_page.content => {
                if let Some(scope) = cache::SCOPES.get(self.cache_page.scope).copied() {
                    if self.cache_page.checked.contains(&scope) {
                        self.cache_page.checked.retain(|s| *s != scope);
                    } else {
                        self.cache_page.checked.push(scope);
                    }
                    self.status =
                        format!("已勾选 {} 个范围 · x 清理", self.cache_page.checked.len());
                }
            }
            KeyCode::Enter => {
                if let Some(item) = self.cache_items().get(self.cache_page.row).cloned() {
                    if let Some(group) = item.group {
                        if !self.cache_page.collapsed.remove(&group) {
                            self.cache_page.collapsed.insert(group);
                        }
                    } else if let Some(key) = item.record {
                        self.start_work(Work::Record(key));
                    }
                }
            }
            KeyCode::Delete | KeyCode::Char('x') => {
                if self.job.is_some() {
                    self.status = "任务执行中，请等待或取消".into();
                    return false;
                }
                let clear = key.code == KeyCode::Char('x');
                if !clear && !self.cache_page.content {
                    self.status = "先按 → 选择要删除的缓存条目".into();
                    return false;
                }
                let item = self.cache_items().get(self.cache_page.row).cloned();
                if !clear && item.is_none() {
                    return false;
                }
                if self.cache_page.confirm && self.cache_page.confirm_key == Some(key.code) {
                    self.cache_page.confirm = false;
                    if clear {
                        self.start_work(Work::Clear(self.cache_page.checked.clone()));
                    } else if let Some(item) = item {
                        self.start_work(Work::RemoveCache(item.paths));
                    }
                } else {
                    self.cache_page.confirm = true;
                    self.cache_page.confirm_key = Some(key.code);
                    self.status = if clear {
                        let files =
                            cache::selected(&self.cache_page.entries, &self.cache_page.checked);
                        let bytes: u64 = files.iter().map(|e| e.bytes).sum();
                        format!(
                            "再按 x 确认清理 {} 个文件 / {:.1} MiB · 不触碰原镜像、导出文件、设置和资源清单",
                            files.len(),
                            bytes as f64 / 1048576.0
                        )
                    } else {
                        let item = item.unwrap();
                        format!(
                            "再按 Delete 确认删除 {} · {:.1} MiB · 保留原文件",
                            item.label,
                            item.bytes as f64 / 1048576.0
                        )
                    };
                }
            }
            _ => {
                if let Some(command) = Command::from_key(Page::Cache, key.code) {
                    return self.run_command(command);
                }
            }
        }
        if old_scope != self.cache_page.scope {
            self.cache_page.row = 0;
            *self.cache_page.state.borrow_mut() = ListState::default();
        }
        false
    }
    pub(super) fn cache_page_mouse(&mut self, mouse: MouseEvent) -> bool {
        let hits = self.hits.borrow().clone();
        let point = Position::new(mouse.column, mouse.row);
        let click = mouse.kind == MouseEventKind::Down(MouseButton::Left);
        if hits
            .cache_scopes
            .inner(ratatui::layout::Margin::new(1, 1))
            .contains(point)
        {
            if click {
                let index = mouse.row.saturating_sub(hits.cache_scopes.y + 1) as usize;
                if index >= cache::SCOPES.len() {
                    return false;
                }
                let activate = !self.cache_page.content && self.cache_page.scope == index;
                if self.cache_page.scope != index {
                    self.cache_page.row = 0;
                    *self.cache_page.state.borrow_mut() = ListState::default();
                }
                self.cache_page.content = false;
                self.cache_page.scope = index;
                self.cache_page.confirm = false;
                if activate {
                    self.cache_page_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
                }
            } else {
                self.cache_page.content = false;
            }
        } else if hits
            .cache_items
            .inner(ratatui::layout::Margin::new(1, 1))
            .contains(point)
        {
            if click {
                let index =
                    hits.cache_offset + mouse.row.saturating_sub(hits.cache_items.y + 1) as usize;
                if index >= self.cache_items().len() {
                    return false;
                }
                let activate = self.cache_page.content && self.cache_page.row == index;
                self.cache_page.content = true;
                self.cache_page.row = index;
                self.cache_page.confirm = false;
                if activate {
                    self.cache_page_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                }
            } else {
                self.cache_page.content = true;
            }
        } else {
            return false;
        }
        let key = match mouse.kind {
            MouseEventKind::ScrollUp => Some(KeyCode::Up),
            MouseEventKind::ScrollDown => Some(KeyCode::Down),
            _ => None,
        };
        if let Some(key) = key {
            for _ in 0..3 {
                self.cache_page_key(KeyEvent::new(key, KeyModifiers::NONE));
            }
        }
        false
    }
}

impl Drop for CachePage {
    fn drop(&mut self) {
        if let Some(worker) = self.query_worker.take() {
            let _ = worker.join();
        }
    }
}
