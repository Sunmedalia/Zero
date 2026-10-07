use super::*;

impl App {
    pub(super) fn local_work(&self) -> Work {
        let paths = self
            .assets
            .iter()
            .filter(|a| {
                a.kind == Kind::Symbols
                    && a.available
                    && !a.directory
                    && !self.hidden_cache_copies.contains(&a.path)
            })
            .map(|a| a.path.clone())
            .collect();
        Work::MatchLocal(paths, self.local_stamp())
    }
    pub(super) fn prepare_selected_image(&mut self) {
        self.refresh_assets();
        self.preparation = Preparation::Matching;
        if self.job.is_some() {
            return;
        }
        if self.local_match_stamp.as_ref() == Some(&self.local_stamp()) {
            self.apply_local_preparation();
            self.local_only_matches = true;
            self.status = "复用内核识别与本地符号匹配；x 进入分析".into();
        } else {
            self.start_work(self.local_work());
        }
    }
    pub(super) fn start(&mut self) {
        self.request_analysis(false);
    }
    pub(super) fn request_analysis(&mut self, force: bool) {
        if self.plugin == Plugin::WinPrintkey && self.analysis_options.hive.is_none() {
            self.windows_parameters();
            self.status = "printkey 必须填写 hive 地址".into();
            return;
        }
        if self.image.is_some() && self.job.is_none() {
            self.refresh_assets();
            if self
                .prepared_stamp
                .as_ref()
                .is_some_and(|stamp| *stamp != self.local_stamp())
            {
                self.invalidate_source();
                self.page = Page::Assets;
                self.prepare_selected_image();
                self.status = "对象文件发生变化，正在重新识别并匹配符号".into();
                return;
            }
        }
        if self.plugin.is_dump() {
            self.open_dump(self.plugin, force);
        } else {
            self.start_work(Work::Analyze(force));
        }
    }
    pub(super) fn start_work(&mut self, work: Work) {
        if let Work::Analyze(force) = work
            && self.plugin.is_dump()
            && self
                .dump_options
                .as_ref()
                .is_none_or(|(p, _)| *p != self.plugin)
        {
            self.request_analysis(force);
            return;
        }
        if self.job.is_some() {
            let execution = matches!(work, Work::Analyze(_)).then(|| ExecutionSnapshot {
                force: matches!(work, Work::Analyze(true)),
                plugin: self.plugin,
                options: self.analysis_options.clone(),
                dump: self.dump_options.clone(),
            });
            self.cancel();
            self.pending_execution = execution;
            self.pending_work = Some(work);
            self.status = "正在取消；随后执行最后一次请求".into();
            return;
        }
        let image = self.image.clone().or_else(|| {
            matches!(
                work,
                Work::Clear(_)
                    | Work::InspectSymbols(_)
                    | Work::RefreshLookup
                    | Work::Catalog(_, _)
                    | Work::CatalogDownload(_)
            )
            .then(PathBuf::new)
        });
        let Some(image) = image else {
            self.pending_work = Some(work);
            self.open_files(InputKind::Image);
            return;
        };
        self.task_id += 1;
        self.active_request = matches!(work, Work::Analyze(_)).then(|| Execution {
            plugin: self.plugin,
            key: self.request_key(),
            parameters: self.parameter_summary(),
            snapshot: ExecutionSnapshot {
                force: matches!(work, Work::Analyze(true)),
                plugin: self.plugin,
                options: self.analysis_options.clone(),
                dump: self.dump_options.clone(),
            },
        });
        let (sender, rx) = mpsc::channel();
        let tx = EventSender {
            sender,
            id: self.task_id,
            version: self.object_version,
        };
        let progress = tx.clone();
        let job = Job::new(move |s| {
            let _ = progress.send(WorkerEvent::Progress(s));
        });
        let worker_job = job.clone();
        let symbols = if self.symbols.as_os_str().is_empty() {
            store::expand_home(&self.settings.symbols)
        } else {
            self.symbols.clone()
        };
        let cache = self.cache.clone();
        let choice = self.choice.clone();
        let plugin = self.plugin;
        let dump = self
            .dump_options
            .as_ref()
            .filter(|(p, _)| *p == plugin)
            .map(|(_, o)| o.clone());
        let analysis_options = self.analysis_options.clone();
        let enabled = self.settings.enable_cache;
        let windows = self.windows;
        let network = self.settings.remote_symbols && !matches!(work, Work::Analyze(_));
        let saved_download = self
            .downloads
            .get(match &work {
                Work::CatalogDownload(candidate) => candidate.url.as_str(),
                _ => "",
            })
            .filter(|p| p.is_file())
            .cloned();
        let local_library = store::expand_home(&self.settings.symbols);
        let local_library = if local_library.extension().is_some() && !local_library.is_dir() {
            self.root.join("symbols")
        } else {
            local_library
        };
        let session = self.session.clone();
        if matches!(
            work,
            Work::Analyze(_) | Work::Download(_) | Work::PrepareKali | Work::GenerateSymbols(_)
        ) {
            self.history = None;
        }
        self.last_error = None;
        self.job = Some(job);
        self.receiver = Some(rx);
        self.download_url = match &work {
            Work::Download(candidate) | Work::CatalogDownload(candidate) => {
                Some(candidate.url.clone())
            }
            _ => None,
        };
        self.preparation_lookup = matches!(work, Work::FetchMatched);
        self.status = "任务启动中".into();
        self.started = Some(Instant::now());
        self.progress = None;
        self.worker = Some(thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut session = session
                    .lock()
                    .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?;
                match work {
                    Work::Catalog(query, refresh) => {
                        if windows && !image.as_os_str().is_empty() {
                            let prepared = session.prepare_image(&image, &cache, &worker_job)?;
                            let mut matches =
                                symbols::remote_matches(&prepared, &cache, network, &worker_job)?;
                            matches.retain(|m| {
                                format!("{} {}", m.banner, m.path)
                                    .to_lowercase()
                                    .contains(&query.to_lowercase())
                            });
                            return Ok(WorkerEvent::CatalogLinks(matches));
                        }

                        if refresh {
                            anyhow::ensure!(network, "离线模式不能刷新索引；按 o 开启在线");
                            symbols::refresh_index(&cache, &worker_job)?;
                        }
                        symbols::catalog_search(&cache, &query, network, &worker_job)
                            .map(WorkerEvent::CatalogLinks)
                    }
                    Work::CatalogDownload(candidate) => {
                        if let Some(path) = saved_download {
                            symbols::validate_remote(&candidate)?;
                            let valid = symbols::inspect(&path, &worker_job).is_ok_and(|isfs| {
                                isfs.len() == 1
                                    && String::from_utf8_lossy(&isfs[0].banner)
                                        .trim_end_matches(['\0', '\n'])
                                        == candidate.banner
                            });
                            worker_job.check()?;
                            if valid {
                                return Ok(WorkerEvent::CatalogDownloaded(path));
                            }
                        }
                        let isf =
                            symbols::download_catalog(&candidate, &cache, network, &worker_job)?;
                        let target =
                            save_remote_symbol(&candidate, &isf, &local_library, &worker_job)?;
                        Ok(WorkerEvent::CatalogDownloaded(target))
                    }
                    Work::Identify => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        linux::banner_result(&image, &worker_job).map(WorkerEvent::Identified)
                    }
                    Work::InspectSymbols(path) => workspace::inspect_symbols(&path, &worker_job)
                        .map(|text| WorkerEvent::SymbolDetails(path, text)),
                    Work::RefreshLookup => {
                        if windows && !image.as_os_str().is_empty() {
                            let prepared = session.prepare_image(&image, &cache, &worker_job)?;
                            return symbols::remote_matches(
                                &prepared,
                                &cache,
                                network,
                                &worker_job,
                            )
                            .map(WorkerEvent::Links);
                        }
                        if network {
                            symbols::refresh_index(&cache, &worker_job)?;
                        } else {
                            anyhow::ensure!(
                                cache.join("symbols/banners_plain.json").is_file(),
                                "离线模式且没有索引缓存；按 o 开启在线模式后按 r"
                            );
                        }
                        if image.as_os_str().is_empty() {
                            return Ok(WorkerEvent::IndexRefreshed);
                        }
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        symbols::remote_matches(&image, &cache, network, &worker_job)
                            .map(WorkerEvent::Links)
                    }
                    Work::PrepareKali => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        let path =
                            crate::prepare::prepare_kali(&image, &cache, network, &worker_job)?;
                        save_generated_symbol(&path, &local_library, &worker_job)
                            .map(WorkerEvent::Downloaded)
                    }
                    Work::GenerateSymbols([elf, config, tool]) => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        let path = crate::prepare::generate(
                            &elf,
                            &config,
                            &tool,
                            &image,
                            &cache,
                            &worker_job,
                        )?;
                        save_generated_symbol(&path, &local_library, &worker_job)
                            .map(WorkerEvent::Downloaded)
                    }
                    Work::Clear(scopes) => {
                        session.clear();
                        cache::clear_with_job(&cache, &scopes, &worker_job)
                            .map(WorkerEvent::Cleared)
                    }
                    Work::Analyze(force) => crate::analysis::analyze(
                        &mut session,
                        &linux::Request {
                            image: &image,
                            symbols: &symbols,
                            choice: choice.as_deref(),
                            plugin,
                            cache: &cache,
                            use_cache: enabled && !force,
                            network,
                        },
                        dump.as_ref(),
                        &analysis_options,
                        &worker_job,
                    )
                    .map(WorkerEvent::Done),
                    Work::MatchLocal(paths, stamp) => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        let banner = linux::banner_result(&image, &worker_job)?;
                        let report = symbols::match_local_files(&paths, &image, &worker_job)?;
                        Ok(WorkerEvent::LocalMatched(report, stamp, banner))
                    }
                    Work::FetchMatched => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        symbols::remote_matches(&image, &cache, network, &worker_job)
                            .map(WorkerEvent::Links)
                    }
                    Work::Download(candidate) => {
                        let image = session.prepare_image(&image, &cache, &worker_job)?;
                        let isf =
                            symbols::download(&candidate, &image, &cache, network, &worker_job)?;
                        save_remote_symbol(&candidate, &isf, &local_library, &worker_job)
                            .map(WorkerEvent::Downloaded)
                    }
                }
            }));
            let event = match outcome {
                Ok(Ok(event)) => event,
                Ok(Err(error)) => WorkerEvent::Failed(format!("{error:#}")),
                Err(_) => WorkerEvent::Failed("分析线程 panic；任务已终止".into()),
            };
            let _ = tx.send(event);
        }));
    }
    pub(super) fn cancel(&mut self) {
        self.enter_when_ready = false;
        self.pending_work = None;
        self.pending_path = None;
        self.pending_execution = None;
        self.preparation_lookup = false;
        self.pending_os = None;
        if let Some(job) = &self.job {
            job.cancel.store(true, Ordering::Relaxed);
            self.status = "正在取消…".into();
        }
    }
    pub(super) fn drain(&mut self) -> bool {
        let events: Vec<_> = self
            .receiver
            .as_ref()
            .map(|r| r.try_iter().collect())
            .unwrap_or_default();
        let mut changed = !events.is_empty();
        for event in events {
            let event = match event {
                WorkerEvent::Tagged(id, version, event) => {
                    if id != self.task_id || version != self.object_version {
                        if id == self.task_id && !matches!(*event, WorkerEvent::Progress(_)) {
                            self.finish_worker();
                        }
                        continue;
                    }
                    *event
                }
                event => event,
            };
            let cancelled = self
                .job
                .as_ref()
                .is_some_and(|j| j.cancel.load(Ordering::Relaxed));
            if cancelled
                && !matches!(
                    event,
                    WorkerEvent::Progress(_) | WorkerEvent::Done(Outcome::Ready(_))
                )
            {
                self.finish_worker();
                self.preparation_lookup = false;
                if self.preparation == Preparation::Matching {
                    self.preparation = Preparation::Cancelled;
                }
                self.status = "已取消；可重试".into();
                continue;
            }
            let progress_event = matches!(&event, WorkerEvent::Progress(_));
            match event {
                WorkerEvent::Tagged(..) => unreachable!("事件已解包"),
                WorkerEvent::LocalMatched(report, stamp, banner) => {
                    self.finish_worker();
                    self.apply_identification(&banner);
                    let identification = self.identification_status(&banner);
                    self.results.insert("banners".into(), banner);
                    self.local_matches = report.matched;
                    self.local_match_errors = report.diagnostics;
                    self.local_match_stamp = Some(stamp);
                    self.local_only_matches = true;
                    self.asset_rows[1] = 0;
                    self.status = format!(
                        "{} · 本地符号匹配：{} 个文件 · {} 条诊断；Space 选用，Enter 进入控制台，d 详情，t 远程，z 全部",
                        identification,
                        self.local_matches.len(),
                        self.local_match_errors.len()
                    );
                    if !self.local_match_errors.is_empty() {
                        self.last_error = Some(self.local_match_errors.join("\n"));
                    }
                    self.apply_local_preparation();
                }
                WorkerEvent::CatalogLinks(matches) => {
                    self.finish_worker();
                    self.status =
                        format!("远程索引：{} 项；可输入多个关键词缩小范围", matches.len());
                    self.remote = matches;
                    self.remote_catalog = true;
                    self.asset_rows[2] =
                        self.asset_rows[2].min(self.remote_list().len().saturating_sub(1));
                }
                WorkerEvent::CatalogDownloaded(path) => {
                    self.finish_worker();
                    if let Some(url) = self.download_url.take() {
                        self.downloads.insert(url, path.clone());
                    }
                    if let Err(e) = self.registry.register(&path, Kind::Symbols, &self.cache) {
                        self.last_error = Some(format!("下载成功但清单保存失败: {e:#}"));
                    }
                    self.refresh_assets();
                    self.status = format!("已保存到 {}；在本地库定位后可选用", path.display());
                }
                WorkerEvent::IndexRefreshed => {
                    self.finish_worker();
                    self.status = "远程索引已刷新；选择镜像后按 M 精确匹配".into();
                }
                WorkerEvent::Identified(result) => {
                    self.finish_worker();
                    self.apply_identification(&result);
                    self.status = format!(
                        "{} · {} 个候选；尚未验证页表",
                        self.identification_status(&result),
                        result.rows.len()
                    );
                    self.results.insert("banners".into(), result);
                }
                WorkerEvent::SymbolDetails(path, text) => {
                    self.finish_worker();
                    self.asset_details.insert(path, text);
                    self.status = "符号详情已读取；选用后通过镜像验证匹配".into();
                }
                WorkerEvent::Cleared(report) => {
                    self.finish_worker();
                    self.results.clear();
                    self.views.clear();
                    self.refresh_assets();
                    self.status = format!(
                        "已清理 {} 个文件 · 释放 {:.1} MiB · {} 项失败",
                        report.removed,
                        report.bytes as f64 / 1048576.0,
                        report.failures.len()
                    );
                    if !report.failures.is_empty() {
                        self.last_error = Some(report.failures.join("\n"));
                    }
                }
                WorkerEvent::Links(matches) => {
                    self.finish_worker();
                    self.status = format!(
                        "{} 个完整 banner 匹配 · Enter 进入控制台 · d 详情 · w 下载到 symbols",
                        matches.len()
                    );
                    self.remote = matches.clone();
                    self.asset_rows[2] = 0;
                    self.asset_states.borrow_mut()[2] = ListState::default();
                    if self.preparation_lookup {
                        self.preparation_lookup = false;
                        if matches.len() == 1 {
                            self.start_work(Work::Download(matches[0].clone()));
                        } else if matches.len() > 1 {
                            self.dialog = Some(Dialog::Links {
                                matches,
                                selected: 0,
                            });
                        } else {
                            if self.preparation != Preparation::Ready {
                                self.preparation = Preparation::MissingSymbols;
                            }
                            self.status = if self.windows {
                                "未找到精确 PDB 身份；b 重新识别，y 导入本地符号".into()
                            } else if self.supports_kali_symbols() {
                                format!(
                                    "GitHub 没有该完整 banner 的精确符号；K 生成当前镜像符号表 · {}",
                                    symbols::REPOSITORY
                                )
                            } else {
                                format!(
                                    "GitHub 没有该完整 banner 的精确符号；y 导入，M 重试 · {}",
                                    symbols::REPOSITORY
                                )
                            };
                        }
                    } else if matches.is_empty() {
                        self.status =
                            "仓库没有完整 banner 匹配；t 切换本地，g 获取索引，/ 手动搜索".into();
                    }
                }
                WorkerEvent::Downloaded(path) => {
                    self.finish_worker();
                    if let Some(url) = self.download_url.take() {
                        self.downloads.insert(url, path.clone());
                    }
                    self.symbols = path.clone();
                    self.choice = None;
                    let banner = self.results.get("banners").cloned();
                    self.results.clear();
                    if let Some(banner) = banner {
                        self.results.insert("banners".into(), banner);
                    }
                    self.views.clear();
                    self.history = None;
                    self.query.clear();
                    self.sort = None;
                    self.row = 0;
                    self.horizontal = 0;
                    self.collapsed.clear();
                    if let Err(e) = self.registry.import(&path, Kind::Symbols, &self.cache) {
                        self.last_error = Some(format!("下载成功但清单保存失败: {e:#}"));
                    }
                    self.refresh_assets();
                    self.focus_asset(Kind::Symbols, &path);
                    self.status = format!("符号已选用: {}；x 进入分析", path.display());
                    self.preparation = Preparation::Ready;
                    self.prepared_stamp = Some(self.local_stamp());
                    self.status = "符号已选用；x 进入分析，点击插件运行并验证页表".into();
                }
                WorkerEvent::Progress(s) => {
                    self.progress = s
                        .split_whitespace()
                        .find_map(|v| v.strip_suffix('%').and_then(|v| v.parse::<u16>().ok()))
                        .map(|p| p.min(100));
                    self.logs.push_back(s.clone());
                    if self.logs.len() > 200 {
                        self.logs.pop_front();
                    }
                    self.status = s;
                }
                WorkerEvent::Failed(s) => {
                    self.last_error = Some(s.clone());
                    self.preparation_lookup = false;
                    if self.preparation == Preparation::Matching {
                        self.preparation = Preparation::MissingSymbols;
                    }
                    self.status = format!("失败：{s} · 可重试");
                    self.finish_worker();
                }
                WorkerEvent::Done(outcome) => {
                    self.finish_worker();
                    match outcome {
                        Outcome::Choose(labels) => {
                            self.symbol_retry = self.active_request.take().map(|r| r.snapshot);
                            self.status = "多个匹配 ISF，必须选择".into();
                            self.dialog = Some(Dialog::Symbols {
                                labels,
                                selected: 0,
                            });
                        }
                        Outcome::Ready(result) => {
                            self.last_error = None;
                            self.status = format!(
                                "{} · {} 条 · {}{}",
                                result.plugin,
                                result.rows.len(),
                                if result.complete {
                                    "完整"
                                } else {
                                    "部分结果 / 未缓存"
                                },
                                if result.diagnostics.is_empty() {
                                    String::new()
                                } else {
                                    format!(" · {} 条诊断（v 查看）", result.diagnostics.len())
                                }
                            );
                            let execution = self.active_request.take();
                            let viewing = self.history.is_none()
                                && execution.as_ref().is_none_or(|r| {
                                    r.plugin == self.plugin && r.key == self.request_key()
                                });
                            if let Some(request) = execution {
                                self.result_requests
                                    .insert(request.plugin.name().into(), request.parameters);
                                self.results.insert(request.key, result.clone());
                            }
                            self.results.insert(result.plugin.clone(), result);
                            if viewing {
                                self.row = self.row.min(self.visible().len().saturating_sub(1));
                                self.focus = Focus::Content;
                            }
                        }
                    }
                }
            }
            if !progress_event {
                self.logs.push_back(self.status.clone());
                if self.logs.len() > 200 {
                    self.logs.pop_front();
                }
            }
        }
        if self.job.is_none()
            && let Some(os) = self.pending_os.take()
        {
            self.select_os(os);
        }
        if self.job.is_none() {
            if let Some((kind, path)) = self.pending_path.take() {
                self.accept_path(kind, path);
            } else if let Some(work) = self.pending_work.take() {
                if let Some(request) = self.pending_execution.take() {
                    self.start_snapshot(request);
                } else {
                    self.start_work(work);
                }
            }
        }
        changed |= self.resolve_enter_intent();
        changed
    }
    pub(super) fn finish_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.receiver = None;
        self.job = None;
        self.started = None;
        self.progress = None;
    }
}

fn save_remote_symbol(
    candidate: &RemoteMatch,
    isf: &symbols::Isf,
    local_library: &std::path::Path,
    job: &Job,
) -> anyhow::Result<PathBuf> {
    job.check()?;
    std::fs::create_dir_all(local_library)?;
    let stem = candidate
        .path
        .rsplit('/')
        .next()
        .unwrap_or("symbol.json.xz")
        .trim_end_matches(".json.xz");
    let extension = if isf.is_windows() { "json" } else { "json.xz" };
    let target = local_library.join(format!(
        "{}-{}.{extension}",
        stem.chars().take(100).collect::<String>(),
        isf.digest
    ));
    let bytes = std::fs::read(&isf.label)?;
    if target.exists() {
        anyhow::ensure!(
            std::fs::read(&target)? == bytes,
            "同名本地符号内容不同，拒绝覆盖: {}",
            target.display()
        );
    } else {
        store::atomic_write(&target, &bytes)?;
    }
    job.check()?;
    store::atomic_write(
        &target.with_extension("source.json"),
        &serde_json::to_vec_pretty(candidate)?,
    )?;
    Ok(target.canonicalize()?)
}

fn save_generated_symbol(
    path: &std::path::Path,
    library: &std::path::Path,
    job: &Job,
) -> anyhow::Result<PathBuf> {
    job.check()?;
    std::fs::create_dir_all(library)?;
    let name = path.file_name().context("生成符号路径无效")?;
    let target = library.join(name);
    let bytes = std::fs::read(path)?;
    if target.exists() {
        anyhow::ensure!(
            std::fs::read(&target)? == bytes,
            "同名符号内容不同，拒绝覆盖"
        );
    } else {
        store::atomic_write(&target, &bytes)?;
    }
    job.check()?;
    let source = path.with_extension("source.json");
    if source.is_file() {
        store::atomic_write(
            &target.with_extension("source.json"),
            &std::fs::read(source)?,
        )?;
    }
    Ok(target.canonicalize()?)
}
