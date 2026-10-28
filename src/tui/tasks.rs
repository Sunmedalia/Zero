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
            let next = self.local_work();
            self.start_work(Work::Verify);
            self.pending_work = Some(next);
        }
    }
    pub(super) fn start(&mut self) {
        self.request_analysis(false);
    }
    pub(super) fn request_analysis(&mut self, force: bool) {
        if matches!(
            self.plugin,
            Plugin::Vmayarascan | Plugin::WinVadyarascan | Plugin::VmaRegExScan
        ) && self
            .analysis_options
            .pattern
            .as_ref()
            .is_none_or(|p| self.plugin != Plugin::VmaRegExScan && p.trim().is_empty())
        {
            self.windows_parameters();
            return;
        }
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
                Work::SavedCatalog(_)
                    | Work::Inventory
                    | Work::RemoveCache(_)
                    | Work::Record(_)
                    | Work::History(_)
                    | Work::Export(..)
                    | Work::ExportDiagnostic(..)
                    | Work::Clear(_)
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
        if matches!(work, Work::Analyze(_)) {
            self.ensure_plugin_tab(self.plugin);
        }
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
            self.directory(&self.settings.symbols)
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
        let context = self.engine_context();
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
        let local_library = self.directory(&self.settings.symbols);
        let local_library = if local_library.extension().is_some() && !local_library.is_dir() {
            self.root.join("symbols")
        } else {
            local_library
        };
        let session = self.session.clone();
        let origin_job = worker_job.clone();
        if matches!(
            work,
            Work::Analyze(_) | Work::Download(_) | Work::PrepareKali | Work::GenerateSymbols(_)
        ) {
            self.history_revision += 1;
            self.history = None;
        }
        let prior_error = self.last_error.clone();
        self.last_error = None;
        self.diagnosis_running = matches!(work, Work::KernelDiagnostic);
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
                    Work::KernelDiagnostic => crate::kernel_diagnostics::run(
                        &mut session,
                        crate::kernel_diagnostics::Request {
                            image: &context.expand(&image),
                            symbols: &context.expand(&symbols),
                            cache: &cache,
                            choice: choice.as_deref(),
                            os: analysis_options.os,
                            previous_error: prior_error,
                        },
                        &worker_job,
                    )
                    .map(WorkerEvent::KernelDiagnosed),
                    Work::ExportDiagnostic(path, report) => {
                        report.export(&path, &worker_job)?;
                        Ok(WorkerEvent::DiagnosticExported(path))
                    }
                    Work::SavedCatalog(query) => {
                        let repo = symbols::Repository::configured(&cache)?;
                        if !repo.index_file(&cache).is_file() {
                            return Ok(WorkerEvent::SavedCatalog(None));
                        }
                        symbols::catalog(&cache, &query, 500, false, &worker_job)
                            .map(|page| WorkerEvent::SavedCatalog(Some(page)))
                    }

                    Work::Inventory => context.inventory(&worker_job).map(WorkerEvent::Inventory),
                    Work::RemoveCache(paths) => {
                        session.clear();
                        cache::remove(&cache, &paths, &worker_job).map(WorkerEvent::Cleared)
                    }
                    Work::Record(key) => store::open_record(&cache, &key, &worker_job)
                        .map(|r| WorkerEvent::Opened(PathBuf::from(key), r)),
                    Work::History(path) => {
                        store::exported(&path).map(|r| WorkerEvent::Opened(path, r))
                    }
                    Work::Export(path, result, rows) => {
                        store::export_rows(&path, &result, rows.iter(), &worker_job)?;
                        let error =
                            store::record_export(&cache, &path, &result, rows.len(), &worker_job)
                                .err()
                                .map(|e| format!("{e:#}"));
                        Ok(WorkerEvent::Exported(path, rows.len(), error))
                    }

                    Work::Verify => context
                        .verify(&mut session, &image, &worker_job)
                        .map(WorkerEvent::Verified),
                    Work::Catalog(query, refresh) => {
                        if refresh {
                            anyhow::ensure!(network, "离线模式不能刷新索引；按 o 开启在线");
                            symbols::refresh_index(&cache, &worker_job)?;
                        }
                        let page = symbols::catalog(&cache, &query, 500, network, &worker_job)?;
                        let _ = tx.send(WorkerEvent::Progress(format!(
                            "远程索引 {} 个 banner · {} 项 · {} bytes · {} 个匹配，显示前 500",
                            page.index.banners, page.index.entries, page.index.bytes, page.total
                        )));
                        Ok(WorkerEvent::CatalogPage(page))
                    }
                    Work::CatalogDownload(candidate) => {
                        if let Some(path) = saved_download {
                            symbols::validate_remote(
                                &symbols::Repository::configured(&cache)?,
                                &candidate,
                            )?;
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
                    Work::Identify => context
                        .identify(&mut session, &image, &worker_job)
                        .map(WorkerEvent::Identified),
                    Work::InspectSymbols(path) => workspace::inspect_symbols(&path, &worker_job)
                        .map(|text| WorkerEvent::SymbolDetails(path, text)),
                    Work::RefreshLookup => {
                        if windows && !image.as_os_str().is_empty() {
                            let prepared = session.identify_image(&image, &cache, &worker_job)?;
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
                        let image = session.identify_image(&image, &cache, &worker_job)?;
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
                    Work::Analyze(force) => context
                        .analyze(
                            &mut session,
                            &image,
                            &symbols,
                            choice.as_deref(),
                            plugin,
                            force,
                            dump.as_ref(),
                            &analysis_options,
                            &worker_job,
                        )
                        .map(WorkerEvent::Done),
                    Work::MatchLocal(paths, stamp) => {
                        let (report, banner) =
                            context.match_local(&mut session, &image, &paths, &worker_job)?;
                        Ok(WorkerEvent::LocalMatched(report, stamp, banner))
                    }
                    Work::FetchMatched => {
                        let image = session.identify_image(&image, &cache, &worker_job)?;
                        symbols::remote_matches(&image, &cache, network, &worker_job)
                            .map(WorkerEvent::Links)
                    }
                    Work::Download(candidate) => {
                        let image = session.identify_image(&image, &cache, &worker_job)?;
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
            if matches!(event, WorkerEvent::Done(_)) {
                let _ = tx.send(WorkerEvent::Progress(format!(
                    "结果来源: {} · {}",
                    if origin_job.served_from_cache() {
                        "缓存"
                    } else {
                        "本次分析"
                    },
                    if origin_job.prepared_image() {
                        "包含镜像校验"
                    } else {
                        "复用已校验镜像"
                    }
                )));
            }
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
        let mut changed = self.drain_cache_query() || !events.is_empty();
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
            if cancelled && !matches!(event, WorkerEvent::Progress(_)) {
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
                WorkerEvent::Inventory(inventory) => {
                    self.finish_worker();
                    self.apply_inventory(inventory);
                    self.status =
                        "缓存已刷新 · Space 勾选 · x 清理 · Delete 删除 · Enter 打开／折叠".into();
                }
                WorkerEvent::Opened(path, result) => {
                    self.finish_worker();
                    self.open_history_tab(path, result);
                }
                WorkerEvent::Exported(path, rows, error) => {
                    self.finish_worker();
                    self.status = format!(
                        "已导出 {rows} 条: {}{}",
                        path.display(),
                        error
                            .map(|e| format!(" · 记录失败: {e}"))
                            .unwrap_or_default()
                    );
                }
                WorkerEvent::Verified(verified) => {
                    self.finish_worker();
                    self.status = format!(
                        "SHA256 {} · {:.2}s · {}",
                        verified.digest,
                        verified.seconds,
                        if verified.computed {
                            "本次校验"
                        } else {
                            "复用校验"
                        }
                    );
                    self.verified = Some(verified);
                    self.refresh_assets();
                }
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
                WorkerEvent::SavedCatalog(page) => {
                    self.finish_worker();
                    if let Some(page) = page {
                        self.remote_total = page.total;
                        self.remote = page.matches;
                        self.status = format!(
                            "本地已保存索引 {} 条 · 显示 {} 项（r 重新获取）",
                            page.index.entries,
                            self.remote.len()
                        );
                    } else {
                        self.status = "尚未获取远程索引；g 获取".into();
                    }
                }
                WorkerEvent::CatalogPage(page) => {
                    self.finish_worker();
                    self.status = format!(
                        "远程索引：显示 {} / {} 项 · {} 个 banner · {} bytes · / 输入关键词",
                        page.matches.len(),
                        page.total,
                        page.index.banners,
                        page.index.bytes
                    );
                    self.remote_loaded = true;
                    self.remote_total = page.total;
                    self.remote = page.matches;
                    self.remote_catalog = true;
                    self.asset_rows[2] = 0;
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
                    if self.page == Page::Cache {
                        self.pending_work = Some(Work::Inventory);
                    }
                    self.finish_worker();
                    self.clear_plugin_tabs();
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
                    self.remote_matches = Some(matches.clone());
                    self.remote_catalog = false;
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
                    self.enter_when_ready |= self.page == Page::Assets;
                    if let Some(url) = self.download_url.take() {
                        self.downloads.insert(url, path.clone());
                    }
                    self.symbols = path.clone();
                    self.choice = None;
                    let banner = self.results.get("banners").cloned();
                    self.clear_plugin_tabs();
                    self.results.clear();
                    if let Some(banner) = banner {
                        self.results.insert("banners".into(), banner);
                    }
                    self.views.clear();
                    self.history_revision += 1;
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
                WorkerEvent::KernelDiagnosed(report) => {
                    self.finish_worker();
                    self.status = format!("内核诊断完成 · {} · J 查看／e 导出", report.summary());
                    self.kernel_report = Some(Arc::new(report));
                }
                WorkerEvent::DiagnosticExported(path) => {
                    self.finish_worker();
                    self.status = format!("诊断报告已导出: {}", path.display());
                }
                WorkerEvent::Failed(s) => {
                    self.pending_work = None;
                    self.pending_execution = None;
                    self.last_error = Some(s.clone());
                    self.preparation_lookup = false;
                    if self.preparation == Preparation::Matching {
                        self.preparation = Preparation::MissingSymbols;
                    }
                    self.status = failure_status(&s);
                    self.finish_worker();
                }
                WorkerEvent::Done(outcome) => {
                    if let Some(job) = &self.job {
                        let plugin = self
                            .active_request
                            .as_ref()
                            .map_or(self.plugin, |r| r.plugin);
                        let origin = format!(
                            "{} · {}{}",
                            if job.served_from_cache() {
                                "读取缓存"
                            } else {
                                "重新分析"
                            },
                            status::format_duration(
                                self.started.map_or(0.0, |s| s.elapsed().as_secs_f64())
                            ),
                            if job.prepared_image() {
                                "（含镜像校验）"
                            } else {
                                ""
                            }
                        );
                        if let Some(request) = &self.active_request {
                            self.result_origins
                                .insert(request.key.clone(), origin.clone());
                        }
                        self.result_origins.insert(plugin.name().into(), origin);
                    }
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
                            let label = format!(
                                "{} · {} 条 · {} · {}{}",
                                result.plugin,
                                result.rows.len(),
                                self.result_origins
                                    .get(&result.plugin)
                                    .map(String::as_str)
                                    .unwrap_or("本次会话已加载"),
                                if result.complete { "完整" } else { "部分" },
                                if result.diagnostics.is_empty() {
                                    String::new()
                                } else {
                                    format!(
                                        " · {} 条诊断：{}（v 查看）",
                                        result.diagnostics.len(),
                                        status::diagnostic_summary(&result.diagnostics)
                                    )
                                }
                            );
                            self.results.insert(result.plugin.clone(), result);
                            self.status = label;
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
        self.diagnosis_running = false;
        self.started = None;
        self.progress = None;
    }
}

use crate::engine_service::{save_generated_symbol, save_remote_symbol};

fn failure_status(error: &str) -> String {
    let action = if error.contains("HTTP 404") || error.contains("官方符号包未包含精确 ISF")
    {
        "需导入精确符号"
    } else {
        "可重试"
    };
    let message = error.split_whitespace().collect::<Vec<_>>().join(" ");
    if message.contains("需导入精确符号") || message.contains("需手动选择本地 ISF") {
        format!("失败：{message}")
    } else {
        format!("失败：{message} · {action}")
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    #[test]
    fn missing_symbols_do_not_offer_network_retry() {
        assert!(!failure_status("符号下载 HTTP 404：test\n").contains("可重试"));
        assert!(failure_status("官方符号包未包含精确 ISF：test").contains("需导入精确符号"));
        assert!(failure_status("符号下载 HTTP 503：test").contains("可重试"));
        assert!(!failure_status("curl error\nline2").contains('\n'));
    }
}
