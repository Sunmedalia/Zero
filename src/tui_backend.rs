//! Compatible newline-delimited JSON-RPC adapter for the native engine.
//!
//! The in-process Ratatui interface shares typed operations from
//! `engine_service`; external clients can continue using this stdio adapter.
//!
//! Protocol, one JSON object per line in each direction:
//!
//! * request `{"id":N,"method":"assets","params":{…}}`
//! * reply   `{"id":N,"result":…}` or `{"id":N,"error":{"message":"…"}}`
//! * notify  `{"method":"task.progress","params":{"id":"t1","message":"…"}}`
//!   `{"method":"task.done","params":{"id":"t1","result":…}}`
//!   `{"method":"task.error","params":{"id":"t1","message":"…","cancelled":false}}`
//!
//! Long operations run through `task.start`, which answers immediately with a
//! task id; the work continues on a worker thread and reports progress until it
//! finishes. `task.cancel` sets the same cooperative cancellation flag the
//! engine already checks, so no evidence reader keeps running after the user
//! cancels.
use crate::{
    Job,
    analysis::{Options, Os},
    cache,
    dump::{DumpOptions, parse_address},
    linux::{self, Outcome, Plugin, Session},
    store::{self, Results, Settings},
    symbols::{self, RemoteMatch},
    windows::{Architecture, paging::Attachment},
    workspace::{self, Asset, Kind, Registry},
};
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const MAX_REQUEST: usize = 4 * 1024 * 1024;

use crate::engine_service::{
    EngineContext as BackendContext, save_generated_symbol, save_remote_symbol,
};

#[derive(Clone)]
struct TaskHandle {
    id: String,
    cancel: Arc<AtomicBool>,
    worker: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
}

impl TaskHandle {
    fn join(&self) {
        let mut slot = self.worker.lock().expect("task lock");
        if let Some(worker) = slot.take() {
            let _ = worker.join();
        }
    }
}

enum Event {
    Line(Result<String, &'static str>),
    End,
    Reply(Value),
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn send(stdout: &mut impl Write, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

pub fn run() -> Result<()> {
    let root = std::env::var_os("ZERO_ROOT")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_dir()?);
    let context = BackendContext {
        cache: root.join(".zero/rust"),
        settings: Settings::default(),
        root,
    };
    std::fs::create_dir_all(&context.cache)?;
    let settings = store::settings(&context.cache)?;
    let mut context = BackendContext {
        settings,
        ..context
    };
    for directory in [
        context.settings.image_dir.clone(),
        context.settings.export_dir.clone(),
        context.settings.symbols.clone(),
    ] {
        let path = context.directory(&directory);
        if !path.exists() && path.extension().is_none() {
            let _ = std::fs::create_dir_all(path);
        }
    }
    let instance = format!("{}-{}", std::process::id(), now_nanos());
    let session = Arc::new(Mutex::new(Session::default()));

    let (sender, receiver) = mpsc::channel();
    let input = sender.clone();
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut line = Vec::new();
        loop {
            match bounded_line(&mut reader, &mut line) {
                Ok(Read::Line) => {
                    if input
                        .send(Event::Line(
                            String::from_utf8(line.clone()).map_err(|_| "请求不是有效 UTF-8"),
                        ))
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(Read::Oversized) => {
                    if input
                        .send(Event::Line(Err("请求超过 4 MiB，已丢弃")))
                        .is_err()
                    {
                        return;
                    }
                }
                Ok(Read::Eof) => {
                    let _ = input.send(Event::End);
                    return;
                }
                Err(_) => {
                    let _ = input.send(Event::Line(Err("请求读取失败")));
                    return;
                }
            }
        }
    });

    let mut stdout = io::stdout().lock();
    let mut task: Option<TaskHandle> = None;
    let mut sequence = 0u64;
    let mut eof = false;
    loop {
        if eof && task.is_none() {
            break;
        }
        let event = match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => event,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        match event {
            Event::End => eof = true,
            Event::Reply(value) => {
                // The worker's final message releases the task slot. Waiting for
                // the client to send `task.finish` would deadlock a client that
                // exits right after a result, so completion is authoritative
                // here and `task.finish` remains a no-op safety net.
                if matches!(
                    value.get("method").and_then(Value::as_str),
                    Some("task.done" | "task.error")
                ) && let Some(finished) = task.take()
                {
                    finished.join();
                }
                send(&mut stdout, &value)?;
            }
            Event::Line(line) => {
                let request = match line {
                    Err(message) => {
                        send(&mut stdout, &rpc_error(Value::Null, -32700, message))?;
                        continue;
                    }
                    Ok(line) => match serde_json::from_str::<Value>(&line) {
                        Ok(value) => value,
                        Err(_) => {
                            send(&mut stdout, &rpc_error(Value::Null, -32700, "解析失败"))?;
                            continue;
                        }
                    },
                };
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                let method = request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let params = request.get("params").cloned().unwrap_or(json!({}));
                let reply = match method.as_str() {
                    "task.start" => {
                        if let Some(running) = &task {
                            rpc_error(
                                id,
                                -32001,
                                &format!("任务 {} 仍在执行；请先取消", running.id),
                            )
                        } else {
                            sequence += 1;
                            let task_id = format!("t{sequence}");
                            match start_task(
                                task_id.clone(),
                                &context,
                                &session,
                                &instance,
                                params,
                                sender.clone(),
                            ) {
                                Ok(handle) => {
                                    task = Some(handle);
                                    json!({"jsonrpc":"2.0","id":id,"result":{"task":task_id}})
                                }
                                Err(error) => rpc_error(id, -32000, &format!("{error:#}")),
                            }
                        }
                    }
                    "task.cancel" => {
                        if let Some(running) = &task
                            && params.get("id").and_then(Value::as_str) == Some(running.id.as_str())
                        {
                            running.cancel.store(true, Ordering::Relaxed);
                        }
                        json!({"jsonrpc":"2.0","id":id,"result":{"cancelling":true}})
                    }
                    "task.finish" => {
                        if let Some(running) = task.take() {
                            running.join();
                        }
                        json!({"jsonrpc":"2.0","id":id,"result":{"finished":true}})
                    }
                    "task.running" => json!({
                        "jsonrpc":"2.0","id":id,
                        "result":{"task":task.as_ref().map(|t| t.id.clone())},
                    }),
                    _ => match dispatch(&context, &session, &instance, &method, &params) {
                        Ok(value) => {
                            // Later tasks clone the context, so a saved
                            // setting (the offline toggle above all) must
                            // replace the startup snapshot right away.
                            if method == "settings.save" {
                                context.settings = settings_from_json(&value)?;
                            }
                            json!({"jsonrpc":"2.0","id":id,"result":value})
                        }
                        Err(error) => rpc_error(id, -32000, &format!("{error:#}")),
                    },
                };
                send(&mut stdout, &reply)?;
            }
        }
    }
    if let Some(running) = task.take() {
        running.cancel.store(true, Ordering::Relaxed);
        running.join();
    }
    Ok(())
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

enum Read {
    Line,
    /// The line exceeded [`MAX_REQUEST`]; it was discarded whole so the next
    /// request still parses.
    Oversized,
    Eof,
}

/// Read one line, capping it at [`MAX_REQUEST`]; the remainder of an oversized
/// line is discarded so the next request still parses.
fn bounded_line(reader: &mut impl BufRead, out: &mut Vec<u8>) -> io::Result<Read> {
    out.clear();
    let mut oversized = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if out.is_empty() && !oversized {
                Read::Eof
            } else if oversized {
                Read::Oversized
            } else {
                Read::Line
            });
        }
        let end = buffer.iter().position(|&b| b == b'\n');
        let take = end.unwrap_or(buffer.len());
        let consumed = end.map_or(take, |i| i + 1);
        if !oversized {
            if out.len() + take > MAX_REQUEST {
                oversized = true;
                out.clear();
            } else {
                out.extend_from_slice(&buffer[..take]);
            }
        }
        reader.consume(consumed);
        if end.is_some() {
            return Ok(if oversized {
                Read::Oversized
            } else {
                Read::Line
            });
        }
    }
}

fn start_task(
    id: String,
    context: &BackendContext,
    session: &Arc<Mutex<Session>>,
    instance: &str,
    params: Value,
    sender: mpsc::Sender<Event>,
) -> Result<TaskHandle> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Args {
        op: String,
        #[serde(default)]
        args: Value,
    }
    let args: Args = serde_json::from_value(params).context("task.start 参数无效")?;
    let op = args.op.clone();
    let payload = args.args.clone();
    let job = Job::new({
        let sender = sender.clone();
        let id = id.clone();
        move |message| {
            let _ = sender.send(Event::Reply(json!({
                "jsonrpc":"2.0",
                "method":"task.progress",
                "params":{"id":id,"message":message},
            })));
        }
    });
    let cancel = job.cancel.clone();
    let context = context.clone();
    let session = session.clone();
    let instance = instance.to_owned();
    let worker_id = id.clone();
    let finished = sender.clone();
    let worker = thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_task(&op, payload, &context, &session, &instance, &job)
        }));
        let cancelled = job.cancel.load(Ordering::Relaxed);
        let message = match outcome {
            Ok(Ok(result)) => json!({
                "jsonrpc":"2.0",
                "method":"task.done",
                "params":{"id":worker_id,"result":result},
            }),
            Ok(Err(error)) => json!({
                "jsonrpc":"2.0",
                "method":"task.error",
                "params":{"id":worker_id,"message":format!("{error:#}"),"cancelled":cancelled},
            }),
            Err(_) => json!({
                "jsonrpc":"2.0",
                "method":"task.error",
                "params":{"id":worker_id,"message":"任务线程 panic；已终止","cancelled":false},
            }),
        };
        let _ = finished.send(Event::Reply(message));
    });
    Ok(TaskHandle {
        id,
        cancel,
        worker: Arc::new(Mutex::new(Some(worker))),
    })
}

fn run_task(
    op: &str,
    payload: Value,
    context: &BackendContext,
    session: &Arc<Mutex<Session>>,
    instance: &str,
    job: &Job,
) -> Result<Value> {
    match op {
        "analyze" => analyze(context, session, payload, job),
        "dump" => dump(context, session, payload, job),
        "identify" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                image: PathBuf,
            }
            let args: Args = serde_json::from_value(payload)?;
            let banner = context.identify(
                &mut *session
                    .lock()
                    .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?,
                &args.image,
                job,
            )?;
            Ok(json!({"banner": results_json(&banner)}))
        }
        // Verify the image's content (SHA256) once for this session. Analysis
        // reuses the verified image, so the first plugin does not pay for it.
        "verify" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                image: PathBuf,
            }
            let args: Args = serde_json::from_value(payload)?;
            let verified = context.verify(
                &mut *session
                    .lock()
                    .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?,
                &args.image,
                job,
            )?;
            Ok(
                json!({"digest": verified.digest, "computed": verified.computed, "seconds": verified.seconds}),
            )
        }
        "matchLocal" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                image: PathBuf,
                paths: Vec<PathBuf>,
            }
            let args: Args = serde_json::from_value(payload)?;
            let (report, banner) = context.match_local(
                &mut *session
                    .lock()
                    .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?,
                &args.image,
                &args.paths,
                job,
            )?;
            Ok(json!({
                "banner": results_json(&banner),
                "matched": report.matched.iter().map(|(path, labels)| json!({
                    "path": path,
                    "labels": labels,
                })).collect::<Vec<_>>(),
                "diagnostics": report.diagnostics,
            }))
        }
        "remote" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                #[serde(default)]
                image: Option<PathBuf>,
                #[serde(default)]
                query: String,
                #[serde(default)]
                refresh: bool,
                #[serde(default)]
                catalog: bool,
                #[serde(default)]
                limit: Option<usize>,
                /// Only read an index already saved on disk: never download,
                /// and report "no index" instead of failing.
                #[serde(default)]
                local_only: bool,
            }
            let args: Args = serde_json::from_value(payload)?;
            let network = context.settings.remote_symbols;
            let mut total = None;
            let mut index = None;
            let index_file =
                symbols::Repository::configured(&context.cache)?.index_file(&context.cache);
            if args.catalog && args.local_only && !index_file.is_file() {
                return Ok(json!({"matches": [], "catalog": true, "total": 0, "index": null}));
            }
            let matches = if let Some(image) = &args.image {
                let image = session
                    .lock()
                    .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?
                    .identify_image(&context.expand(image), &context.cache, job)?;
                symbols::remote_matches(&image, &context.cache, network, job)?
            } else if args.catalog {
                if args.refresh {
                    ensure!(network, "离线模式不能刷新索引；按 o 开启在线");
                    symbols::refresh_index(&context.cache, job)?;
                }
                let page = symbols::catalog(
                    &context.cache,
                    &args.query,
                    args.limit.unwrap_or(500).clamp(1, 5000),
                    network,
                    job,
                )?;
                total = Some(page.total);
                index = Some(page.index);
                page.matches
            } else {
                if network {
                    symbols::refresh_index(&context.cache, job)?;
                } else {
                    ensure!(
                        index_file.is_file(),
                        "离线模式且没有索引缓存；按 o 开启在线模式后按 r"
                    );
                }
                Vec::new()
            };
            Ok(json!({
                "matches": matches.iter().map(remote_json).collect::<Vec<_>>(),
                "catalog": args.catalog,
                "total": total.unwrap_or(matches.len()),
                "index": index,
            }))
        }
        "download" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                candidate: Value,
                #[serde(default)]
                image: Option<PathBuf>,
                #[serde(default)]
                catalog: bool,
            }
            let args: Args = serde_json::from_value(payload)?;
            let candidate = remote_from_json(&args.candidate)?;
            let network = context.settings.remote_symbols;
            let isf = if args.catalog {
                symbols::download_catalog(&candidate, &context.cache, network, job)?
            } else {
                let image = args
                    .image
                    .as_ref()
                    .context("需要当前镜像才能校验精确匹配")?;
                let image = session
                    .lock()
                    .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?
                    .identify_image(&context.expand(image), &context.cache, job)?;
                symbols::download(&candidate, &image, &context.cache, network, job)?
            };
            let path = save_remote_symbol(&candidate, &isf, &context.library(), job)?;
            register(&context.cache, &path)?;
            Ok(json!({"path": path}))
        }
        "generate" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                image: PathBuf,
                #[serde(default)]
                kali: bool,
                #[serde(default)]
                elf: Option<PathBuf>,
                #[serde(default)]
                config: Option<PathBuf>,
                #[serde(default)]
                tool: Option<PathBuf>,
            }
            let args: Args = serde_json::from_value(payload)?;
            let image = session
                .lock()
                .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?
                .prepare_image(&context.expand(&args.image), &context.cache, job)?;
            let path = if args.kali {
                crate::prepare::prepare_kali(
                    &image,
                    &context.cache,
                    context.settings.remote_symbols,
                    job,
                )?
            } else {
                crate::prepare::generate(
                    args.elf.as_deref().context("需要调试 ELF")?,
                    args.config.as_deref().context("需要内核配置")?,
                    args.tool
                        .as_deref()
                        .unwrap_or(&context.cache.join("symbols/build/dwarf2json/dwarf2json")),
                    &image,
                    &context.cache,
                    job,
                )?
            };
            let saved = save_generated_symbol(&path, &context.library(), job)?;
            register(&context.cache, &saved)?;
            Ok(json!({"path": saved}))
        }
        "inspectSymbols" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                path: PathBuf,
            }
            let args: Args = serde_json::from_value(payload)?;
            Ok(json!({
                "text": workspace::inspect_symbols(&context.expand(&args.path), job)?,
            }))
        }
        "cacheClear" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                scopes: Vec<String>,
            }
            let args: Args = serde_json::from_value(payload)?;
            let scopes = args
                .scopes
                .iter()
                .map(|s| scope_from_id(s))
                .collect::<Result<Vec<_>>>()?;
            let report = cache::clear_with_job(&context.cache, &scopes, job)?;
            Ok(json!({
                "removed": report.removed,
                "bytes": report.bytes,
                "failures": report.failures,
            }))
        }
        "cacheRemove" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                paths: Vec<PathBuf>,
            }
            let args: Args = serde_json::from_value(payload)?;
            let report = cache::remove(&context.cache, &args.paths, job)?;
            Ok(json!({
                "removed": report.removed,
                "bytes": report.bytes,
                "failures": report.failures,
            }))
        }
        "record" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                key: String,
            }
            let args: Args = serde_json::from_value(payload)?;
            Ok(json!({
                "result": results_json(&store::open_record(&context.cache, &args.key, job)?),
            }))
        }
        "export" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                path: PathBuf,
                result: Value,
                #[serde(default)]
                rows: Option<Vec<Vec<String>>>,
            }
            let args: Args = serde_json::from_value(payload)?;
            let result = results_from_json(&args.result)?;
            let path = context.expand(&args.path);
            let count = args.rows.as_ref().map_or(result.rows.len(), Vec::len);
            match &args.rows {
                Some(rows) => store::export_rows(&path, &result, rows.iter(), job)?,
                None => store::export_rows(&path, &result, result.rows.iter(), job)?,
            }
            // The export itself is published; a failed record only loses the local copy.
            let (record, record_error) = if context.settings.enable_cache {
                match store::record_export(&context.cache, &path, &result, count, job) {
                    Ok(record) => (Some(record), None),
                    Err(error) => {
                        job.check()?;
                        (None, Some(format!("{error:#}")))
                    }
                }
            } else {
                (None, None)
            };
            Ok(json!({
                "path": path,
                "rows": count,
                "record": record,
                "record_error": record_error,
            }))
        }
        "history" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                path: PathBuf,
            }
            let args: Args = serde_json::from_value(payload)?;
            job.check()?;
            Ok(json!({
                "result": results_json(&store::exported(&context.expand(&args.path))?),
            }))
        }
        other => anyhow::bail!("未知任务 {other}（backend {instance}）"),
    }
}

fn analyze(
    context: &BackendContext,
    session: &Arc<Mutex<Session>>,
    payload: Value,
    job: &Job,
) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Args {
        image: PathBuf,
        #[serde(default)]
        symbols: Option<PathBuf>,
        plugin: String,
        #[serde(default)]
        symbol_choice: Option<String>,
        #[serde(default)]
        options: Value,
        #[serde(default)]
        dump: Value,
        #[serde(default)]
        no_cache: bool,
    }
    let args: Args = serde_json::from_value(payload)?;
    let plugin = Plugin::from_str(&args.plugin, true).map_err(anyhow::Error::msg)?;
    let options = options_from_json(&args.options)?;
    let dump = dump_from_json(&args.dump)?;
    let image = context.expand(&args.image);
    let symbols = context.symbol_source(args.symbols);
    let outcome = context.analyze(
        &mut *session
            .lock()
            .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?,
        &image,
        &symbols,
        args.symbol_choice.as_deref(),
        plugin,
        args.no_cache,
        dump.as_ref().map(|(_, d)| d),
        &options,
        job,
    )?;
    Ok(match outcome {
        Outcome::Choose(labels) => json!({"choose": labels}),
        Outcome::Ready(result) => json!({
            "result": results_json(&result),
            "source": if job.served_from_cache() { "cache" } else { "fresh" },
            "prepared": job.prepared_image(),
        }),
    })
}

fn dump(
    context: &BackendContext,
    session: &Arc<Mutex<Session>>,
    payload: Value,
    job: &Job,
) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Args {
        image: PathBuf,
        #[serde(default)]
        symbols: Option<PathBuf>,
        #[serde(default)]
        symbol_choice: Option<String>,
        mode: String,
        pid: u32,
        directory: PathBuf,
        #[serde(default)]
        start: Option<String>,
        #[serde(default)]
        end: Option<String>,
        #[serde(default)]
        options: Value,
    }
    let args: Args = serde_json::from_value(payload)?;
    let plugin = match args.mode.as_str() {
        "process" => Plugin::Procdump,
        "range" => Plugin::Memdump,
        "elf" => Plugin::Elfdump,
        "pe" => Plugin::WinPedump,
        "vad" => Plugin::WinVaddump,
        "dll" => Plugin::WinDlldump,
        "module" => Plugin::WinModdump,
        "files" => Plugin::WinDumpfiles,
        other => anyhow::bail!("无效 dump 模式 {other}"),
    };
    let address = |value: Option<String>| -> Result<Option<u64>> {
        value
            .map(|s| parse_address(&s).map_err(anyhow::Error::msg))
            .transpose()
    };
    let options = DumpOptions {
        pid: args.pid,
        directory: context.expand(&args.directory),
        start: address(args.start)?,
        end: address(args.end)?,
    };
    options.validate(plugin)?;
    let analysis_options = options_from_json(&args.options)?;
    let image = context.expand(&args.image);
    let symbols = context.symbol_source(args.symbols);
    let mut guard = session
        .lock()
        .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?;
    let outcome = crate::analysis::analyze(
        &mut guard,
        &linux::Request {
            image: &image,
            symbols: &symbols,
            choice: args.symbol_choice.as_deref(),
            plugin,
            cache: &context.cache,
            use_cache: false,
            network: context.settings.remote_symbols,
        },
        Some(&options),
        &analysis_options,
        job,
    )?;
    Ok(match outcome {
        Outcome::Choose(labels) => json!({"choose": labels}),
        Outcome::Ready(result) => json!({"result": results_json(&result)}),
    })
}

fn dispatch(
    context: &BackendContext,
    session: &Arc<Mutex<Session>>,
    instance: &str,
    method: &str,
    params: &Value,
) -> Result<Value> {
    match method {
        "hello" => Ok(json!({
            "instance": instance,
            "root": context.root,
            "cache": context.cache,
            "version": env!("CARGO_PKG_VERSION"),
            "engine": crate::ENGINE_VERSION,
            "settings": settings_json(&context.settings),
            "plugins": plugins(),
            "scopes": cache::SCOPES
                .iter()
                .map(|s| json!({"id": scope_id(*s), "label": s.label()}))
                .collect::<Vec<_>>(),
            "repository": symbols::Repository::parse(&context.settings.symbol_repository)
                .map(|r| r.web)
                .unwrap_or_else(|_| symbols::REPOSITORY.into()),
            "platform": if cfg!(target_os = "windows") { "windows" } else { "unix" },
        })),
        "assets" => {
            let registry = Registry::load(&context.cache)?;
            let assets = registry.discover_with_dirs(
                &context.root,
                &context.cache,
                &context.image_dir(),
                &context.symbol_dir(),
            )?;
            Ok(Value::Array(
                assets
                    .iter()
                    .map(|asset| asset_json(asset, &context.cache))
                    .collect(),
            ))
        }
        "registry.select" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                kind: String,
                path: PathBuf,
            }
            let args: Args = serde_json::from_value(params.clone())?;
            let kind = kind_of(&args.kind)?;
            let path = args.path.canonicalize()?;
            let mut registry = Registry::load(&context.cache)?;
            registry.import(&path, kind, &context.cache)?;
            Ok(json!({"path": path}))
        }
        "registry.register" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                kind: String,
                path: PathBuf,
            }
            let args: Args = serde_json::from_value(params.clone())?;
            let kind = kind_of(&args.kind)?;
            let mut registry = Registry::load(&context.cache)?;
            Ok(json!({
                "path": registry.register(&args.path, kind, &context.cache)?,
            }))
        }
        "registry.remove" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                path: PathBuf,
            }
            let args: Args = serde_json::from_value(params.clone())?;
            let mut registry = Registry::load(&context.cache)?;
            registry.remove(&args.path, &context.cache)?;
            Ok(json!({"removed": args.path}))
        }
        "registry.selected" => {
            let registry = Registry::load(&context.cache)?;
            Ok(json!({
                "image": registry.selected(Kind::Image),
                "symbols": registry.selected(Kind::Symbols),
            }))
        }
        "browse" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                path: PathBuf,
                filter: String,
            }
            let args: Args = serde_json::from_value(params.clone())?;
            let filter = match args.filter.as_str() {
                "files" => crate::browser::Filter::Files,
                "images" => crate::browser::Filter::Images,
                "symbols" => crate::browser::Filter::Symbols,
                "exports" => crate::browser::Filter::Exports,
                _ => crate::browser::Filter::Directories,
            };
            let root = context.expand(&args.path);
            let entries = crate::browser::entries(&root, filter)?;
            Ok(json!({
                "root": root,
                "entries": entries.iter().map(|e| json!({
                    "path": e.path,
                    "name": e.path.file_name().unwrap_or_default().to_string_lossy(),
                    "directory": e.directory,
                    "kind": match crate::browser::file_kind(&e.path) {
                        crate::browser::FileKind::Image => "image",
                        crate::browser::FileKind::Symbols => "symbols",
                        crate::browser::FileKind::Other => "file",
                    },
                })).collect::<Vec<_>>(),
            }))
        }
        "cache.inventory" => {
            let inventory = context.inventory(&Job::default())?;
            Ok(json!({"entries": inventory.entries.iter().map(|e| json!({
                "path": e.path, "scope": scope_id(e.scope), "bytes": e.bytes, "modified": e.modified,
                "result": inventory.summaries.get(&e.path),
            })).collect::<Vec<_>>(), "records": inventory.records}))
        }
        "settings.get" => Ok(settings_json(&context.settings)),
        "settings.save" => {
            let settings = settings_from_json(params)?;
            store::save_settings(&context.cache, &settings)?;
            Ok(settings_json(&settings))
        }
        "history.list" => Ok(json!({
            "paths": store::history_paths(&context.history_dir()),
        })),
        "symbols.cached" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                paths: Vec<String>,
            }
            let args: Args = serde_json::from_value(params.clone())?;
            let cached = args
                .paths
                .iter()
                .map(|path| {
                    symbols::cache_filename(path)
                        .map(|name| context.cache.join("symbols/isf").join(name).is_file())
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>();
            Ok(json!({"cached": cached}))
        }
        "session.reset" => {
            session
                .lock()
                .map_err(|_| anyhow::anyhow!("分析会话锁损坏"))?
                .clear();
            Ok(json!({"cleared": true}))
        }
        "ping" => Ok(json!({"pong": true})),
        other => anyhow::bail!("未知方法 {other}"),
    }
}

fn register(cache: &Path, path: &Path) -> Result<()> {
    let mut registry = Registry::load(cache)?;
    registry.register(path, Kind::Symbols, cache)?;
    Ok(())
}

fn plugins() -> Value {
    Value::Array(
        crate::plugin::PLUGINS
            .iter()
            .map(|descriptor| {
                let plugin = descriptor.plugin;
                json!({
                    "name": descriptor.name,
                    "label": descriptor.label,
                    "columns": descriptor.columns,
                    "widths": descriptor.widths,
                    "category": plugin.category(),
                    "os": if plugin.is_windows() { "windows" } else { "linux" },
                    "dump": plugin.is_dump(),
                    "tree": plugin.is_tree(),
                    "description": plugin.description(),
                })
            })
            .collect(),
    )
}

fn settings_json(settings: &Settings) -> Value {
    json!({
        "layout_version": settings.layout_version,
        "image_dir": settings.image_dir,
        "page_size": settings.page_size,
        "export_dir": settings.export_dir,
        "symbols": settings.symbols,
        "history_dir": settings.history_dir,
        "enable_cache": settings.enable_cache,
        "remote_symbols": settings.remote_symbols,
        "theme": settings.theme,
        "symbol_repository": settings.symbol_repository,
        "reuse_recorded_digest": settings.reuse_recorded_digest,
        "resources": settings.resources,
    })
}

fn settings_from_json(value: &Value) -> Result<Settings> {
    serde_json::from_value(value.clone()).context("设置 JSON 无效")
}

fn asset_json(asset: &Asset, cache: &Path) -> Value {
    json!({
        "id": asset.id(),
        "path": asset.path,
        "name": asset.name(),
        "kind": if asset.kind == Kind::Image { "image" } else { "symbols" },
        "bytes": asset.bytes,
        "available": asset.available,
        "directory": asset.directory,
        "format": asset.format(),
        "origin": asset.origin,
        "stamp": asset.stamp,
        "source_url": source_url(&asset.path),
        "identity": (asset.kind == Kind::Image && !asset.directory)
            .then(|| crate::image::bound_identity(&asset.path, cache))
            .flatten(),
        "digest": (asset.kind == Kind::Image && !asset.directory)
            .then(|| crate::image::recorded_digest(&asset.path, cache))
            .flatten(),
    })
}

/// Repository URL recorded beside a downloaded or generated symbol.
///
/// The interface uses it to show `[已保存]` on remote candidates and to hide a
/// regenerable cache copy that duplicates the managed library entry. The
/// sidecar is bounded and read-only; a malformed or oversized file is ignored.
fn source_url(path: &Path) -> Option<String> {
    let sidecar = path.with_extension("source.json");
    let metadata = std::fs::metadata(&sidecar).ok()?;
    if metadata.len() > 1024 * 1024 {
        return None;
    }
    let bytes = std::fs::read(&sidecar).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.get("url").and_then(Value::as_str).map(str::to_owned)
}

fn remote_json(candidate: &RemoteMatch) -> Value {
    json!({
        "banner": candidate.banner,
        "path": candidate.path,
        "url": candidate.url,
    })
}

fn remote_from_json(value: &Value) -> Result<RemoteMatch> {
    serde_json::from_value(value.clone()).context("远程候选 JSON 无效")
}

fn results_json(result: &Results) -> Value {
    json!({
        "plugin": result.plugin,
        "columns": result.columns,
        "rows": result.rows,
        "complete": result.complete,
        "diagnostics": result.diagnostics,
        "banner": result.banner,
        "symbol": result.symbol,
        "page_table": result.page_table,
        "historical": result.historical,
        "system": result.system,
        "kernel_identity": result.kernel_identity,
    })
}

fn results_from_json(value: &Value) -> Result<Results> {
    serde_json::from_value(value.clone()).context("结果 JSON 无效")
}

fn options_from_json(value: &Value) -> Result<Options> {
    let os = match value.get("os").and_then(Value::as_str).unwrap_or("auto") {
        "auto" => Os::Auto,
        "linux" => Os::Linux,
        "windows" => Os::Windows,
        other => anyhow::bail!("无效系统 {other}"),
    };
    let arch = match value.get("arch").and_then(Value::as_str).unwrap_or("auto") {
        "auto" => Architecture::Auto,
        "x86" => Architecture::X86,
        "x64" => Architecture::X64,
        "arm64" => Architecture::Arm64,
        other => anyhow::bail!("无效架构 {other}"),
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pagefile {
        index: u8,
        path: PathBuf,
    }
    let pagefiles: Vec<Pagefile> = match value.get("pagefiles") {
        Some(value) => serde_json::from_value(value.clone()).context("pagefiles 无效")?,
        None => Vec::new(),
    };
    ensure!(
        pagefiles
            .iter()
            .all(|f| f.index <= 15 && !f.path.as_os_str().is_empty()),
        "分页文件索引必须为 0..15，路径不能为空"
    );
    Ok(Options {
        os,
        arch,
        pid: value.get("pid").and_then(Value::as_u64).map(|v| v as u32),
        // Kernel addresses exceed the JSON/JS safe-integer range, so the
        // interface sends them as decimal strings; numbers stay accepted for
        // CLI-shaped callers.
        hive: address_value(value.get("hive"))?,
        key: value
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        pattern: value
            .get("pattern")
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty())
            .map(str::to_owned),
        pagefiles: pagefiles
            .into_iter()
            .map(|f| Attachment {
                index: f.index,
                path: f.path,
            })
            .collect(),
        swapfile: value
            .get("swapfile")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
    })
}

fn dump_from_json(value: &Value) -> Result<Option<(Plugin, DumpOptions)>> {
    if value.is_null() {
        return Ok(None);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Raw {
        plugin: String,
        pid: u32,
        directory: PathBuf,
        #[serde(default)]
        start: Option<u64>,
        #[serde(default)]
        end: Option<u64>,
    }
    let raw: Raw = serde_json::from_value(value.clone()).context("dump 参数无效")?;
    let plugin = Plugin::from_str(&raw.plugin, true).map_err(anyhow::Error::msg)?;
    ensure!(plugin.is_dump(), "非 Dump 插件");
    Ok(Some((
        plugin,
        DumpOptions {
            pid: raw.pid,
            directory: raw.directory,
            start: raw.start,
            end: raw.end,
        },
    )))
}

/// A 64-bit address from either a decimal string or a JSON integer.
fn address_value(value: Option<&Value>) -> Result<Option<u64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => Ok(number.as_u64()),
        Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
        Some(Value::String(text)) => parse_address(text).map(Some).map_err(anyhow::Error::msg),
        Some(_) => anyhow::bail!("地址必须是十进制字符串或整数"),
    }
}

fn kind_of(value: &str) -> Result<Kind> {
    match value {
        "image" => Ok(Kind::Image),
        "symbols" => Ok(Kind::Symbols),
        other => anyhow::bail!("无效资产类型 {other}"),
    }
}

fn scope_id(scope: cache::Scope) -> &'static str {
    match scope {
        cache::Scope::Results => "results",
        cache::Scope::Identification => "identification",
        cache::Scope::Images => "images",
        cache::Scope::Symbols => "symbols",
        cache::Scope::Dumps => "dumps",
        cache::Scope::Exports => "exports",
        cache::Scope::All => "all",
    }
}

fn scope_from_id(value: &str) -> Result<cache::Scope> {
    Ok(match value {
        "results" => cache::Scope::Results,
        "identification" => cache::Scope::Identification,
        "images" => cache::Scope::Images,
        "symbols" => cache::Scope::Symbols,
        "dumps" => cache::Scope::Dumps,
        "exports" => cache::Scope::Exports,
        "all" => cache::Scope::All,
        other => anyhow::bail!("无效缓存范围 {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_line_discards_an_oversized_request_and_keeps_the_next() {
        let mut input = vec![b'x'; MAX_REQUEST + 16];
        input.extend_from_slice(b"\nping\n");
        let mut reader = io::BufReader::with_capacity(4096, input.as_slice());
        let mut line = Vec::new();
        assert!(matches!(
            bounded_line(&mut reader, &mut line).unwrap(),
            Read::Oversized
        ));
        assert!(line.is_empty());
        assert!(matches!(
            bounded_line(&mut reader, &mut line).unwrap(),
            Read::Line
        ));
        assert_eq!(line, b"ping");
        assert!(matches!(
            bounded_line(&mut reader, &mut line).unwrap(),
            Read::Eof
        ));
    }

    #[test]
    fn options_round_trip_through_the_protocol_shape() {
        let options = options_from_json(&json!({
            "os": "windows",
            "arch": "x64",
            "pid": 4,
            "hive": 4096,
            "key": "Software",
            "pagefiles": [{"index": 1, "path": "/evidence/pagefile.sys"}],
            "swapfile": "/evidence/swapfile.sys",
        }))
        .unwrap();
        assert_eq!(options.os, Os::Windows);
        assert_eq!(options.arch, Architecture::X64);
        assert_eq!(options.pid, Some(4));
        assert_eq!(options.pagefiles[0].index, 1);
        assert!(options.swapfile.is_some());
        assert!(options_from_json(&json!({"pagefiles":[{"index":99,"path":"x"}]})).is_err());
    }

    #[test]
    fn scopes_round_trip() {
        for scope in cache::SCOPES {
            assert_eq!(scope_from_id(scope_id(scope)).unwrap(), scope);
        }
        assert!(scope_from_id("unknown").is_err());
    }
}
