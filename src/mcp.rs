//! Local, newline-delimited JSON-RPC MCP adapter for the native engine.
use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};
use zero_tui::{
    Job, cache, dump,
    linux::{self, Outcome, Plugin},
    store, symbols,
};

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_ROWS: usize = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyzeArgs {
    image: PathBuf,
    plugin: String,
    os: Option<zero_tui::analysis::Os>,
    arch: Option<zero_tui::windows::Architecture>,
    pagefiles: Option<Vec<zero_tui::windows::paging::Attachment>>,
    swapfile: Option<PathBuf>,
    pid: Option<u32>,
    hive: Option<String>,
    key: Option<String>,
    symbols: Option<PathBuf>,
    symbol_choice: Option<String>,
    offline: Option<bool>,
    no_cache: Option<bool>,
    limit: Option<usize>,
    output: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DumpArgs {
    image: PathBuf,
    symbols: Option<PathBuf>,
    symbol_choice: Option<String>,
    mode: String,
    os: Option<zero_tui::analysis::Os>,
    arch: Option<zero_tui::windows::Architecture>,
    pagefiles: Option<Vec<zero_tui::windows::paging::Attachment>>,
    swapfile: Option<PathBuf>,
    pid: u32,
    dump_dir: PathBuf,
    output: PathBuf,
    start: Option<String>,
    end: Option<String>,
    offline: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

fn root() -> Result<PathBuf> {
    Ok(env::var_os("ZERO_ROOT")
        .map(PathBuf::from)
        .unwrap_or(env::current_dir()?))
}

fn path(root: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        root.join(value)
    }
}

fn job() -> Job {
    Job::new(|message| eprintln!("zero-mcp: {message}"))
}

fn settings(root: &Path, offline: bool) -> Result<(PathBuf, store::Settings)> {
    let cache_dir = root.join(".zero/rust");
    let mut settings = store::settings(&cache_dir)?;
    if offline {
        settings.remote_symbols = false;
    }
    Ok((cache_dir, settings))
}

fn result_page(result: store::Results, offset: usize, limit: usize) -> Value {
    let total = result.rows.len();
    let rows = result
        .rows
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(rows.len());
    json!({
        "plugin": result.plugin, "columns": result.columns, "rows": rows,
        "total_rows": total, "offset": offset, "next_offset": (next_offset < total).then_some(next_offset),
        "complete": result.complete, "diagnostics": result.diagnostics,
        "banner": result.banner, "symbol": result.symbol,
        "page_table": result.page_table, "historical": result.historical,
        "system":result.system,"kernel_identity":result.kernel_identity
    })
}

fn tools() -> Value {
    json!({"tools": [
        {"name":"zero_plugins","description":"List native Linux and Windows memory forensics plugins and their result columns.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"zero_symbols","description":"Identify image banners and exact ISF repository matches. Optional download saves verified symbols locally.","inputSchema":{"type":"object","properties":{"image":{"type":"string"},"offline":{"type":"boolean"},"download":{"type":"boolean"}},"required":["image"],"additionalProperties":false}},
        {"name":"zero_analyze","description":"Run a native analysis plugin on a local memory image. Returns at most 200 rows and may export all rows to JSON/CSV. Returns result_id; use zero_results for subsequent pages.","inputSchema":{"type":"object","properties":{"image":{"type":"string"},"plugin":{"type":"string"},"os":{"type":"string","enum":["auto","linux","windows"]},"arch":{"type":"string","enum":["auto","x86","x64","arm64"]},"pagefiles":{"type":"array","items":{"type":"object","properties":{"index":{"type":"integer","minimum":0,"maximum":15},"path":{"type":"string"}},"required":["index","path"],"additionalProperties":false}},"swapfile":{"type":"string"},"pid":{"type":"integer","minimum":0},"hive":{"type":"string"},"key":{"type":"string"},"symbols":{"type":"string"},"symbol_choice":{"type":"string"},"offline":{"type":"boolean"},"no_cache":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":200},"output":{"type":"string"}},"required":["image","plugin"],"additionalProperties":false}},
        {"name":"zero_results","description":"Read or export an immutable analysis snapshot. Does not run analysis; expired IDs require a new zero_analyze call.","inputSchema":{"type":"object","properties":{"result_id":{"type":"string"},"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":200},"output":{"type":"string"}},"required":["result_id"],"additionalProperties":false}},
        {"name":"zero_dump","description":"Export one process, one PID address range, or ELF mappings to a local directory with a JSON/CSV manifest. Requires explicit PID and paths.","inputSchema":{"type":"object","properties":{"image":{"type":"string"},"symbols":{"type":"string"},"symbol_choice":{"type":"string"},"os":{"type":"string","enum":["auto","linux","windows"]},"arch":{"type":"string","enum":["auto","x86","x64","arm64"]},"pagefiles":{"type":"array","items":{"type":"object","properties":{"index":{"type":"integer","minimum":0,"maximum":15},"path":{"type":"string"}},"required":["index","path"],"additionalProperties":false}},"swapfile":{"type":"string"},"mode":{"type":"string","enum":["process","range","elf","pe"]},"pid":{"type":"integer","minimum":0},"dump_dir":{"type":"string"},"output":{"type":"string"},"start":{"type":"string"},"end":{"type":"string"},"offline":{"type":"boolean"}},"required":["image","mode","pid","dump_dir","output"],"additionalProperties":false}},
        {"name":"zero_cache_list","description":"Inspect regenerable local cache without deleting it.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
    ]})
}

/// `session` lives for the whole server so repeated calls on one image reuse its
/// digest, symbols and page-table discovery; it re-prepares when the file changes.
fn call(
    name: &str,
    args: Value,
    root: &Path,
    session: &mut linux::Session,
    snapshots: &std::sync::Mutex<zero_tui::snapshots::Snapshots>,
    job: &Job,
) -> Result<Value> {
    if matches!(name, "zero_plugins" | "zero_cache_list") {
        let _: EmptyArgs = serde_json::from_value(args.clone())?;
    }
    match name {
        "zero_plugins" => Ok(
            json!({"plugins":linux::PLUGINS.iter().map(|p| json!({"name":p.name,"category":p.plugin.category(),"columns":p.columns,"os":if p.plugin.is_windows(){"windows"}else{"linux"}})).collect::<Vec<_>>()}),
        ),
        "zero_cache_list" => Ok(serde_json::to_value(cache::inventory(
            &root.join(".zero/rust"),
        )?)?),
        "zero_symbols" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                image: PathBuf,
                offline: Option<bool>,
                download: Option<bool>,
            }
            let a: Args = serde_json::from_value(args)?;
            let (cache_dir, settings) = settings(root, a.offline.unwrap_or(false))?;
            let image = session.identify_image(&path(root, &a.image), &cache_dir, job)?;
            let banners = linux::banner_result(&image, job)?;
            let matches =
                symbols::remote_matches(&image, &cache_dir, settings.remote_symbols, job)?;
            let mut downloaded = Vec::new();
            if a.download.unwrap_or(false) {
                for item in &matches {
                    match symbols::download(item, &image, &cache_dir, settings.remote_symbols, job)
                    {
                        Ok(isf) => downloaded.push(isf.label),
                        Err(e) => {
                            job.check()?;
                            job.report(format!("候选下载失败: {e:#}"));
                        }
                    }
                }
            }
            Ok(json!({"banners":banners.rows,"matches":matches,"downloaded":downloaded}))
        }
        "zero_results" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Args {
                result_id: String,
                offset: Option<usize>,
                limit: Option<usize>,
                output: Option<PathBuf>,
            }
            let a: Args = serde_json::from_value(args)?;
            let output = a.output.as_deref().map(|p| path(root, p));
            snapshots
                .lock()
                .map_err(|_| anyhow::anyhow!("快照锁不可用"))?
                .page(
                    &a.result_id,
                    a.offset.unwrap_or(0),
                    a.limit.unwrap_or(50),
                    output.as_deref(),
                    job,
                )
        }
        "zero_analyze" => {
            ensure!(
                args.get("offset").is_none(),
                "zero_analyze 不再接受 offset；首次分析后使用 zero_results(result_id, offset, limit) 翻页"
            );
            let a: AnalyzeArgs = serde_json::from_value(args)?;
            let plugin = Plugin::from_str(&a.plugin, true).map_err(anyhow::Error::msg)?;
            ensure!(!plugin.is_dump(), "转储请调用 zero_dump");
            let limit = a.limit.unwrap_or(50);
            ensure!((1..=MAX_ROWS).contains(&limit), "limit 必须在 1..=200");
            let (cache_dir, settings) = settings(root, a.offline.unwrap_or(false))?;
            let symbols = a
                .symbols
                .as_deref()
                .map(|p| path(root, p))
                .unwrap_or_else(|| path(root, Path::new(&settings.symbols)));
            let outcome = zero_tui::analysis::analyze(
                session,
                &linux::Request {
                    image: &path(root, &a.image),
                    symbols: &symbols,
                    choice: a.symbol_choice.as_deref(),
                    plugin,
                    cache: &cache_dir,
                    use_cache: settings.enable_cache && !a.no_cache.unwrap_or(false),
                    network: settings.remote_symbols,
                },
                None,
                &zero_tui::analysis::Options {
                    os: a.os.unwrap_or_default(),
                    arch: a.arch.unwrap_or_default(),
                    pagefiles: a
                        .pagefiles
                        .unwrap_or_default()
                        .into_iter()
                        .map(|f| zero_tui::windows::paging::Attachment {
                            index: f.index,
                            path: path(root, &f.path),
                        })
                        .collect(),
                    swapfile: a.swapfile.map(|p| path(root, &p)),
                    pid: a.pid,
                    hive: a
                        .hive
                        .as_deref()
                        .map(dump::parse_address)
                        .transpose()
                        .map_err(anyhow::Error::msg)?,
                    key: a.key.unwrap_or_default(),
                },
                job,
            )?;
            match outcome {
                Outcome::Choose(labels) => {
                    Ok(json!({"symbol_choices":labels,"needs_symbol_choice":true}))
                }
                Outcome::Ready(result) => {
                    let output = a.output.as_deref().map(|p| path(root, p));
                    if let Some(output) = &output {
                        store::export_rows(output, &result, result.rows.iter(), job)?;
                    }
                    let id = zero_tui::snapshots::Snapshots::insert_shared(snapshots, result, job)?;
                    let mut snapshots = snapshots
                        .lock()
                        .map_err(|_| anyhow::anyhow!("快照锁不可用"))?;
                    let mut page = snapshots.page(&id, 0, limit, None, job)?;
                    if let Some(output) = output {
                        page["output"] = json!(output);
                    }
                    Ok(page)
                }
            }
        }
        "zero_dump" => {
            let a: DumpArgs = serde_json::from_value(args)?;
            let plugin = match a.mode.as_str() {
                "process" => Plugin::Procdump,
                "range" => Plugin::Memdump,
                "elf" => Plugin::Elfdump,
                "pe" => Plugin::WinPedump,
                _ => bail!("mode 必须为 process、range 或 elf"),
            };
            let parse = |v: Option<String>| -> Result<Option<u64>> {
                v.map(|s| dump::parse_address(&s).map_err(anyhow::Error::msg))
                    .transpose()
            };
            let start = parse(a.start)?;
            let end = parse(a.end)?;
            ensure!(
                a.mode != "range" || (start.is_some() && end.is_some()),
                "range 需要 start 和 end"
            );
            let (cache_dir, settings) = settings(root, a.offline.unwrap_or(false))?;
            let symbols = a
                .symbols
                .as_deref()
                .map(|p| path(root, p))
                .unwrap_or_else(|| path(root, Path::new(&settings.symbols)));
            let options = dump::DumpOptions {
                pid: a.pid,
                directory: path(root, &a.dump_dir),
                start,
                end,
            };
            let outcome = zero_tui::analysis::analyze(
                session,
                &linux::Request {
                    image: &path(root, &a.image),
                    symbols: &symbols,
                    choice: a.symbol_choice.as_deref(),
                    plugin,
                    cache: &cache_dir,
                    use_cache: false,
                    network: settings.remote_symbols,
                },
                Some(&options),
                &zero_tui::analysis::Options {
                    os: a.os.unwrap_or_default(),
                    arch: a.arch.unwrap_or_default(),
                    pagefiles: a
                        .pagefiles
                        .unwrap_or_default()
                        .into_iter()
                        .map(|f| zero_tui::windows::paging::Attachment {
                            index: f.index,
                            path: path(root, &f.path),
                        })
                        .collect(),
                    swapfile: a.swapfile.map(|p| path(root, &p)),
                    ..Default::default()
                },
                job,
            )?;
            match outcome {
                Outcome::Choose(labels) => {
                    Ok(json!({"symbol_choices":labels,"needs_symbol_choice":true}))
                }
                Outcome::Ready(result) => {
                    let output = path(root, &a.output);
                    store::export_rows(&output, &result, result.rows.iter(), job)?;
                    let mut page = result_page(result, 0, MAX_ROWS);
                    page["output"] = json!(output);
                    Ok(page)
                }
            }
        }
        _ => bail!("未知工具: {name}"),
    }
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn response(
    request: Value,
    root: &Path,
    session: &mut linux::Session,
    snapshots: &std::sync::Mutex<zero_tui::snapshots::Snapshots>,
    job: &Job,
) -> Option<Value> {
    if !request.is_object()
        || request.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || request.get("method").and_then(Value::as_str).is_none()
        || request
            .get("id")
            .is_some_and(|id| !id.is_string() && !id.is_number())
    {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    let id = request.get("id")?.clone();
    if request
        .get("params")
        .is_some_and(|params| !params.is_object())
    {
        return Some(rpc_error(id, -32602, "params must be an object"));
    }
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => Ok(
            json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"zero","version":env!("CARGO_PKG_VERSION")}}),
        ),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools()),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_default();
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let (value, error) = match call(name, args, root, session, snapshots, job) {
                Ok(value) => (value, false),
                Err(error) => (json!({"error":format!("{error:#}")}), true),
            };
            Ok(
                json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":error}),
            )
        }
        _ => Err((-32601, format!("Method not found: {method}"))),
    };
    Some(match result {
        Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
        Err((code, message)) => rpc_error(id, code, &message),
    })
}

// Read at most MAX_REQUEST bytes, then discard the rest of an oversized line.
fn bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Result<String, &'static str>>> {
    let mut bytes = Vec::new();
    let mut oversized = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if bytes.is_empty() && !oversized {
                Ok(None)
            } else if oversized {
                Ok(Some(Err("Request exceeds 1 MiB")))
            } else {
                Ok(Some(String::from_utf8(bytes).map_err(|_| "Invalid UTF-8")))
            };
        }
        let end = buffer.iter().position(|&b| b == b'\n');
        let n = end.map_or(buffer.len(), |i| i + 1);
        let content = end.unwrap_or(n);
        if !oversized {
            if bytes.len().saturating_add(content) > MAX_REQUEST {
                oversized = true;
                bytes.clear();
            } else {
                bytes.extend_from_slice(&buffer[..content]);
            }
        }
        reader.consume(n);
        if end.is_some() {
            return Ok(Some(if oversized {
                Err("Request exceeds 1 MiB")
            } else {
                String::from_utf8(bytes).map_err(|_| "Invalid UTF-8")
            }));
        }
    }
}
enum Event {
    Input(Result<String, &'static str>),
    End,
    InputError(io::Error),
    Finished(Option<Value>, Box<linux::Session>),
}
struct Active {
    id: Value,
    job: Job,
    thread: std::thread::JoinHandle<()>,
}
fn send_reply(stdout: &mut impl Write, reply: &Value) -> Result<()> {
    serde_json::to_writer(&mut *stdout, reply)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
fn main() -> Result<()> {
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;
    let root = root()?.canonicalize().context("ZERO_ROOT 不是现有目录")?;
    let snapshots = Arc::new(Mutex::new(zero_tui::snapshots::Snapshots::new(
        settings(&root, false)?.1.resources,
    )?));
    let (sender, receiver) = mpsc::sync_channel(64);
    let input_sender = sender.clone();
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        loop {
            let event = match bounded_line(&mut input) {
                Ok(Some(line)) => Event::Input(line),
                Ok(None) => {
                    let _ = input_sender.send(Event::End);
                    break;
                }
                Err(error) => {
                    let _ = input_sender.send(Event::InputError(error));
                    break;
                }
            };
            if input_sender.send(event).is_err() {
                break;
            }
        }
    });
    let mut stdout = io::stdout().lock();
    let mut session = Some(linux::Session::default());
    let mut active: Option<Active> = None;
    let mut eof = false;
    loop {
        snapshots
            .lock()
            .map_err(|_| anyhow::anyhow!("快照锁不可用"))?
            .expire();
        if eof && active.is_none() {
            break;
        }
        let event = match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => event,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        match event {
            Event::End => eof = true,
            Event::InputError(error) => {
                if let Some(worker) = active.take() {
                    worker
                        .job
                        .cancel
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = worker.thread.join();
                }
                return Err(error.into());
            }
            Event::Finished(reply, returned) => {
                if let Some(worker) = active.take() {
                    let _ = worker.thread.join();
                }
                session = Some(*returned);
                if let Some(reply) = reply {
                    send_reply(&mut stdout, &reply)?;
                }
            }
            Event::Input(line) => {
                let request = match line {
                    Err(message) => {
                        send_reply(&mut stdout, &rpc_error(Value::Null, -32600, message))?;
                        continue;
                    }
                    Ok(line) => match serde_json::from_str::<Value>(&line) {
                        Ok(value) => value,
                        Err(_) => {
                            send_reply(
                                &mut stdout,
                                &rpc_error(Value::Null, -32700, "Parse error"),
                            )?;
                            continue;
                        }
                    },
                };
                if request["jsonrpc"] == "2.0"
                    && request["method"] == "notifications/cancelled"
                    && request.get("id").is_none()
                {
                    if let Some(worker) = &active
                        && request["params"]["requestId"] == worker.id
                    {
                        worker
                            .job
                            .cancel
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    continue;
                }
                let expensive = request["jsonrpc"] == "2.0"
                    && request["method"] == "tools/call"
                    && request
                        .get("id")
                        .is_some_and(|id| id.is_string() || id.is_number())
                    && matches!(
                        request["params"]["name"].as_str(),
                        Some("zero_analyze" | "zero_dump" | "zero_symbols")
                    );
                if expensive {
                    if active.is_some() {
                        send_reply(
                            &mut stdout,
                            &rpc_error(
                                request["id"].clone(),
                                -32000,
                                "Analysis worker busy; retry after the active request finishes",
                            ),
                        )?;
                        continue;
                    }
                    let mut worker_session = session.take().context("分析会话不可用")?;
                    let worker_job = job();
                    let job = worker_job.clone();
                    let root = root.clone();
                    let snapshots = snapshots.clone();
                    let sender = sender.clone();
                    let id = request["id"].clone();
                    let error_id = id.clone();
                    let thread = std::thread::spawn(move || {
                        let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            response(request, &root, &mut worker_session, &snapshots, &job)
                        }))
                        .unwrap_or_else(|_| {
                            worker_session.clear();
                            Some(rpc_error(error_id, -32603, "Analysis worker panicked"))
                        });
                        let _ = sender.send(Event::Finished(reply, Box::new(worker_session)));
                    });
                    active = Some(Active {
                        id,
                        job: worker_job,
                        thread,
                    });
                } else {
                    let mut unused_session = linux::Session::default();
                    if let Some(reply) = response(
                        request,
                        &root,
                        &mut unused_session,
                        &snapshots,
                        &Job::default(),
                    ) {
                        send_reply(&mut stdout, &reply)?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    #[test]
    fn oversized_line_is_discarded_and_next_request_survives() {
        let mut input = vec![b'x'; MAX_REQUEST + 8000];
        input.extend_from_slice(b"\nping\n");
        let mut reader = io::BufReader::with_capacity(4096, input.as_slice());
        assert!(bounded_line(&mut reader).unwrap().unwrap().is_err());
        assert_eq!(bounded_line(&mut reader).unwrap().unwrap().unwrap(), "ping");
        assert!(bounded_line(&mut reader).unwrap().is_none());
    }
}
