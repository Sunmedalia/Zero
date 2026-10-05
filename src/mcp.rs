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
struct AnalyzeArgs {
    image: PathBuf,
    plugin: String,
    os: Option<zero_tui::analysis::Os>,
    pid: Option<u32>,
    hive: Option<String>,
    key: Option<String>,
    symbols: Option<PathBuf>,
    symbol_choice: Option<String>,
    offline: Option<bool>,
    no_cache: Option<bool>,
    offset: Option<usize>,
    limit: Option<usize>,
    output: Option<PathBuf>,
}

#[derive(Deserialize)]
struct DumpArgs {
    image: PathBuf,
    symbols: Option<PathBuf>,
    symbol_choice: Option<String>,
    mode: String,
    os: Option<zero_tui::analysis::Os>,
    pid: u32,
    dump_dir: PathBuf,
    output: PathBuf,
    start: Option<String>,
    end: Option<String>,
    offline: Option<bool>,
}

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
    json!({
        "plugin": result.plugin, "columns": result.columns, "rows": rows,
        "total_rows": total, "offset": offset, "next_offset": (offset + limit < total).then_some(offset + limit),
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
        {"name":"zero_analyze","description":"Run a native analysis plugin on a local memory image. Returns at most 200 rows and may export all rows to JSON/CSV. Use offset/limit to page the result.","inputSchema":{"type":"object","properties":{"image":{"type":"string"},"plugin":{"type":"string"},"os":{"type":"string","enum":["auto","linux","windows"]},"pid":{"type":"integer","minimum":0},"hive":{"type":"string"},"key":{"type":"string"},"symbols":{"type":"string"},"symbol_choice":{"type":"string"},"offline":{"type":"boolean"},"no_cache":{"type":"boolean"},"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":200},"output":{"type":"string"}},"required":["image","plugin"],"additionalProperties":false}},
        {"name":"zero_dump","description":"Export one process, one PID address range, or ELF mappings to a local directory with a JSON/CSV manifest. Requires explicit PID and paths.","inputSchema":{"type":"object","properties":{"image":{"type":"string"},"symbols":{"type":"string"},"symbol_choice":{"type":"string"},"os":{"type":"string","enum":["auto","linux","windows"]},"mode":{"type":"string","enum":["process","range","elf","pe"]},"pid":{"type":"integer","minimum":0},"dump_dir":{"type":"string"},"output":{"type":"string"},"start":{"type":"string"},"end":{"type":"string"},"offline":{"type":"boolean"}},"required":["image","mode","pid","dump_dir","output"],"additionalProperties":false}},
        {"name":"zero_cache_list","description":"Inspect regenerable local cache without deleting it.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
    ]})
}

fn call(name: &str, args: Value, root: &Path) -> Result<Value> {
    match name {
        "zero_plugins" => Ok(
            json!({"plugins":linux::PLUGINS.iter().map(|p| json!({"name":p.name,"category":p.plugin.category(),"columns":p.columns,"os":if p.plugin.is_windows(){"windows"}else{"linux"}})).collect::<Vec<_>>()}),
        ),
        "zero_cache_list" => Ok(serde_json::to_value(cache::inventory(
            &root.join(".zero/rust"),
        )?)?),
        "zero_symbols" => {
            #[derive(Deserialize)]
            struct Args {
                image: PathBuf,
                offline: Option<bool>,
                download: Option<bool>,
            }
            let a: Args = serde_json::from_value(args)?;
            let (cache_dir, settings) = settings(root, a.offline.unwrap_or(false))?;
            let job = job();
            let mut session = linux::Session::default();
            let image = session.prepare_image(&path(root, &a.image), &cache_dir, &job)?;
            let banners = linux::banner_result(&image, &job)?;
            let matches =
                symbols::remote_matches(&image, &cache_dir, settings.remote_symbols, &job)?;
            let mut downloaded = Vec::new();
            if a.download.unwrap_or(false) {
                for item in &matches {
                    match symbols::download(item, &image, &cache_dir, settings.remote_symbols, &job)
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
        "zero_analyze" => {
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
            let mut session = linux::Session::default();
            let outcome = zero_tui::analysis::analyze(
                &mut session,
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
                    pid: a.pid,
                    hive: a
                        .hive
                        .as_deref()
                        .map(dump::parse_address)
                        .transpose()
                        .map_err(anyhow::Error::msg)?,
                    key: a.key.unwrap_or_default(),
                },
                &job(),
            )?;
            match outcome {
                Outcome::Choose(labels) => {
                    Ok(json!({"symbol_choices":labels,"needs_symbol_choice":true}))
                }
                Outcome::Ready(result) => {
                    let output = a.output.as_deref().map(|p| path(root, p));
                    if let Some(output) = &output {
                        store::export(output, &result, result.rows.clone())?;
                    }
                    let mut page = result_page(result, a.offset.unwrap_or(0), limit);
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
            let mut session = linux::Session::default();
            let outcome = zero_tui::analysis::analyze(
                &mut session,
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
                    ..Default::default()
                },
                &job(),
            )?;
            match outcome {
                Outcome::Choose(labels) => {
                    Ok(json!({"symbol_choices":labels,"needs_symbol_choice":true}))
                }
                Outcome::Ready(result) => {
                    let output = path(root, &a.output);
                    store::export(&output, &result, result.rows.clone())?;
                    let mut page = result_page(result, 0, MAX_ROWS);
                    page["output"] = json!(output);
                    Ok(page)
                }
            }
        }
        _ => bail!("未知工具: {name}"),
    }
}

fn response(request: Value, root: &Path) -> Option<Value> {
    let id = request.get("id")?.clone();
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
            let (value, error) = match call(name, args, root) {
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
        Err((code, message)) => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
        }
    })
}

fn main() -> Result<()> {
    let root = root()?.canonicalize().context("ZERO_ROOT 不是现有目录")?;
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.len() > MAX_REQUEST {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(request) => {
                if let Some(reply) = response(request, &root) {
                    serde_json::to_writer(&mut stdout, &reply)?;
                    stdout.write_all(b"\n")?;
                    stdout.flush()?;
                }
            }
            Err(error) => eprintln!("zero-mcp: invalid JSON: {error}"),
        }
    }
    Ok(())
}
