use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zero_tui::{
    Job, cache,
    linux::{self, Outcome, Plugin},
    store, symbols,
};

#[derive(Parser)]
#[command(
    name = "zero",
    version,
    about = "Rust 原生 Linux / Windows 内存取证与符号匹配"
)]
struct Cli {
    #[arg(long)]
    image: Option<PathBuf>,
    #[arg(long)]
    symbols: Option<PathBuf>,
    /// Use only local symbols and previously downloaded files.
    #[arg(long, global = true)]
    offline: bool,
    #[arg(long, global = true, value_enum, default_value = "auto")]
    os: zero_tui::analysis::Os,
    #[arg(long, global=true, value_parser=zero_tui::dump::parse_address)]
    hive: Option<u64>,
    #[arg(long, global = true, default_value = "")]
    key: String,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Inspect or clear regenerable cache files.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Generate exact symbols from local debug ELF/config or the supported Kali archive.
    SymbolsGenerate {
        #[arg(long)]
        image: PathBuf,
        #[arg(long, requires = "config", conflicts_with = "kali")]
        elf: Option<PathBuf>,
        #[arg(long, requires = "elf")]
        config: Option<PathBuf>,
        #[arg(long)]
        tool: Option<PathBuf>,
        #[arg(long, conflicts_with = "elf")]
        kali: bool,
    },
    /// Identify kernel banners and exact repository download links.
    Symbols {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        download: bool,
        #[arg(long)]
        refresh: bool,
    },
    /// Export evidence through one entry point; requires a target and export parameters.
    Dump {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        symbols: Option<PathBuf>,
        #[arg(long, value_enum)]
        mode: zero_tui::dump::Mode,
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        dump_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_parser = zero_tui::dump::parse_address)]
        start: Option<u64>,
        #[arg(long, value_parser = zero_tui::dump::parse_address)]
        end: Option<u64>,
        #[arg(long)]
        symbol_choice: Option<String>,
    },
    Analyze {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        symbols: Option<PathBuf>,
        #[arg(long, value_enum)]
        plugin: Plugin,
        #[arg(long)]
        output: PathBuf,
        /// Exact candidate label printed when more than one ISF matches.
        #[arg(long)]
        symbol_choice: Option<String>,
        #[arg(long)]
        no_cache: bool,
        /// Filter analysis by PID or select the target process for a dump.
        #[arg(long)]
        pid: Option<u32>,
        /// Directory for binary dumps; --output remains the CSV/JSON manifest.
        #[arg(long)]
        dump_dir: Option<PathBuf>,
        /// User virtual address, decimal or 0x hex; end is exclusive.
        #[arg(long, value_parser = zero_tui::dump::parse_address)]
        start: Option<u64>,
        #[arg(long, value_parser = zero_tui::dump::parse_address)]
        end: Option<u64>,
    },
}
#[derive(Subcommand)]
enum CacheAction {
    List,
    Clear {
        #[arg(
            long,
            value_enum,
            value_delimiter = ',',
            default_value = "results,identification"
        )]
        scope: Vec<cache::Scope>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        yes: bool,
    },
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let cache = PathBuf::from(".zero/rust");
    if let Some(Command::Cache { action }) = &cli.command {
        match action {
            CacheAction::List => println!(
                "{}",
                serde_json::to_string_pretty(&cache::inventory(&cache)?)?
            ),
            CacheAction::Clear {
                scope,
                dry_run,
                yes,
            } => {
                if *dry_run || !*yes {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&cache::selected(
                            &cache::inventory(&cache)?,
                            scope
                        ))?
                    );
                    eprintln!("预览；添加 --yes 执行清理");
                } else {
                    let report = cache::clear(&cache, scope)?;
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    anyhow::ensure!(report.failures.is_empty(), "部分缓存未能清理");
                }
            }
        }
        return Ok(());
    }
    let mut settings = store::settings(&cache)?;
    if cli.offline {
        settings.remote_symbols = false;
    }
    if let Some(Command::SymbolsGenerate {
        image,
        elf,
        config,
        tool,
        kali,
    }) = &cli.command
    {
        let job = Job::new(|s| eprintln!("{s}"));
        let mut session = linux::Session::default();
        let image = session.prepare_image(image, &cache, &job)?;
        let path = if *kali {
            zero_tui::prepare::prepare_kali(&image, &cache, settings.remote_symbols, &job)?
        } else {
            zero_tui::prepare::generate(
                elf.as_deref()
                    .ok_or_else(|| anyhow::anyhow!("需要 --elf / --config 或 --kali"))?,
                config.as_deref().unwrap(),
                tool.as_deref()
                    .unwrap_or(&cache.join("symbols/build/dwarf2json/dwarf2json")),
                &image,
                &cache,
                &job,
            )?
        };
        println!("{}", path.display());
        return Ok(());
    }
    if let Some(Command::Symbols {
        image,
        output,
        download,
        refresh,
    }) = &cli.command
    {
        let job = Job::new(|s| eprintln!("{s}"));
        let mut session = linux::Session::default();
        let image = session.prepare_image(image, &cache, &job)?;
        let banners = linux::banner_result(&image, &job)?;
        if *refresh && !image.banners(&job)?.is_empty() {
            anyhow::ensure!(settings.remote_symbols, "--offline 不能刷新在线索引");
            symbols::refresh_index(&cache, &job)?;
        }
        let matches = symbols::remote_matches(&image, &cache, settings.remote_symbols, &job)?;
        let mut downloaded = Vec::new();
        if *download {
            for m in &matches {
                match symbols::download(m, &image, &cache, settings.remote_symbols, &job) {
                    Ok(isf) => downloaded.push(isf.label),
                    Err(e) => {
                        job.check()?;
                        eprintln!("候选下载失败 {}: {e:#}", m.path);
                    }
                }
            }
        }
        if *download {
            anyhow::ensure!(!downloaded.is_empty(), "没有候选符号下载成功");
        }
        let bytes = serde_json::to_vec_pretty(
            &serde_json::json!({"banners":banners.rows,"matches":matches,"downloaded":downloaded}),
        )?;
        if let Some(path) = output {
            store::atomic_write(path, &bytes)?;
        } else {
            println!("{}", String::from_utf8(bytes)?);
        }
        return Ok(());
    }
    let analysis = match cli.command {
        Some(Command::Analyze {
            image,
            symbols,
            plugin,
            output,
            symbol_choice,
            no_cache,
            pid,
            dump_dir,
            start,
            end,
        }) => Some((
            image,
            symbols,
            plugin,
            output,
            symbol_choice,
            no_cache,
            pid,
            dump_dir,
            start,
            end,
        )),
        Some(Command::Dump {
            image,
            symbols,
            mode,
            pid,
            dump_dir,
            output,
            start,
            end,
            symbol_choice,
        }) => Some((
            image,
            symbols,
            mode.plugin(),
            output,
            symbol_choice,
            true,
            Some(pid),
            Some(dump_dir),
            start,
            end,
        )),
        _ => None,
    };
    if let Some((
        image,
        symbols,
        plugin,
        output,
        symbol_choice,
        no_cache,
        pid,
        dump_dir,
        start,
        end,
    )) = analysis
    {
        let job = Job::new(|s| eprintln!("{s}"));
        let symbols = symbols.unwrap_or_else(|| PathBuf::from(&settings.symbols));
        let mut session = linux::Session::default();
        let dump = if plugin.is_dump() {
            Some(zero_tui::dump::DumpOptions {
                pid: pid.ok_or_else(|| anyhow::anyhow!("Dump 插件必须指定 --pid"))?,
                directory: dump_dir
                    .ok_or_else(|| anyhow::anyhow!("Dump 插件必须指定 --dump-dir"))?,
                start,
                end,
            })
        } else {
            anyhow::ensure!(
                dump_dir.is_none() && start.is_none() && end.is_none(),
                "转储参数仅用于 Dump 插件"
            );
            None
        };
        match zero_tui::analysis::analyze(
            &mut session,
            &linux::Request {
                image: &image,
                symbols: &symbols,
                choice: symbol_choice.as_deref(),
                plugin,
                cache: &cache,
                use_cache: settings.enable_cache && !no_cache,
                network: settings.remote_symbols,
            },
            dump.as_ref(),
            &zero_tui::analysis::Options {
                os: cli.os,
                pid: if plugin.is_dump() { None } else { pid },
                hive: cli.hive,
                key: cli.key.clone(),
            },
            &job,
        )? {
            Outcome::Choose(labels) => bail!(
                "多个完整 banner 匹配符号，请用 --symbol-choice 指定:\n{}",
                labels.join("\n")
            ),
            Outcome::Ready(result) => {
                store::export(&output, &result, result.rows.clone())?;
                eprintln!(
                    "{}: {} 条；{}；导出 {}",
                    result.plugin,
                    result.rows.len(),
                    if result.complete {
                        "完整"
                    } else {
                        "部分结果"
                    },
                    output.display()
                );
                for diagnostic in &result.diagnostics {
                    eprintln!("{diagnostic}");
                }
                if !result.complete {
                    bail!("分析不完整；已导出部分结果，未写入成功缓存");
                }
            }
        }
        Ok(())
    } else {
        // A new TUI session only loads paths explicitly supplied for this launch.
        // The registry retains assets and last selections as history, not startup input.
        zero_tui::tui::run_with_options(
            cli.image,
            cli.symbols.unwrap_or_default(),
            cache,
            settings,
            zero_tui::analysis::Options {
                os: cli.os,
                hive: cli.hive,
                key: cli.key,
                pid: None,
            },
        )
    }
}
