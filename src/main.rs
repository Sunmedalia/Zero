use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zero_tui::{
    Job, cache,
    linux::{self, Outcome, Plugin},
    store, symbols,
};

#[derive(Parser)]
#[command(version, about = "Rust 原生 Linux x86_64／ARM64 内存取证与符号匹配")]
struct Cli {
    #[arg(long)]
    image: Option<PathBuf>,
    #[arg(long)]
    symbols: Option<PathBuf>,
    /// Use only local symbols and previously downloaded files.
    #[arg(long, global = true)]
    offline: bool,
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
        if *refresh {
            anyhow::ensure!(settings.remote_symbols, "--offline 不能刷新在线索引");
            symbols::refresh_index(&cache, &job)?;
        }
        let matches = symbols::remote_matches(&image, &cache, settings.remote_symbols, &job)?;
        let mut downloaded = Vec::new();
        if *download {
            for m in &matches {
                downloaded.push(
                    symbols::download(m, &image, &cache, settings.remote_symbols, &job)?.label,
                );
            }
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
    if let Some(Command::Analyze {
        image,
        symbols,
        plugin,
        output,
        symbol_choice,
        no_cache,
    }) = cli.command
    {
        let job = Job::new(|s| eprintln!("{s}"));
        let symbols = symbols.unwrap_or_else(|| PathBuf::from(&settings.symbols));
        let mut session = linux::Session::default();
        match session.analyze(
            &linux::Request {
                image: &image,
                symbols: &symbols,
                choice: symbol_choice.as_deref(),
                plugin,
                cache: &cache,
                use_cache: settings.enable_cache && !no_cache,
                network: settings.remote_symbols,
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
        let registry = zero_tui::workspace::Registry::load(&cache)?;
        let image = cli.image.or_else(|| {
            registry
                .selected(zero_tui::workspace::Kind::Image)
                .filter(|p| p.is_file())
                .map(PathBuf::from)
        });
        let symbols = cli.symbols.or_else(|| {
            registry
                .selected(zero_tui::workspace::Kind::Symbols)
                .filter(|p| p.exists())
                .map(PathBuf::from)
        });
        let default_symbols = store::expand_home(&settings.symbols);
        zero_tui::tui::run(
            image,
            symbols.unwrap_or_else(|| {
                if registry.excluded(&default_symbols) {
                    PathBuf::new()
                } else {
                    default_symbols
                }
            }),
            cache,
            settings,
        )
    }
}
