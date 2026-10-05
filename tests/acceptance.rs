//! Large local sample is intentionally excluded from Git. Run `make acceptance`.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};
use zero_tui::{
    Job,
    image::Image,
    linux::{self, Outcome, Plugin},
};
fn local_sample(name: &str) -> PathBuf {
    [
        PathBuf::from(name),
        PathBuf::from("images").join(name),
        PathBuf::from("symbols").join(name),
    ]
    .into_iter()
    .find(|p| p.is_file())
    .unwrap_or_else(|| PathBuf::from(name))
}
#[derive(Deserialize)]
struct Baseline {
    image_sha256: String,
    page_table: u64,
    pslist: Vec<Vec<String>>,
    lsmod: Vec<Vec<String>>,
}
#[test]
#[ignore = "requires the local official Debian 3.2 image and symbol package"]
fn debian_full_field_baseline() -> Result<()> {
    let baseline: Baseline = serde_json::from_str(include_str!("fixtures/debian-3.2.json"))?;
    let image = PathBuf::from(
        std::env::var("ZERO_TEST_IMAGE")
            .unwrap_or_else(|_| local_sample("linux-sample-1.bin.gz").display().to_string()),
    );
    let symbols = std::env::var("ZERO_TEST_SYMBOLS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| local_sample("linux.zip"));
    let cache = PathBuf::from(".zero/rust");
    let job = Job::default();
    ensure!(
        Image::open(&image, &cache, &job)?.digest == baseline.image_sha256,
        "sample SHA256 does not match official baseline"
    );
    for plugin in [Plugin::Pslist, Plugin::Pstree, Plugin::Lsmod] {
        let Outcome::Ready(result) =
            linux::analyze(&image, &symbols, None, plugin, &cache, false, &job)?
        else {
            anyhow::bail!("ambiguous baseline symbols")
        };
        ensure!(
            result.complete && result.diagnostics.is_empty(),
            "incomplete baseline: {:?}",
            result.diagnostics
        );
        ensure!(
            result.page_table == baseline.page_table,
            "page table changed"
        );
        let expected = if plugin == Plugin::Lsmod {
            &baseline.lsmod
        } else {
            &baseline.pslist
        };
        ensure!(
            &result.rows == expected,
            "{} full fields changed",
            plugin.name()
        );
        ensure!(
            result.rows.len() == if plugin == Plugin::Lsmod { 79 } else { 133 },
            "baseline count changed"
        );
        if plugin != Plugin::Lsmod {
            let parents: HashMap<_, _> = result.rows.iter().map(|r| (&r[0], &r[2])).collect();
            for row in &result.rows {
                let mut current = &row[0];
                let mut seen = std::collections::HashSet::new();
                while current != "0" {
                    ensure!(seen.insert(current), "parent cycle");
                    current = parents
                        .get(current)
                        .copied()
                        .ok_or_else(|| anyhow::anyhow!("parent missing: {current}"))?;
                }
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct ExtendedBaseline {
    columns: Vec<String>,
    count: usize,
    rows_sha256: String,
    complete: bool,
    diagnostics: Vec<String>,
}
#[test]
#[ignore = "requires the local official Debian 3.2 image and symbol package"]
fn debian_extended_full_field_baseline() -> Result<()> {
    use sha2::{Digest, Sha256};
    use zero_tui::store;
    let original: Baseline = serde_json::from_str(include_str!("fixtures/debian-3.2.json"))?;
    let baseline: HashMap<String, ExtendedBaseline> =
        serde_json::from_str(include_str!("fixtures/debian-3.2-extended.json"))?;
    let image = PathBuf::from(
        std::env::var("ZERO_TEST_IMAGE")
            .unwrap_or_else(|_| local_sample("linux-sample-1.bin.gz").display().to_string()),
    );
    let symbols = std::env::var("ZERO_TEST_SYMBOLS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| local_sample("linux.zip"));
    let cache = tempfile::tempdir()?;
    let prepared = PathBuf::from(".zero/rust");
    let job = Job::default();
    ensure!(
        Image::open(&image, &prepared, &job)?.digest == original.image_sha256,
        "wrong sample"
    );
    let mut session = linux::Session::default();
    for plugin in [
        Plugin::Psstate,
        Plugin::Capabilities,
        Plugin::Fdsummary,
        Plugin::Psaux,
        Plugin::Envars,
        Plugin::Maps,
        Plugin::Lsof,
        Plugin::Sockstat,
        Plugin::Banners,
        Plugin::Pwd,
        Plugin::Pscred,
        Plugin::Threads,
        Plugin::Mountinfo,
        Plugin::CheckCreds,
        Plugin::Dmesg,
        Plugin::Systeminfo,
        Plugin::Elfs,
        Plugin::Bash,
        Plugin::Malfind,
        Plugin::Psxview,
        Plugin::CheckModules,
        Plugin::CheckSyscall,
    ] {
        let Outcome::Ready(result) = session.analyze(
            &linux::Request {
                image: &image,
                symbols: &symbols,
                choice: None,
                plugin,
                cache: &prepared,
                use_cache: false,
                network: false,
            },
            &job,
        )?
        else {
            anyhow::bail!("ambiguous symbols")
        };
        let expected = &baseline[plugin.name()];
        ensure!(
            result.columns == expected.columns && result.rows.len() == expected.count,
            "{} schema/count changed",
            plugin.name()
        );
        ensure!(
            result.complete == expected.complete && result.diagnostics == expected.diagnostics,
            "{} sample damage/diagnostics changed",
            plugin.name()
        );
        ensure!(
            result.page_table
                == if plugin == Plugin::Banners {
                    0
                } else {
                    original.page_table
                },
            "page table changed"
        );
        let hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&baseline_rows(&result))?)
        );
        ensure!(
            hash == expected.rows_sha256,
            "{} full fields changed",
            plugin.name()
        );
        let key = store::key(&original.image_sha256, "sample", plugin.name());
        store::save(cache.path(), &key, &result, &job)?;
        ensure!(
            store::load(cache.path(), &key).is_some() == result.complete,
            "partial result cached"
        );
        let query = result.rows.first().map(|r| r[0].as_str()).unwrap_or("");
        let filtered = result.filtered(query);
        let path = cache.path().join(format!("{}.json", plugin.name()));
        store::export(&path, &result, filtered.clone())?;
        let exported: store::Results = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(exported.rows == filtered, "filtered export changed");
    }
    Ok(())
}

fn baseline_rows(result: &zero_tui::store::Results) -> Vec<Vec<String>> {
    let mut rows = result.rows.clone();
    if result.plugin == "systeminfo" {
        for row in &mut rows {
            if row[0] == "SymbolSource" {
                row[1] = "[selected-isf]".into();
            }
            if row[0] == "SymbolSHA256" {
                row[1] = "[selected-isf-sha256]".into();
            }
        }
    }
    rows
}
#[derive(Deserialize)]
struct ModernBaseline {
    image_sha256: String,
    page_table: u64,
    plugins: HashMap<String, ExtendedBaseline>,
}
#[test]
#[ignore = "requires local Kali ARM64 image and generated exact debug symbols"]
fn kali_arm64_all_plugins_full_field_baseline() -> Result<()> {
    use sha2::{Digest, Sha256};
    use zero_tui::{store, symbols};
    let baseline: ModernBaseline =
        serde_json::from_str(include_str!("fixtures/kali-6.8.11-arm64.json"))?;
    let image = std::env::var("ZERO_KALI_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| local_sample("kali.raw"));
    let prepared = PathBuf::from(".zero/rust");
    let job = Job::default();
    let mut session = linux::Session::default();
    let im = session.prepare_image(&image, &prepared, &job)?;
    ensure!(im.digest == baseline.image_sha256, "Kali image changed");
    let symbols = if let Ok(path) = std::env::var("ZERO_KALI_SYMBOLS") {
        PathBuf::from(path)
    } else {
        let found = symbols::matching(&PathBuf::from("symbols"), &im, &job)?;
        let exact = found
            .into_iter()
            .find(|s| {
                s.data["metadata"]["zero"]["symbol_sizes"]["sys_call_table"].as_u64() == Some(3696)
            })
            .ok_or_else(|| anyhow::anyhow!("Run symbols-generate --image kali.raw --kali first"))?;
        PathBuf::from(exact.label)
    };
    let selected = symbols::matching(&symbols, &im, &job)?;
    ensure!(selected.len() == 1, "ambiguous Kali symbols");
    let symbol_hash = &selected[0].digest;
    drop(im);
    let cache = tempfile::tempdir()?;
    for descriptor in linux::PLUGINS {
        let plugin = descriptor.plugin;
        // Dump plugins require explicit parameters; exercised in the targeted sample test below.
        if plugin.is_dump() {
            continue;
        }
        let Outcome::Ready(result) = session.analyze(
            &linux::Request {
                image: &image,
                symbols: &symbols,
                choice: None,
                plugin,
                cache: &prepared,
                use_cache: false,
                network: false,
            },
            &job,
        )?
        else {
            anyhow::bail!("ambiguous symbols");
        };
        let Some(expected) = baseline.plugins.get(plugin.name()) else {
            ensure!(
                result.columns
                    == descriptor
                        .columns
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>(),
                "{} schema changed",
                plugin.name()
            );
            continue;
        };
        ensure!(
            result.columns == expected.columns && result.rows.len() == expected.count,
            "{} schema/count changed",
            plugin.name()
        );
        ensure!(
            result.complete == expected.complete && result.diagnostics == expected.diagnostics,
            "{} diagnostics changed",
            plugin.name()
        );
        ensure!(
            result.page_table
                == if plugin == Plugin::Banners {
                    0
                } else {
                    baseline.page_table
                },
            "DTB changed"
        );
        ensure!(
            format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&baseline_rows(&result))?)
            ) == expected.rows_sha256,
            "{} full fields changed",
            plugin.name()
        );
        if plugin == Plugin::Systeminfo {
            ensure!(
                result
                    .rows
                    .iter()
                    .any(|r| r[0] == "SymbolSHA256" && &r[1] == symbol_hash),
                "symbol digest wrong"
            );
            ensure!(
                result
                    .rows
                    .iter()
                    .any(|r| r[0] == "SymbolSource" && r[1] == symbols.to_string_lossy()),
                "symbol source wrong"
            );
        }
        let key = store::key(&baseline.image_sha256, symbol_hash, plugin.name());
        store::save(cache.path(), &key, &result, &job)?;
        ensure!(
            store::load(cache.path(), &key).is_some() == result.complete,
            "partial cached"
        );
        let filtered = result.filtered(result.rows.first().map(|r| r[0].as_str()).unwrap_or(""));
        let path = cache.path().join(format!("{}.json", plugin.name()));
        store::export(&path, &result, filtered.clone())?;
        let exported: store::Results = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(exported.rows == filtered, "filtered export changed");
    }
    Ok(())
}

#[test]
#[ignore = "requires local Debian and Kali samples; targeted dump artifacts use a temporary directory"]
fn targeted_dumps_and_history_on_both_samples() -> Result<()> {
    use sha2::{Digest, Sha256};
    use zero_tui::dump::DumpOptions;
    let cases =
        [
            (
                PathBuf::from(std::env::var("ZERO_TEST_IMAGE").unwrap_or_else(|_| {
                    local_sample("linux-sample-1.bin.gz").display().to_string()
                })),
                PathBuf::from(
                    std::env::var("ZERO_TEST_SYMBOLS")
                        .unwrap_or_else(|_| local_sample("linux.zip").display().to_string()),
                ),
            ),
            (
                PathBuf::from(
                    std::env::var("ZERO_KALI_IMAGE")
                        .unwrap_or_else(|_| local_sample("kali.raw").display().to_string()),
                ),
                PathBuf::from(
                    std::env::var("ZERO_KALI_SYMBOLS")
                        .unwrap_or_else(|_| "symbols/kali-6.8.11-arm64.json.xz".into()),
                ),
            ),
        ];
    let output = tempfile::tempdir()?;
    let cache = PathBuf::from(".zero/rust");
    let job = Job::default();
    for (image, symbols) in cases {
        let mut session = linux::Session::default();
        let prepared = session.prepare_image(&image, &cache, &job)?;
        let request = |plugin| linux::Request {
            image: &image,
            symbols: &symbols,
            choice: None,
            plugin,
            cache: &cache,
            use_cache: false,
            network: false,
        };
        let Outcome::Ready(maps) = session.analyze(&request(Plugin::Maps), &job)? else {
            anyhow::bail!("ambiguous symbols")
        };
        // VMA membership does not imply residency. Preserve the missing-page case,
        // then select a resident page for byte-for-byte export checks.
        let mut selected = None;
        for target in maps
            .rows
            .iter()
            .filter(|row| row[0] == "1" && row[4].starts_with('r'))
        {
            let start = u64::from_str_radix(target[2].trim_start_matches("0x"), 16)?;
            let options = DumpOptions {
                pid: 1,
                directory: output.path().canonicalize()?.join(&prepared.digest),
                start: Some(start),
                end: Some(start + 128),
            };
            let Outcome::Ready(probe) =
                session.analyze_with_dump(&request(Plugin::Memdump), Some(&options), &job)?
            else {
                anyhow::bail!("ambiguous symbols")
            };
            if !probe.rows.is_empty() {
                selected = Some(options);
                break;
            }
            ensure!(
                !probe.complete && !probe.diagnostics.is_empty(),
                "missing sample page falsely reported success"
            );
        }
        let options =
            selected.ok_or_else(|| anyhow::anyhow!("PID 1 has no resident VMA start in sample"))?;
        let mut previous = None;
        for plugin in [Plugin::Memdump, Plugin::Procdump, Plugin::Elfdump] {
            let options = if plugin == Plugin::Elfdump {
                DumpOptions {
                    start: None,
                    end: None,
                    ..options.clone()
                }
            } else {
                options.clone()
            };
            let Outcome::Ready(result) =
                session.analyze_with_dump(&request(plugin), Some(&options), &job)?
            else {
                anyhow::bail!("ambiguous symbols")
            };
            ensure!(
                !result.rows.is_empty(),
                "{} exported no sample bytes: {:?}",
                plugin.name(),
                result.diagnostics
            );
            for row in &result.rows {
                ensure!(row[0] == "1", "dump leaked another PID");
                let bytes = std::fs::read(&row[6])?;
                ensure!(
                    bytes.len().to_string() == row[4]
                        && format!("{:x}", Sha256::digest(&bytes)) == row[5],
                    "dump manifest differs from binary evidence"
                );
                if plugin == Plugin::Elfdump {
                    ensure!(bytes.starts_with(b"\x7fELF"), "ELF export lacks header");
                } else {
                    ensure!(bytes.len() == 128, "range was not respected");
                    if let Some(previous) = &previous {
                        ensure!(&bytes == previous, "memdump / procdump bytes differ");
                    }
                    previous = Some(bytes);
                }
            }
        }
        let Outcome::Ready(history) = session.analyze(&request(Plugin::History), &job)? else {
            anyhow::bail!("ambiguous symbols")
        };
        let Outcome::Ready(bash) = session.analyze(&request(Plugin::Bash), &job)? else {
            anyhow::bail!("ambiguous symbols")
        };
        ensure!(
            history.rows == bash.rows
                && history.complete == bash.complete
                && history.diagnostics == bash.diagnostics,
            "history alias changed verified Bash evidence"
        );
        ensure!(history.columns[1] == "Shell", "history schema changed");
    }
    Ok(())
}
