//! Public OSForensics RAW samples. Opt-in: make windows-acceptance.
use std::path::{Path, PathBuf};
use zero_tui::{
    Job,
    analysis::{self, Options},
    linux::{Outcome, Plugin, Request, Session},
};

#[test]
#[ignore = "requires multi-gigabyte public Windows samples and prepared exact symbols"]
fn public_windows_images() {
    let baseline: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/windows.json")).unwrap();
    for (variable, default, expected_processes, expected_modules, expected_hives) in [
        (
            "ZERO_WINDOWS10_IMAGE",
            "images/WinDump/WinDump.mem",
            139,
            183,
            22,
        ),
        (
            "ZERO_WINDOWS11_IMAGE",
            "images/Win11Dump/Win11Dump.mem",
            102,
            156,
            38,
        ),
    ] {
        let image = std::env::var_os(variable)
            .map(PathBuf::from)
            .unwrap_or_else(|| default.into());
        let symbols = std::env::var_os("ZERO_WINDOWS_SYMBOLS")
            .map(PathBuf::from)
            .unwrap_or_else(|| ".zero/rust/symbols/isf/windows".into());
        let mut session = Session::default();
        let fixture = baseline["samples"]
            .as_array()
            .unwrap()
            .iter()
            .find(|sample| sample["path"] == default)
            .unwrap();
        let prepared = session
            .prepare_image(&image, Path::new(".zero/rust"), &Job::default())
            .unwrap();
        assert_eq!(
            prepared.digest,
            fixture["sha256"].as_str().unwrap(),
            "sample SHA256"
        );
        for (plugin, expected) in [
            (Plugin::WinPslist, expected_processes),
            (Plugin::WinModules, expected_modules),
            (Plugin::WinHivelist, expected_hives),
            (
                Plugin::WinAutoruns,
                fixture["rows"]["windows.autoruns"].as_u64().unwrap() as usize,
            ),
            (
                Plugin::WinThreads,
                fixture["rows"]["windows.threads"].as_u64().unwrap() as usize,
            ),
            (
                Plugin::WinEnvars,
                fixture["rows"]["windows.envars"].as_u64().unwrap() as usize,
            ),
            (
                Plugin::WinDriverscan,
                fixture["rows"]["windows.driverscan"].as_u64().unwrap() as usize,
            ),
        ] {
            let outcome = analysis::analyze(
                &mut session,
                &Request {
                    image: &image,
                    symbols: &symbols,
                    choice: None,
                    plugin,
                    cache: Path::new(".zero/rust"),
                    use_cache: false,
                    network: false,
                },
                None,
                &Options::default(),
                &Job::default(),
            )
            .unwrap();
            let Outcome::Ready(result) = outcome else {
                panic!("ambiguous symbols")
            };
            assert_eq!(result.system, "windows");
            assert_eq!(result.rows.len(), expected, "{variable} {plugin:?}");
            assert_eq!(
                result.kernel_identity["registry_process"]["kernel_dtb"]
                    .as_u64()
                    .unwrap_or(result.page_table),
                u64::from_str_radix(
                    fixture["dtb"].as_str().unwrap().trim_start_matches("0x"),
                    16
                )
                .unwrap()
            );
            assert!(
                result
                    .rows
                    .iter()
                    .all(|row| row.len() == result.columns.len())
            );
            if plugin == Plugin::WinPslist {
                assert!(!result.complete);
                assert!(!result.diagnostics.is_empty());
            }
        }
    }
}

#[test]
#[ignore = "requires downloaded public Microsoft kernel PDBs"]
fn native_pdb_conversion_is_deterministic_and_preserves_anonymous_layouts() {
    use zero_tui::{
        symbols::Isf,
        windows_symbols::{self, PdbIdentity},
    };
    let cache = std::env::var_os("ZERO_WINDOWS_PDB_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| ".zero/rust/symbols/build/pdb".into());
    for (guid, prcb_size) in [
        ("0C9CC659210046EC84231597DADFDB3B", 32448),
        ("8E3373D6124E747F0E72EF8E02E676B3", 48896),
    ] {
        let identity = PdbIdentity {
            name: "ntkrnlmp.pdb".into(),
            guid: guid.into(),
            age: 1,
        };
        let pdb = std::fs::read(cache.join(format!("ntkrnlmp.pdb-{guid}1.pdb"))).unwrap();
        let first = windows_symbols::convert(&pdb, &identity, &Job::default()).unwrap();
        let second = windows_symbols::convert(&pdb, &identity, &Job::default()).unwrap();
        assert_eq!(first, second);
        let isf = Isf::parse(&first, "converted fixture".into()).unwrap();
        assert_eq!(isf.data["user_types"]["_KPRCB"]["size"], prcb_size);
        assert_eq!(isf.size("_MMVAD_SHORT", "u").unwrap(), 4);
        assert_eq!(isf.size("_MMVAD_SHORT", "u1").unwrap(), 4);
        assert_ne!(
            isf.field("_MMVAD_SHORT", "u").unwrap()["type"]["name"],
            isf.field("_MMVAD_SHORT", "u1").unwrap()["type"]["name"]
        );
    }
}

#[test]
#[ignore = "requires public Windows 10 bitmap crash dump and exact local PDB"]
fn public_bitmap_crash_processes_and_networks() {
    let image = std::env::var_os("ZERO_WINDOWS_CRASH_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "images/win-10_19041-2025_03.dmp.gz".into());
    let symbols = Path::new(".zero/rust/symbols/isf/windows");
    let cache = Path::new(".zero/rust");
    let job = Job::default();
    let mut session = Session::default();
    let prepared = session.prepare_image(&image, cache, &job).unwrap();
    assert_eq!(
        prepared.digest,
        "ef92b50aa2ba2f830e3f816eb55ed8d15b0658fdfff0ab7af8adb68f2c8da460"
    );
    assert_eq!(prepared.format, "Windows crash");
    for (plugin, count) in [(Plugin::WinPslist, 120), (Plugin::WinNetscan, 108)] {
        let outcome = analysis::analyze(
            &mut session,
            &Request {
                image: &image,
                symbols,
                choice: None,
                plugin,
                cache,
                use_cache: false,
                network: false,
            },
            None,
            &Options::default(),
            &job,
        )
        .unwrap();
        let Outcome::Ready(result) = outcome else {
            panic!("ambiguous symbols")
        };
        assert!(result.complete, "{:?}", result.diagnostics);
        assert_eq!(result.rows.len(), count);
        assert_eq!(result.page_table, 0x6d4000);
        assert!(result.rows.iter().all(|r| r.len() == result.columns.len()));
        if plugin == Plugin::WinNetscan {
            assert_eq!(
                result.kernel_identity["network_layout"]["validation"],
                "public-crash-reference"
            );
            assert_eq!(
                result.kernel_identity["tcpip_pdb"]["guid"],
                "822833E2F09280241D136E5E1F087784"
            );
        }
    }
}

#[test]
#[ignore = "requires public rust-minidump x86 Windows XP crash fixture"]
fn public_user_minidump_context_and_exception() {
    let image = std::env::var_os("ZERO_WINDOWS_MINIDUMP_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "images/rust-minidump-test.dmp".into());
    let mut session = Session::default();
    let cache = tempfile::tempdir().unwrap();
    let prepared = session
        .prepare_image(&image, cache.path(), &Job::default())
        .unwrap();
    assert_eq!(
        prepared.digest,
        "24b0ea7794b2d2523c46c9aea72c03ccbb0ab88ad76d8258d3752c7b71d233ff"
    );
    let Outcome::Ready(result) = analysis::analyze(
        &mut session,
        &Request {
            image: &image,
            symbols: Path::new("unused"),
            choice: None,
            plugin: Plugin::WinCrashinfo,
            cache: cache.path(),
            use_cache: false,
            network: false,
        },
        None,
        &Options::default(),
        &Job::default(),
    )
    .unwrap() else {
        panic!("unexpected symbol selection")
    };
    assert!(!result.complete);
    assert!(
        result
            .rows
            .contains(&vec!["Code".into(), "0xc0000005".into()])
    );
    assert!(result.rows.contains(&vec![
        "ExceptionAddress".into(),
        "0x000000000040429e".into()
    ]));
    assert!(result.rows.contains(&vec![
        "Context2.Thread3060.Eip".into(),
        "0x000000000040429e".into()
    ]));
    assert_eq!(
        result.kernel_identity["metadata"]["contexts"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}
