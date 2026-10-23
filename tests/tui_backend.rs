//! End-to-end checks of the `tui-backend` protocol that the TypeScript interface
//! speaks: handshake, asset discovery, identification, analysis, cancellation
//! and one-task-at-a-time enforcement.
//!
//! These run the released binary over stdio, so they cover the same path the UI
//! uses. The offline acceptance test at the bottom needs local samples and is
//! marked `#[ignore]`, matching the previous `make tui-acceptance` contract.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

/// A throwaway stdin used only so the field can be replaced and dropped.
///
/// The spawned `cat` is killed immediately; its pipe never receives data.
fn dummy_stdin() -> ChildStdin {
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("placeholder");
    let stdin = child.stdin.take().expect("stdin");
    let _ = child.kill();
    let _ = child.wait();
    stdin
}

struct Backend {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: u64,
}

impl Backend {
    fn start(root: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zero"))
            .arg("tui-backend")
            .env("ZERO_ROOT", root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("backend starts");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
            next: 0,
        }
    }

    fn send(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let request = json!({"jsonrpc":"2.0","id":self.next,"method":method,"params":params});
        writeln!(self.stdin, "{request}").expect("write request");
        self.stdin.flush().expect("flush");
        loop {
            let mut line = String::new();
            assert!(self.stdout.read_line(&mut line).expect("read") > 0, "eof");
            let reply: Value = serde_json::from_str(line.trim()).expect("json reply");
            if reply.get("method").is_some() {
                // A task notification overtook the reply; ignore it here.
                continue;
            }
            assert_eq!(reply["id"], self.next);
            return reply;
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let reply = self.send(method, params);
        assert!(
            reply.get("error").is_none(),
            "{method} failed: {}",
            reply["error"]
        );
        reply["result"].clone()
    }

    /// Start a task and collect progress until it finishes.
    fn task(&mut self, op: &str, args: Value) -> Result<Value, String> {
        let started = self.call("task.start", json!({"op":op,"args":args}));
        let id = started["task"].as_str().expect("task id").to_owned();
        loop {
            let mut line = String::new();
            assert!(self.stdout.read_line(&mut line).expect("read") > 0, "eof");
            let message: Value = serde_json::from_str(line.trim()).expect("json");
            let params = &message["params"];
            if params["id"] != id.as_str() {
                continue;
            }
            match message["method"].as_str() {
                Some("task.progress") => continue,
                Some("task.done") => return Ok(params["result"].clone()),
                _ => {
                    let cancelled = params["cancelled"].as_bool().unwrap_or(false);
                    return Err(format!(
                        "{}{}",
                        params["message"].as_str().unwrap_or("task failed"),
                        if cancelled { " (cancelled)" } else { "" }
                    ));
                }
            }
        }
    }

    fn finish(&mut self) {
        let _ = self.call("task.finish", json!({}));
        // Dropping our handle to the child's stdin sends EOF, which ends the
        // backend loop.
        let stdin = std::mem::replace(&mut self.stdin, dummy_stdin());
        drop(stdin);
        let _ = self.child.wait();
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sandbox() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["images", "symbols", "exports"] {
        std::fs::create_dir_all(dir.path().join(name)).expect("dir");
    }
    std::fs::write(
        dir.path().join("images/sample.raw"),
        b"Linux version synthetic (gcc version 1) #1 SMP\n\0",
    )
    .expect("image");
    dir
}

#[test]
fn handshake_reports_plugins_settings_and_scopes() {
    let root = sandbox();
    let mut backend = Backend::start(root.path());
    let hello = backend.call("hello", json!({}));
    assert_eq!(hello["platform"], "unix");
    assert!(hello["plugins"].as_array().expect("plugins").len() >= 34);
    assert!(
        hello["plugins"]
            .as_array()
            .expect("plugins")
            .iter()
            .any(|plugin| plugin["name"] == "windows.pslist" && plugin["os"] == "windows")
    );
    assert!(
        hello["plugins"]
            .as_array()
            .expect("plugins")
            .iter()
            .all(|plugin| plugin["description"]
                .as_str()
                .is_some_and(|d| !d.is_empty()))
    );
    assert_eq!(hello["settings"]["page_size"], 0);
    assert_eq!(hello["scopes"].as_array().expect("scopes").len(), 5);
    backend.finish();
}

#[test]
fn assets_and_browse_are_relative_to_the_project_root() {
    let root = sandbox();
    let mut backend = Backend::start(root.path());
    backend.call("hello", json!({}));
    // Default settings are relative to the project root, never the process cwd.
    let assets = backend.call("assets", json!({}));
    assert!(
        assets
            .as_array()
            .expect("assets")
            .iter()
            .any(|asset| asset["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("sample.raw"))),
        "configured images directory must be discovered: {assets}"
    );
    let browse = backend.call("browse", json!({"path":"images","filter":"files"}));
    assert_eq!(browse["entries"].as_array().expect("entries").len(), 1);
    assert_eq!(browse["entries"][0]["kind"], "image");
    let absolute = backend.call(
        "browse",
        json!({"path": root.path().join("symbols"), "filter":"directories"}),
    );
    assert!(absolute["entries"].as_array().expect("entries").is_empty());
    backend.finish();
}

#[test]
fn identification_runs_as_a_task_and_reports_banners() {
    let root = sandbox();
    let mut backend = Backend::start(root.path());
    backend.call("hello", json!({}));
    let result = backend
        .task("identify", json!({"image":"images/sample.raw"}))
        .expect("identify");
    let banner = &result["banner"];
    assert_eq!(banner["plugin"], "banners");
    // The engine reports the banner bytes verbatim, including the trailing
    // newline before the NUL terminator.
    assert_eq!(
        banner["rows"][0][1],
        "Linux version synthetic (gcc version 1) #1 SMP\n"
    );
    backend.finish();
}

#[cfg(target_os = "linux")]
#[test]
fn only_one_task_runs_and_cancel_is_acknowledged() {
    let root = sandbox();
    // A FIFO image blocks the worker in `open` until a writer appears, so the
    // first task is still running when the second request arrives instead of
    // racing a sub-millisecond identification of a tiny file.
    let fifo = root.path().join("images/blocked.raw");
    let status = Command::new("mkfifo").arg(&fifo).status().expect("mkfifo");
    assert!(status.success(), "mkfifo failed");
    let mut backend = Backend::start(root.path());
    backend.call("hello", json!({}));
    let started = backend.call(
        "task.start",
        json!({"op":"identify","args":{"image":"images/blocked.raw"}}),
    );
    let id = started["task"].as_str().expect("task id").to_owned();
    let busy = backend.send(
        "task.start",
        json!({"op":"identify","args":{"image":"images/sample.raw"}}),
    );
    assert!(
        busy["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("仍在执行")),
        "second task must be refused: {busy}"
    );
    let cancelled = backend.call("task.cancel", json!({"id": id}));
    assert_eq!(cancelled["cancelling"], true);
    // The worker is either blocked opening the FIFO or already stopped by the
    // cancellation. A non-blocking writer open succeeds only while it waits,
    // and closing that writer releases it with EOF; retry until the slot is free.
    use std::os::unix::fs::OpenOptionsExt;
    const O_NONBLOCK: i32 = 0o4000;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !backend.call("task.running", json!({}))["task"].is_null() {
        assert!(std::time::Instant::now() < deadline, "cancelled task never ended");
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(O_NONBLOCK)
                .open(&fifo),
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    backend.finish();
}

#[test]
fn unknown_methods_and_bad_parameters_return_errors_not_crashes() {
    let root = sandbox();
    let mut backend = Backend::start(root.path());
    backend.call("hello", json!({}));
    let unknown = backend.send("does.not.exist", json!({}));
    assert!(
        unknown["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("未知方法"))
    );
    let bad = backend.send("registry.select", json!({"kind":"nonsense","path":"x"}));
    assert!(bad["error"].is_object());
    // The connection still works after both errors.
    assert_eq!(backend.call("ping", json!({}))["pong"], true);
    backend.finish();
}

#[test]
fn settings_round_trip_and_reject_an_oversized_page() {
    let root = sandbox();
    let mut backend = Backend::start(root.path());
    let hello = backend.call("hello", json!({}));
    let mut settings = hello["settings"].clone();
    settings["page_size"] = json!(25);
    let saved = backend.call("settings.save", settings.clone());
    assert_eq!(saved["page_size"], 25);
    settings["page_size"] = json!(10001);
    let rejected = backend.send("settings.save", settings);
    assert!(
        rejected["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("1–10000")),
        "{rejected}"
    );
    backend.finish();
}

#[test]
fn cache_inventory_is_scoped_and_clear_preview_matches_it() {
    let root = sandbox();
    std::fs::write(root.path().join(".zero/rust/abc.result.json"), b"{}").ok();
    let mut backend = Backend::start(root.path());
    let inventory = backend.call("cache.inventory", json!({}));
    assert!(inventory["entries"].is_array());
    let cleared = backend
        .task("cacheClear", json!({"scopes":["results"]}))
        .expect("clear");
    assert!(cleared["removed"].as_u64().is_some());
    backend.finish();
}

/// Full offline path with a real image and symbols: select the image, match
/// local symbols, enter the workbench and produce a verified page table.
///
/// Needs the official Debian 3.2 sample and symbols. Override with
/// `ZERO_TEST_IMAGE` / `ZERO_TEST_SYMBOLS`.
#[test]
#[ignore]
fn offline_acceptance_identifies_matches_and_analyzes() {
    let root = project_root();
    let image = std::env::var_os("ZERO_TEST_IMAGE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("images/linux-sample-1.bin.gz"));
    let symbols = std::env::var_os("ZERO_TEST_SYMBOLS")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("symbols/linux.zip"));
    assert!(image.is_file(), "sample missing: {}", image.display());
    assert!(symbols.exists(), "symbols missing: {}", symbols.display());

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".zero/rust")).expect("cache dir");
    std::fs::write(
        dir.path().join(".zero/rust/settings.json"),
        br#"{"image_dir":"images","symbols":"symbols","export_dir":"exports","enable_cache":false,"remote_symbols":false}"#,
    )
    .expect("settings");
    let mut backend = Backend::start(dir.path());
    backend.call("hello", json!({}));
    backend.call("registry.select", json!({"kind":"image","path":image}));
    backend.call("registry.select", json!({"kind":"symbols","path":symbols}));

    let matched = backend
        .task("matchLocal", json!({"image": image, "paths": [symbols]}))
        .expect("match local");
    assert!(
        !matched["matched"].as_array().expect("matches").is_empty(),
        "no exact banner match: {}",
        matched["diagnostics"]
    );
    let label = matched["matched"][0]["labels"][0]
        .as_str()
        .expect("label")
        .to_owned();

    let analyzed = backend
        .task(
            "analyze",
            json!({
                "image": image,
                "symbols": symbols,
                "plugin": "pslist",
                "symbol_choice": label,
                "options": {},
                "dump": null,
                "no_cache": true,
            }),
        )
        .expect("analyze");
    let result = &analyzed["result"];
    assert!(!result["rows"].as_array().expect("rows").is_empty());
    assert!(
        result["page_table"].as_u64().expect("page table") > 0,
        "page table not verified"
    );
    assert_eq!(result["system"], "linux");
    eprintln!(
        "tui-backend acceptance: {} rows · page table {:#x}",
        result["rows"].as_array().expect("rows").len(),
        result["page_table"].as_u64().expect("page table")
    );
    backend.finish();
}
