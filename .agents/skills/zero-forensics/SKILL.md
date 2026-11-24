---
name: zero-forensics
description: Perform local Linux and Windows memory forensics with Zero's native MCP tools or CLI (`zero`). Use when analyzing RAW/LiME, Windows crash/minidump, or supported hibernation images (including `.gz`), identifying or generating exact ISF/PDB symbols (remote repo, Microsoft PDB, official debug packages, or offline x86_64 BTF+kallsyms), running offline kernel validation diagnostics, inspecting processes/network/registry/kernel artifacts, or exporting targeted memory/binary evidence with SHA256 manifests.
---

# Zero Memory Forensics

Prefer the configured `zero` MCP tools for structured results. For a shell workflow, use `zero`; if unavailable or older than the checkout, build with `cargo build --release --locked` and run `target/release/zero`.

## Path, Network, and Evidence Rules

- **Paths**: MCP resolves relative paths against `ZERO_ROOT` (or its launch directory when unset). CLI resolves paths, settings, cache, and default asset directories against CWD. Use absolute paths when assets live outside the checkout; get the project root from config or `git rev-parse --show-toplevel`.
- **Offline mode**: Pass `offline: true` on **every** MCP call that supports it when network access is disallowed (it is not a session toggle); CLI uses `--offline`. Online calls only fetch symbol indexes, debug packages, or exact ISF/PDB files—memory images always stay local.
- **Read-only evidence**: The engine reads images locally and never executes ISF files, package scripts, or legacy Python plugins. Never upload memory images or recovered contents to external services without explicit authorization.
- **Single active job**: Only one analysis, symbol, or dump job runs at a time; concurrent requests return JSON-RPC `-32000` (busy). Cancel an active job via `notifications/cancelled` (`params.requestId`) and wait for completion before starting the next.

## Tool Selection

| Goal | MCP Tool | CLI Equivalent |
| --- | --- | --- |
| List plugins, categories, and columns | `zero_plugins` | `zero plugins` |
| Check `git`/`go` availability for symbol builds | `zero_doctor` | `zero doctor` |
| Identify banners & match/download exact remote symbols | `zero_symbols` | `zero symbols` |
| Generate exact Linux ISF (BTF+kallsyms, debug pkgs, ELF+config) | `zero_symbols_generate` | `zero symbols-generate` |
| Run offline kernel/symbol validation diagnostics | `zero_diagnose` | `zero diagnose` |
| Run an analysis plugin (returns `result_id`, ≤200 rows) | `zero_analyze` | `zero analyze` |
| Paginate or export an immutable analysis snapshot | `zero_results` | *(use `--output` on analyze)* |
| Export targeted memory, binaries, or modules with manifest | `zero_dump` | `zero dump` |
| Inspect regenerable local cache | `zero_cache_list` | `zero cache list` |

Cache clearing is **CLI-only**: preview with `zero cache clear --dry-run` and execute (`--yes`) only within the user's requested scope.

## Workflow

### 1. Identify and Prepare Symbols

- **Explicit local ISF**: Call `zero_analyze` directly with `symbols`; do not query the remote index first.
- **Offline Linux banner identification**: Call `zero_analyze` with `plugin: "linux.banners"` (alias `banners`; needs no ISF or index). `zero_symbols` both identifies banners **and** queries the remote index; offline calls to `zero_symbols` require a cached index and do not scan the local ISF directory.
- **Remote matching & download**: Call `zero_symbols` (`download: true` only when fetching is desired; `refresh: true` forces an online index update).
  - Match the **complete** Linux banner + architecture, or the **exact** Windows kernel PDB name/GUID/Age. Never substitute a near-version symbol.
  - Windows downloads fetch exact Microsoft PDBs and convert them to ISF in Rust; HTTP 404 automatically falls back to exact-ISF range reads from the official Volatility Windows ZIP (cached for offline reuse). Timeouts/503 do not trigger fallback.
- **Missing Linux ISF**: Call `zero_symbols_generate` with exactly one mode:
  - `from_image: true`: Offline x86_64 generation from embedded BTF + kallsyms (or validates/reuses an exact local ISF when unavailable); needs no network or `git`/`go`.
  - `auto: true`: Discovers official Ubuntu/Debian/Kali debug packages (check `zero_doctor` first). If `needs_candidate: true`, present `candidates` and retry with `candidate` (1-based) and omit `refresh`.
  - `elf` + `config`: Local debug ELF and kernel config.
  - `kali: true`: Compatibility path for Kali 6.8.11 ARM64.
- **Ambiguous symbols**: When analysis returns `needs_symbol_choice: true`, use an already-specified label or present `symbol_choices` for explicit selection; repeat with `symbol_choice` (`--symbol-choice`).
- **Kernel/symbol troubleshooting**: Call `zero_diagnose` to run offline per-symbol validation and optionally export a JSON/TXT report.

### 2. Discover and Run Analysis Plugins

- Call `zero_plugins` to get exact plugin names and columns (unified `<os>.<id>` canonical names such as `linux.pslist`, `linux.pslist.full`, `linux.maps.full`, `linux.pagecache.files`, `windows.pslist`, `windows.netstat`, `windows.registry.amcache.full`; legacy bare names and Volatility 3 class-path names remain accepted as aliases).
- Set `os: "windows"` (or `windows.*` plugin names) when targeting Windows; set `arch: "auto"|"x86"|"x64"|"arm64"` when needed.
- **Filtering & options**:
  - `pids` (array) filters supported Linux plugins (`linux.pslist.full`, `linux.pstree.full`, `linux.psaux.full`, `linux.envars.full`, `linux.capabilities.full`, `linux.maps.full`, `linux.lsof.full`, `linux.sockstat.full`, `linux.malfind.full`, `linux.mountinfo.full`, `linux.bash.full`, `linux.elfs.full`, `linux.library_list.full`, `linux.vmaregexscan`, `linux.pscallstack`) and Windows plugins (`windows.strings`, `windows.vadregexscan`, `windows.vadwalk`, `windows.pebmasquerade`).
  - `pid` filters targeted Windows plugins (e.g., `windows.vadinfo`, `windows.threads`, `windows.envars`, `windows.getsids`; on `windows.svcscan` it selects the `services.exe` host).
  - `windows.printkey` requires `hive` (address from `windows.hivelist`) and optional hive-relative `key`.
  - `dump_dir` on `zero_analyze` enables inline binary export for supported listing plugins (`linux.maps.full`, `linux.malfind.full`, `linux.elfs.full`, `linux.lsmod`, `linux.fbdev`, `windows.memmap`).
  - Keep arguments strictly within the tool schema (`deny_unknown_fields` rejects misspelled or unsupported parameters).

### 3. Interpret Results and Paginate

- Read `structuredContent` (or parse JSON text in `content` if the client exposes text only). `isError: true` indicates tool failure.
- **Completeness**: A successful call may still return `complete: false`. Always preserve `diagnostics` and report findings as partial. CLI may export partial results before exiting nonzero—inspect both the exported JSON and stderr.
- **Pagination**: `zero_analyze` returns 50 rows by default (max 200) and a `result_id`; it does **not** accept `offset`. Use `zero_results` with `result_id` and `next_offset` until `next_offset` is `null`. `total_rows` is the full snapshot count, not the page size. Snapshots preserve partial diagnostics and expire on idle timeout (30 min), eviction (8 snapshots), or server restart.
- **Large outputs**: Pass `output` (`.json` or `.csv`) to `zero_analyze` or `zero_results` and inspect the local artifact instead of paging repeatedly. JSON preserves completeness, metadata, and diagnostics; CSV contains only table rows.
- **Reporting standard**: Derive column positions from `columns`. Always report image, plugin, selected symbol, counts, completeness, diagnostics, and artifact paths. An empty complete table is valid; incomplete views never prove absence; suspicious rows alone are leads, not proof of compromise.

### 4. Targeted Evidence Dumps

Confirm the authorized target first via `pslist`/`windows.pslist` and locate ranges via `maps`/`elfs` or Windows memory plugins. Never invent a target PID or dump all processes.

`zero_dump` requires `image`, `mode`, `dump_dir`, and a separate `.json`/`.csv` manifest `output` (returns ≤200 manifest rows; inspect `output` for the full manifest if `next_offset` is non-null):

- **Process/range modes** (require positive `pid`; Windows kernel range dumps use `pid: 0`):
  - `range`: `start` and `end` as decimal or `0x` **strings** (end exclusive, ≤256 MiB).
  - `process`: readable mappings of `pid` (optional `start`+`end` must be given together).
  - `elf` (Linux): mappings starting with an ELF header; omit bounds (does not reconstruct on-disk binary).
  - `pe` / `vad` / `dll` / `files` / `memmap` (Windows): PE reconstruction, per-VAD export, DLL reconstruction (optional `start` base), resident cached files, or physical page export (256 MiB cap).
- **Kernel/device modes** (omit `pid` or `pid: 0`):
  - `kernel-module` (Linux): reconstructs module ELF; requires `start` (`struct module` address), no `end`.
  - `lsmod` (Linux): exports listed Linux module ELFs; no `pid` or bounds.
  - `framebuffer` (Linux): dumps fbdev buffers; optional `start` (`fb_info` address), no `end`.
  - `module` (Windows): reconstructs kernel modules; optional `start` base, no `end`.

A readable VMA/VAD does not guarantee pages are resident. Preserve diagnostics on missing pages and report failed/partial exports—never substitute zero bytes or claim unrecovered evidence was extracted. Verify manifest sizes and SHA256 hashes against exported files. Repeated dumps create separate destinations and never overwrite prior binaries.

## Detailed References

- **MCP payloads, CLI equivalents, all 12 dump modes, plugin options, and error recovery**: read [references/calls.md](references/calls.md).
- **Windows architecture/container coverage, paging/hibernation/compressed-store rules, and validation caveats**: read [references/windows.md](references/windows.md).
