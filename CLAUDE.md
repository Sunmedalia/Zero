# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Zero is a native Rust 2024 local Linux and Windows memory forensics tool (TUI, CLI and stdio MCP from one `zero` binary) with exact ISF/PDB symbol matching. The crate is `zero-tui`; the toolchain is pinned to Rust 1.95.0 (`rust-toolchain.toml`). User-facing strings and docs are Chinese.

## Commands

```sh
make check                      # required before finishing: fmt --check, clippy -D warnings (all targets), tests, release build, python tooling checks (needs python3)
cargo test --locked --lib <filter>   # single unit test / module, e.g. linux::envars:: or tui::
cargo test --locked --test native    # synthetic integration tests
make ui-test                    # TUI tests only (cargo test --locked --lib tui::)
make deny                       # cargo-deny 0.20.2; not part of make check but run in CI, so run it when dependencies change
make run ARGS="--offline ..."   # release run of the TUI/CLI (zero analyze|symbols|symbols-generate|dump|doctor|mcp; see --help)
make screenshots                # regenerate docs/assets/*.svg after UI changes (IMAGE= SYMBOLS= override)
```

Real-sample acceptance (`#[ignore]`d, offline, local samples only; paths via `ZERO_TEST_IMAGE` / `ZERO_TEST_SYMBOLS` / `ZERO_KALI_IMAGE` / `ZERO_KALI_SYMBOLS`; baselines in `tests/fixtures/*.json`):

- `make acceptance`: Debian 3.2 and Kali 6.8.11 ARM64; all fields, counts, list closure and parent relationships. Run when Linux parsing or plugin output changes.
- `make windows-acceptance`: public Windows RAW / crash dump samples with prepared matching PDBs. Run when Windows parsing or plugin output changes.
- `make tui-acceptance`: real image through `App` and `engine_service`.

CI also runs `python3 -I scripts/verify_release.py` on the packaged archives. Benchmarks are examples (`bench_plugins`, `benchmark_results`, ...), see `docs/development.md`. `.mcp.json` starts `zero mcp` via `cargo run`, so it fails when `cargo` is not on PATH.

## Architecture

Flow: `image.rs` opens evidence read-only and prepares digest/banner → `symbols.rs` / `windows_symbols.rs` find an exact ISF/PDB → `analysis.rs` routes to `linux/` or `windows/` → plugins return `store::Results` (with partial diagnostics from `report.rs`) → `store.rs` caches only complete results. `engine_service.rs` is the shared session API (verify, identify, match, analyze, inventory, symbol saving) used directly by TUI workers (typed requests and channels), the CLI (`main.rs`) and `mcp.rs`. Cancellation and progress flow through `Job` in `src/lib.rs`; long loops must poll it.

Boundaries and invariants that span files:

- `src/symbols/http.rs` is the only network path: native rustls HTTPS, HTTPS-only redirects, size limits, immediate cancellation. `github_access` (`auto`, `direct`, `gh-proxy`) uses gh-proxy.com for public GitHub URLs only; keep canonical repository URL checks, download validation, cancellation and offline gates intact.
- `src/bytes.rs` is the only way to read image-derived bytes (`at`/`at_mut`, `key`/`key_mut` for JSON, `cell` for result rows, `Cells` for terminal coordinates).
- `src/plugin.rs` + `src/plugin/catalog.rs` are the single source of plugin identity, category, description and columns for both platforms.
- `src/linux/engine.rs` holds ISF field readers, typed tasks and the exhaustive plugin router; `session.rs` the prepared image/symbols/roots; `discover.rs` page-table validation; `walk.rs` lists, maple trees, VMAs and address spaces. Other `src/linux/*.rs` files are plugin families.
- `src/windows/` has its own `CLAUDE.md` with Windows-specific rules.
- `src/dump.rs`: unified `dump --mode process|range|elf|pe`, streamed atomic exports with SHA256 manifests; never dump all processes or use result caches.
- `src/prepare.rs`: exact debug ELF/config generation and explicit Kali archive preparation (may compile the pinned dwarf2json with Go; analyses stay native Rust). `src/prepare/from_image.rs` (`--from-image`, TUI F8): x86_64 generation from embedded BTF (`btf.rs`, dwarf2json naming rules), core kallsyms (`image_kallsyms.rs`) and a cross-checked VMCOREINFO KASLR offset (`vmcoreinfo.rs`). Every link is verified against the image and page tables before saving; `metadata.zero.source = "image"` keeps it out of debug-package reuse; missing global-variable types must fail explicitly.
- `src/store.rs`: atomic exports, digest/version keyed successful results, settings, historical CSV. `src/cache.rs`: allowlisted inventories, categorized clear, shared/exclusive occupancy locks. `src/workspace.rs`: asset registry, persisted selections, symbol inspection.
- `src/snapshots.rs` (immutable paged result snapshots, spilled to private temp dirs beyond budget), `src/resources.rs` (weighted LRU budgets from `settings.json` `resources`; eviction never changes evidence), `src/result_view.rs` (index-based filter/sort/tree views without cell copies). `pattern.rs` / `byte_regex.rs` / `regex_scan.rs` / `physical.rs` / `stack_scan.rs` are bounded, cancellable scan primitives shared by plugins.
- `src/kernel_diagnostics.rs`: offline kernel validation reports with per-symbol evidence and protected JSON/TXT export; TUI key J, its own popup, never replaces plugin results.
- `src/tui/`: Ratatui/Crossterm app state, typed worker events, rendering/hit rectangles, dialogs, tabs, themes. `tests.rs` / `migration_tests.rs` test state and TestBackend rendering without a terminal; `screenshots.rs` renders SVG from the same Buffer and real engine.

`ENGINE_VERSION` in `src/lib.rs` (`<cargo version>-native-N`) keys successful-result caches: bump `N`, with a one-line comment on why, whenever a change alters plugin output or invalidates cached results.

### Adding a plugin

1. Add a `Plugin` variant in `src/plugin.rs` with `#[value(name = "linux.x.X", alias = "linux.x")]`; the `windows.` name prefix decides the platform.
2. Add exactly one row in `src/plugin/catalog.rs` (row order is display order; a compile-time index rejects missing or duplicate rows).
3. Route it: Linux via the exhaustive `match` in `Linux::run` (`src/linux/engine.rs`, the compiler enforces it); Windows via `Windows::run` in `src/windows.rs` (not exhaustive, easy to miss).
4. Windows: record coverage in `src/windows/compatibility.json` and re-render `docs/compatibility.md` with `python3 scripts/windows_compatibility.py` (`--check` runs in `make check`).
5. Add tests and fixture baselines, document fields in `docs/usage.md`, and bump `ENGINE_VERSION` if cached outputs change.

Docs: `docs/usage.md` (CLI, plugin fields, cache, settings), `docs/tui.md` (TUI architecture, worker threads, gh-proxy), `docs/development.md` (resource budgets, CI, release), `docs/volatility-parity.md` (pinned Volatility v2.28.2 cases under `tests/reference/parity`). Release: bump `Cargo.toml`/`Cargo.lock`, rewrite `RELEASE_NOTES.md`, tag `vX.Y.Z` (CI checks tag == Cargo version).

## Rules

- Production code denies unwrap/expect/panic/unreachable/todo/unimplemented, `clippy::indexing_slicing` and `clippy::cast_possible_truncation` (tests are exempt). Handle failure with `Result` or explicit partial diagnostics; narrow image-derived values with `try_from`.
- Partial analyses must carry explicit diagnostics and never enter successful caches; incomplete views never prove absence. Ambiguous symbols require explicit selection; never substitute a near-version symbol.
- Evidence is read-only. Asset import/removal changes only the project registry, never source files. Never upload memory images, or execute symbol files, legacy plugins or package installation scripts.
- Symbol network access is authorized by default only for the Abyss-W4tcher volatility3-symbols repository, exact Microsoft symbol-server PDB identities, and the official Volatility Windows symbol ZIP as an HTTP-404-only exact-ISF fallback. Keep `--offline` and the TUI offline toggle functional. Same-session preparation reuse must invalidate when source metadata changes.
- Do not restore the removed legacy Python/web sources or configuration migration. Python under `scripts/` (release packaging, compatibility checks) and `tests/reference/` (parity references) is current tooling, not legacy source.
- Preserve the original test images (`images/`), `linux.zip` and `symbols/kali-6.8.11-arm64.json.xz` with their provenance when present; they are gitignored. Never commit memory images, symbols, credentials or runtime data.
- Runtime state lives in `.zero/rust/` (recreated automatically); settings and `workspace.json` are protected from cache clearing.
