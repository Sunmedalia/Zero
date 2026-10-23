# Zero development

This repository is a native Rust 2024 local Linux and Windows memory forensics TUI with exact ISF/PDB symbol matching.

- `src/image.rs`: read-only RAW / LiME / Windows container address spaces, fused digest/banner preparation, x86_64 and ARM64 4K page translation.
- `src/symbols.rs`: local ISF JSON / XZ / ZIP, complete banners, repository links and validated downloads.
- `src/analysis.rs`: platform routing, OS choice and targeted PID/hive/key options.
- `src/windows.rs` / `src/windows/`: native Windows kernel discovery, processes, VADs, handles, registry, symbol/architecture/driver-version network layouts and atomic process/range/PE dumps.
- `src/windows/malware.rs`: PEB/VAD loader cross-views, hollowing leads and active thread start checks; incomplete views never prove absence.
- `src/windows/hiber.rs` / `paging.rs` / `compressed.rs`: bounded saved-page containers, explicit paging attachments and symbol-driven SMKM reconstruction; preserve coverage diagnostics.
- `src/windows_symbols.rs`: exact RSDS identity, Microsoft PDB acquisition and deterministic native conversion.
- `src/plugin.rs`: plugin identities, descriptors, columns and categories for both platforms.
- `src/report.rs`: shared address formatting and partial-result diagnostics.
- `src/linux.rs` / `src/linux/`: Linux analysis. `session.rs` (prepared image, symbols, roots), `discover.rs` (page-table validation), `engine.rs` (ISF field readers, typed tasks and the exhaustive plugin router), `walk.rs` (lists, maple trees, VMAs, address spaces), `process.rs` (psaux / envars / pwd / creds / threads / state / ptrace), `memory.rs` (maps / elfs / malfind / bash), `fs.rs` (lsof / paths / mounts), `net.rs` (sockstat), `kernel.rs` (dmesg / systeminfo / iomem / notifiers / check_modules / check_syscall / psxview), `tests.rs` (shared fixtures).
- `src/dump.rs`: unified `dump --mode process|range|elf|pe` command and targeted procdump / memdump / elfdump backends, streamed atomic exports and SHA256 manifests; never dump all processes or use result caches.
- `src/cache.rs`: allowlisted inventories, categorized clear, shared/exclusive occupancy locks.
- `src/prepare.rs`: exact debug ELF/config generation and explicit Kali archive preparation.
- `src/store.rs`: atomic exports, digest/version keyed successful results, settings and historical CSV.
- `src/workspace.rs`: discovered/imported assets, persisted selections, non-destructive removal and symbol inspection.
- `ts/`: the terminal interface. `src/app.ts` is the state machine (preparation, one-task-at-a-time lifecycle, selection, dialogs, commands); `src/layoutTree.ts` computes every rectangle once per frame and is shared by painting and mouse hit-testing; `src/canvas.ts` composes the whole screen grid so frames are deterministic and wide glyphs cannot split; `src/views/paint.ts` draws regions into that canvas and `src/views/root.tsx` mounts it; `src/mouse.ts` decodes SGR reports from the raw stdin because Ink's parser discards them; `src/actions.ts` is the single action table (key, label, availability, palette/toolbar/footer placement); `src/state.ts` holds derived selectors and the indexed result view. The interface never reads evidence itself.
- `src/tui_backend.rs`: newline-delimited JSON-RPC backend behind `zero tui-backend`. Owns the prepared-image session, symbol resolution, cache writes, atomic exports and cancellation; long operations run as cancellable tasks with progress notifications. `tests/tui_backend.rs` drives the released binary over stdio and is what `make tui-acceptance` runs.

Run `make check` for fmt, Clippy, tests and release build. Run `make acceptance` with the local official Debian 3.2 and Kali 6.8.11 ARM64 samples and symbols for all fields, counts, list closure and parent relationships. Run `make windows-acceptance` with the public Windows 10/11 RAW samples and prepared matching PDBs. Never commit large memory images, symbols, credentials or runtime data.

The user explicitly requested removal of all legacy project files and runtime data. Keep the current Rust project, original test images, `linux.zip`, and `symbols/kali-6.8.11-arm64.json.xz` with provenance intact. Do not restore Python/web sources or configuration migration. The current runtime recreates `.zero/rust/`; settings and `workspace.json` are protected from cache clearing. Asset import/removal changes only the project registry, never source files. Partial analyses must carry explicit diagnostics and must not enter successful caches. Ambiguous symbols require explicit selection.

Symbol network access is authorized by default for the specified Abyss-W4tcher repository and exact Microsoft symbol-server PDB identities, and the official Volatility Windows symbol ZIP as an HTTP-404-only exact-ISF fallback; keep `--offline` and the TUI offline toggle functional. Never upload memory images or execute symbol files, legacy plugins or package installation scripts. The explicitly invoked Kali preparation may compile the pinned dwarf2json tool using Go; all analyses remain native Rust. Same-session preparation reuse must invalidate when source metadata changes.
