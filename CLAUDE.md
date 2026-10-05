# Zero development

This repository is a native Rust 2024 local Linux memory forensics TUI with optional exact GitHub symbol matching.

- `src/image.rs`: read-only RAW / LiME address space, fused digest/banner preparation, x86_64 and ARM64 4K page translation.
- `src/symbols.rs`: local ISF JSON / XZ / ZIP, complete banners, repository links and validated downloads.
- `src/linux.rs`: candidate page table validation, shared tasks traversal, pslist / pstree / lsmod and plugin catalog.
- `src/extended.rs`: psaux / envars / maps / lsof / sockstat, process address spaces, FD and mount path readers.
- `src/more.rs`: pwd / pscred / threads / mountinfo / check_creds / dmesg.
- `src/modern.rs`: maple VMAs, modern mounts/threads and structured printk.
- `src/volatility_extra.rs`: iomem / ioports resource trees, per-thread ptrace relationships and keyboard notifier callbacks.
- `src/process_extra.rs`: ISF process state and capability masks, per-process FD summaries.
- `src/inspect.rs`: systeminfo / elfs / bash / history / malfind / psxview / check_modules / check_syscall.
- `src/dump.rs`: unified `dump --mode process|range|elf` command and targeted procdump / memdump / elfdump backends, streamed atomic exports and SHA256 manifests; never dump all processes or use result caches.
- `src/cache.rs`: allowlisted inventories, categorized clear, shared/exclusive occupancy locks.
- `src/prepare.rs`: exact debug ELF/config generation and explicit Kali archive preparation.
- `src/store.rs`: atomic exports, digest/version keyed successful results, settings and historical CSV.
- `src/workspace.rs`: discovered/imported assets, persisted selections, non-destructive removal and symbol inspection.
- `src/tui.rs`: Ratatui / Crossterm interface, background analysis and cancellation.

Run `make check` for fmt, Clippy, tests and release build. Run `make acceptance` with the local official Debian 3.2 and Kali 6.8.11 ARM64 samples and symbols for all fields, counts, list closure and parent relationships. Never commit large memory images, symbols, credentials or runtime data.

The user explicitly requested removal of all legacy project files and runtime data. Keep the current Rust project, original test images, `linux.zip`, and `symbols/kali-6.8.11-arm64.json.xz` with provenance intact. Do not restore Python/web sources or configuration migration. The current runtime recreates `.zero/rust/`; settings and `workspace.json` are protected from cache clearing. Asset import/removal changes only the project registry, never source files. Partial analyses must carry explicit diagnostics and must not enter successful caches. Ambiguous symbols require explicit selection.

Symbol network access is authorized by default for the specified Abyss-W4tcher repository; keep `--offline` and the TUI offline toggle functional. Never upload memory images or execute symbol files, legacy plugins or package installation scripts. The explicitly invoked Kali preparation may compile the pinned dwarf2json tool using Go; all analyses remain native Rust. Same-session preparation reuse must invalidate when source metadata changes.
