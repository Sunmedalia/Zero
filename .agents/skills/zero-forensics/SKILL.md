---
name: zero-forensics
description: Analyze local Linux RAW/LiME or Windows RAW, crash/minidump or supported hibernation memory images, including gzip with Zero's native MCP tools; identify symbols, inspect processes and kernel artifacts, and export targeted evidence.
---

# Zero memory forensics

Prefer the configured `zero` MCP tools for structured results. For a shell workflow, use `zero`; if it is unavailable or predates the checkout, build with `cargo build --release --locked` and use the checkout's `target/release/zero`.

MCP resolves relative paths against `ZERO_ROOT` in the server configuration, or its launch directory when unset. CLI paths, settings, cache and default asset directories resolve against its current working directory. Use absolute input paths when assets live outside the checkout; obtain the actual project root from the configuration or `git rev-parse --show-toplevel`.

## Choose an entry point

- With an image and explicit local ISF, call `zero_analyze` directly. There is no need to query the remote symbol index first.
- To identify a Linux kernel offline, use `zero_analyze` with `plugin: "banners"`; this needs no ISF or remote index. `zero_symbols` identifies banners **and queries the remote index**. Offline Linux calls to it require an existing index cache and do not search the local ISF directory.
- For repository matches or verified downloads, use `zero_symbols`; match the complete Linux banner and architecture or the exact Windows kernel PDB identity. Windows downloads fetch exact Microsoft PDBs and convert them to ISF in Rust; Linux downloads fetch matching ISFs. When analysis returns `needs_symbol_choice`, use an already specified label or present the returned `symbol_choices` for explicit selection. Do not choose by version alone.
- Use `zero_plugins` to discover plugin names and columns. Ordinary process inspections go through `zero_analyze`; Linux analysis has no PID filter; Windows plugins support `pid` for targeted analysis. Use `windows.*` plugin names and `os: windows` when necessary. `windows.printkey` requires a hive address from `windows.hivelist`; `key` is a hive-relative registry path. Select target rows by their returned PID column, then use `zero_dump` for evidence export.

Set `offline: true` on **every** MCP call that supports it when network access is disallowed; it is not a session toggle. CLI uses `--offline`. Otherwise network access follows the local settings and only fetches symbol indexes and files; images stay local.

## Interpret results and retrieve evidence

Read `structuredContent`, or parse the JSON text in `content` when the client only exposes text. `isError: true` means the tool failed. A successful tool response may still have `complete: false`; keep its diagnostics and describe the findings as partial. CLI can export partial results before returning a nonzero exit code; inspect the JSON artifact and stderr.

`zero_analyze` returns 50 rows by default and at most 200. Keep the image, symbols, plugin and choice fixed while following `next_offset`; `null` ends pagination. `total_rows` is the full count, not the number in the current page. For large results, set `output` to a `.json` or `.csv` path and inspect that full local artifact instead of repeatedly running analysis for many pages. JSON preserves completeness and diagnostics; CSV contains only the table.

Derive field positions from `columns`. Include the image, plugin, selected symbol, counts, completeness, diagnostics and artifact paths with findings. An empty complete table is a valid result; suspicious rows alone do not prove compromise.

## Targeted dumps

Confirm the authorized target using `pslist` or `windows.pslist` and obtain relevant ranges with Linux `maps`/`elfs` or Windows memory plugins. `zero_dump` requires an explicit PID (positive for Linux; Windows kernel range dumps use 0), `dump_dir`, and a separate `.json` or `.csv` manifest `output`.

A readable VMA does not guarantee its pages are resident in the captured image. If a range has missing pages, preserve the diagnostics and report the failed or partial export; do not substitute zero bytes or claim that the requested evidence was recovered.

- `mode: "range"`: supply `start` and `end` as decimal or `0x` **strings**. End is exclusive; the range must be at most 256 MiB.
- `mode: "process"`: export readable mappings of that PID; optional bounds must be supplied together.
- `mode: "pe"`: reconstruct Windows PE images.
- `mode: "elf"`: export mappings starting with an ELF header; omit bounds. This does not reconstruct an original on-disk executable.

Use a PID established by the user's request or by analysis within the authorized scope; do not invent a target or default to all processes. Read `complete` and `diagnostics`, and verify manifest sizes and SHA256 values against the exported files. Repeated dumps create separate evidence destinations; they do not overwrite previous binaries.

Use `zero_cache_list` for cache inspection. Cache clearing is CLI-only: preview with `zero cache clear --dry-run`; execute only within the user's requested scope.

For tested MCP arguments and equivalent CLI commands, read [references/calls.md](references/calls.md). The analysis engine reads images locally and never executes ISF files. Do not upload memory images or send recovered contents to external services without explicit authorization.

## Windows coverage and evidence

Windows architecture selection is `arch: auto|x86|x64|arm64`. Exact symbols must agree with the container and pointer width. Real-image validation covers Server 2003 SP0/2008 SP1 x86, Server 2012/2012 R2 and Windows 7 SP1/10/11 x64 RAW and Windows 10 build 19041/Server 2019 build 17763/Server 2022 build 20348 bitmap crash dumps; other architecture/container paths primarily have synthetic coverage. Use src/windows/compatibility.json for per-plugin evidence; do not describe it as complete Server 2003–2025 or Windows 7–11 coverage.

WOW64 command lines and DLLs have a `View` column. User minidumps provide captured-process metadata, DLLs and targeted dumps when the PID is recorded; kernel plugins are unavailable. Summary kernel dumps provide header metadata only; triage dumps expose captured kernel virtual ranges, contexts and driver records with synthetic validation. Use windows.crashinfo for captured faults and integer/control registers without kernel symbols; windows.modules on triage lists saved records only. Kernel range dumps use pid 0 through the common API. Registry segmented values are bounded to 1 MiB.

Use explicit same-capture attachments only: `pagefiles: [{"index": 0, "path": "..."}]` and optional `swapfile: "..."`. Never guess an index or search adjacent files. Swapfile indexing needs exact kernel symbols. Paging results record file digests and page offsets. Compressed store recovery requires private SMKM symbols/types and a verified virtual pagefile; Known Windows 11 x64 builds 22000/22621/22631/26100 have synthetic store coverage (26100 uses native LZ4); unknown builds and ARM64 stores remain unsupported. Modern nonswizzled pagefile offsets require exact MiState.Hardware.InvalidPteMask metadata. Hibernation reads saved physical pages and reports damaged/missing blocks; Fast Startup can omit user sessions. Hibernation and compressed-store recovery currently carry synthetic-validation diagnostics and partial results.

Network analysis first tries exact tcpip.sys PDB types, then architecture/driver-version layouts. An unvalidated exact driver identity remains partial; an unknown layout fails explicitly. Pool scans are candidates, not proof of a hidden process. FILETIME values are decimal 100 ns ticks since 1601 UTC. Always distinguish virtual addresses from `physical:` addresses.


Additional Windows plugins: threads, envars, svcscan, driverscan, drivercheck, autoruns, cmdscan, consoles and crashinfo. Use the windows. prefix. Threads/envars accept PID; svcscan PID selects the services.exe host. Autoruns optionally accepts hive and covers Run/RunOnce, Winlogon, IFEO and current ControlSet services; this is not a complete persistence inventory. Driver dispatch addresses in another module are observations, not maliciousness verdicts. Services/consoles require supported layouts and retain validation diagnostics; console output currently includes title/history metadata, not screen text. Native/WOW64 environment rows include a View. Registry-process hive mappings and prototype-to-pagefile recovery preserve source/coverage diagnostics. Real user-minidump context coverage currently includes one Windows XP x86 fixture; Real kernel triage metadata coverage is limited to the publisher-reported Server 2016 fixture described below.

Windows additions: callbacks (process/thread/image-load/registry only), unloadedmodules, filescan, mutantscan, getsids (PID supported), and NT5 connscan/sockscan. Use netscan for NT6+; no cross-generation layout fallback. Pool object rows include physical and verified virtual addresses; missing names remain partial. Getsids resolves built-in SID names only. Service layouts use explicit architecture/build mappings; console layouts also check supported revisions. Unknown versions fail with diagnostics rather than choosing a nearby version. Zero-row scans and synthetic pointer-width tests do not establish real recovery coverage. The compatibility manifest records exact sample builds, containers, hashes and PDB identities; Server 2003/R2 identity may remain ambiguous.

Server 2016 real triage evidence covers only saved faults/context/modules, with publisher-reported product identity and header-verified build 14393; ProductType is unavailable. Do not imply full Server 2016 kernel coverage. Identical duplicated triage ranges are verified byte-for-byte; differing bytes fail. Server 2012 R2 has two known missing UDP wildcard reference connections because its LocalAddr pointer is non-canonical; preserve the diagnostic and do not count these as equality evidence. Server 2003 R2/2008 R2/2025 still need separately verified samples.
