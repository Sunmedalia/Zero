---
name: zero-forensics
description: Analyze local Linux RAW/LiME or Windows RAW, crash/minidump or supported hibernation memory images, including gzip with Zero's native MCP tools; identify symbols, inspect processes and kernel artifacts, and export targeted evidence.
---

# Zero memory forensics

Use the `zero` MCP server for this repository's local memory analysis. Paths may be absolute or relative to the current project root.

For a shell workflow, the equivalent native CLI is `zero` (`zero --help` lists commands). Run it from the project root so its local cache and default directories resolve correctly.

1. Call `zero_symbols` with the image to inspect Linux kernel banners or Windows kernel PDB identities and exact symbol matches. Set `offline: true` when the user requires no network access. Windows downloads fetch exact Microsoft PDBs and convert them to ISF in Rust; Linux downloads fetch matching ISFs; memory images stay local.
2. Call `zero_plugins` when choosing an analysis plugin. Use `zero_analyze` with the image, plugin, and optional symbols path. For Windows use `windows.*` plugin names, `os: windows` when necessary, and `pid` for targeted analysis. `windows.printkey` requires a hive address from `windows.hivelist`; `key` is a hive-relative registry path. When it returns `symbol_choices`, ask the user to select the matching label or use a label they already specified.
3. Use `offset` and `limit` to page results; a call returns at most 200 rows. Set `output` to a `.json` or `.csv` path when the complete result should be saved. Report `complete` and any `diagnostics` with findings.
4. Use `zero_dump` only for a user specified PID and destination. For `mode: range`, supply `start` and `end` as decimal or `0x` strings; the end is exclusive. Windows `mode: pe` reconstructs PE images; Linux supports `mode: elf`. The manifest contains SHA256 hashes. Never infer a PID or dump every process.

The analysis engine reads images locally and does not execute symbol files. Do not upload memory images or disclose raw contents to external services. Cache inspection is available through `zero_cache_list`.

Windows architecture selection is `arch: auto|x86|x64|arm64`. Exact symbols must agree with the container and pointer width. Real-image validation covers Windows 10/11 x64 RAW and a Windows 10 build 19041 bitmap crash dump; other architecture/container paths primarily have synthetic coverage. Do not describe that as full Windows 7–11 plugin coverage.

WOW64 command lines and DLLs have a `View` column. User minidumps provide captured-process metadata, DLLs and targeted dumps when the PID is recorded; kernel plugins are unavailable. Small kernel dumps currently provide header metadata only. Registry segmented values are bounded to 1 MiB.

Use explicit same-capture attachments only: `pagefiles: [{"index": 0, "path": "..."}]` and optional `swapfile: "..."`. Never guess an index or search adjacent files. Swapfile indexing needs exact kernel symbols. Paging results record file digests and page offsets. Compressed store recovery requires private SMKM symbols/types and a verified virtual pagefile; Known Windows 11 x64 builds 22000/22621/22631/26100 have synthetic store coverage (26100 uses native LZ4); unknown builds and ARM64 stores remain unsupported. Modern nonswizzled pagefile offsets require exact MiState.Hardware.InvalidPteMask metadata. Hibernation reads saved physical pages and reports damaged/missing blocks; Fast Startup can omit user sessions. Hibernation and compressed-store recovery currently carry synthetic-validation diagnostics and partial results.

Network analysis first tries exact tcpip.sys PDB types, then architecture/driver-version layouts. An unvalidated exact driver identity remains partial; an unknown layout fails explicitly. Pool scans are candidates, not proof of a hidden process. FILETIME values are decimal 100 ns ticks since 1601 UTC. Always distinguish virtual addresses from `physical:` addresses.
