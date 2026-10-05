---
name: zero-forensics
description: Analyze local Linux RAW/LiME or Windows x64 RAW memory images, including gzip with Zero's native MCP tools; identify symbols, inspect processes and kernel artifacts, and export targeted evidence.
---

# Zero memory forensics

Use the `zero` MCP server for this repository's local memory analysis. Paths may be absolute or relative to the current project root.

For a shell workflow, the equivalent native CLI is `zero` (`zero --help` lists commands). Run it from the project root so its local cache and default directories resolve correctly.

1. Call `zero_symbols` with the image to inspect Linux kernel banners or Windows kernel PDB identities and exact symbol matches. Set `offline: true` when the user requires no network access. Windows downloads fetch exact Microsoft PDBs and convert them to ISF in Rust; Linux downloads fetch matching ISFs; memory images stay local.
2. Call `zero_plugins` when choosing an analysis plugin. Use `zero_analyze` with the image, plugin, and optional symbols path. For Windows use `windows.*` plugin names, `os: windows` when necessary, and `pid` for targeted analysis. `windows.printkey` requires a hive address from `windows.hivelist`; `key` is a hive-relative registry path. When it returns `symbol_choices`, ask the user to select the matching label or use a label they already specified.
3. Use `offset` and `limit` to page results; a call returns at most 200 rows. Set `output` to a `.json` or `.csv` path when the complete result should be saved. Report `complete` and any `diagnostics` with findings.
4. Use `zero_dump` only for a user specified PID and destination. For `mode: range`, supply `start` and `end` as decimal or `0x` strings; the end is exclusive. Windows `mode: pe` reconstructs PE images; Linux supports `mode: elf`. The manifest contains SHA256 hashes. Never infer a PID or dump every process.

The analysis engine reads images locally and does not execute symbol files. Do not upload memory images or disclose raw contents to external services. Cache inspection is available through `zero_cache_list`.

Windows support targets Windows 10/11 x64 RAW/gzip. Crash/minidumps, hibernation images, WOW64 PEB decoding, and pagefile/compressed pages are unsupported. Network analysis requires an exact allowlisted tcpip.sys PDB identity. Pool scans are candidates, not proof of a hidden process. FILETIME values are decimal 100 ns ticks since 1601 UTC. Always distinguish virtual addresses from `physical:` addresses.
