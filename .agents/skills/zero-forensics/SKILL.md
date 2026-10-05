---
name: zero-forensics
description: Use Zero's native CLI or MCP tools to analyze local Linux RAW, LiME, or gzip memory images, match ISF symbols, inspect processes and kernel artifacts, and export targeted evidence.
---

# Zero memory forensics

Prefer the configured `zero` MCP tools for structured results. For a shell workflow, use `zero`; if it is unavailable or predates the checkout, build with `cargo build --release --locked` and use the checkout's `target/release/zero`.

MCP resolves relative paths against `ZERO_ROOT` in the server configuration, or its launch directory when unset. CLI paths, settings, cache and default asset directories resolve against its current working directory. Use absolute input paths when assets live outside the checkout; obtain the actual project root from the configuration or `git rev-parse --show-toplevel`.

## Choose an entry point

- With an image and explicit local ISF, call `zero_analyze` directly. There is no need to query the remote symbol index first.
- To identify a kernel offline, use `zero_analyze` with `plugin: "banners"`; this needs no ISF or remote index. `zero_symbols` identifies banners **and queries the remote index**. Offline calls to it require an existing index cache and do not search the local ISF directory.
- For repository matches or verified downloads, use `zero_symbols`; match the complete banner and architecture. When analysis returns `needs_symbol_choice`, use an already specified label or present the returned `symbol_choices` for explicit selection. Do not choose by version alone.
- Use `zero_plugins` to discover plugin names and columns. Ordinary process inspections go through `zero_analyze`; it has no PID filter argument. Select target rows by their returned PID column, then use `zero_dump` for evidence export.

Set `offline: true` on **every** MCP call that supports it when network access is disallowed; it is not a session toggle. CLI uses `--offline`. Otherwise network access follows the local settings and only fetches symbol indexes and files; images stay local.

## Interpret results and retrieve evidence

Read `structuredContent`, or parse the JSON text in `content` when the client only exposes text. `isError: true` means the tool failed. A successful tool response may still have `complete: false`; keep its diagnostics and describe the findings as partial. CLI can export partial results before returning a nonzero exit code; inspect the JSON artifact and stderr.

`zero_analyze` returns 50 rows by default and at most 200. Keep the image, symbols, plugin and choice fixed while following `next_offset`; `null` ends pagination. `total_rows` is the full count, not the number in the current page. For large results, set `output` to a `.json` or `.csv` path and inspect that full local artifact instead of repeatedly running analysis for many pages. JSON preserves completeness and diagnostics; CSV contains only the table.

Derive field positions from `columns`. Include the image, plugin, selected symbol, counts, completeness, diagnostics and artifact paths with findings. An empty complete table is a valid result; suspicious rows alone do not prove compromise.

## Targeted dumps

Confirm the authorized target using `pslist` and obtain relevant ranges with `maps` or `elfs`. `zero_dump` requires a positive integer PID, `dump_dir`, and a separate `.json` or `.csv` manifest `output`.

A readable VMA does not guarantee its pages are resident in the captured image. If a range has missing pages, preserve the diagnostics and report the failed or partial export; do not substitute zero bytes or claim that the requested evidence was recovered.

- `mode: "range"`: supply `start` and `end` as decimal or `0x` **strings**. End is exclusive; the range must be at most 256 MiB.
- `mode: "process"`: export readable mappings of that PID; optional bounds must be supplied together.
- `mode: "elf"`: export mappings starting with an ELF header; omit bounds. This does not reconstruct an original on-disk executable.

Use a PID established by the user's request or by analysis within the authorized scope; do not invent a target or default to all processes. Read `complete` and `diagnostics`, and verify manifest sizes and SHA256 values against the exported files. Repeated dumps create separate evidence destinations; they do not overwrite previous binaries.

Use `zero_cache_list` for cache inspection. Cache clearing is CLI-only: preview with `zero cache clear --dry-run`; execute only within the user's requested scope.

For tested MCP arguments and equivalent CLI commands, read [references/calls.md](references/calls.md). The analysis engine reads images locally and never executes ISF files. Do not upload memory images or send recovered contents to external services without explicit authorization.
