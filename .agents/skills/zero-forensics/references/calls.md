# Calls and CLI equivalents

Replace all paths and targets with the user's assets. CLI examples assume execution from the project root. File exports may overwrite an existing manifest; choose an appropriate destination.

## Offline analysis and full export

MCP `zero_analyze` arguments:

```json
{
  "image": "/evidence/memory.raw",
  "symbols": "/evidence/kernel.json.xz",
  "plugin": "pslist",
  "offline": true,
  "limit": 50,
  "output": "exports/processes.json"
}
```

```sh
zero --offline analyze --image /evidence/memory.raw \
  --symbols /evidence/kernel.json.xz --plugin pslist \
  --output exports/processes.json
```

For an ambiguous ISF, repeat with the exact returned label in MCP `symbol_choice` or CLI `--symbol-choice`. MCP `no_cache: true` and CLI `--no-cache` bypass successful analysis result caches.

For offline kernel identification, use the same analysis entry point with `plugin: "banners"`, omitting symbols. CLI still requires an output path.

## Snapshot pagination

`zero_analyze` returns `result_id`; it no longer accepts `offset`, even zero.
Call `zero_results` using that ID and `next_offset` from the previous page:

```json
{"result_id":"COPY_RETURNED_ID","offset":50,"limit":50}
```

Pass `output` to `zero_results` to export the entire snapshot. Snapshot pages preserve partial-result diagnostics without rerunning analysis. IDs expire after 30 idle minutes by default, on eviction (8 snapshots by default), or on server restart. Rerun analysis when an ID expires. `no_cache` only bypasses successful analysis caches, not snapshot creation.

While an analysis is active, another analysis/dump/symbol request returns busy (`-32000`); retry after completion. Cancel the active request with `notifications/cancelled` and `params.requestId`. Wait for its response before starting another job.

## Exact repository matches

```json
{"image":"/evidence/memory.raw","offline":false,"download":false}
```

Pass these arguments to `zero_symbols`. Set `download: true` only when fetching symbols is desired. Microsoft PDB HTTP 404 automatically invokes the official Volatility Windows ZIP fallback using HTTPS ranges and exact ISF metadata checks; successful fallback ISFs are cached for offline reuse. Timeout/503 errors do not invoke this fallback. An empty `matches` array means the index has no exact match; do not substitute a similar kernel.

```sh
zero symbols --image /evidence/memory.raw --output exports/symbol-matches.json
# To fetch verified exact matches:
zero symbols --image /evidence/memory.raw --download
```

Offline `zero_symbols` needs a cached repository index. If it reports that the index is missing, continue offline banner identification through `zero_analyze` with `plugin: "banners"`; use a local ISF if available.

## Targeted address range

MCP `zero_dump` arguments:

```json
{
  "image": "/evidence/memory.raw",
  "symbols": "/evidence/kernel.json.xz",
  "offline": true,
  "mode": "range",
  "pid": 123,
  "start": "0x400000",
  "end": "0x401000",
  "dump_dir": "exports/pid-123",
  "output": "exports/pid-123-manifest.json"
}
```

```sh
zero --offline dump --image /evidence/memory.raw \
  --symbols /evidence/kernel.json.xz --mode range --pid 123 \
  --start 0x400000 --end 0x401000 \
  --dump-dir exports/pid-123 --output exports/pid-123-manifest.json
```

MCP dump responses show at most 200 manifest rows. Inspect `output` for the full manifest if `next_offset` is non-null; `zero_dump` does not accept pagination parameters.

## Errors and recovery

- Keep arguments within the advertised schema; misspelled fields are rejected.
- Wrong symbols or unavailable pages require corrected inputs or reporting a partial analysis, not fabricated results.
- On a missing image, incorrect path or invalid dump range, correct the named input before retrying.
- A tool error should not break the MCP connection; continue with a corrected call.
- If configured MCP tools are absent, use the CLI for the authorized operation and inspect the MCP configuration. Reopening the client session may be necessary to load a changed server configuration.
