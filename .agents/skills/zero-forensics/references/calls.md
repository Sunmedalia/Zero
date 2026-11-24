# Calls, Parameters, and CLI Equivalents

Replace all paths and targets with the user's assets. CLI examples assume execution from the project root. Manifest `output` files may overwrite an existing manifest at the same path; binary dumps never overwrite prior evidence files.

## 1. Offline Analysis and Full Export

MCP `zero_analyze`:

```json
{
  "image": "/evidence/memory.raw",
  "symbols": "/evidence/kernel.json.xz",
  "plugin": "linux.pslist.PsList",
  "pids": [1, 123],
  "include_threads": false,
  "decorate_comm": false,
  "offline": true,
  "limit": 50,
  "output": "exports/processes.json"
}
```

CLI equivalent:

```sh
zero --offline analyze --image /evidence/memory.raw \
  --symbols /evidence/kernel.json.xz --plugin linux.pslist.PsList \
  --pids 1,123 --output exports/processes.json
```

- **Ambiguous ISF**: Repeat with the exact returned label in MCP `symbol_choice` or CLI `--symbol-choice`.
- **Bypass cache**: MCP `no_cache: true` or CLI `--no-cache` bypasses successful analysis caches (still creates an MCP snapshot).
- **Offline Linux banner identification**: Call `zero_analyze` with `plugin: "banners"`, omitting `symbols`. CLI still requires `--output`.
- **Inline binary export on listing plugins**: Pass `dump_dir` to `zero_analyze` (CLI `--dump-dir`) for `linux.proc.Maps`, `linux.malware.malfind.Malfind`, `linux.elfs.Elfs`, `lsmod`, `linux.graphics.fbdev.Fbdev`, or `windows.memmap.Memmap` (`windows.memmap.Memmap` also requires `pid`).

## 2. Snapshot Pagination and Concurrency

`zero_analyze` returns `result_id` and does **not** accept `offset` (even `0`). Page with `zero_results`:

```json
{"result_id": "COPY_RETURNED_ID", "offset": 50, "limit": 50}
```

- Pass `output` to `zero_results` to export the entire snapshot regardless of the current page.
- Snapshots preserve partial-result diagnostics without rerunning analysis.
- IDs expire after 30 idle minutes (default), on LRU eviction (8 snapshots default), or on server restart; rerun `zero_analyze` when expired.
- While an analysis, symbol, or dump job is active, another returns JSON-RPC `-32000` (busy); `ping` and `zero_results` remain available. Cancel with `notifications/cancelled` (`params.requestId`) and wait for its response before submitting a new job.

## 3. Symbol Identification, Generation, and Diagnostics

### Remote repository matching (`zero_symbols`)

```json
{"image": "/evidence/memory.raw", "offline": false, "download": false, "refresh": false}
```

```sh
zero symbols --image /evidence/memory.raw --output exports/symbol-matches.json
# Fetch verified exact matches (add --refresh to force online index update):
zero symbols --image /evidence/memory.raw --download
```

- `refresh: true` forces an online index update (rejected when `offline: true`).
- Windows Microsoft PDB HTTP 404 automatically invokes the official Volatility Windows ZIP fallback via bounded HTTPS ranges and exact ISF checks; successful fallback ISFs are cached for offline reuse. Timeout/503 errors do not invoke fallback.
- Empty `matches` means no exact match; never substitute a similar kernel.
- Offline `zero_symbols` requires a cached repository index; if missing, use `zero_analyze` with `plugin: "banners"`.

### Linux symbol generation (`zero_symbols_generate` & `zero_doctor`)

Check external build tools (`git`, `go`) before package-based generation:

```json
{}
```
*(call `zero_doctor`; CLI: `zero doctor`)*

Choose **exactly one** generation mode in `zero_symbols_generate`:

```json
// 1. Offline x86_64 generation from embedded BTF + kallsyms (no git/go or network needed):
{"image": "/evidence/memory.raw", "from_image": true, "offline": true}

// 2. Official Ubuntu / Debian / Kali debug package discovery:
{"image": "/evidence/memory.raw", "auto": true, "offline": false}
// If response has {"needs_candidate": true, "candidates": [...]}, retry with 1-based candidate and omit refresh:
{"image": "/evidence/memory.raw", "auto": true, "candidate": 1, "offline": false}

// 3. Local debug ELF + kernel config (uses server dwarf2json or ZERO_MCP_DWARF2JSON):
{"image": "/evidence/memory.raw", "elf": "/evidence/vmlinux", "config": "/evidence/kernel.config", "offline": true}
```

CLI equivalents:

```sh
zero --offline symbols-generate --image /evidence/memory.raw --from-image
zero symbols-generate --image /evidence/memory.raw --auto
zero symbols-generate --image /evidence/memory.raw --auto --candidate 1
zero --offline symbols-generate --image /evidence/memory.raw --elf /evidence/vmlinux --config /evidence/kernel.config --tool /path/to/dwarf2json
```

### Offline kernel validation (`zero_diagnose`)

```json
{
  "image": "/evidence/memory.raw",
  "symbols": "/evidence/kernel.json.xz",
  "os": "auto",
  "output": "exports/diagnosis.json"
}
```

```sh
zero diagnose --image /evidence/memory.raw --symbols /evidence/kernel.json.xz --output exports/diagnosis.json
```

## 4. Targeted Dumps (`zero_dump`)

MCP `zero_dump` (example: address range):

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

### Mode Parameter Rules

| `mode` | OS | `pid` | `start` / `end` | Notes |
| --- | --- | --- | --- | --- |
| `process` | Linux / Win | Required (>0) | Optional pair (`start` < `end`, ≤256 MiB) | Readable process mappings |
| `range` | Linux / Win | Required (>0; Win kernel uses `0`) | Required pair (`start` < `end`, ≤256 MiB) | End is exclusive; pass as decimal or `0x` strings |
| `elf` | Linux | Required (>0) | Forbidden | Mappings starting with `\x7fELF`; not on-disk reconstruction |
| `kernel-module` | Linux | Omit (`0`) | `start` required (`struct module`), `end` forbidden | Reconstructs Linux module ELF; padded ranges in metadata |
| `lsmod` | Linux | Omit (`0`) | Forbidden | Exports listed Linux module ELFs |
| `framebuffer` | Linux | Omit (`0`) | `start` optional (`fb_info`), `end` forbidden | Dumps fbdev buffers |
| `pe` | Windows | Required (>0) | Forbidden | Reconstructs Windows PE images |
| `vad` | Windows | Required (>0) | Optional pair (per-VAD intersection filter) | Exports process VADs |
| `dll` | Windows | Required (>0) | `start` optional (exact base), `end` forbidden | Reconstructs process DLLs |
| `module` | Windows | Omit (`0`) | `start` optional (exact base), `end` forbidden | Reconstructs kernel modules |
| `files` | Windows | Required (>0) | Forbidden | Resident cached files from handles/VADs |
| `memmap` | Windows | Required (>0) | Forbidden | Process physical pages (256 MiB cap) |

MCP `zero_dump` returns at most 200 manifest rows and does not accept pagination parameters; inspect `output` when `next_offset` is non-null.

## 5. Key Plugin-Specific Parameters (`zero_analyze`)

- **Linux process/memory/FS/network**:
  - `linux.pslist.PsList` / `linux.pstree.PsTree`: `pids`, `include_threads` (CLI `--threads`), `decorate_comm` (CLI `--decorate-comm`).
  - `linux.proc.Maps`: `pids`, `addresses` (string array, decimal or `0x`), `maxsize`, `dump_dir`.
  - `linux.malware.malfind.Malfind`: `pids`, `hexdump_size` (0–4096, default 64), `show_all_dirty_pages`, `maxsize`, `dump_dir`.
  - `linux.lsof.Lsof`: `pids`, `files_only`.
  - `linux.sockstat.Sockstat`: `pids`, `netns` (inode integer).
  - `linux.mountinfo.MountInfo`: `pids`, `mntns` (inode integer), `mount_format`.
  - `linux.pagecache.Files`: `file_types` (e.g. `["REG", "DIR"]`), `find` (path substring).
  - `linux.kallsyms.Kallsyms`: `core`, `modules`, `ftrace`, `bpf` (all omitted/false selects all).
  - `linux.malware.modxview.Modxview`: `plain_taints`.
  - `linux.pscallstack.PsCallStack`: `pids`, `unresolved`.
- **Windows registry, symbols, scanning, paging**:
  - `windows.printkey`: `hive` (address string from `windows.hivelist`), `key` (hive-relative path).
  - `windows.autoruns`: optional `hive`.
  - `windows.pe_symbols.PESymbols`: `source` (`"kernel"` | `"processes"`), `module` (filename), `symbol_names` (string array) or `addresses` (string array, decimal/`0x`, ≤4096 items; names take precedence).
  - `windows.strings.Strings`: `strings_file` (local decimal-offset file), optional `pids`.
  - `windows.truecrypt.Passphrase`: `min_length` (default 5).
  - `vmayarascan` / `windows.vadyarascan`: `pattern` (`text`, `wide:TEXT`, or `hex:4d5a??00`). `VmaRegExScan` / `VadRegExScan`: `pattern` (byte regex), `pids`, `maxsize`.
  - External paging (Windows `zero_analyze` / `zero_dump`): `pagefiles: [{"index": 0, "path": "/evidence/pagefile.sys"}]`, `swapfile: "/evidence/swapfile.sys"` (CLI `--pagefile 0=/evidence/pagefile.sys --swapfile ...`).

## 6. Errors and Recovery

- Keep arguments within the advertised schema; unknown fields are rejected (`deny_unknown_fields`).
- Do not fabricate results for wrong symbols or missing pages—correct inputs or report partial analysis with diagnostics.
- On missing image, bad path, or invalid dump range, fix the named parameter before retrying.
- A tool error does not break the MCP session; continue with a corrected call.
- If configured MCP tools are absent, fall back to the `zero` CLI and inspect `.mcp.json` or `.codex/config.toml` (reopening the client may be required to reload server config).
