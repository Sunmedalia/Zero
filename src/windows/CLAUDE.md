# Windows analysis

Loaded when working under `src/windows/`; the root `CLAUDE.md` rules still apply.

- Entry points: `analyze.rs`; plugin routing is the exhaustive `match` in `Windows::run` (`src/windows.rs`); a new `Plugin` variant must be routed or explicitly rejected there. `analyze.rs` pre-dispatches dumps and plugins that may download symbols (cache/network). `discovery.rs` finds kernel roots; `address_space.rs` does translation.
- Symbols come from `src/windows_symbols.rs` (exact RSDS GUID/Age, Microsoft PDB download, deterministic native conversion) and `src/windows_symbols_archive.rs` (bounded HTTPS range reads of the official Volatility ZIP directory and the exact `<pdb name>/<guid>-<age>` ISF entry). The archive is reached only when a Microsoft PDB fetch fails with a typed `HttpError` 404 (`symbols::is_not_found`); timeouts and other errors must not fall back.
- Version-dependent layouts are data: `network_layouts.json`, `legacy_network_layouts.json`, `callback_layouts.json`. Select them by symbols, architecture and driver version, never by guessing.
- `compatibility.json` is the per-target/architecture coverage manifest (`real` / `synthetic` / `pending` / `unsupported`). Every Windows plugin needs a cell in every target × architecture; `real` needs matching evidence, both enforced by a unit test in `compatibility.rs`. `docs/compatibility.md` is rendered from it by `scripts/windows_compatibility.py`.
- `malware.rs`: PEB/VAD loader cross-views, hollowing leads and active thread start checks. These are leads to review, not verdicts, and incomplete views never prove absence.
- `hiber.rs` / `paging.rs` / `compressed.rs`: bounded saved-page containers, explicit paging-file attachments and symbol-driven SMKM reconstruction. Preserve coverage diagnostics; some paths only have synthetic validation.
- Process / range / PE dumps go through atomic publishing (see `src/dump.rs`).
