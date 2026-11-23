# Windows analysis

Loaded when working under `src/windows/`; the root `CLAUDE.md` rules still apply.

- Entry points: `analyze.rs`; plugin routing is the non-exhaustive `Windows::run` in `src/windows.rs`, so check it when adding a plugin. `discovery.rs` finds kernel roots; `address_space.rs` does translation.
- Symbols come from `src/windows_symbols.rs` (exact RSDS GUID/Age, Microsoft PDB download, deterministic native conversion) and `src/windows_symbols_archive.rs` (bounded HTTPS range reads of the official Volatility ZIP directory and the exact ISF entry, only after a Microsoft 404).
- Version-dependent layouts are data: `network_layouts.json`, `legacy_network_layouts.json`, `callback_layouts.json`. Select them by symbols, architecture and driver version, never by guessing.
- `compatibility.json` is the per-target/architecture coverage manifest (`real` / `synthetic` / `pending` / `unsupported`); `docs/compatibility.md` is rendered from it by `scripts/windows_compatibility.py`. Only mark `real` with real-sample evidence.
- `malware.rs`: PEB/VAD loader cross-views, hollowing leads and active thread start checks. These are leads to review, not verdicts, and incomplete views never prove absence.
- `hiber.rs` / `paging.rs` / `compressed.rs`: bounded saved-page containers, explicit paging-file attachments and symbol-driven SMKM reconstruction. Preserve coverage diagnostics; some paths only have synthetic validation.
- Process / range / PE dumps go through atomic publishing (see `src/dump.rs`).
