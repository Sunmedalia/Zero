# Windows Forensics Coverage and Evidence Rules

Consult `src/windows/compatibility.json` (rendered in `docs/compatibility.md`) for per-plugin, per-target verification status (`real`, `synthetic`, `pending`, `unsupported`). Do not claim complete Server 2003–2025 or Windows 7–11 coverage; zero-row scans and synthetic pointer-width tests do not establish real recovery coverage.

## Architecture and Container Support

- **Architecture selection**: `arch: "auto"|"x86"|"x64"|"arm64"` (CLI `--arch`). Exact symbols must match container pointer width and PDB machine type; mismatches fail explicitly.
- **Real-image validation**:
  - RAW: Server 2003 SP0 / 2008 SP1 x86; Server 2012 / 2012 R2 x64; Windows 7 SP1 / 10 (15063) / 11 (22000) x64.
  - Bitmap crash dumps (FDMP): Windows 10 build 19041, Server 2019 build 17763, Server 2022 build 20348.
  - User minidump (MDMP): Windows XP x86 (`rust-minidump` fixture).
  - Kernel triage dump: Server 2016 build 14393 (saved faults/context/modules only; publisher-reported product identity, header-verified build, `ProductType` unavailable—do not imply full Server 2016 kernel coverage).
  - Other architectures/containers primarily have synthetic validation. Server 2003/R2 identity may remain ambiguous; Server 2003 R2, 2008 R2, and 2025 still need separately verified samples.
- **Container boundaries**:
  - **User minidumps**: Expose captured-process metadata, DLLs, and targeted dumps when PID is recorded; kernel plugins are unavailable.
  - **Summary kernel dumps**: Header metadata only.
  - **Triage dumps**: Expose saved faults/contexts (`windows.crashinfo`, no kernel symbols needed), saved driver records (`windows.modules`), and captured kernel virtual ranges (`zero_dump` `mode: "range"`, `pid: 0`). Identical duplicated triage ranges are verified byte-for-byte; differing bytes fail.

## Paging, Compressed Store, and Hibernation

- **External paging attachments**: Pass explicit same-capture files only: `pagefiles: [{"index": 0, "path": "..."}]` and optional `swapfile: "..."`. Never guess a pagefile index or search adjacent files. Swapfile indexing requires exact kernel symbols. Paging results record file digests and page offsets.
- **Modern nonswizzled pagefile offsets**: Require exact `MiState.Hardware.InvalidPteMask` metadata; missing private metadata is not guessed.
- **Compressed store (SMKM)**: Requires private SMKM symbols/types and a verified virtual pagefile. Windows 10 x86/x64 and Windows 11 x64 builds 22000/22621/22631/26100 (26100 uses native LZ4) have synthetic store coverage; unknown builds and ARM64 stores are unsupported.
- **Hibernation**: Reads saved physical pages (Win7 range array and NT6.2+ restoration sets, XPRESS / XPRESS Huffman) and reports damaged/missing blocks. Fast Startup can omit user sessions. Both hibernation and compressed-store recovery carry synthetic-validation diagnostics and mark results partial.

## Artifact and Plugin Nuances

- **Timestamps & addresses**: `FILETIME` values are decimal 100 ns ticks since 1601 UTC. Always distinguish virtual addresses from `physical:` addresses.
- **WOW64**: `windows.cmdline`, `windows.dlllist`, and `windows.envars` include a `View` column (`native` / `wow64` / `minidump`).
- **Registry**: `windows.printkey` takes `hive` (from `windows.hivelist`) and hive-relative `key`. Segmented `db` values are bounded to 1 MiB. Registry-process hive mappings and prototype-to-pagefile recovery preserve source/coverage diagnostics.
- **Network**:
  - NT6+: Use `windows.netscan` or `windows.netstat.NetStat`. Prefers exact `tcpip.sys` PDB types, then architecture/driver-version layouts. Unvalidated exact driver identities stay partial; unknown layouts fail explicitly.
  - NT5 (Server 2003): Use `windows.connscan` / `windows.sockscan`. No cross-generation layout fallback.
  - Known sample caveat: Server 2012 R2 has two known missing UDP wildcard reference connections due to a non-canonical `LocalAddr` pointer; preserve the diagnostic and do not count them as equality evidence.
- **Services & consoles**: `windows.svcscan` (`pid` selects `services.exe` host), `windows.svcscan.SvcScan` (11-column reference contract), `windows.svclist.SvcList`, `windows.malware.svcdiff.SvcDiff`, `windows.cmdscan`, and `windows.consoles` require supported architecture/build/revision layouts and retain validation diagnostics; unknown versions fail explicitly. Console output covers title/history metadata, not screen text.
- **Persistence, integrity, and pool scans**:
  - `windows.autoruns` (optional `hive`) covers Run/RunOnce, Winlogon, IFEO, and current ControlSet services—not a complete persistence inventory.
  - `windows.callbacks` covers process, thread, image-load, and registry callbacks only.
  - `windows.drivercheck` dispatch targets outside the driver's module are observations, not maliciousness verdicts.
  - `windows.getsids` resolves built-in SID names only; `pid` filter supported.
  - Pool scans (`windows.psscan`, `windows.filescan`, `windows.mutantscan`, `windows.driverscan`, `windows.modscan`, `windows.poolscanner.PoolScanner`) return candidates with physical and verified virtual addresses (missing names remain partial); they are not proof of hidden objects.
- **Additional Windows families**: Credential extraction (`windows.hashdump`, `windows.lsadump`, `windows.cachedump`), integrity/malware (`windows.ldrmodules`, `windows.hollowprocesses`, `windows.suspicious_threads`, `windows.malware.pebmasquerade.PebMasquerade`, `windows.etwpatch`, `windows.orphan_kernel_threads`, `windows.processghosting`, `windows.debugregisters.DebugRegisters`, `windows.suspended_threads.SuspendedThreads`, `windows.malware.skeleton_key_check.Skeleton_Key_Check`, syscall checks), and timeline/filesystem (`windows.mftscan`, `windows.timeliner`, `windows.shimcachemem.ShimcacheMem`, `windows.registry.amcache.Amcache`, `windows.registry.userassist.UserAssist`). Call `zero_plugins` for exact names and columns.
