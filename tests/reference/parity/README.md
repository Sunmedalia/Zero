# Volatility differential tests

This test-only harness pins official Volatility 3 **v2.28.2**, commit
`881e970121c16f0932fb9d16fbd5fb258cbcbf75`. Python and the reference framework
are development dependencies; neither is packaged or invoked by Zero's runtime.
Reference metadata and test wrappers in this directory are provided under the
[Volatility Software License 1.0](LICENSE); attribution belongs to the Volatility
Foundation and contributors. Runtime implementation is independently written Rust.

Run the small offline gates without downloading anything:

```sh
python3 -m unittest discover -s tests/reference/parity -p 'test_*.py'
python3 tests/reference/parity/audit.py
python3 tests/reference/parity/audit.py --require-complete
```

The last command intentionally fails while full parity remains unfinished.
`inventory.json` records 163 Linux/Windows class entries: 135 canonical plugins
(49 Linux, 86 Windows), plus 28 deprecated aliases. `zero_candidates` are possible
implementation correspondences, **not verified equivalence**. Static column
extraction can be incomplete for dynamically constructed TreeGrids; inspect the
pinned source before writing a mapping/contract. Requirements include dependency
expressions rather than resolving them into an executable environment.

Prepare the reference environment separately (requires network):

```sh
git clone --branch v2.28.2 --depth 1 https://github.com/volatilityfoundation/volatility3 target/reference/volatility3
python3 -m venv target/reference/venv
target/reference/venv/bin/python -m pip install -e target/reference/volatility3 pefile==2024.8.26
python3 tests/reference/parity/inventory.py --check
```

Additional reference dependencies are needed for plugins such as YARA; missing
imports/dependencies are failures, never passing comparisons. Do not run reference
plugins from an untrusted repository. Generation verifies the pinned commit;
the runner also rejects modifications to tracked reference source.

`debian.example.json` supplies relative local paths, public image URL and hashes.
Run it from the project root after preparing its files. The uncompressed image
SHA256 is checked independently of the download container. Download the matching
ISF from:

https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/Debian/amd64/3.2.0/4/Debian_3.2.0-4-amd64_3.2.57-3%2Bdeb7u2_amd64.json.xz

Keep the same verified ISF in the configured Zero file and in the reference
`target/reference/symbols/linux/` directory. The example specifies both file
hashes. Use an otherwise clean reference symbols directory. The runner verifies
listed files, not arbitrary additional files in that directory. For an explicit
JSON ISF input (including supported compressed JSON names), native98 also checks
the actual native result symbol file against the configured bytes; a different
cached fallback fails the case. Directory/archive selection is outside this
additional file guard.

```sh
python3 tests/reference/parity/run.py \
  --config tests/reference/parity/debian.example.json \
  --output target/reference/results/debian
```

Each engine runs offline with a timeout. Raw JSON, console/stderr logs, commands,
elapsed time, hashes, comparisons and the summary remain under the output path.
No image or recovered contents are uploaded. Large fixtures and raw outputs are
ignored by git; committed `evidence.json` contains counts, differences and hashes.
An example/sample run proves only those cases on that sample and symbol table.

Comparisons require nonempty positive evidence, all output columns, unique record
keys, exact normalized values and complete native results by default. Missing,
extra, duplicate, conflicting and unavailable fields fail separately. Empty results
and partial results require explicit per-mapping allowances and still cannot count
as positive full-plugin evidence. Canonical address sign extension is explicit;
addresses are never blindly masked to 48 bits. Timestamps retain microseconds.

`audit.py` distinguishes passing cases from verified plugins. A plugin requires
an explicitly reviewed contract in `contracts.json` covering parameters, output
and failure behavior against its source hash, plus passing evidence for **every**
required case. This file is currently empty: `PsList --dump`, multiple PID
selection and broader kernel/platform cases remain unfinished, so five passing
PsList cases do not count as complete plugin parity. Aliases do not inflate the
canonical count. `make check` validates the offline tooling, not full parity.

ProcessSpoofing cases use `spoofing.example.json` and the same public Debian sample.
Its mapping explicitly allows partial native output: the sample has missing argv
pages, rendered as `N/A` by the reference. Zero preserves the matching values and
also reports the missing pages. This case parity does not certify the plugin's
multi-PID interface or its behavior on other kernels and attack samples.

Modxview cases use `modxview.example.json`: both default and `--plain-taints`
compare all six fields over 79 Debian modules. `Taints` alone declares reference
`empty_text` normalization: the reference null here means no taint characters,
which Zero renders as empty text. Ordinary text nulls remain unverifiable.
These cases require complete native output. Synthetic coverage of hidden modules
and damaged views is not real-sample proof of those behaviors.

ModuleExtract cases use `module-extract.example.json`. With `artifact_dump: true`,
the runner creates fresh `zero-files` / `reference-files` directories, compares
all output files by relative filename, nonzero length and SHA256, and records
those hashes along with the full-field comparison. Reusing an existing case's
binary directories is refused. The audit requires matching binary evidence for
ModuleExtract; matching filenames and reported lengths alone cannot pass.
The mapping allows partial native output because the public sample requires
explicitly recorded zero padding to reproduce the reference reconstruction.
Original samples remain read-only, and no recovered binaries enter this repository.

Kallsyms cases use `kallsyms.example.json` and compare all eight fields for default,
core, modules and core+modules. `allow_absent` is declared only for Size/Exported:
both absent values are counted under `matched_absent`; one-sided absence still
fails. Counts contain no recovered symbol names. The cases require complete
native output and do not establish positive ftrace/BPF behavior on this sample.

PsScan cases use `psscan.example.json` and compare all six fields, keyed by physical
object address (not PID). The case requires complete native output. Physical
addresses use ordinary address normalization without virtual sign extension.
The native scan reports captured-segment coverage and candidate/parent read errors;
parent fallback to PPID 0 does not silently certify absence. This default Debian
case does not certify 32-bit support, all kernel versions or damaged captures.

Sockscan cases use `sockscan.example.json`. The unfiltered default case deliberately
retains the pinned reference's duplicate Unix row and physical/virtual IPv6 read
issues; it currently fails full comparison. Its failure is not converted to a pass.
The separate IPv4/Netlink mapping declares `record_selection` on Family, includes
only AF_INET/AF_NETLINK, and reports excluded row counts for both original outputs.
All ten fields and unique physical addresses within that scope must match. Raw
outputs remain unchanged. The scoped mapping permits explicit native partial
candidate-read diagnostics. This proves only those families on this capture.

`na_text` is a per-field opt-in normalization of the native N/A marker to absence;
empty text stays empty. `allow_absent` is still separately required for two absent
values to match. Default text comparisons keep the literal N/A. One-sided absence
still fails. Scoped cases are counted separately by the audit, and scoped evidence
alone cannot satisfy a whole-plugin contract. Running the combined Sockscan config
returns nonzero while the default case remains divergent; inspect both case records.

VmaRegExScan cases use `vmaregexscan.example.json`: literal, lookbehind, named
backreference, multi-PID, all-process and single/list PID union searches compare all five fields. Both
text and the full spaced-hex byte output must match. Keys include PID and virtual
Offset. The mapping permits native partial output because absent user pages are
reported rather than silently skipped; this does not certify complete coverage.
The separate `vmaregexscan-maxsize.example.json` exercises the pinned reference's
unused maxsize option. Starting with native98, canonical Zero also reads a fixed
128-byte display context regardless of that argument; earlier native36/native96
failures remain historical evidence. Raw matched bytes remain in ignored artifacts.

PsCallStack uses `pscallstack.example.json`. Unfiltered PID 1, unresolved PID 1 and
all-task cases retain known differences in the pinned reference's module symbol
lookup. Its module-boundary expression parses as value & (mask + size), instead
of (value & mask) + size. Native looks up captured positive-size ELF intervals;
this does not turn stack candidates into proven return addresses. The raw default
cases remain failed. Kthreadd (with/without unresolved), a seven-task thread group,
and PID union cases compare all eight fields without record selection. The
separate core-row case explicitly selects Module=kernel and reports excluded
counts, preserving all original artifacts. This scoped case alone certifies no
whole-plugin behavior. The combined config returns nonzero for known differences.
`address48` restores the reference's masked address/Value display for x86 cases;
optional Name/Type/Module absence is declared explicitly, never filled with false.

### Fbdev

`fbdev.example.json` preserves both attempted real samples, including failures:
Debian has zero registered framebuffers (no positive evidence); the local original
Kali ARM64 image produces a native framebuffer/PNG, but the pinned reference only
supports Intel Linux layers and fails after stacking it as LinuxIntel. The combined
configuration intentionally exits nonzero. `fbdev-known-limitations.json` stores
hashes/counts/reasons, never recovered framebuffer pixels. No Fbdev real-image case
is added to passed evidence yet. The Kali source is a local original fixture, not
a publicly downloadable sample; both symbol paths must contain the exact declared bytes.

A separate generated-data conversion-function check uses Python 3.13, Pillow 10.4.0
(within the pinned framework's declared dependency range), and pefile 2024.8.26 in a
test-only environment. It does not run on recovered desktop pixels:

```sh
ZERO_REFERENCE_PYTHON=target/reference/venv-fbdev-py313/bin/python \
  cargo test --lib native_pixels_and_raw_match_reference -- --ignored --nocapture
```

It compares every decoded RGBA byte (not PNG compression bytes) for contiguous
RGB565, RGBA8, 64-bit channels, and every RAW byte for FOURCC. The padded RGB565
case explicitly asserts a difference: Zero respects line_length; the reference
consumes pixels consecutively across row padding. `fbdev-pixel-evidence.json` keeps
those synthetic hashes and the known divergence, separately from whole-plugin
real-image evidence. Runtime Zero has no Python/Pillow dependency.

### Windows VadRegExScan

`vadregexscan.example.json` compares all five columns on the public OSForensics
Windows 10 15063 image, including standalone PID controls for the multi-PID cases.
The exact PDB identity is 0C9CC659210046EC84231597DADFDB3B1. Both engines use the same
native PDB-derived ISF; these tests do not independently validate type conversion.
Both engines now read the same frozen converter8 ISF named by the configuration;
the runner and evidence archive verify the actual native symbol file too.

Native99 passes all nine main cases and four maxsize cases, including PID 7688's
701 rows, the 727-row PID union and PID 468's 27 rows. Native39/native98's extra
prototype-backed hits remain in historical reports. Canonical regex scanning now
reads through the pinned Intel layer policy before searching and displaying:
resident/transition pages and explicit swap layers, without native prototype or
compressed-store reconstruction. No result rows are filtered after matching.
The general native recovery reader remains available to other consumers. These
bounded cases do not establish every plugin/platform contract or complete capture.

`vadregexscan-maxsize.example.json` exercises the pinned generator's unused
maxsize parameter; display context stays 128 bytes. `windows_layer_read_vectors.py`
adds actual x86/PAE/x64 layer reads over complete synthetic table bytes and explicit
swap buffers. The 57 cases include 570 reads: fixed swap flags/indices, unaligned
and crossing reads, large PAT, prototypes, transition, missing attachments,
short/empty backing files and capture holes. Native ordinary attachments now
accept partial tails and validate each read's bounds and file identity.

The latest proof is `windows-layer-read-known-limitations.json`. Older difference
files preserve historical counts/hashes with a superseding link. Native coverage
and damaged-tree warnings remain explicit; zero-table skip hints never certify
readability. The ARM64 path retains native recovery and has no pinned Windows
ARM64 reference parity evidence. Synthetic read results do not establish all
scanner mappings, chunk boundaries, padding, exception text or resource behavior.

### Windows VadWalk

`vadwalk.example.json` compares all nine columns, with no record selection, on
Windows 10 15063 x64, Windows 11 22000 x64 and Server 2008 6001 x86. It includes
all-process runs on each sample plus Windows 10 single-PID, PID-list and union
controls. The seven cases have matching positive row counts: 16165, 596, 159,
755, 755, 5229 and 17405. Server 2008 is complete; Windows 10/11 retain explicit
partial diagnostics. Matching rows do not prove complete capture or absence of
objects outside reachable, tagged VAD trees.

All symbol files are exact native PDB-derived ISFs shared by the two extractors;
their hashes are pinned and must be copied unchanged to the declared reference
symbol directories. This is not independent layout/conversion validation. Parent,
Left, Right and Offset explicitly normalize reference masked 48-bit addresses;
Start and inclusive End are compared strictly. Unavailable native links are not
normalized to zero or accepted as a positive match.

The shared walker regression retains the prior Windows regex outcome: PID 468
passes 27 positive rows; PID 7688 still fails with eight native prototype-backed
extras and no missing reference rows/common-field conflicts. Counts and output
hashes are saved in `vadwalk-regex-regression.json`. Source samples, symbols,
recovered rows and binary evidence are never committed.

`kpcrs.example.json` compares both fields on Win10 15063 x64 and Win11 22000 x64
with the same exact native PDB-derived ISF on both sides. Each has four matching
records. The native converter includes the Windows ABI `unsigned int` primitive
name required by the reference plugin; no global-variable type is fabricated.
Server 2008 6001 x86 is deliberately retained as a failing reference case:
the pinned plugin reads the legacy byte count as four bytes and uses the pointer
`Prcb` offset instead of embedded `PrcbData`. `probes/processor_probe.py` is a
development-only Volatility diagnostic plugin (load with `-p` pointing at the
`probes` directory and run `processor_probe.ProcessorProbe`). It records only the
count and symbol-layout evidence; it does not patch the reference plugin.
`kpcrs-known-differences.json` stores counts/hashes and also records the remaining
partial timer/DPC analysis. Neither failure is added as passing parity evidence.

### Windows DriverIrp

`driverirp.example.json` includes three unfiltered default comparisons and three
explicit `record_selection` cases for the `ntoskrnl` module. The latter compare
all six columns: 2066 rows on Win10 15063 x64, 1723 on Server 2008 6001 x86 and
1656 on Win11 22000 x64. Both engines use the same exact native PDB-derived ISF
(pdb-native-8); this does not independently validate conversion. The converter
now declares the standard Windows C ABI char/short/int/long/long-long names,
including LLP64 four-byte long. Global variable types remain source-derived.

The full configuration deliberately remains failing. Default native row counts
are 4255 / 3724 / 3444; reference counts are 4255 / 3724 / 3453. Unique projections
of Offset, Driver Name, IRP, Address and Module agree on all three samples. The
reference applies the kernel ISF to external modules and emits 250 / 96 / 158
external symbol rows; native external symbols remain unavailable. Nine additional
reference Win11 rows are extra aliases for the same handlers. Projection equality
and matching totals do not replace six-field/multiplicity verification. The full
failures, source/output hashes and limits are saved in
`driverirp-known-differences.json`; only the explicitly scoped successful cases
enter `evidence.json`. Full plugin contracts remain unverified.

The shared physical reader preserves pre-Win10 pool bodies even without a virtual
body mapping. Protected Dri-f6 tags alone add DRIVER_EXTENSION in legacy bottom-up
carving. Modern scans retain virtual aliases, with memoized relative subtree
mappings instead of skipping a previously seen table or expanding aliases without
bounds. Name/path faults retain readable module ranges with partial diagnostics.
Modules counts therefore rise from 183 to 191 on Win10 and 105 to 149 on Server
2008. Readable handler slots survive later missing pages. Module intervals are
half-open and malformed optional padding is rejected. ARM64 is unsupported and
exact external driver PDB resolution remains outstanding.

Native44 external-module symbols are recorded separately in
`module-symbols-known-differences.json`. The Win10 exact MUP PDB acquisition,
native conversion and subsequent offline lookup produce 28 named external IRP
rows; `public_win10_exact_driver_symbols` checks every address against that
exact converted ISF. Prepare the exact PDB/ISF stated in the evidence before
running this opt-in test. It performs no downloads. The three existing
kernel-scoped DriverIrp cases were rerun, and all full default comparisons still
fail. These reruns do not increase the positive-case count. Missing external
PDBs now generate partial diagnostics; DriverIrp result caching is disabled until
its keys include external symbol dependencies. The original native43 evidence
and mapping scope descriptions remain historical records of that earlier run.

Native45 restores dependency-validated DriverIrp result caching. The exact local
ISF/PDB presence, streaming SHA256, metadata stamps, converter version and network
policy are checked before reuse and storage. Unresolved online acquisitions retry;
offline negative dependencies may use only the separate partial cache. Resource
changes invalidate both positive and negative entries. No download occurs while
validating cache dependencies.

`module-cache-known-differences.json` records both x64 Win10 and x86 Server 2008
five-phase actual-image runs. Prepare both exact original PDBs and ISFs listed
in that evidence, then run `cargo test --locked --release --test
windows_acceptance exact_driver_symbols -- --ignored`. The final phase restores
only the original PDB and verifies offline conversion, pinned ISF hash, symbol
lookup and negative-cache invalidation. Optional `ZERO_DRIVER_SYMBOL_EVIDENCE_DIR`
saves raw phase artifacts under an ignored directory. These tests do not download.
The handler-address oracle is the native-converted exact ISF, not independent
validation of every PDB record. Full default differential failures are preserved;
scoped reruns do not increase the 42 positive-case count or full-contract count.

Native46 adds `windows.malware.drivermodule.DriverModule`.
`drivermodule.example.json` checks all five columns on Win10 x64, Server 2008 x86
and Win11 x64. Visible record counts are 3 / 2 / 1; partial output is explicitly
allowed and does not establish complete recovery. Native driver starts use
half-open module intervals and reject overflow. Reference inclusive-end behavior
is intentionally not reproduced; synthetic tests exercise this boundary. Missing
module/name/range data remains diagnostic, and ARM64 is rejected. The six
synthetic tests plus actual differential cases are still insufficient to establish
a whole-plugin contract, including malicious hidden-driver and damaged-input
coverage. No recovered row values are stored in committed evidence.

Native47 adds `windows.registry.hivescan.HiveScan` (alias `windows.hivescan`).
`hivescan.example.json` checks its single Offset column on Win10 x64, Server 2008
x86, Win11 x64 and Win7 x64: 22 / 17 / 38 / 16 candidates, respectively. Modern
x64 uses allocated CM10 big-pool entries; older builds use paged/free small-pool
headers with total size >= 800. Win10 x86 retains verified virtual aliases.
The reference imposes neither header-address alignment nor CMHIVE signature
validation: four Win7 candidates are incidental CM10 text. These are candidate
positions, not proof of live hives. No extra filtering hides reference records.
Missing mappings/pages and invalid layouts remain diagnostic; ARM64 and the
reference's static big-pool layout fallback remain unsupported here. The shared
BigPools iterator reads the count as ULONG and retries entries around missing
pages. Native46/native47 Win10 and Win11 BigPools rows match exactly (30323 / 8442).
See `hivescan-known-limitations.json` for hashes and bounded evidence. These four
positive cases raise the count to 49 (5 scoped), not whole-plugin certification.

Native48 adds `windows.malware.pebmasquerade.PebMasquerade` (alias
`windows.pebmasquerade`), including PID union/deduplication and six output fields.
`pebmasquerade.example.json` retains four default cases and three explicit Win10
PID invocations. Win10 / Server2008 x86 / Win7 default cases match 139 / 48 / 53
records. Win11 remains a failed default comparison: 102 native versus 103 reference
records, with one invalid reference PID above u32 from the damaged process list.
It is never silently filtered or accepted. Native keeps the invalid-object diagnostic.
The pinned generator swaps ImagePathName/CommandLine flags relative to its column
labels; the reviewed mapping explicitly swaps the reference fields, while native
labels name the descriptor actually checked. Optional paths absent on both sides
are counted as matched_absent, not recovered data; one-sided absence still fails.
All real results remain partial. The scalar-based UTF-16 length test is a heuristic,
not a malware verdict, and missing PEB input does not prove a clean process.
Six new unit tests cover independent flags, capacity inconsistencies, replacement
UTF-16/NUL decoding, null pointers, missing fields, PID unions and cancellation.
See `pebmasquerade-known-differences.json` for hashes, coverage and negative evidence.

Native50 adds `windows.svclist.SvcList` (alias `windows.svclist`) for explicitly
mapped Win10 15063+ x64 builds. `svclist.example.json` compares every record and
all eleven columns on Win10 15063 and Win11 22000. Counts are 575 / 636. Both
remain partial with explicit process-list, VAD, registry-sibling and missing-page
diagnostics; equality of visible output does not establish complete recovery.

The pinned renderer reports the first record VA, then each preceding record's
`PrevEntry` pointer-storage VA in its Offset column. Native preserves that output
contract explicitly; diagnostics still identify actual dereferenced record VAs.
Registry path components use case-insensitive lookup, while `Parameters`,
`ImagePath` and `ServiceDll` use the reference service plugin's exact-name checks.
Unreadable unrelated siblings are diagnosed and skipped rather than hiding a
readable target. A missing/invalid regf base block permits validation of the first
HBIN cell at 0x20, with partial diagnostics. Cell allocation/signature, bounds and
ambiguity checks remain enforced. Optional unavailable fields on both sides are
recorded as matched absence; one-sided absence still fails.

Nine service tests and an extended registry fixture cover all eleven fields,
running processes/drivers/stopped records, Order zero/bounds, type flags, pointer
storage offsets, duplicate/aligned/range-limited headers, cycles, missing pages,
independent field faults, strict registry decoding, cancellation, unsupported
builds/PID filters, corrupt siblings and case-sensitive service lookups.
`svclist-known-limitations.json` retains final hashes and failed development-run
counts. Two default positive cases do not establish a complete plugin contract.


Native51 adds the separate canonical `windows.svcscan.SvcScan` eleven-column
entry and `windows.malware.svcdiff.SvcDiff` (`windows.svcdiff`). The existing
`windows.svcscan` eight-column output remains a separate legacy contract.
`svcscan.example.json` compares all VADs in services.exe on Win10 15063 x64,
Win11 22000 x64, Win7 7601 x64 and Server2008 6001 x86. The expected full
record counts are 1247, 1462, 863 and 728, respectively. Registry value
lookup reads names before data, skips invalid sibling value nodes with partial
diagnostics, and preserves exact-case ImagePath/Parameters/ServiceDll checks.

The reference tuple deduplication depends on absent-value object identity:
PID/name/display/binary absences are fresh on each visit; registry absences are
shared when the name exists in the prebuilt map. Thus visually identical rows
can legitimately recur. The `duplicate_keys: "multiset"` mapping explicitly
compares every occurrence of all eleven normalized fields and exact counts per
Offset; differing multiplicity, fields or one-sided absence still fail. The
default comparator continues to reject duplicates. No scope filtering is used.

`svcdiff.example.json` compares the two modern samples by case-sensitive service
name, retaining the last scanned row per name. Both produce zero differences;
this is negative evidence only, kept outside positive `evidence.json`. Partial
scan/list diagnostics and coverage remain attached; an empty result does not
prove absence of hidden services. Real positive hidden-service validation and
whole-plugin contracts remain outstanding.

`svcscan-nt5.example.json` preserves the Server2003 3790 x86 attempt. Native
returns 230 records using direct sErv tags; pinned Volatility rejects this build
with NotImplementedError, so that run must fail differential acceptance. It is
kept separate from the four comparable cases and remains native-only evidence.
`service-scan-known-limitations.json` records final and development-run metadata,
the two SvcList reruns, and the explicitly unsupported reference case.

Native52 adds canonical `windows.memmap.Memmap` (`windows.memmap`) with all five
reference columns. It walks Intel page tables independently of VADs, retaining
present and transition entries, x86/PAE/x64 geometry, large-page PAT handling,
raw lower-48-bit x64 virtual addresses, the reference 45-bit x64 PFN projection,
and the final-byte exclusion caused by the reference maximum-address range.
Only ranges contiguous in both virtual and backing-file addresses are merged;
physical and explicit pagefile layers never merge with one another. Unreadable
or uniform tables, unavailable captured spans and resource bounds retain partial
diagnostics. No global visited-table set discards legitimate aliases.

`memmap.example.json` compares PID 4 on Win10 15063 x64 (131493 rows), Win11
22000 x64 (63692), Win7 7601 x64 (34991), and Server2008 6001 x86 PAE (15297).
Every row and all five fields match. `memmap-dump.example.json` also compares
fresh targeted `pid.4.dmp` files on Server2008 and Win7: 119320576 and 223760384
bytes, respectively, with exact SHA256 agreement. Dump cases require binary
artifact proof in the audit, in addition to field equality. These six positive
cases raise the total to 67 (5 record-scoped cases), not full-plugin certification.

Exports require a single nonzero PID and enforce the repository's 256 MiB
limit; the reference's unrestricted all-process export is not implemented.
Listing defaults to all active processes, with a one-million-row total bound;
per-process traversal also bounds table reads and interval counts. Exports
bypass both result-cache reads and writes, record SHA256 and size, and commit
atomically. Fixture `row_options` explicitly records the PID used for row
baselines. Real default/all-process, non-PAE x86 and attached-pagefile parity
remain outstanding; the latter two have synthetic tests. ARM64 is unsupported.
See `memmap-known-limitations.json` for final executable/output hashes, binary
artifact evidence, coverage diagnostics and development findings. No recovered
memory bytes are committed.

## Canonical UserAssist and NT5 Memmap (native53)

`userassist.example.json` compares all twelve columns from
`windows.registry.userassist.UserAssist`, including parent keys, direct subkeys,
value names and exact raw bytes. The legacy seven-column entry remains separate.
The mapping groups records by hive/path/type and compares the complete multiset:
parent Key rows have no Name, so Name cannot be a mandatory identity field.
Missing names or fields are accepted only when explicitly absent on both sides;
no rows are selected out of these cases.

Five default cases cover Win10 15063 x64 (83 rows), Server2008 6001 x86 (51),
Win11 22000 x64 (58), Win7 7601 x64 (60), and Server2003 3790 x86 (11).
Four explicit `--hive`/reference `--offset` cases cover the first four images.
Modern record layout follows the exact ISF's CookiePad field. XP counts below
five are preserved; larger counts subtract five. Short values remain raw-only.
FILETIME output truncates to whole seconds; focus duration includes 500 ms.
The known-folder display table retains its upstream data attribution and license.

Registry reads use the validated Registry process address space when available.
When BaseBlock is absent or lacks a valid regf signature, the conventional root
at cell 0x20 is usable only after independently reading and validating its nk
cell. Unreadable siblings do not hide a readable named path: their diagnostics
remain in partial results. Invalid value-cell references are diagnosed and
excluded before interpreting a value; unreadable data in a valid value stays
absent, never zero-filled. Explicit hive selection verifies HHIVE.Signature and
does not require the address to remain in the loaded-hive list.

`memmap-nt5.example.json` adds Server2003 x86 non-PAE PID 4 listing and dump
comparisons: 8,044 mappings and 138,715,136 exported bytes, with matching SHA256
`3ec790561ace3d27295742907301ab7d8b68d5aa2b5d6ae2744d5dca99c4e79a`.
These are bounded real-image cases; neither plugin has a complete contract.
UserAssist boundaries and reproducible hashes are recorded in
`userassist-known-limitations.json`.

The runner pins the native executable hash before starting and rejects a batch
if it changes during native or reference execution. Do not rebuild the executable
while recording evidence; a mixed-build batch must be rerun in full.

Final native53 verification: `make check` passed 568 Rust and 25 Python tests;
Linux real regressions passed 4/4 and available Windows regressions 13/13.
Server2012R2 remains excluded because the original sample is unavailable locally.
The eleven new positive cases raise the total to 78 across 20 plugins (five cases
remain explicitly record-scoped). There are 117/135 candidate correspondences,
18 missing canonical entries, and zero complete plugin contracts. Final native
executable SHA256 is
`cab7ad951d29f5f44a44f12589865ddf5b191b9ba207155e79f6f0d844110316`.

### Amcache standard records (native54)

`amcache.example.json` compares the canonical eleven-column
`windows.registry.amcache.Amcache` output. The legacy six-column entry stays
separate. The mapping compares every record and its multiplicity, including
all absent fields, without selecting recovered rows. Drivers, legacy programs
and volume-nested files, and modern application/file inventory are parsed in
native Rust. Program grouping retains dictionary insertion/last-value semantics;
the native flat table does not reproduce TreeGrid indentation.

Pinned v2.28.2's string date helper requires both integer and string types and
therefore never returns a date. Modern InstallDate/LinkDate remain absent in
this standard output. This is a documented reference limitation, not evidence
of recovered times. The legacy entry retains raw LinkDate text.

`amcache-negative.example.json` records absent-hive observations separately.
The comparator intentionally refuses zero-row comparisons as positive parity;
its failed positive-evidence gate on these cases is expected, not a recovery
claim. Full contracts, Timeliner integration, pool-scan fallback, other builds
and arbitrary non-ASCII key names remain outstanding.

Final native54 positive cases match all eleven columns and every record:
Windows 10 15063 x64 1,230 records and Windows 11 22000 x64 665 records.
Both retain partial diagnostics. Verification passed 571 Rust / 25 Python tests,
Linux real regressions 4/4 and available Windows regressions 13/13 (Server2012R2
still lacks its local sample). The two cases bring positive evidence to 80 cases
across 21 plugins, including five explicitly scoped cases. Canonical candidate
correspondences are 118/135, with 17 missing entries and zero complete contracts.
Executable SHA256:
`cda77c2a0a51ea0a7d1c72cf1b8d895b36758aeb5af4242aab999e26a6a39453`.


## PESymbols (native55)

`pe-symbols.example.json` runs 16 bounded Intel cases with all three output
fields and exact record multiplicity, including duplicate/name-priority and
absolute-address queries. The frozen native55 executable yields 14 positive
passing cases on five public images. Native x64 address arguments are canonical;
reference arguments retain its documented 48-bit representation. See
`mappings/windows-pe-symbols.json` and `pe-symbols-known-limitations.json`.

Win10 ntdll name queries remain a failed comparison: native prototype recovery
reads an earlier WOW64 header that the pinned reference rejects at e_magic,
then the reference selects a later x64 instance. Native page-table and header
recovery provenance is retained. Win11 fltmgr exports are unavailable in both
offline engines and its PDB is absent; the empty result is a separate negative
observation, not positive evidence. External PDB acquisition, broader alias
ordering, malformed PE behavior and other builds need further validation.

`make check` passed 582 Rust and 25 Python tests; Linux 4/4 and Windows 13/13 real
regressions passed, excluding the unavailable Server2012R2 image. Positive
evidence is now 94 cases across 22 plugins (five cases remain record-scoped),
with 119/135 candidate correspondences, 16 missing entries and zero complete
plugin contracts. Native55 executable SHA256:
`f64ef19d21dbcf2a8868332d13bc1225faca7b0ed542ff0060ea466c8e64cff4`.


## SuspendedThreads (native56)

`suspended-threads.example.json` compares all nine fields of canonical
`windows.suspended_threads.SuspendedThreads` on the same five public Intel
samples used by PESymbols. Missing optional path/symbol text is normalized to
empty text; addresses compare full native canonical values with the reference's
48-bit presentation. Empty/empty cases remain negative observations and are
never registered as positive evidence.

Native tests exercise positive thread rows with exact PE export symbols for both
entry points, shared module queries, legacy ownership precedence, terminated and
unsuspended exclusion, WorkFolders filtering, missing SuspendCount, cancellation,
half-open VAD attribution, missing symbols and retained rows at resource limits.
These synthetic fixtures are not real recovery evidence. The known-limitations
file records the frozen final executable, real sample observations and remaining
contract gaps. Positive evidence remains 94 cases across 22 plugins (five scoped);
candidate correspondences become 120/135, 15 absent, zero complete contracts.


## DebugRegisters (native57)

`debugregisters.example.json` runs the canonical
`windows.debugregisters.DebugRegisters` on five public Intel samples. The mapping
covers all 17 columns; Dr7 is an integer and Dr0–Dr3 use address48 normalization
for the reference representation. Missing optional paths and symbols normalize
to empty text. Empty/empty results remain negative observations.

Native tests cover all four register addresses and exact export symbols, owner-PID
semantics, legacy ownership precedence, four exclusion paths, unmapped boundaries,
missing TrapFrame/register fields, unavailable PDBs with retained rows, cancellation,
resource limits, x86 pointer width and explicit ARM64 rejection. Shared path/symbol
helpers and synthetic PE fixtures also serve SuspendedThreads; its five tests are
rerun with this change. The frozen known-limitations file records real results
without promoting negative observations to positive recovery evidence.

Final native57 evidence adds one Server2008 SP1 x86 default case: 3/3 records,
all 17 fields equal, with native partial diagnostics explicitly retained. All
symbol columns are absent on that real case; nonempty symbols remain synthetic
coverage. The other four cases are empty/empty negative observations. Registered
positive evidence totals 95 cases across 23 plugins (five scoped), 121/135
candidate correspondences, 14 absent and zero complete contracts. The frozen
executable SHA256 is `7a503c0d5f9e65c71e9294300134038b220ba1dcfa30193aad3859119db46cfe`.


The canonical ScheduledTasks case uses every one of the pinned source's fifteen columns.
Run scheduled-tasks.example.json with the standard runner. Win10 15063 yields 232 rows,
Win7 7601 yields 92, with exact action/trigger multiplicities. The explicit partial allowance
keeps damaged hive/process-list diagnostics; it does not remove rows or permit differing fields.
The na_boolean normalization preserves false distinctly from an absent Enabled value.
DynamicInfo field order, unpadded COM GUID components, absent Time descriptions and absent Email
objects follow pinned v2.28.2. See scheduled-tasks-known-limitations.json for limits.
There are now 129/135 candidate correspondences, six missing entries, and zero complete contracts.


UnhookedSystemCalls: run unhooked-system-calls.example.json with the standard offline runner.
All three columns and all 45 functions match on Win10 15063 and Win7 7601, including nonempty
minority process lists. Partial process/VAD diagnostics are explicit. The fixed plugin compares
only its first two byte groups, chooses the second as majority on ties, and reads 32-byte windows.
Captured-page symbol queries use the same PE resolver with prototype recovery disabled; ordinary
PESymbols retains its broader recovery policy. Grouping is not proof of malware or complete
coverage of unreadable process pages. No complete plugin contract is certified.


Strings: first generate the local sidecars from the public RAW samples:

    python3 tests/reference/parity/strings_input.py --image images/feat-windows-plugins/WinDump/WinDump.mem --output target/reference/strings-input/win10.txt
    python3 tests/reference/parity/strings_input.py --image images/feat-windows-plugins/inctf-win7/Challenge.raw --output target/reference/strings-input/win7.txt

Then run strings.example.json with the usual runner. The sample input_files hashes are checked
alongside symbol files; every input string comes from the capture at its recorded offset, plus
an intentional duplicate. All three columns and multiplicities are compared. The strings_owners
normalizer checks exact set membership and addresses, normalizing only randomized member order.
The fixed reference uses process virtual keys and contiguous-block starts; this is recorded
explicitly rather than presenting those results as a corrected reverse-physical mapping.
The all-process reference case can take several minutes because it builds the full reverse map.

系统调用检测使用 `system-calls.example.json`，真实用例比较全部五列及命中重复数。
参考环境需 Capstone 5.0.6 和 Yara（本轮使用 yara-x 1.22.1）；Zero 静态编译同版本
Capstone 引擎，使用等价的固定字节规则，不运行 Python/Yara。
`system_calls_blocks.py` 在未修改的固定 checkout 上生成
`fixtures/system-calls.json`，由 Rust 回归验证 14 个合成指令块用例，包含间接调用正向
命中、无符号位移、错误目标／路径和缺失上下文。这些合成向量不能替代真实正向样本，
也不登记为整插件通过。空结果比较单独记录，不计入 positive evidence。

Skeleton Key 的两项公开镜像用例见 `skeleton-key.example.json`，五列及重复数严格
比较。Win7 空结果独立记录，不能作为正向证据。`skeleton_key_vectors.py` 使用未修改
固定参考生成 8 个导出函数分析用例和 6 个 hook 边界用例；Rust 回归读取
`fixtures/skeleton-key.json`。此外原生合成测试覆盖 PDB 数组优先级、计数缺页、数组
缺页、签名结构跨物理页和取消。公开样本内容不提交。

TrueCrypt 的 `truecrypt_vectors.py` 在固定参考上生成 16 个 PE32/PE32+、长度和
填充边界用例，全部口令为编造的测试字符串。Rust 使用相同 PE/section 数据和参考
期望验证；另外覆盖模块枚举、min-length 缓存隔离、缺页、扫描／输出上限和取消。
`truecrypt.example.json` 保留公开 Win7/Win10 的空结果比较，**不计正向证据**；需要
取得包含 truecrypt.sys 缓存口令的真实镜像后再补真实正向验收。

GUI 名称解码的 `gui_name_vectors.py` 使用固定参考 utility 生成
`fixtures/gui-process-names.json`；数据全部为合成字节。窗口列表的 Win10 真实用例
严格比较八列和重复数，Win7 空结果通过独立 allow_empty 映射记录，不计正向证据。

GUI 过程分类使用 `gui_procedure_vectors.py` 执行固定参考的实际 Windows 生成器，
生成 `fixtures/gui-window-procedures.json`。假进程身份不属于该分类测试的验收范围。
Windows 映射 v2 将 Procedure 作为可缺失负载字段；双侧缺失、单侧缺失、不同地址
和重复数的比较有工具回归测试，不通过排除字段或选择记录来消除差异。

`gui-regression.example.json` 联合复核 WindowStations、Desktops、DeskScan 和 Windows。
站名称与 UTF-16 使用 `gui_station_vectors.py` 执行固定 String 构造器和 get_info；
`gui_padding_vectors.py` 执行固定 pool.get_object 的 padding 分支（对象 is_valid 为
测试桩，只证明 carving 条件）。GUI offset 映射 v2 比较两侧实际报告的 48-bit 值，
不再只对参考端做 canonical 地址扩展；其他字段和重复数仍严格比较。

PoolScanner 的 `pool_header_vectors.py` 执行固定 `PoolHeaderScanner`，覆盖 executive／
non-executive 标签在 0、1、3、7、15 地址偏移时均按标签相对位置读取池头，alignment
仅缩放 BlockSize。相同生成器还执行实际 `PoolScanner._generator`，验证文件名
缺页时跳过该文件并继续下一条；carving／对象有效性由合成对象隔离，不计真实正向证据。

`pool_type_vectors.py` 执行固定 Handles.get_type_map、非 executive get_object 和
Pointer._unmarshall，覆盖类型表 100 项边界／空哨兵／缺名、未经结构有效性检查
保留 hive、native-layer 地址掩码。数据全为合成对象，不能替代真实正向证据。
`gui_padding_vectors.py` 还确认 top-down 窗口使用 pad=True，缺尾窗口保留候选；
对象有效性为测试桩，原生另测物理可读前缀与缺字节补零。

池扫描分页覆盖另由 `pool_type_vectors.py` 的实际 Intel32e.mapping 验证：
递归根表 alias 与已映射用户半区都必须保留。原生遍历按固定层数终止；这两个
向量不替代损坏分页结构、其他架构和附件恢复的完整合同。

`pool_validity_vectors.py` 执行固定 EPROCESS／ETHREAD.is_valid 与实际时间
转换，冻结 2026／2035 年本地时钟。33 个进程、11 个线程向量覆盖公历边界、
同秒 FILETIME、异常退出时间、名称和 PID／DTB／链表字段域。array_to_string
适配器使用实际字节解码器，其他输入为合成字段；未证明缺页名称读取或全 carving。

`sockscan_vectors.py` 执行固定 Sockscan._generator 的六种来源／去重情形、
MultiStringScanner 的 4／8 字节混合模式次序，以及 inet_sock 实际地址方法和
Pointer 解码的四种原始层读取情形。来源向量隔离字段格式化，地址向量记录生成
宿主 AF_INET6 并隔离家族门槛与真实物理 BufferDataLayer。Linux 镜像家族 10
与宿主 socket 常量不总相同，不能把 macOS 的缺失结果误判为所有平台的规则。
完整默认映射 v2 比较全部十列／重复数／成对缺失，无记录筛选；范围映射另保留。

`callstack_vectors.py` 执行固定 Kallsyms 全局门槛、module ELF 边界、首模块
查询及 get_task_callstack 栈循环。15 个模块查询、7 个栈字向量使用合成字段／
字节层，分别验证地址域／Python 优先级／重叠归属和未对齐尾字／首错停止／
无效 SP。真实八个 PsCallStack 用例与合成向量分开统计；core 范围不代替全表。

`dispatch_vectors.py` 执行实际 SSDT.build_module_collection 和 SizedModule／
ModuleCollection 地址查询，验证默认 DriverIrp 将所有模块绑定同一个内核 ISF，
精确 RVA／全部别名／inclusive 末端及数字后缀命名。合成 SymbolSpace 只隔离
精确查找，向量不验证外部 PDB 获取或驱动池扫描。

`driver_target_vectors.py` 的八个实际固定 DriverIrp 生成器用例验证 handler
指针掩码、Modules.get_kernel_space_start 的真实值／缺页默认及包含边界，
同时保留数组单项读取失败后继续。驱动池／名称和模块符号由测试桩隔离；原生
另有真实页表下跨页数组读取回归，不将这些向量计入真实正向差分数量。

`driver_name_vectors.py` 的 15 用例执行实际 NameInfo 属性、驱动名称方法、
UNICODE_STRING.String 和 String 构造器，验证偏移选择／名称表与长度解码。
字段提取使用合成适配器，原生另在 x86/x64、物理／虚拟四种真实合成页表组合
重读描述符。MaximumLength 检查属于其他路径，不能误加到 DriverIrp 的直接
NameInfo.Name.String 上。名称向量不计入真实正向差分。

`driver_scan_vectors.py` 执行实际 DriverScan.scan_drivers、builtin Driver
约束及内核门槛方法，14 用例检查零／严格边界／指针域和必须八字节可读
（包括 x86）。pool candidate 恢复使用共享固定 carving；原生另测零
padding、未对齐标签与虚拟别名。用例的 carved objects 是测试桩，不替代
DriverIrp、DriverModule 和 GUI 的真实联合差分。

`driver-regression.example.json` 汇总 DriverIrp 六例、DriverModule 三例及 GUI
五例，覆盖共享池候选恢复的调用方。native82 实际验收以原三个配置并行执行，
三个报告绑定同一最终二进制摘要；汇总配置可顺序复现相同 14 个 case。


Native83 aligns DriverModule ownership with inclusive SSDT ModuleCollection
intervals, native pointer domains, zero-size/readable empty-name modules, and
forward-only LIST_ENTRY traversal. It avoids querying FullDllName. Names reuse
direct NameInfo/UNICODE_STRING.String decoding, including odd UTF16,
MaximumLength-independent reads and readable user-half extension pointers.
`driver_module_vectors.py` regenerates 50 actual generator/collection/name-helper
vectors plus 16 actual LIST_ENTRY.to_list vectors in `fixtures/driver-module.json`.
Adapters supply synthetic fields and validity; native counterparts use real
fixture page tables and both physical/virtual pool bodies. Equality at the kernel
boundary is explicitly split between the generator's inclusive gate and the
upstream scanner's strict gate. These vectors do not establish a complete fault
or platform contract; individual missing-name diagnostics still differ.


Native84 merges the four-byte pool tags by scan-range address, with the same
non-overlapping match consumption as the pinned MultiStringScanner. Both driver
tags now share one range read. `pool_order_vectors.py` executes the actual
MultiStringScanner and PoolHeaderScanner to regenerate 11 cases in
`fixtures/pool-order.json`; decoded header fields are synthetic. Native tests
also exercise interleaved driver tags on real x86/x64 physical/virtual fixtures.
This does not establish scan-chunk/overlap or boundary-spanning header behavior.

Record sequence can now be checked explicitly in addition to the usual full-field
comparison. This preserves duplicate occurrences, uses the same field and address
normalization, and applies any declared record selection before checking order:

```sh
python3 tests/reference/parity/compare.py \
  --zero target/reference/results/poolscanner-native84/000/zero.json \
  --reference target/reference/results/poolscanner-native84/000/reference.json \
  --mapping tests/reference/parity/mappings/windows-poolscanner.json \
  --record-order \
  --output target/reference/results/poolscanner-native84/000/ordered-comparison.json
```

Order agreement does not waive incomplete-output, missing-value, duplicate-key or
coverage gates. Empty order agreement is still not positive evidence.


Final native84 jointly reruns five PoolScanner, six DriverIrp, three DriverModule
and five GUI cases. All 19 full-field/multiplicity comparisons pass (one empty
Win7 case is non-positive); 18 strict sequence checks pass. Windows has 3063
matching records but a sequence difference at index 245. Its pinned reference
also changes child traversal order between the stored native82/native84 reference
runs (same full-field multiset, first sequence difference at index 262): the source
iterates a set containing identity-hashed tagWND objects. Both the failed strict
check and the reference/reference observation remain recorded in
`windows-known-limitations.json`; no records are reordered to hide that failure.
Evidence remains 122 positive cases, five scoped, zero complete contracts.


Native85 removes a scan-buffer containment requirement on pool headers. The tag
still has to be discovered in the supplied slice, but BlockSize and PoolType are
read independently at their exact header field addresses. A fully cached field
uses the slice; a partially/external field reads the matching physical/virtual
layer. Unused header tails no longer gate candidates, and required-field holes
still reject them. `pool_boundary_vectors.py` runs the actual PoolHeaderScanner
and pre-Vista/Vista predicates for 48 independent-field cases in
`fixtures/pool-boundaries.json`. Native counterparts use x86/x64 physical/virtual
fixtures with real missing image segments. A shared-carver integration fixture
places a tag at a segment start with its prefix in the previous segment and an
unreadable unused tail. These checks do not prove discovery of split tags or
layer chunk/overlap equivalence; those remain separate gaps.


Final native85 reruns the same 19 PoolScanner/driver/GUI cases against the fixed
reference. All mapped fields and multiplicities pass; 18 emitted sequences pass.
Windows retains its recorded strict sequence discrepancy at index 245 and the
native84 reference/reference instability observation is preserved. Empty Win7
agreement remains non-positive. Fresh reports and ordered comparisons are under
the four `*-native85` result directories, bound to the final binary hash.
Evidence remains 122 positive cases (five scoped), zero complete contracts.


Native86 bounds pool scan reads to the pinned 16 MiB chunk plus 4 KiB overlap.
Only starts below chunk_size are emitted from each buffer. DataLayer and
TranslationLayer have separate final-step behavior, including the actual RAW
short-tail duplicate observations; these are retained rather than deduplicated.
Physical default scans exclude maximum_address itself, matching the reference's
exclusive default section length. `pool_chunk_vectors.py` regenerates 26 actual
layer-iterator plans, 12 actual _scan_chunk/MultiStringScanner cases and a default
section boundary observation in `fixtures/pool-chunks.json`. Mapping/fault
adapters are synthetic; native tests also exercise the shared carver across a
16 MiB tag boundary and a short RAW tail. Complete mapping enumeration, container
format behavior and all missing-page reporting contracts remain outstanding.


Final native86 reruns the same 19 pool/driver/GUI cases against the pinned
reference: all mapped fields and multiplicities pass, including one non-positive
empty Win7 agreement. Eighteen strict emitted sequences pass; Windows retains
the strict sequence discrepancy at index 245 and the prior reference/reference
instability observation. Reports and ordered comparisons are under the four
`*-native86` result directories and bound to the final executable hash.
Evidence remains 122 positive cases (five scoped), zero complete contracts.


Native87 aligns virtual pool range enumeration with the actual Windows Intel
mapping layer: validate complete captured backing spans before coalescing, clip
the uppermost native-domain page to the exclusive default maximum, validate full
4 KiB PAE root pages, restrict large-page flags to their valid levels and apply
the pinned PAE 40-bit physical mask. `pool_mapping_vectors.py` regenerates 38
actual WindowsIntel/WindowsIntelPAE/WindowsIntel32e.mapping cases from complete
synthetic page-table bytes in `fixtures/pool-mappings.json`. Native tests compare
all three mapping columns (virtual start, length, physical start), including
explicit backing holes. Arbitrary reserved PFNs, custom transition layouts,
container mapping/decompression and full scan-fault reporting remain unverified.


Final native87 jointly reruns the same 19 cases: all full-field/multiplicity
comparisons pass, 18 emitted sequences pass, and Windows retains its recorded
strict sequence discrepancy at index 245. One empty Win7 agreement is non-positive.
Win11 DriverIrp and DriverModule retain matching rows while their 5258 native86
unbacked-range diagnostics become zero and the outputs become complete. This
reflects actual backing-span mapping checks rather than suppressing read errors.
Reports and ordered comparisons are bound to the final binary under the four
`*-native87` directories. Evidence remains 122 positive cases (five scoped), zero
complete contracts.


Native88 fixes the Windows-specific PFN domain exposed by the new Win10 bitmap
crash default: the pinned WindowsIntel32e uses 45 physical bits rather than the
generic Intel32e 52. Paging, Intel transition extraction, root self-reference
checks and pool mappings now share the correct architecture domain (x86 32,
PAE 40, Windows x64 45; ARM64 unchanged). The 42 actual mapping vectors include
software high flags and native Memory.translate endpoint checks. Fourteen new
actual crash-layer fixtures in `fixtures/crash-mappings.json` validate full and
bitmap dump segments/reads against both 32/64-bit reference constructors and
their real bundled symbols.

`crash-pool.example.json` covers the three complete default pool/driver plugins
on the public Win10 bitmap capture. Prepare its decompressed file first; the
runner checks its raw SHA256 and separately checks the listed gzip input digest:

```sh
mkdir -p target/reference/prepared
gzip -dc images/feat-windows-plugins/win-10_19041-2025_03.dmp.gz > target/reference/prepared/win-10_19041-2025_03.dmp
python3 tests/reference/parity/run.py \
  --config tests/reference/parity/crash-pool.example.json \
  --output target/reference/results/crash-pool-native88
```

Place the exact kernel ISF at both local and reference paths listed in the config
before running. Server 2019 type 6 is not accepted by the pinned reference crash
layer; its initial requirement failures are retained as incomparable, never
positive evidence. Direct reference gzip random-seek performance is not part of
the container plugin parity claim. Truncated/malformed containers and full fault
contracts remain unverified.


Final native88 passes 22 real full-field/multiplicity cases, including three new
unscoped bitmap crash defaults: PoolScanner 8090/8090 (native87 missed ten files),
DriverIrp 3972/3972 and DriverModule 1/1. Twenty-one strict sequences pass; the
existing Windows child-order difference at index 245 remains recorded. The empty
Win7 agreement is non-positive. Positive evidence increases from 122 to 125 cases
(five scoped); complete plugin contracts remain zero. The final five
`*-native88` result groups share one executable digest. See
`crash-pool-known-limitations.json` for the old mismatch, prepared-input hashes,
actual container vectors and unsupported Server 2019 reference failures.


Native89 shares full captured Intel page-table validation across direct translation,
prototype lookup, captured portions of pagefile-table walks and absent-page hints.
Unreadable or uniformly repeated 4 KiB tables are rejected before reading a
particular entry. A validity-only LRU retains at most 1025 results, bounded by the
configured page-cache budget, and caches failed tables as well. ARM64 remains
separate. The actual Windows Intel vectors now contain 45 cases and 186 direct
translation/read queries, including partially readable tables and failed reads.
Native cache-disabled/single-entry tests retain the same results. Direct reads now
allow the native-domain last byte without unsigned overflow; this is distinct
from the reference default scan section's exclusive upper bound. Exact exception
formatting, swap-backed table validity and complete malformed-input contracts
remain unverified.


Final native89 repeats all 22 real cases: mapped fields and multiplicities pass;
21 strict sequences pass, with the known Windows child-order difference at index
245 retained. The release gzip-crash process/network acceptance also passes
(120/108 complete rows, DTB and exact TCP/IP identity checked). All five
`*-native89` report groups bind the final binary. Same case identities replace
prior proofs; evidence remains 125 positive cases (five scoped), zero complete
plugin contracts. Empty Win7 agreement and row-count-only acceptance do not add
positive differential cases.


Native90 follows the actual Intel large-page PFN/offset OR semantics without
extra alignment of reserved PFN bits. The virtual-page cache also retains mapping
shift, so reads consume the current large mapping instead of remapping every
4 KiB. This matters for reserved-bit entries where the pinned whole-range mapping
assumes linearity but independent direct translations OR each queried start;
both API observations are checked independently. Intel transition large-page
flags are retained through the level check. ARM64 descriptor behavior remains
separate. The actual reference vectors now contain 54 cases and 240 direct
queries, including per-physical-page byte patterns and 32-byte reads crossing
4 KiB boundaries. All malformed combinations, canonical-midpoint coalescing and
software/pagefile-backed extents remain unverified.

Final native90 repeats all 22 real cases with mapped fields and multiplicities
passing; 21 strict sequences pass. The known Windows GUI child sequence
difference at index 245 remains a failure. The five `*-native90` report groups
bind the same final binary; repeated case identities replace previous proofs.
Evidence remains 125 positive cases (five scoped), zero complete plugin contracts.
`make check`, release package smoke and gzip-crash process/network acceptance
(120/108 rows, DTB and exact TCP/IP identity) pass. Large mapping read sizes are
limited in u64 before conversion to usize for 32-bit hosts.

Native91 normalizes Intel translation inputs to their architectural address bits
before cache lookup; canonical pointer validation remains distinct, and ARM64
keeps its address checks. Prototype/pagefile entry points use the same input
interpretation. Pool mappings coalesce in the native address domain before sign
extending their output starts, preserving physical/virtual continuity across the
x64 sign boundary. Actual pinned-reference vectors now contain 55 cases and
257 queries, including raw and canonical aliases and patterned 32-byte reads
across the midpoint. Native tests pass the queried raw address directly and check
captured failure states as well as successful bytes. This does not certify all
architectures, u64-overflow reads, software paging combinations or fault contracts.

Final native91 repeats the five groups (22 real cases): mapped fields and
multiplicities pass, and 21 strict sequences pass. Windows GUI child ordering
retains its known difference at index 245. `*-native91` raw reports bind one
binary. Evidence stays at 125 positive cases (five scoped), zero complete plugin
contracts. `make check`, package smoke in unrelated/empty-PATH environments and
release gzip-crash acceptance (PsList120/Netscan108 with DTB/TCP-IP checks) pass.

Native92 adds `linux.boottime.Boottime` (`linux.boottime`) with namespace/time
columns. `boottime.example.json` compares every field of the public Debian case;
`linux-boottime.json` explicitly permits unavailable namespace IDs on old kernels
and compares full row multisets keyed by timestamp, preserving different namespaces
with identical boot times. Missing timestamps cannot establish positive identity.
`boottime_vectors.py` calls pinned Boottime, PsList iteration and bound task time
methods through synthetic typed field/list adapters. Its 22 cases cover timekeeping
branches, first-ID order, namespace offsets, missing namespace fields, empty tasks,
unsupported timekeeping and datetime boundaries. The native tests use complete
synthetic memory/ISF layouts. Modern ktime conversion reproduces the reference's
floating NSEC_PER_SEC divmod before applying namespace offsets and datetime
rounding. This does not prove every architecture, real modern namespace samples,
all corruption contracts or TimeLiner integration. The legacy key/value interface
is retained and shares the kernel timekeeping reader.

Final native92 real Debian Boottime and five PsList cases pass all fields,
multiplicities and strict emitted sequences. The legacy boot summary's columns
and rows equal the native91 baseline. The new Boottime case raises cumulative
positive cases to 126 (five scoped), with zero complete plugin contracts. Raw
reports are `boottime-native92` and `debian-native92`, bound to one final binary.
`make check` passes 623 library, 8 CLI/MCP, 50 protocol and 36 Python tests;
release package smoke passes in project/unrelated directories with empty PATH.
Modern namespaces remain synthetic method coverage, not real-image parity.

Native93 adds `linux.capabilities.Capabilities` (`linux.capabilities`), decoding
real-credential capability sets while reading EUID from task credentials. It
selects task.pid before reading capability fields, supports PID/list unions and
keys the cache by both selectors. Parent TGID follows the reference's whole-object
readability/zero fallback without discarding task-list integrity diagnostics.
`capabilities_vectors.py` calls fixed extraction/decode and bound capability/parent
methods through typed adapters. Its 96 cases cover all 41 names, supported layouts,
mask/all/empty handling and selected fault boundaries; native memory fixtures
deliberately distinguish override credentials and PID/TGID.

`capabilities.example.json` and `capabilities-kali.example.json` currently expose
reference failures and intentionally return failing batch status. The Debian ISF
has an old cap-array under kernel_cap_t while the pinned extension demands val.
Kali ARM64 reaches a failing Intel translation. Sources and symbols are not
changed to force passing. Only Debian's unmatched PID case agrees emptily; it is
not positive evidence. Native Kali completes 169 default rows; an isolated native
MCP session verifies 169/1/1/1/2 rows, selector isolation and a repeated cache hit.
Those are native regression evidence, never positive reference cases. Full proofs
and failure hashes are in `capabilities-known-limitations.json`; raw reports use
`capabilities-native93`, `capabilities-kali-native93` and
`capabilities-kali-cache-native93`. Five PsList and one Boottime real regressions
pass all fields and emitted sequences; cumulative positive cases remain 126 (five
scoped), zero complete contracts. `make check` and release package smoke pass.

Native94 adds `linux.envars.Envars` (`linux.envars`) with the five reference
columns, early task.pid selection, PID/list unions and selector-specific caches.
It skips PF_KTHREAD tasks and uses the shared whole-parent/TGID fallback. Buffers
must be 1..8192 bytes and wholly readable; unavailable process layers/buffers are
skipped without padded or prefix-derived environment output. Parsing strips only
trailing NULs, preserves empty keys/values and duplicate pairs, replaces invalid
UTF8, splits on the first equals sign and stops at the first malformed entry.
The old four-column interface retains its existing behavior.
`envars_vectors.py` exercises actual pinned Envars methods, flag/parent methods
and PID filter over typed field/layer adapters. Its 28 native memory fixtures
include noncontiguous pages and a three-page 8192-byte buffer. This does not
certify all real layer construction, damaged layouts, architectures or fault and
resource contracts. `envars.example.json` supplies default and selected-shell
real Debian cases; unmatched PID agreement is explicitly non-positive.

Final native94 default Envars compares 1402 real Debian rows; single-shell
selection compares 26, and paired/repeated/union selectors each compare 38.
All five nonempty cases and six existing PsList/Boottime cases pass every field,
multiplicity and strict emitted sequence. The unmatched selector is empty
agreement. A persistent isolated MCP cache session compares 1402/26/12/26/38
totals, first 200 API rows and every row of four stored caches, including a
verified cache hit; this is not an extra differential case. Evidence grows to
131 positives (five scoped), zero complete contracts. `make check` passes 625
library, 8 CLI/MCP, 50 protocol and 36 Python tests; package smoke passes in
project/unrelated directories with empty PATH. Raw groups are `envars-native94`,
`debian-native94`, `boottime-native94` and `envars-cache-native94`.

Native95 adds `linux.psaux.PsAux` (`linux.psaux`) with PID/PPID/COMM/ARGS, early
task.pid selection and independent PID/list cache keys. The standard view emits
N/A for a nonempty-mm task whose process layer, 1..4096-byte bounds or complete
read is unavailable; null/unreadable mm uses `[COMM]`. PF_KTHREAD does not replace
the mm decision. UTF8 replacement and NUL-to-space decoding remove only one final
ASCII space when the resulting string contains more than one character.
`psaux_vectors.py` calls actual pinned argument/generator/parent methods and the
PID filter over field/layer adapters. Its 29 native fixtures cover spacing, bounds,
missing pages/layers/mm, noncontiguous user pages and pointer-byte capture holes.
They do not certify full list_tasks validity, every architecture or layer build,
all corrupt layouts or complete fault/resource contracts. `psaux.example.json`
compares all fields, with explicit matched-absent ARGS handling; unmatched PID
agreement remains non-positive. The legacy status-column interface is retained.

Final native95 PsAux compares 133 default rows, one selected shell and two rows
for paired/repeated/union selectors. All fields, multiplicities and strict
sequences pass; unmatched selection is empty agreement. Existing Envars, five
PsList and Boottime cases also pass: 18 cases, 16 nonempty, two empty. Same IDs
replace prior proofs, adding five new positive identities for a cumulative
136 (five scoped), zero complete contracts. The isolated MCP cache session
compares 133/1/1/1/2 rows and full cached results with a verified cache hit.
`make check` passes 626 library, 8 CLI/MCP, 50 protocol and 36 Python tests;
release package smoke passes in project/unrelated directories with empty PATH.
Raw groups are `psaux-native95`, `envars-native95`, `debian-native95`,
`boottime-native95` and `psaux-cache-native95`, bound to one final binary.

Native96 standard task consumers use the pinned task_struct admission and
list_head direction rules. Whole tasks/pointed objects must be readable; signed
IDs reject negatives while zero/unsigned-high IDs remain valid. Optional signal,
nsproxy and real_parent pointers must be nonnull/readable; active_mm is checked
when nonnull, and nonnull mm must be readable and equal active_mm. Lists dedupe
addresses, not PIDs, and retain reference COMM handling (unterminated/empty/control
text, truncate at NUL/replacement). Legacy recovery diagnostics remain separate.
`task_validity_vectors.py` calls actual fixed validity/list/selection/name methods
with byte-backed adapters: 50 validity cases and 18 walks. Native uses identical
field bytes with full x64 page tables/capture holes. Width4 cases do not certify
Intel32 paging. Existing generator-only fixtures now use a separate native
extraction adapter, never task-admission evidence. Full thread enumeration and
all fault/resource/architecture contracts remain unverified.

Final native96 reruns 35 real cases across eight groups. 34 mapped comparisons
(32 nonempty, two empty) and their strict sequences pass. The known regex
maxsize4 Text/Hex conflict remains failing. Three native MCP cache sessions
(PsAux, Envars and Kali capabilities) pass; native-only cases never add reference
positives. Evidence stays 136 positives (five scoped), zero complete contracts.
`task-validity-known-limitations.json` binds case/known-failure/cache/vector proofs;
raw reports are under the eight `*-native96` groups. `make check` passes 628 lib,
8 CLI/MCP, 50 protocol and 36 Python tests; release package smoke passes.

native97 adds `pslist-selection.example.json`: leader PID filtering before full
thread expansion, PID lists/unions/repeated selectors, decorated thread groups,
leader-only lists and unmatched selection. The shared typed-byte method vectors
now include 28 thread cases running pinned `get_threads`, `_get_tasks_iterable`,
`list_head.to_list` and `PsList.list_tasks`. Modern signal-list precedence is
covered by these method cases, not a modern real-image differential. Full plugin
contracts remain unverified.
All 19 native97 real cases pass mapped fields and strict sequence (18 positive,
one empty); the persistent MCP selector/thread/decoration cache session and
release package smoke also pass. Stable evidence identities replace older
records; five added positive identities bring the total to 141 (five scoped),
zero complete contracts. `pslist-selection-known-limitations.json` binds the
proofs to native97 and retains the native96 one-versus-seven-row regression.

native98 aligns both canonical regex generators with the pinned 128-byte display
context, including ignored signed maxsize values, and separates Linux task.pid
filtering from displayed task.tgid. `regex_context_vectors.py` captures 96 actual
generator/scanner cases and five PID-filter methods over supplied adapters.
Four suites retain 23 real cases: 14 pass all mapped fields and strict sequence,
nine Windows cases remain failed. Linux maxsize4 field conflicts and Windows
maxsize4's 1,402 common-field conflicts are fixed; the latter still has eight
extra recovered records and is not a positive case. The Windows suites now share
a frozen current converter8 ISF, and archived actual native symbol files are
checked against that input. Earlier cache-dependent exploratory output is not
used as new evidence. Two persistent MCP sessions retain partial status and
create zero success cache files. The current proof is
`regex-context-known-limitations.json`; older known-difference files retain their
historical hashes with a link to the replacement context proof. Stable evidence
now totals 148 positive cases (five scoped), zero complete plugin contracts.

Native99 resolves the nine native98 Windows regex failures by admitting scan
bytes through the pinned Intel layer policy, including explicit swap support.
All 13 real VadRegExScan cases pass full fields and strict sequence; the native
prototype recovery reader remains separate. The 57 actual layer cases cover 570
read calls, and one persistent MCP session verifies every result page across
eight analyses (20 protocol calls), preserving partial state and avoiding success
cache files. `windows-layer-read-known-limitations.json` binds current proof and
historical failure summaries to native99. Stable evidence totals 157 positive
cases (five scoped), zero complete plugin contracts.

Native100 follows the pinned nested/zero-length section coalescing and suppresses
zero-length hits starting exactly at chunk_size. Original requested byte counts
are retained; reference coalescing omissions are explicit and keep results partial.
`regex_sections_vectors.py` covers 36 coalescing and 13 contiguous-map chunk cases
using actual pinned methods at reduced 8/4 geometry (production stays 16MiB/4KiB).
Two mapping cases remain explicitly failed in an ignored method test: discontinuous
backing can be concatenated natively, and the pinned leading empty chunk is absent.
The failure is retained, not counted as parity. See `regex-sections-known-limitations.json`.

All 29 affected real regressions pass mapped fields and strict sequence on the
final binary (26 positive, three empty). The final native rerun reuses the same
batch's fixed reference outputs after input/symbol/argument/mapping/output hash
and clean pinned-checkout validation; `reference_execution` records that reuse.
No new positive identities are added: totals remain 157 (five scoped), zero
complete contracts. The complete gate and release smoke pass; the known mapping
method test is explicitly excluded from the default gate and still fails when run.

Native101 uses selected-range Intel mapping events for canonical regex chunking,
Windows system-call scans and Skeleton Key fallback scans. Linux x64 and Windows
x86/PAE/x64 have explicit page-table-derived backing boundaries; ARM64 retains a
separate native path. The former ignored discontinuity/leading-empty cases are
now normal mapped-scanner tests, alongside a failed-read empty-subject case.
`intel_scan_vectors.py` adds 87 actual Intel cases (870 reads, 261 mapping queries).
`scan-mapping.example.json` compares real empty-chunk and mapping-start anchors;
its `duplicate_keys: multiset` mapping preserves every full record occurrence and
strict sequence is separately checked. Native100's failures remain archived;
no post-match filtering is used to fix the output.

The final native101 binary reruns all seven affected configurations: 33 cases
match every field, duplicate occurrence and strict output order (30 positive,
three empty agreements). Four new anchor identities bring stable positive
evidence to 161 cases (five scoped); complete plugin contracts remain zero.
`scan-mapping-known-limitations.json` binds the final binary, fixture/source
hashes, pre-fix failures, final summaries and validation boundaries. The separate
actual Intel32e zero-length-section probe still exposes a missing empty event;
that edge remains unresolved. Large-sample acceptance also retains stale
DriverModule completeness and pre-native79 independent-PDB assertions, documented
as failures instead of being claimed as passing regressions.
