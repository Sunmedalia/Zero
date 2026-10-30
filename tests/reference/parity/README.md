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
listed files, not arbitrary additional files in that directory.

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
The separate `vmaregexscan-maxsize.example.json` records the pinned reference's
unused maxsize option: Zero applies the parameter, so that case remains divergent
and must not be counted as passed. Raw matched bytes remain in ignored artifacts.

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
Before running, copy that exact cached ISF to the declared reference symbol path
without changing its bytes (both hashes are pinned in the configuration).

PID 468 has 27 matching positive rows. The other eight cases remain failed: every
extra native row is matched to native prototype-page recovery evidence, with no
missing reference rows or common-field conflicts. No rows are removed to make a
case pass. The combined configuration deliberately exits nonzero. Page recovery
can make native output larger than reference output; it does not establish a
hidden-memory finding. Partial coverage/tree warnings remain explicit.

`vadregexscan-maxsize.example.json` separately preserves the reference's unused
maxsize parameter. With maxsize=4, common-record Text/Hex differ; this is not marked
passed. `vadregexscan-known-differences.json` records counts, origin validation,
coverage and output hashes, never recovered match contents. The scanner can skip
only proven zero-page-table spans, with every skipped byte retained in unavailable
coverage. Nonzero software PTEs and missing page-table pages still use recovery or
the bounded page-by-page fallback. The compatibility matrix records synthetic x64
coverage; the one real positive PID case is not generalized to all Windows builds.

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
