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
