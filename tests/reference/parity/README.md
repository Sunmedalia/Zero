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
