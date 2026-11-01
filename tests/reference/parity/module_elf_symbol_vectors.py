#!/usr/bin/env python3
"""Execute pinned module symbol normalization with synthetic objects only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from types import SimpleNamespace

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework.symbols.linux.utilities.modules import ModuleExtract
    sections = [('.text', 1, 0x1000, 0x100), ('.data', 2, 0x2000, 0x100), ('.rela.text', 3, 0x3000, 0x100)]
    inputs = [
        (0, 0, 0, 0), (0, 0x1010, 8, 99), (1, 0x1010, 8, 99),
        (1, 0x2010, 8, 99), (1, 0x3010, 8, 99), (1, 0x9000, 8, 7),
        (1, 0, 8, 7), (1, 0x1000, 8, 99), (1, 0x1100, 8, 7),
        (1, 1 << 32, 8, 7), (1, 0x1010, 1 << 32, 99),
    ]
    cases = []
    for bits in [32, 64]:
        for name, address, size, shndx in inputs:
            sym = SimpleNamespace(st_name=name, st_value=address, st_size=size, st_info=0xff, st_other=2, st_shndx=shndx)
            fmt = '<I' if bits == 32 else '<Q'
            kernel = SimpleNamespace(get_type=lambda _: SimpleNamespace(size=16 if bits == 32 else 24), object=lambda **_: [sym])
            context = SimpleNamespace(modules={'kernel': kernel})
            original = {address: name for name, _, address, _ in sections}
            lengths = {address: size for _, _, address, size in sections}
            try:
                value = ModuleExtract._fix_sym_table(context, 'kernel', original, lengths, 'Elf32_Sym' if bits == 32 else 'Elf64_Sym', fmt, SimpleNamespace(section_symtab=0, num_symtab=1))
                error = None
            except struct.error:
                value, error = None, 'struct.error'
            cases.append(dict(bits=bits, name=name, address=address, size=size, other=2, shndx=shndx, expected_hex=None if value is None else value.hex(), error=error))
    source = 'volatility3/framework/symbols/linux/utilities/modules.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout / source).read_bytes()).hexdigest()}, sections=sections, cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
