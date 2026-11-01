#!/usr/bin/env python3
"""Execute pinned ELF header builders; synthetic values only (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import sys

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework.symbols.linux.utilities.modules import ModuleExtract
    headers = []
    sections = []
    for bits in [32, 64]:
        for offset, count in [(52, 1), (0x12345, 7), (1 << 32, 7), (52, 65535)]:
            try:
                value = ModuleExtract._make_elf_header(bits, offset, count)
                error = None
            except struct.error:
                value = None
                error = 'struct.error'
            headers.append(dict(bits=bits, offset=offset, count=count, expected_hex=None if value is None else value.hex(), error=error))
        for name in ['.text', '.data', '.bss', '.symtab', '.strtab', '.shstrtab', '.rela.text', '.rel.text', '.note.gnu.build-id']:
            args = [bits, 3, name, 0xc0010000, 0x123, 0x456, 2, 4]
            value = ModuleExtract._make_section_header(*args)
            sections.append(dict(args=args, expected_hex=value.hex()))
        for index in [3, 4, 5]:
            args = [bits, 3, '.text', 0xc0010000, 0x123, 0x456, 2, 4]
            args[index] = 1 << 32
            value = ModuleExtract._make_section_header(*args)
            sections.append(dict(args=args, expected_hex=None if value is None else value.hex(), reference_result='none' if value is None else 'bytes'))
    source = 'volatility3/framework/symbols/linux/utilities/modules.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout / source).read_bytes()).hexdigest()}, scope='Actual pinned ELF32/ELF64 header and section-header methods only; no full module reconstruction claim.', headers=headers, sections=sections)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
