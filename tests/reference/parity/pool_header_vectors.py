#!/usr/bin/env python3
"""Execute pinned PoolHeaderScanner tag-relative header cases (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.plugins.windows.poolscanner import PoolHeaderScanner, PoolScanner
    from volatility3.framework import exceptions
    cases = []
    for tag, block, minimum in [(b'Pro\xe3', 41, 600), (b'AtmT', 13, 200)]:
        for offset in [0, 1, 3, 7, 15]:
            data = bytearray(128)
            data[offset:offset + 2] = block.to_bytes(2, 'little')
            data[offset + 4:offset + 8] = tag
            module = SimpleNamespace(
                get_type=lambda name: SimpleNamespace(relative_child_offset=lambda field: 4),
                object=lambda object_type, offset, absolute: SimpleNamespace(
                    BlockSize=int.from_bytes(data[offset - 0x1000:offset - 0x1000 + 2], 'little'),
                    vol=SimpleNamespace(offset=offset)))
            constraint = SimpleNamespace(size=(minimum, None), page_type=None, index=None)
            scanner = PoolHeaderScanner(module, {tag: constraint}, alignment=16)
            headers = [header.vol.offset - 0x1000 for _, header in scanner(bytes(data), 0x1000)]
            cases.append({'tag_hex': tag.hex(), 'header_offset': offset, 'expected_headers': headers})
    class MissingName:
        @property
        def String(self):
            raise exceptions.InvalidAddressException('synthetic', 0x2000)

    file_constraint = SimpleNamespace(object_type='File', type_name='synthetic!_FILE_OBJECT')
    objects = [
        SimpleNamespace(FileName=MissingName(), vol=SimpleNamespace(offset=0x4000)),
        SimpleNamespace(FileName=SimpleNamespace(String='ok'), vol=SimpleNamespace(offset=0x4100)),
    ]
    header = SimpleNamespace(vol=SimpleNamespace(offset=0x3000, layer_name='synthetic'))
    context = SimpleNamespace(modules={'kernel': SimpleNamespace(symbol_table_name='synthetic')})
    harness = SimpleNamespace(context=context, config={'kernel': 'kernel'},
                              builtin_constraints=lambda table: [],
                              generate_pool_scan=lambda *args: ((file_constraint, obj, header) for obj in objects))
    file_names = [row[1][3] for row in PoolScanner._generator(harness)]
    return {
        'reference_commit': PIN,
        'source_sha256': hashlib.sha256((checkout / 'volatility3/framework/plugins/windows/poolscanner.py').read_bytes()).hexdigest(),
        'scope': 'Actual PoolHeaderScanner tag offsets and size checks; synthetic module fields, page/index checks disabled. Does not validate object carving or object identity.',
        'cases': cases,
        'file_name_fault': {'scope': 'Actual PoolScanner generator, synthetic carved objects and missing file-name read; verifies skip and continuation only.', 'expected_names': file_names},
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/pool-headers.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
