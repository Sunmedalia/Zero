#!/usr/bin/env python3
"""Actual pinned multi-pattern pool tag order and non-overlap (VSL 1.0)."""
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
    from volatility3.framework.layers.scanners import MultiStringScanner
    builtins = PoolScanner.builtin_constraints('nt')
    driver_data = b'.' * 4 + b'Driv' + b'.' * 4 + bytes([68, 114, 105, 246]) + b'Driv' + b'.' * 4 + bytes([68, 114, 105, 246])
    inputs = [
        ('interleaved-drivers', [b'Dri\xf6', b'Driv'], driver_data, []),
        ('reversed-drivers', [b'Driv', b'Dri\xf6'], driver_data, []),
        ('reversed-builtins', [c.tag for c in builtins], b'0000' + b'0000'.join(c.tag for c in reversed(builtins)), []),
        ('one-gui-tag', [b'Wind'], b'0000WindWind000Wind', []),
        ('self-overlap', [b'AAAA'], b'AAAAAAAAA', []),
        ('cross-pattern-overlap', [b'AAAA', b'AAAB'], b'AAAAAAAB', []),
        ('reversed-overlap', [b'AAAB', b'AAAA'], b'AAAAAAAB', []),
        ('rejected-first-overlap', [b'AAAA', b'AAAB'], b'AAAAAAAB', [b'AAAA']),
        ('binary-tags', [b'\x00A\xff\x00', b'\xff\x00\x00A'], b'\x00A\xff\x00\xff\x00\x00A\x00A\xff\x00', []),
        ('no-hit', [b'Driv', b'Wind'], b'none', []),
        ('empty-buffer', [b'Driv'], b'', []),
    ]
    cases = []
    for name, tags, data, reject in inputs:
        constraints = {tag: SimpleNamespace(tag=tag, size=(2, None) if tag in reject else None, page_type=None, index=None) for tag in tags}
        module = SimpleNamespace(get_type=lambda _: SimpleNamespace(relative_child_offset=lambda _: 4), object=lambda object_type, offset, absolute: SimpleNamespace(BlockSize=1, vol=SimpleNamespace(offset=offset)))
        scanner = PoolHeaderScanner(module, constraints, alignment=1)
        matches = [[at, tags.index(tag)] for at, tag in MultiStringScanner(tags)(data, 0)]
        headers = [[header.vol.offset, tags.index(constraint.tag)] for constraint, header in scanner(data, 0x1000)]
        cases.append(dict(id=name, tags_hex=[tag.hex() for tag in tags], data_hex=data.hex(), rejected_indices=[tags.index(tag) for tag in reject], expected_matches=matches, expected_headers=headers))
    duplicate = SimpleNamespace(tag=b'Driv')
    try:
        list(PoolScanner.pool_scan(None, 'kernel', 'virtual', 'nt', [duplicate, duplicate]))
    except ValueError as error:
        duplicate_error = str(error)
    else:
        raise AssertionError('duplicate pool tags were accepted')
    files = ['plugins/windows/poolscanner.py', 'layers/scanners/__init__.py']
    return dict(reference_commit=PIN, source_sha256={name: hashlib.sha256((checkout / 'volatility3/framework' / name).read_bytes()).hexdigest() for name in files}, scope='Actual MultiStringScanner and PoolHeaderScanner, with synthetic decoded pool-header scalars. Tests address order across four-byte tags, constraint-order independence, non-overlap including rejected matches, binary patterns and empty buffers. Does not validate layer chunking, physical/virtual ranges, object carving or field read faults.', duplicate_error=duplicate_error, cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/pool-order.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
