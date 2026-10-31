#!/usr/bin/env python3
"""Pinned PoolHeaderScanner lazy reads outside the supplied scan slice (VSL 1.0)."""
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
    from volatility3.plugins.windows.poolscanner import PoolHeaderScanner, PoolConstraint, PoolType
    from volatility3.framework import exceptions
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER, POOL_HEADER_VISTA
    cases = []
    for vista in [False, True]:
        for name, start, length, missing in [
            ('full-header', 0x1000, 32, []),
            ('tag-only', 0x1004, 4, []),
            ('tag-plus-tail', 0x1004, 12, []),
            ('one-prefix-byte', 0x1003, 5, []),
            ('unused-tail-missing', 0x1000, 8, list(range(0x1008, 0x1010))),
            ('required-block-missing', 0x1004, 4, [0x1000]),
            ('required-page-missing', 0x1004, 4, [0x1002]),
            ('first-unmapped-tail-byte', 0x1000, 8, [0x1008]),
        ]:
            for page in [0, 1, 2]:
                payload = bytearray(32)
                payload[0:2] = (32).to_bytes(2, 'little')
                payload[2:4] = page.to_bytes(2, 'little')
                payload[4:8] = b'Wind'
                reads = []
                def read(at, size):
                    reads.append([at, size])
                    if any(address in missing for address in range(at, at + size)):
                        raise exceptions.InvalidAddressException('synthetic', at)
                    return int.from_bytes(payload[at - 0x1000:at - 0x1000 + size], 'little')
                pool = POOL_HEADER_VISTA if vista else POOL_HEADER
                class Header:
                    vol = SimpleNamespace(offset=0x1000)
                    BlockSize = property(lambda self: read(0x1000, 2))
                    PoolType = property(lambda self: read(0x1002, 2))
                    is_free_pool = pool.is_free_pool
                    is_paged_pool = pool.is_paged_pool
                    is_nonpaged_pool = pool.is_nonpaged_pool
                module = SimpleNamespace(get_type=lambda _: SimpleNamespace(relative_child_offset=lambda _: 4), object=lambda **kwargs: Header())
                constraint = PoolConstraint(b'Wind', 'gui!station', size=(0x90, None), page_type=PoolType.PAGED | PoolType.NONPAGED)
                scanner = PoolHeaderScanner(module, {b'Wind': constraint}, alignment=16)
                actual = [header.vol.offset for _, header in scanner(bytes(payload[start-0x1000:start-0x1000+length]), start)]
                cases.append(dict(id=f'{int(vista)}-{name}-{page}', vista=vista, scan_start=start, scan_length=length, missing=missing, payload_hex=payload.hex(), expected=actual, reads=reads))
    source = checkout / 'volatility3/framework/plugins/windows/poolscanner.py'
    return dict(reference_commit=PIN, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), pool_extension_sha256=hashlib.sha256((checkout / 'volatility3/framework/symbols/windows/extensions/pool.py').read_bytes()).hexdigest(), scope='Actual PoolHeaderScanner plus actual pre-Vista/Vista pool predicates. Synthetic independent scalar reads isolate tag-only slices, partially external headers, unreadable unused tails and necessary fields. Native tests use real physical/virtual page tables and missing backing segments; these vectors do not prove layer scan chunking or tag discovery across slice boundaries.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/pool-boundaries.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
