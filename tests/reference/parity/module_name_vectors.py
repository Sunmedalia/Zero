#!/usr/bin/env python3
"""Execute pinned name reads over actual Intel32e translation layers (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.objects.utility import address_to_string

    cases = []
    for name, payload, first, second in [
        ('prefix', b'abcdefghijklmnop', True, False),
        ('nul-prefix', b'test\0abcdefghijk', True, False),
        ('first-missing', b'abcdefghijklmnop', False, True),
        ('control', b'a\x01b\0abcdefghijkl', True, False),
        ('invalid-utf8', b'a\xffb\0abcdefghijkl', True, False),
    ]:
        data = bytearray(0x20000)
        def put(at, value):
            data[at:at + 8] = value.to_bytes(8, 'little')
        for at, value in [(0x1000, 0x2003), (0x2000, 0x3003), (0x3000, 0x4003),
                          (0x4000, 0x8003 if first else 0), (0x4008, 0x9003 if second else 0)]:
            put(at, value)
        data[0x8ff0:0x9000] = payload
        data[0x9000:0xa000] = b'Z' * 4096
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', buffer=bytes(data)))
        context.config['kernel.memory_layer'] = 'physical'
        context.config['kernel.page_map_offset'] = 0x1000
        context.layers.add_layer(Intel32e(context, 'kernel', 'kernel'))
        try:
            value = address_to_string(context, 'kernel', 0xff0, 64)
            error = None
        except exceptions.InvalidAddressException as exc:
            value, error = None, type(exc).__name__
        cases.append(dict(id=name, payload_hex=payload.hex(), first_present=first,
                          second_present=second, expected=value, error=error))
    source = 'volatility3/framework/objects/utility.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout / source).read_bytes()).hexdigest()},
                scope='Actual address_to_string over Intel32e and BufferDataLayer; synthetic 4K page tables. Not ARM64 or full module display evidence.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), ensure_ascii=False, indent=2) + '\n')
