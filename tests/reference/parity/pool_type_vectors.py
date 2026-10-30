#!/usr/bin/env python3
"""Pinned Handles.get_type_map boundaries for canonical PoolScanner (VSL 1.0)."""
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
    from volatility3.plugins.windows.handles import Handles
    from volatility3.framework import exceptions, objects, contexts
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import Intel32e
    from volatility3.framework.symbols.windows.extensions.pool import POOL_HEADER
    cases = []
    for case_id, entries, valid in [
        ('null-sentinel', [None, 'File', None, 'SymbolicLink'], True),
        ('null-at-one', [None, None, 'File'], True),
        ('unreadable-name', [None, '!unreadable', 'File', None], True),
        ('hundred-limit', [None] + ['File'] * 100, True),
        ('invalid-table', [None, 'File', None], False),
        ('nonzero-index-zero', ['Zero', 'File', None], True),
    ]:
        class Pointer(int):
            @property
            def vol(self):
                return SimpleNamespace(offset=0x1000 + int(self) * 8)

            def dereference(self):
                if int(self) == 0:
                    raise exceptions.InvalidAddressException('synthetic', 0)
                value = entries[int(self) - 1]
                if value == '!unreadable' or value is None:
                    raise exceptions.InvalidAddressException('synthetic', int(self))
                return SimpleNamespace(cast=lambda _: SimpleNamespace(Name=SimpleNamespace(String=value)))

        pointers = [Pointer(i + 1) if value is not None else Pointer(0) for i, value in enumerate(entries)]
        kernel = SimpleNamespace(
            layer_name='synthetic', offset=0, symbol_table_name='synthetic',
            get_symbol=lambda _: SimpleNamespace(address=0x1000),
            get_type=lambda _: None,
            object=lambda **kw: pointers[:kw['count']],
        )
        context = SimpleNamespace(modules={'kernel': kernel}, layers={'synthetic': SimpleNamespace(is_valid=lambda _: valid)})
        expected = Handles.get_type_map(context, 'kernel')
        cases.append(dict(id=case_id, entries=entries, table_valid=valid, expected=expected))
    context = SimpleNamespace(
        symbol_space=SimpleNamespace(get_type=lambda _: None),
        object=lambda *args, **kw: SimpleNamespace(vol=SimpleNamespace(offset=kw['offset']), is_valid=lambda: False))
    header = SimpleNamespace(_context=context, vol=SimpleNamespace(type_name='synthetic!_POOL_HEADER', size=16, offset=0x1000, layer_name='synthetic'))
    constraint = SimpleNamespace(type_name='synthetic!_CMHIVE', object_type=None)
    nonexecutive = [obj.vol.offset for obj in POOL_HEADER.get_object(header, constraint, True)]
    pointer_cases = []
    for width, value in [(8, 0xd10000000001011c), (8, 0xffffd98df3046c2c), (8, 0x800000001234), (8, 0x1234), (4, 0xf1234567)]:
        mask = (1 << (48 if width == 8 else 32)) - 1
        class Layers(dict):
            def read(self, layer, offset, length):
                return value.to_bytes(width, 'little')
        context = SimpleNamespace(layers=Layers(synthetic=SimpleNamespace(address_mask=mask)))
        info = SimpleNamespace(native_layer_name='synthetic', layer_name='synthetic', offset=0)
        expected = objects.Pointer._unmarshall(context, objects.DataFormatInfo(width, 'little', False), info)
        pointer_cases.append(dict(width=width, raw=value, expected=expected))
    data = bytearray(0x10000)
    for at, value in [(0x1000, 0x2003), (0x1000 + 256 * 8, 0x2003), (0x1000 + 510 * 8, 0x1003), (0x2000, 0x3003), (0x3000, 0x4003), (0x4000, 0x8003)]:
        data[at:at + 8] = value.to_bytes(8, 'little')
    context = contexts.Context()
    context.layers.add_layer(BufferDataLayer(context, 'physical', 'physical', buffer=bytes(data)))
    context.config['kernel.memory_layer'] = 'physical'
    context.config['kernel.page_map_offset'] = 0x1000
    layer = Intel32e(context, 'kernel', 'kernel')
    context.layers.add_layer(layer)
    alias = (510 << 39) | (256 << 30)
    recursive_mapping = dict(address=alias, mappings=list(layer.mapping(alias, 4096)))
    return dict(reference_commit=PIN,
                source_sha256=hashlib.sha256((checkout / 'volatility3/framework/plugins/windows/handles.py').read_bytes()).hexdigest(),
                scope='Actual get_type_map with synthetic pointers and names; validates boundaries and missing-name handling only. Non-executive get_object stub returns an object with is_valid=False; verifies that this validation is not called.', cases=cases,
                nonexecutive_bodies=nonexecutive, pointer_cases=pointer_cases,
                intel_source_sha256=hashlib.sha256((checkout / 'volatility3/framework/layers/intel.py').read_bytes()).hexdigest(),
                recursive_mapping=recursive_mapping,
                user_mapping=dict(address=0, mappings=list(layer.mapping(0, 4096))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/pool-types.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
