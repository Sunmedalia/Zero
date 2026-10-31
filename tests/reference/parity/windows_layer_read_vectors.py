#!/usr/bin/env python3
"""Actual pinned Intel layer reads including explicit swap layers (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout, extended=False):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework import contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.intel import WindowsIntel, WindowsIntelPAE, WindowsIntel32e, Intel32e

    cases = []
    architectures=[('x86', WindowsIntel, 4, [22, 12]),
                   ('pae', WindowsIntelPAE, 8, [30, 21, 12]),
                   ('x64', WindowsIntel32e, 8, [39, 30, 21, 12])]
    if extended: architectures.append(('linux', Intel32e, 8, [39, 30, 21, 12]))
    for arch, cls, width, shifts in architectures:
        for kind in ['resident', 'transition', 'prototype', 'prototype-transition',
                     'swap-zero', 'swap-three', 'swap-no-attachment', 'swap-wrong-index',
                     'swap-no-bit7', 'swap-no-high', 'swap-transition', 'swap-prototype',
                     'upper-swap', 'upper-swap-pat', 'upper-prototype', 'physical-hole', 'table-hole', 'short-swap', 'empty-swap'] + (((['present-high45'] if width==8 else [])+['uniform-table','large-pat']) if extended else []):
            data = bytearray(0x400000 if kind=='large-pat' else 0x20000)
            writes = []
            def put(at, value):
                data[at:at + width] = value.to_bytes(width, 'little')
                writes.append([at, value])
            for i in range(len(shifts) - 1):
                put(0x1000 + i * 0x1000, 0x2003 + i * 0x1000)
            leaf = 0x1000 * len(shifts)
            put(leaf, 0x8003); put(leaf + width, 0xa003); put(leaf + 2 * width, 0xb800)
            bit_offset = 12 if arch == 'x86' else 32
            attached = 0
            pagefile_length = 0x10000
            holes = []
            if kind=='present-high45' and width==8:put(leaf,(1<<45)|0x8003)
            elif kind=='uniform-table':
                for at in range(leaf,leaf+4096,width):put(at,0x8003)
            elif kind=='large-pat':put(leaf-0x1000,0x201083)
            elif kind == 'transition': put(leaf, 0x8800)
            elif kind == 'prototype': put(leaf, 0x8400)
            elif kind == 'prototype-transition': put(leaf, 0x8c00)
            elif kind.startswith('swap') or kind in ['short-swap', 'empty-swap']:
                entry = (1 << bit_offset) | 0x80
                if kind == 'swap-three': entry |= 3 << 1; attached = 3
                if kind == 'swap-no-attachment': attached = None
                if kind == 'swap-wrong-index': attached = 3
                if kind == 'swap-no-bit7': entry &= ~0x80
                if kind == 'swap-no-high': entry = 0x80
                if kind == 'swap-transition': entry |= 1 << 11
                if kind == 'swap-prototype': entry |= 1 << 10
                if kind == 'short-swap': pagefile_length = 4101
                if kind == 'empty-swap': pagefile_length = 0
                put(leaf + width, entry)
            elif kind.startswith('upper'):
                entry = (1 << bit_offset) | (0x80 if kind.startswith('upper-swap') else 0x400)
                if kind == 'upper-swap-pat': entry = (3 << bit_offset) | 0x80 | (1 << 12)
                put(leaf - 0x1000, entry)
                pagefile_length = (4 << shifts[-2]) + 0x3000
            elif kind == 'physical-hole': holes = [[0x8000, 0x9000]]
            elif kind == 'table-hole': holes = [[leaf, leaf + 4096]]
            patterned_ranges=[[0x8000,0xc000]]+([[0x200000,0x400000]] if kind=='large-pat' else [])
            for start,end in patterned_ranges:
                for i in range(start,end):data[i]=(i*17+3)%251
            class Capture(BufferDataLayer):
                def is_valid(self, offset, length=1):
                    return super().is_valid(offset, length) and not any(offset < end and offset + length > start for start, end in holes)
            ctx = contexts.Context()
            ctx.layers.add_layer(Capture(ctx, 'physical', 'physical', buffer=bytes(data)))
            ctx.config['kernel.memory_layer'] = 'physical'
            ctx.config['kernel.page_map_offset'] = 0x1000
            if attached is not None:
                backing = bytes((i * 13 + 7) % 251 for i in range(pagefile_length))
                ctx.layers.add_layer(BufferDataLayer(ctx, 'swap', 'swap', buffer=backing))
                ctx.config['kernel.swap_layers'] = True
                ctx.config[f'kernel.swap_layers.swap_layers{attached}'] = 'swap'
            layer = cls(ctx, 'kernel', 'kernel'); ctx.layers.add_layer(layer)
            queries = []
            for at, length in [(0, 16), (3, 16), (4090, 24), (4096, 16), (4099, 16), (8192, 16), (0x123, 1), (4096, 4), (4099, 1), (8190, 4)]:
                try:
                    value = layer.read(at, length).hex(); error = None
                except exceptions.InvalidAddressException as exc:
                    value = None; error = type(exc).__name__
                queries.append(dict(address=at, length=length, expected_hex=value, error=error))
            mapping_queries=[]
            if extended:
                for start,length in [(0,12288),(3,4098),(4096,4)]:
                    expected=[[at,at+size,physical,0 if layer_name=='physical' else 1+attached] for at,size,physical,_,layer_name in layer.mapping(start,length,ignore_errors=True)]
                    mapping_queries.append(dict(start=start,end=start+length,expected=expected))
            record=dict(id=f'{arch}-{kind}', arch=arch, width=width, writes=writes,
                              attached=attached, pagefile_length=pagefile_length, holes=holes, queries=queries)
            if extended:record.update(data_length=len(data),patterned_ranges=patterned_ranges,mapping_queries=mapping_queries)
            cases.append(record)
    sources = ['volatility3/framework/layers/intel.py', 'volatility3/framework/interfaces/layers.py',
               'volatility3/framework/layers/physical.py']
    return dict(reference_commit=PIN, source_sha256={p: hashlib.sha256((checkout / p).read_bytes()).hexdigest() for p in sources},
                scope='Actual WindowsIntel/WindowsIntelPAE/WindowsIntel32e read with physical and explicit swap BufferDataLayers over synthetic page tables. Resident/transition/prototype flags, fixed swap bits and indices, unaligned/cross-page reads, upper-level software entries, missing attachments, backing and table holes are covered. Synthetic adapters do not establish all scanner mapping/chunk/padding or full architecture/platform/exception/resource contracts. Reference swap reads intentionally preserve the pinned offset semantics.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/windows-layer-read.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
