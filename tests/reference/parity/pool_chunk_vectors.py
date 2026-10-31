#!/usr/bin/env python3
"""Pinned data/translation layer scan chunks and overlap emission (VSL 1.0)."""
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
    from volatility3.framework import interfaces, contexts, exceptions
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.scanners import MultiStringScanner
    chunk, overlap = 0x1000000, 0x1000
    plans = []
    variants = [(f'length-{length}', [[0, length]]) for length in [0, 1, chunk-1, chunk, chunk+1, chunk+overlap-1, chunk+overlap, chunk+overlap+1, 2*chunk, 2*chunk+overlap+7]]
    variants += [('adjacent-map-boundary', [[0x1000, 0x1000], [0x2000, 0x1000]]), ('mapping-gap', [[0x1000, 0x1000], [0x4000, 0x2000]]), ('unaligned-long-mapping', [[0x1234, chunk+100], [0x1234+chunk+100, 0x2000]])]
    for translated in [False, True]:
        for label, ranges in variants:
            scanner = MultiStringScanner([b'Driv'])
            layer = SimpleNamespace(name='synthetic', mapping=lambda *args, **kwargs: ((at, size, at+0x10000000, size, 'physical') for at, size in ranges))
            if translated:
                iterator = interfaces.layers.TranslationLayerInterface._scan_iterator(layer, scanner, [(0, max(at+size for at,size in ranges))])
            else:
                iterator = interfaces.layers.DataLayerInterface._scan_iterator(layer, scanner, ranges)
            expected = []
            for pieces, end in iterator:
                if not pieces:
                    continue
                assert len(pieces) == 1, pieces
                _, at, size = pieces[0]
                expected.append([at, size])
                assert end == at + size
            plans.append(dict(id=f'{int(translated)}-{label}', translated=translated, ranges=ranges, expected=expected))
    scans = []
    for translated in [False, True]:
        for label, length, tags, faults in [
            ('cross-boundary', chunk+overlap+8, [chunk-2, chunk+8], []),
            ('overlap-only', chunk+overlap+8, [chunk+4, chunk+overlap-4], []),
            ('short-tail-repeat', chunk+100, [chunk-20, chunk+4], []),
            ('exact-full-overlap', chunk+overlap, [chunk-20, chunk+4], []),
            ('bad-first-chunk', 2*chunk+overlap+8, [100, chunk+100, 2*chunk+4], [0]),
            ('bad-second-chunk', 2*chunk+overlap+8, [100, chunk+100, 2*chunk+4], [1]),
        ]:
            data = bytearray(length)
            for at in tags:
                data[at:at+4] = b'Driv'
            ctx = contexts.Context()
            ctx.layers.add_layer(BufferDataLayer(ctx, 'physical', 'physical', buffer=bytes(data)))
            scanner = MultiStringScanner([b'Driv'])
            class Layers:
                def __getitem__(self, name):
                    return self
                def read(self, address, size):
                    if any(address <= bad*chunk < address+size for bad in faults):
                        raise exceptions.InvalidAddressException('physical', address)
                    return bytes(data[address:address+size])
            layer = SimpleNamespace(name='synthetic', context=SimpleNamespace(layers=Layers()), mapping=lambda *args, **kwargs: iter([(0, length, 0, length, 'physical')]))
            if translated:
                iterator = interfaces.layers.TranslationLayerInterface._scan_iterator(layer, scanner, [(0, length)])
            else:
                iterator = interfaces.layers.DataLayerInterface._scan_iterator(layer, scanner, [(0, length)])
            chunks = []
            expected = []
            for pieces, end in iterator:
                if not pieces:
                    continue
                chunks.append([[at,size] for _,at,size in pieces])
                expected.extend(at for at, _ in interfaces.layers.DataLayerInterface._scan_chunk(layer, scanner, SimpleNamespace(value=0), (pieces,end)))
            scans.append(dict(id=f'{int(translated)}-{label}', translated=translated, length=length, tags=tags, fault_chunks=faults, expected=expected, chunks=chunks))
    # Actual default scan omits maximum_address itself (it is inclusive).
    data=b'....Driv'
    ctx=contexts.Context()
    layer=BufferDataLayer(ctx,'physical','physical',buffer=data)
    ctx.layers.add_layer(layer)
    scanner=MultiStringScanner([b'Driv'])
    default_length=layer.maximum_address-layer.minimum_address
    expected=[at for at,_ in layer.scan(ctx,scanner)]
    files=['interfaces/layers.py','layers/scanners/__init__.py']
    return dict(reference_commit=PIN, source_sha256={name:hashlib.sha256((checkout/'volatility3/framework'/name).read_bytes()).hexdigest() for name in files}, chunk_size=chunk, overlap=overlap, scope='Actual DataLayerInterface/TranslationLayerInterface scan iterators and actual _scan_chunk/MultiStringScanner. Synthetic mapping ranges and read-fault adapter isolate chunk plans, overlap output suppression, data-layer tail repeats and continuation after failed chunks. Does not prove mapping enumeration, crash/hibernation decompression or full pool object carving.', plans=plans, scans=scans, default_section=dict(payload_hex=data.hex(), expected=expected, length=default_length))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'))
    parser.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/pool-chunks.json'))
    args=parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()),indent=2)+'\n')
