#!/usr/bin/env python3
"""Pinned section coalescing and translation-layer chunk iteration (VSL 1.0)."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
from types import SimpleNamespace

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework import contexts
    from volatility3.framework.interfaces.layers import DataLayerInterface, TranslationLayerInterface
    from volatility3.framework.layers.physical import BufferDataLayer
    from volatility3.framework.layers.scanners import RegExScanner
    bounds = SimpleNamespace(minimum_address=0, maximum_address=(1 << 48) - 1)
    specs = [[], [(0, 8)], [(0, 8), (8, 4)], [(0, 12), (4, 4)],
             [(4, 4), (0, 12)], [(0, 16), (4, 8), (6, 1)],
             [(0, 8), (4, 0)], [(0, 0)], [(8, 8), (8, 0)],
             [(0, 8), (4, 4), (6, 8)], [(0, 4), (8, 4)]]
    randomizer = random.Random(100)
    for _ in range(25):
        specs.append([(randomizer.randrange(64), randomizer.randrange(24)) for _ in range(randomizer.randrange(1, 8))])
    coalescing = [dict(sections=sections, expected=list(DataLayerInterface._coalesce_sections(bounds, sections))) for sections in specs]
    scans = []
    scan_specs = [
        ('nested-truncation', [(0, 16), (4, 4)], b'xxneedleXXneedleX', 'needle'),
        ('zero-nested-truncation', [(0, 16), (8, 0)], b'xxneedleXXneedleX', 'needle'),
        ('adjacent', [(0, 4), (4, 12)], b'xxneedleXXneedleX', 'needle'),
        ('overlap', [(0, 12), (8, 8)], b'xxneedleXXneedleX', 'needle'),
        ('empty-at-exact-chunk-end', [(0, 8)], b'xxxxxxxx', '$'),
        ('empty-at-short-tail', [(0, 7)], b'xxxxxxxx', '$'),
        ('empty-at-overlap-end', [(0, 9)], b'xxxxxxxxx', '$'),
        ('cross-chunk', [(0, 16)], b'xxxxxxneedleXXXX', 'needle'),
        ('short-final-tail', [(0, 13)], b'xxxxxxxxxxEND', 'END'),
        ('subject-starts', [(0, 16)], b'xxxxxxxxxxxxxxxx', '^x'),
        ('zero-match-at-overlap-boundary', [(0, 16)], b'xxxxxxxXxxxxxxxx', '(?<=X)'),
        ('empty-sections', [], b'xxxx', '$'),
        ('separated-sections', [(0, 4), (8, 4)], b'xxABxxxxCDxx', 'ABCD'),
    ]
    for name, sections, data, pattern in scan_specs:
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context, 'virtual', 'virtual', buffer=data))
        input_sections = sections
        sections = list(DataLayerInterface._coalesce_sections(bounds, sections))
        # These cases deliberately supply one contiguous backing map per selected
        # section. Discontinuity and empty/fault chunks are covered by the separate
        # mapping-event cases below.
        proxy = SimpleNamespace(name='virtual', context=context,
                                mapping=lambda at, length, ignore_errors: iter([(at, length, at, length, 'physical')] if length else []))
        scanner = RegExScanner(pattern.encode()); scanner.chunk_size = 8; scanner.overlap = 4
        chunks = list(TranslationLayerInterface._scan_iterator(proxy, scanner, sections))
        hits = []
        for chunk in chunks:
            hits.extend(DataLayerInterface._scan_chunk(proxy, scanner, SimpleNamespace(value=0), chunk))
        scans.append(dict(id=name, sections=input_sections, coalesced_sections=sections, data_hex=data.hex(), pattern=pattern,
                          chunk_size=8, overlap=4, chunks=chunks, expected=hits))
    mapping_cases = []
    for name, sections, data, pattern, maps in [
        ('discontinuous-backing', [(0, 8)], b'xxneedle', 'needle', [(0, 4, 0, 4, 'physical'), (4, 4, 12, 4, 'physical')]),
        ('leading-empty-chunk', [(4, 4)], b'xxxxxxxx', '^$', [(4, 4, 4, 4, 'physical')]),
        ('read-failure-empty', [(0,8)], b'xxxx', '^$', [(0,8,0,8,'physical')]),
    ]:
        context = contexts.Context()
        context.layers.add_layer(BufferDataLayer(context, 'virtual', 'virtual', buffer=data))
        proxy = SimpleNamespace(name='virtual', context=context, mapping=lambda *_args, **_kwargs: iter(maps))
        scanner = RegExScanner(pattern.encode()); scanner.chunk_size = 8; scanner.overlap = 4
        chunks = list(TranslationLayerInterface._scan_iterator(proxy, scanner, sections))
        hits = []
        for chunk in chunks: hits.extend(DataLayerInterface._scan_chunk(proxy, scanner, SimpleNamespace(value=0), chunk))
        mapping_cases.append(dict(id=name, sections=sections, data_hex=data.hex(), pattern=pattern, maps=maps,
                               chunk_size=8, overlap=4, chunks=chunks, expected=hits))
    sources = ['volatility3/framework/interfaces/layers.py', 'volatility3/framework/layers/scanners/__init__.py']
    return dict(reference_commit=PIN, source_sha256={p: hashlib.sha256((checkout / p).read_bytes()).hexdigest() for p in sources},
                scope='Actual _coalesce_sections, translation-layer _scan_iterator, _scan_chunk and RegExScanner over supplied contiguous maps and immutable bytes. Reduced 8/4 geometry exercises the same chunk boundary algorithm; production remains 16MiB/4KiB. Mapping events cover discontinuous backing, leading empty chunks and failed chunk reads over supplied map events. No complete page-table discovery, layer bounds clipping, arbitrary regex syntax or full resource contract is certified.',
                coalescing=coalescing, scans=scans, mapping_cases=mapping_cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/regex-sections.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
