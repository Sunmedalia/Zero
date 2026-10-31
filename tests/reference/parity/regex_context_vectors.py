#!/usr/bin/env python3
"""Pinned Linux/Windows regex generators with supplied task/section/layer adapters (VSL 1.0)."""
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
    from volatility3.framework import objects
    from volatility3.plugins.linux.vmaregexscan import VmaRegExScan
    from volatility3.plugins.windows.vadregexscan import VadRegExScan
    from volatility3.plugins.linux.pslist import PsList

    class Array(objects.Array):
        def __init__(self, context):
            self._context = context
            self._vol = dict(layer_name='name', offset=0, count=16)

    class Name:
        vol = SimpleNamespace(count=16)
        def cast(self, *_args, **_kwargs):
            return 'sample'

    cases = []
    specs = [
        ('literal', 'ABAB', b'xxABABtail'),
        ('lookbehind', '(?<=AB)AB', b'xxABABtail'),
        ('dotall-display', 'A.B', b'xxA\nBtail'),
        ('long-match', 'A{160}', b'xx' + b'A' * 160 + b'tail'),
        ('backreference', r'(?P<x>AB)(?P=x)', b'xxABABtail'),
        ('invalid-text', r'AB.', b'xxAB\xfftail'),
    ]
    for system, cls, base in [('linux', VmaRegExScan, 0x200000), ('windows', VadRegExScan, 0x1000)]:
        for name, pattern, data in specs:
            for maxsize in [None, -1, 0, 1, 4, 128, 4097, (1 << 63) - 1]:
                reads = []
                class Layer:
                    def read(self, offset, length, pad=False):
                        reads.append([offset, length, pad])
                        relative = offset - base
                        return data[relative:relative + length].ljust(length, b'\0')
                    def scan(self, context, scanner, sections, progress_callback):
                        assert sections == [(base, len(data))]
                        yield from scanner(data, base)
                class NameLayer:
                    maximum_address = 0x1000
                    def read(self, offset, length):
                        return b'sample\0'.ljust(16, b'\0')[offset:offset + length]
                context = SimpleNamespace(layers={'process': Layer(), 'name': NameLayer()})
                task = SimpleNamespace(
                    mm=1, pid=43, tgid=42, UniqueProcessId=42,
                    comm=Array(context), ImageFileName=Name(),
                    add_process_layer=lambda: 'process',
                    get_process_memory_sections=lambda: [(base, len(data))],
                    get_vad_root=lambda: SimpleNamespace(traverse=lambda: [SimpleNamespace(get_start=lambda: base, get_size=lambda: len(data))]),
                )
                plugin = SimpleNamespace(context=context, config={'maxsize': maxsize},
                                         _progress_callback=None, MAXSIZE_DEFAULT=cls.MAXSIZE_DEFAULT)
                rows = []
                for depth, row in cls._generator(plugin, pattern, [task]):
                    assert depth == 0
                    rows.append([str(row[0]), row[1], hex(int(row[2])), row[3], row[4].hex(' ')])
                cases.append(dict(id=f'{system}-{name}-{maxsize}', system=system, pattern=pattern,
                                  maxsize=maxsize, data_hex=data.hex(), expected=rows, reads=reads))
    filters = []
    for pids in [[], [43], [42], [43, 43], [42, 43]]:
        filters.append(dict(pids=pids, pid=43, tgid=42,
                            excluded=PsList.create_pid_filter(pids)(SimpleNamespace(pid=43, tgid=42))))
    sources = ['volatility3/framework/plugins/linux/vmaregexscan.py',
               'volatility3/framework/plugins/windows/vadregexscan.py',
               'volatility3/framework/plugins/linux/pslist.py',
               'volatility3/framework/layers/scanners/__init__.py',
               'volatility3/framework/objects/utility.py']
    return dict(reference_commit=PIN, source_sha256={p: hashlib.sha256((checkout / p).read_bytes()).hexdigest() for p in sources},
                scope='Actual canonical regex generators and RegExScanner over supplied task/section/layer adapters. Read calls, displayed Text/Hex and ignored maxsize configuration are captured. Linux PID filter is executed separately with distinct PID/TGID. Does not certify task/VAD/VMA admission, platform translation, full layer chunk/missing-page behavior, arbitrary Python regex syntax or all failure/resource contracts.',
                cases=cases, pid_filters=filters)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/regex-context.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
