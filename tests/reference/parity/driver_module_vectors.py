#!/usr/bin/env python3
"""Actual pinned DriverModule generator, SSDT collection and name fallback (VSL 1.0)."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework import contexts, exceptions
    from volatility3.plugins.windows import ssdt, modules, driverscan
    from volatility3.plugins.windows.malware import drivermodule

    cases = []
    for width in [4, 8]:
        base = 0x80000000 if width == 4 else 0xffff800000000000
        mask = (1 << (32 if width == 4 else 48)) - 1
        variants = [
            ('below-module', {'start': base + 0x1fff}),
            ('module-base', {}),
            ('module-last-byte', {'start': base + 0x2fff}),
            ('module-end', {'start': base + 0x3000}),
            ('after-module', {'start': base + 0x3001}),
            ('zero-size-base', {'module_size': 0}),
            ('zero-size-after', {'module_size': 0, 'start': base + 0x2001}),
            ('empty-module-name', {'module_name': ''}),
            ('faulted-module-name', {'module_name': None}),
            ('zero-start', {'start': 0}),
            ('equal-kernel-boundary', {'start': base}),
            ('user-start', {'start': 0x4000}),
            ('faulted-driver-name', {'start': 0, 'names': [None, 'service', 'alternate']}),
            ('faulted-service-key', {'start': 0, 'names': ['RAW', None, 'alternate']}),
            ('faulted-alternative', {'start': 0, 'names': ['RAW', 'service', None]}),
            ('all-empty', {'start': 0, 'names': ['', '', '']}),
            ('all-faulted', {'start': 0, 'names': [None, None, None]}),
            ('known-case-sensitive', {'start': 0, 'names': ['raw', '', '']}),
        ]
        variants += [(f'known-{name}', {'start': 0, 'names': [name, '', '']}) for name in drivermodule.KNOWN_DRIVERS]
        if width == 8:
            variants += [('masked-start', {'start': 0x1234800000002000}), ('masked-module-base', {'module_base': 0x1234800000002000})]
        for label, overrides in variants:
            c = dict(id=f'{width}-{label}', width=width, start=base + 0x2000, module_base=base + 0x2000, module_size=0x1000, module_name='loaded.sys', names=['RAW', 'service', 'alternate'])
            c.update(overrides)
            context = contexts.Context()
            context._symbol_space = SimpleNamespace(get_symbols_by_location=lambda **kwargs: iter(()))
            contexts.SizedModule.create(context, 'kernel', 'virtual', base & mask, size=0x1000, symbol_table_name='nt')

            class Name:
                def get_string(self):
                    if c['module_name'] is None:
                        raise exceptions.InvalidAddressException('virtual', 0)
                    return c['module_name']

            module = SimpleNamespace(BaseDllName=Name(), DllBase=c['module_base'] & mask, SizeOfImage=c['module_size'])

            def name(index):
                if c['names'][index] is None:
                    raise exceptions.InvalidAddressException('virtual', index)
                return c['names'][index]

            class Unicode:
                def __init__(self, index):
                    self.index = index

                @property
                def String(self):
                    return name(self.index)

            driver = SimpleNamespace(vol=SimpleNamespace(offset=0x2000), DriverStart=c['start'] & mask, get_driver_name=lambda: name(0), DriverExtension=SimpleNamespace(ServiceKeyName=Unicode(1)), DriverName=Unicode(2))
            harness = SimpleNamespace(context=context, config={'kernel': 'kernel'})
            # Keep the actual SSDT builder, ModuleCollection interval query,
            # DriverScan name helper and DriverModule generator unmodified.
            with patch.object(modules.Modules, 'list_modules', lambda *args: [module]), patch.object(modules.Modules, 'get_kernel_space_start', lambda *args: base & mask), patch.object(driverscan.DriverScan, 'scan_drivers', lambda *args: [driver]):
                rows = list(drivermodule.DriverModule._generator(harness))
            c['expected'] = [[bool(row[1][1])] + [value if isinstance(value, str) else '' for value in row[1][2:]] for row in rows]
            cases.append(c)
    from volatility3.framework.symbols.windows.extensions import LIST_ENTRY
    link_cases = []
    for width in [4, 8]:
        variants = [
            ('reverse-only', 0x700, 0x10, [[0x10000, 0x700, 0x700]]),
            ('wrong-blink', 0x10000, 0x10, [[0x10000, 0x11000, 0], [0x11000, 0x700, 0]]),
            ('cycle-away-from-head', 0x10000, 0x10, [[0x10000, 0x11000, 0], [0x11000, 0x10000, 0]]),
            ('null-next', 0x10000, 0x10, [[0x10000, 0, 0]]),
            ('unreadable-next', 0x10000, 0x10, [[0x10000, 0x800000, 0]]),
            ('unreadable-object', 0x1000, 0x2000, [[0x1000, 0x700, 0]]),
            ('partial-list-entry', 0x1fffc, 0x10, [[0x1fffc, 0x700, 0]]),
            ('unaligned-link', 0x10003, 0x10, [[0x10003, 0x700, 0]]),
        ]
        for label, first, relative, nodes in variants:
            valid = lambda at, length=1: 0 <= at and at + length <= 0x20000
            layer = SimpleNamespace(is_valid=valid)
            context = SimpleNamespace(layers={'virtual': layer}, symbol_space=SimpleNamespace(get_type=lambda _: SimpleNamespace(relative_child_offset=lambda _: relative)), object=lambda ty, layer, offset, **kwargs: SimpleNamespace(vol=SimpleNamespace(offset=offset)))

            class Pointer(int):
                def is_readable(self):
                    return valid(int(self), width * 2)

                def dereference(self):
                    return links[int(self)]

            links = {at: SimpleNamespace(vol=SimpleNamespace(offset=at), Flink=Pointer(nxt), Blink=Pointer(prev)) for at, nxt, prev in nodes}
            head = SimpleNamespace(_context=context, vol=SimpleNamespace(layer_name='virtual', native_layer_name='virtual', offset=0x700), Flink=Pointer(first))
            links[0x700] = head
            link_cases.append(dict(id=f'{width}-{label}', width=width, first=first, relative=relative, nodes=nodes, expected=[entry.vol.offset for entry in LIST_ENTRY.to_list(head, 'nt!module', 'InLoadOrderLinks')]))
    paths = ['plugins/windows/malware/drivermodule.py', 'plugins/windows/driverscan.py', 'plugins/windows/ssdt.py', 'contexts/__init__.py', 'symbols/windows/extensions/__init__.py']
    return dict(reference_commit=PIN, source_sha256={path: hashlib.sha256((checkout / 'volatility3/framework' / path).read_bytes()).hexdigest() for path in paths}, scope='Actual DriverModule generator, SSDT builder/ModuleCollection and DriverScan get_names_for_driver. Synthetic module scalars/names and already-scanned driver objects isolate interval ownership, pointer domain, empty/read-fault names, independent fallback and known exceptions. Kernel threshold and pre-carving scan gates have separate vectors; this fixture does not prove traversal, carving or real UTF16 decoding.', cases=cases, links=link_cases, links_scope='Actual LIST_ENTRY.to_list with synthetic pointer and layer validity adapters; tests forward-only traversal, ignored Blink, non-head cycles, null and unreadable pointers, containing-object validity and unaligned links. Native counterparts run real fixture page tables and captured reads.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/driver-module.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
