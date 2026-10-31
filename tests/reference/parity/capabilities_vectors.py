#!/usr/bin/env python3
"""Pinned capability extraction and decoding over typed field adapters (VSL 1.0)."""
import argparse
from dataclasses import astuple
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
    from volatility3.framework import objects, exceptions, renderers
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.capabilities import Capabilities

    class Node(SimpleNamespace):
        def has_member(self, name): return hasattr(self, name)

    class Array(objects.Array):
        def __init__(self, values, context=None):
            self.entries = values; self._context = context
            self._vol = dict(count=len(values), offset=0, layer_name='memory')
        def __len__(self): return len(self.entries)
        def __getitem__(self, index): return self.entries[index]

    class Modules(dict):
        def get_modules_by_symbol_tables(self, name): return ['kernel']

    class Cap(Node):
        get_kernel_cap_full = extensions.kernel_cap_struct.get_kernel_cap_full
        get_capabilities = extensions.kernel_cap_struct.get_capabilities
        enumerate_capabilities = extensions.kernel_cap_struct.enumerate_capabilities
        get_last_cap_value = extensions.kernel_cap_struct.get_last_cap_value
        capabilities_to_string = extensions.kernel_cap_struct.capabilities_to_string
        def get_symbol_table_name(self): return 'kernel'

    class Val(Cap):
        get_capabilities = extensions.kernel_cap_t.get_capabilities

    specs = [dict(id=f'{kind}-{last}-{value}', kind=kind, last=last, value=value)
             for kind in ['scalar', 'array1', 'array2', 'val']
             for last in [None, 37, 64] for value in [0, (1<<38)-1, (1<<40)|(1<<12), (1<<64)-1]]
    specs += [dict(id=f'bit-{bit}', kind='val', last=40, value=1<<bit) for bit in range(41)]
    specs += [dict(id=f'last-{last}', kind='val', last=last, value=(1<<64)-1) for last in [-2, -1, 0, 63]]
    specs += [dict(id='bad-array-count', kind='array3', last=40, value=1),
              dict(id='ambient-missing', kind='array2', last=37, value=0x2001, ambient=False),
              dict(id='unreadable-parent', kind='val', last=40, value=0x2001, parent_readable=False)]
    cases = []
    for case in specs:
        last, value, kind = case['last'], case['value'], case['kind']
        def symbol(**kw):
            if last is None: raise exceptions.SymbolError('cap_last_cap', 'kernel')
            return last
        context = Node(modules=Modules(kernel=Node(object_from_symbol=symbol)),
                       layers={'memory':Node(maximum_address=100, read=lambda at,length:b'task\0\0\0\0'[at:at+length])})
        cap = Val(_context=context, val=value) if kind == 'val' else Cap(_context=context)
        if kind.startswith('array'):
            cap.cap = Array([(value >> (32*i)) & 0xffffffff for i in range(int(kind[-1]))])
        elif kind == 'scalar': cap.cap = value & 0xffffffff
        real = Node(cap_inheritable=cap, cap_permitted=cap, cap_effective=cap, cap_bset=cap)
        if case.get('ambient', True): real.cap_ambient = cap
        task = Node(comm=Array(list(b'task\0\0\0\0'), context), pid=1, tgid=101,
                    cred=Node(euid=1001), real_cred=real,
                    real_parent=Node(tgid=77, pid=7, is_readable=lambda:case.get('parent_readable', True)))
        task.get_parent_pid = lambda:extensions.task_struct.get_parent_pid(task)
        try:
            identity, caps = Capabilities.get_task_capabilities(task)
            row = list(astuple(identity)) + [Capabilities._decode_cap(c) for c in caps.astuple()]
            case['expected'] = ['N/A' if isinstance(v, renderers.NotAvailableValue) else str(v) for v in row]
        except Exception as error:
            case['error'] = type(error).__name__
        case['value'] = str(value)
        cases.append(case)
    return dict(reference_commit=PIN, source_sha256={p:hashlib.sha256((checkout/p).read_bytes()).hexdigest() for p in [
        'volatility3/framework/plugins/linux/capabilities.py',
        'volatility3/framework/symbols/linux/extensions/__init__.py',
        'volatility3/framework/constants/linux/__init__.py']},
        scope='Actual Capabilities.get_task_capabilities/_decode_cap, bound kernel capability methods and task.get_parent_pid. Typed array/scalar/credential adapters isolate extraction and decoding; no full real task traversal, page recovery, parameter/cache or complete fault contract is certified.', cases=cases)


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'))
    p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/capabilities.json'))
    a=p.parse_args();a.output.write_text(json.dumps(generate(a.checkout.resolve()),indent=2)+'\n')
