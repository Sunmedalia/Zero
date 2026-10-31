#!/usr/bin/env python3
"""Pinned Boottime/timekeeping methods with synthetic typed kernel objects (VSL 1.0)."""
import argparse
import datetime
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
    from volatility3.framework.symbols.linux import extensions
    from volatility3.plugins.linux.boottime import Boottime

    class Node(SimpleNamespace):
        def has_member(self, name):
            return hasattr(self, name)

    class Scalar(int):
        def has_member(self, name):
            return False

    class Modules(dict):
        def get_modules_by_symbol_tables(self, name):
            return ['kernel']

    class Task:
        def get_symbol_table_name(self):
            return 'kernel'

        def has_member(self, name):
            return hasattr(self, name)

        def is_valid(self):
            return True

    for method in ['get_time_namespace', 'get_time_namespace_id', '_get_time_namespace_offsets',
                   '_get_time_namespace_boottime_offset', '_get_boottime_raw', 'get_boottime']:
        setattr(Task, method, getattr(extensions.task_struct, method))

    cases = []
    specifications = [dict(id=kind, kind=kind, root=1_700_000_000_456_789_123, tasks=[None, None])
                      for kind in ['modern', 'wrapped', 'global-timekeeper', 'wall-timespec', 'wall-scalar', 'wall-only']]
    specifications += [
        dict(id='pre-nsproxy', kind='wall-only', root=1_700_000_000_456_789_123, namespace_layout='no-proxy', tasks=[None]),
        dict(id='pre-time-ns', kind='global-timekeeper', root=1_700_000_000_456_789_123, namespace_layout='no-time', tasks=[None]),
        dict(id='namespace-order-and-duplicate', kind='modern', root=1_700_000_000_456_789_123,
             tasks=[dict(id=42, offset=[5, 123456789]), dict(id=42, offset=[99, 0]),
                    dict(id=43, offset=[-2, 800000000]), None]),
        dict(id='no-offset-member', kind='modern', root=1_700_000_000_456_789_123,
             tasks=[dict(id=7), dict(id=8)]),
        dict(id='zero-namespace-distinct-from-none', kind='modern', root=1_700_000_000_000_000_000,
             tasks=[dict(id=0), None, dict(id=0)]),
        dict(id='empty-task-list', kind='unsupported', root=0, tasks=[]),
        dict(id='unsupported-timekeeping', kind='unsupported', root=0, tasks=[None]),
    ]
    for value in [0, -1, 500, 1500, 2500, 999_999_999, 1_700_000_000_123_456_500,
                  4_102_444_801_123_456_789, 253_402_300_799_999_999_999]:
        specifications.append(dict(id=f'datetime-{value}', kind='wall-only' if value > (1<<63)-123_000_000_001 else 'modern', root=value, tasks=[None]))
    for case in specifications:
        kind, root = case['kind'], case['root']
        symbols = {}
        spec = extensions.Timespec64Concrete
        if kind in ['modern', 'wrapped']:
            real, boot = root + 123_000_000_000, 123_000_000_000
            wrap = (lambda v: Node(tv64=v)) if kind == 'wrapped' else Scalar
            symbols['tk_core'] = Node(timekeeper=Node(offs_real=wrap(real), offs_boot=wrap(boot)))
        elif kind == 'global-timekeeper':
            symbols['timekeeper'] = Node(wall_to_monotonic=spec.new_from_nsec(-root-10_000_000_000), total_sleep_time=spec(10, 0))
        elif kind.startswith('wall'):
            sleep = 0 if kind == 'wall-only' else 10_000_000_000
            symbols['wall_to_monotonic'] = spec.new_from_nsec(-root-sleep)
            if kind == 'wall-timespec': symbols['total_sleep_time'] = spec(10, 0)
            if kind == 'wall-scalar': symbols['total_sleep_time'] = Scalar(10)
            if 'total_sleep_time' in symbols:
                symbols['total_sleep_time'].vol = Node(type_name='kernel!'+('timespec' if kind == 'wall-timespec' else 'unsigned long'))
        tasks = []
        module = Node(has_symbol=lambda name: name in symbols,
                      get_type=lambda name: Node(has_member=lambda field: field == ('time_ns' if name == 'nsproxy' else 'wall_to_monotonic') and (name != 'nsproxy' or case.get('namespace_layout') != 'no-time')))
        context = Node(modules=Modules(kernel=module))
        for index, namespace in enumerate(case['tasks']):
            task = Task();task._context = context;task.vol = Node(offset=0xa000+index*0x100)
            ns = None
            if namespace is not None:
                ns = Node(ns=Node(inum=namespace['id']))
                if 'offset' in namespace: ns.offsets = Node(boottime=spec(*namespace['offset']))
            if case.get('namespace_layout') != 'no-proxy': task.nsproxy = Node(time_ns=ns)
            tasks.append(task)
        init = Node(vol=Node(type_name='kernel!task_struct'), tasks=Node(to_list=lambda **kw: iter(tasks if kw['forward'] else reversed(tasks))))
        module.object_from_symbol = lambda symbol_name: init if symbol_name == 'init_task' else symbols[symbol_name]
        try:
            rows = list(Boottime.get_time_namespaces_bootime(context, 'kernel'))
            case['expected'] = [[str(ns) if ns else 'N/A', time.isoformat() if isinstance(time, datetime.datetime) else 'N/A'] for ns,time in rows]
        except Exception as error:
            case['error'] = type(error).__name__
        case['root'] = str(root)
        cases.append(case)
    return dict(reference_commit=PIN,
                source_sha256={p: hashlib.sha256((checkout/p).read_bytes()).hexdigest() for p in [
                    'volatility3/framework/plugins/linux/boottime.py',
                    'volatility3/framework/symbols/linux/extensions/__init__.py',
                    'volatility3/framework/renderers/conversion.py',
                    'volatility3/framework/constants/linux/__init__.py']},
                scope='Actual Boottime.get_time_namespaces_bootime, PsList iteration and bound task_struct time namespace/timekeeping methods. Synthetic typed objects supply fields and list order; this does not prove real page-table recovery, every task validity rule, all layouts, full fault contracts or timeline integration.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/boottime.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2)+'\n')
