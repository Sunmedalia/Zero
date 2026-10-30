#!/usr/bin/env python3
"""Execute pinned EPROCESS/ETHREAD validity predicates on synthetic fields (VSL 1.0)."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
DATE = datetime.datetime


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework import objects
    from volatility3.framework.objects import utility
    from volatility3.framework.symbols.windows import extensions
    from volatility3.framework.renderers.conversion import wintime_to_datetime

    def ticks(text):
        value = DATE.fromisoformat(text).replace(tzinfo=datetime.timezone.utc)
        delta = value - DATE(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return (delta.days * 86400 + delta.seconds) * 10000000

    def pointer(raw):
        return raw & ((1 << 48) - 1)

    class ArrayDtb(objects.Array):
        def __init__(self, value):
            self.value = value
        def cast(self, _):
            return pointer(self.value)

    base = ticks('2020-06-01')
    process = []
    cases = [
        ('default', {}), ('empty-name', {'name_hex': '00'}),
        ('invalid-first', {'name_hex': 'ff776f726b6572'}),
        ('system-invalid-tail', {'name_hex': b'System\xfftail'.hex(), 'pid': 4, 'created': 0}),
        ('pid-zero', {'pid': 0}), ('pid-unaligned', {'pid': 3}),
        ('pid-max', {'pid': 0xfffffffc}), ('pid-too-large', {'pid': 0x100000000}),
        ('pointer-pid-mask', {'pid': 0xd100000000000008, 'pid_pointer': True}),
        ('integer-pid-preserved', {'pid': 0xd100000000000008, 'pid_pointer': False}),
        ('created-zero', {'created': 0}), ('created-subsecond-zero', {'created': 1}),
        ('created-negative', {'created': -1}), ('created-overflow', {'created': 0x7fffffffffffffff}),
        ('year-1998', {'created': ticks('1998-12-31T23:59:59')}),
        ('year-1999-start', {'created': ticks('1999-01-01')}),
        ('upper-before', {'created': ticks('2035-12-31T23:59:59')}),
        ('upper-exact', {'created': ticks('2036-01-01')}),
        ('later-clock-before', {'year': 2035, 'created': ticks('2044-12-31T23:59:59')}),
        ('later-clock-exact', {'year': 2035, 'created': ticks('2045-01-01')}),
        ('exit-before', {'exited': base - 10000000}),
        ('exit-same-second-earlier-tick', {'created': base + 9, 'exited': base + 1}),
        ('exit-subsecond-zero', {'exited': 1}), ('exit-negative', {'exited': -1}),
        ('exit-overflow', {'exited': 0x7fffffffffffffff}),
        ('dtb-zero', {'dtb': 0}), ('dtb-pcid-only', {'dtb': 0x123}),
        ('dtb-integer-high-bit', {'dtb': 1 << 63}),
        ('dtb-array-high-bit', {'dtb': 1 << 63, 'dtb_array': True}),
        ('dtb-array-mask-valid', {'dtb': (1 << 63) | 0x1000, 'dtb_array': True}),
        ('flink-low', {'flink': 0x1234}),
        ('flink-mask-low', {'flink': 0xd100000000001234}),
        ('blink-low', {'blink': 0x1234}),
    ]
    for case_id, overrides in cases:
        c = dict(id=case_id, year=2026, name_hex=b'worker\0'.hex(), pid=8, pid_pointer=True,
                 created=base, exited=0, dtb=0x1000, dtb_array=False, flink=0x80000000, blink=0x80000000)
        c.update(overrides)
        class Clock(DATE):
            @classmethod
            def now(cls, tz=None):
                return cls(c['year'], 6, 1, tzinfo=tz)
        harness = SimpleNamespace(
            ImageFileName=bytes.fromhex(c['name_hex']), UniqueProcessId=pointer(c['pid']) if c['pid_pointer'] else c['pid'],
            CreateTime=SimpleNamespace(QuadPart=c['created']),
            get_create_time=lambda: wintime_to_datetime(c['created']),
            get_exit_time=lambda: wintime_to_datetime(c['exited']),
            Pcb=SimpleNamespace(DirectoryTableBase=ArrayDtb(c['dtb']) if c['dtb_array'] else c['dtb']),
            ThreadListHead=SimpleNamespace(Flink=pointer(c['flink']), Blink=pointer(c['blink'])))
        with patch.object(extensions.datetime, 'datetime', Clock), patch.object(utility, 'array_to_string', lambda data: utility.bytes_to_decoded_string(data, 'utf-8', 'replace')):
            c['expected'] = extensions.EPROCESS.is_valid(harness)
        process.append(c)
    thread = []
    for case_id, overrides in [
        ('default', {}), ('system-no-time', {'pid': 4, 'created': 0}),
        ('pid-unaligned', {'pid': 3}), ('tid-unaligned', {'tid': 3}),
        ('created-zero', {'created': 0}), ('created-negative', {'created': -1}),
        ('year-1999-start', {'created': ticks('1999-01-01')}),
        ('upper-exact', {'created': ticks('2036-01-01')}),
        ('later-clock-before', {'year': 2035, 'created': ticks('2044-12-31T23:59:59')}),
        ('legacy-packed', {'legacy': True, 'created': base << 3}),
        ('legacy-negative', {'legacy': True, 'created': -8}),
    ]:
        c = dict(id=case_id, year=2026, pid=8, tid=12, created=base, legacy=False)
        c.update(overrides)
        class Clock(DATE):
            @classmethod
            def now(cls, tz=None): return cls(c['year'], 6, 1, tzinfo=tz)
        harness = SimpleNamespace(Cid=SimpleNamespace(UniqueProcess=pointer(c['pid']), UniqueThread=pointer(c['tid'])),
            CreateTime=SimpleNamespace(QuadPart=c['created']), has_member=lambda _: c['legacy'])
        harness.get_create_time = lambda: extensions.ETHREAD.get_create_time(harness)
        with patch.object(extensions.datetime, 'datetime', Clock):
            c['expected'] = extensions.ETHREAD.is_valid(harness)
        thread.append(c)
    return dict(reference_commit=PIN,
                source_sha256=hashlib.sha256((checkout / 'volatility3/framework/symbols/windows/extensions/__init__.py').read_bytes()).hexdigest(),
                conversion_sha256=hashlib.sha256((checkout / 'volatility3/framework/renderers/conversion.py').read_bytes()).hexdigest(),
                scope='Actual EPROCESS/ETHREAD validity and datetime conversion; synthetic decoded field inputs, array_to_string adapter uses the actual byte decoder, local calendar frozen to explicit years. Does not model unreadable structure pages or complete pool carving.', process=process, thread=thread)


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    p.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/pool-validity.json'))
    a=p.parse_args()
    a.output.write_text(json.dumps(generate(a.checkout.resolve()), indent=2)+'\n')
