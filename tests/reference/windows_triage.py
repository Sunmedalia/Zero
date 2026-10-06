#!/usr/bin/env python3
"""Independently compare saved x64 TRIAGE_DUMP header, CONTEXT and driver records.
No kernel/plugin coverage is inferred from this small-dump metadata comparison.
"""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('image')
parser.add_argument('prefix')
args = parser.parse_args()
data = Path(args.image).read_bytes()
def uint(offset, width):
    return int.from_bytes(data[offset:offset + width], 'little')
assert data[:8] == b'PAGEDU64' and uint(0xf98, 4) == 4
assert uint(48, 4) == 0x8664
h = 0x2000
crash = json.loads(Path(args.prefix + 'windows.crashinfo.json').read_text())
values = dict(crash['rows'])
assert int(values['Code'], 0) == uint(56, 4)
for index in range(4):
    assert int(values[f'Parameter{index+1}'], 0) == uint(64+index*8, 8)
context = uint(h + 12, 4)
assert uint(context+48, 4) & 0x100003 == 0x100003
assert int(values['Context0.Thread.Rip'], 0) == uint(context+248, 8)
assert int(values['Context0.Thread.Rsp'], 0) == uint(context+152, 8)
modules = json.loads(Path(args.prefix + 'windows.modules.json').read_text())
actual = {(int(row[1], 0), int(row[2]), row[3]) for row in modules['rows']}
drivers, count = uint(h + 48, 4), uint(h + 52, 4)
expected = set()
for index in range(count):
    record = drivers + index*144
    name = uint(record, 4)
    chars = uint(name, 4)
    path = data[name+4:name+4+chars*2].decode('utf-16le')
    expected.add((uint(record+56, 8), uint(record+72, 8), path))
assert actual == expected
assert crash['kernel_identity']['metadata']['build'] == uint(12, 4)
print(f'triage: build={uint(12,4)} drivers={count} shared_modules={len(actual)} '
      'header_fields=5 context_fields=2 conflicts=0; product identity remains publisher-reported')
