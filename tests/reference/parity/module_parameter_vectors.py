#!/usr/bin/env python3
"""Pinned module parameter value methods with scalar adapters (VSL 1.0)."""
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
    from volatility3.framework.symbols.linux.utilities.modules import Modules
    from volatility3.framework import exceptions
    handlers = [('param_get_invbool', 'int', 4, True), ('param_get_bool', 'int', 4, True),
                ('param_get_int', 'int', 4, True), ('param_get_ulong', 'long unsigned int', 8, False),
                ('param_get_ullong', 'long long unsigned int', 8, False), ('param_get_long', 'long int', 8, True),
                ('param_get_uint', 'unsigned int', 4, False), ('param_get_ushort', 'short unsigned int', 2, False),
                ('param_get_short', 'short int', 2, True), ('param_get_byte', 'char', 1, True)]
    addresses = {name: 0x15000 + i*16 for i, (name, _, _, _) in enumerate(handlers)}
    class Kernel:
        def get_absolute_symbol_address(self, name):
            if name not in addresses:
                raise exceptions.SymbolError(name, 'kernel')
            return addresses[name]

        def object(self, object_type, offset):
            assert object_type == case['type'], (object_type, case['type'])
            assert offset == 0x12000
            if case.get('fault'):
                raise exceptions.InvalidAddressException('virtual', offset)
            return case['value']

        def get_symbols_by_absolute_location(self, at):
            return []

    context = SimpleNamespace(modules={'kernel': Kernel()})
    integer_map, getters = Modules._get_param_handlers(context, 'kernel')
    cases = []
    for index, (name, ty, size, signed) in enumerate(handlers):
        values = [0, 1, -1] if signed else [0, (1 << (size*8))-1]
        for value in values:
            case = dict(id=f'{name}-{value}', getter=addresses[name], type=ty, size=size, signed=signed, value=value)
            result = Modules._get_param_val(context, 'kernel', integer_map, getters,
                                            SimpleNamespace(vol=SimpleNamespace(offset=0x10000)),
                                            SimpleNamespace(get=addresses[name], arg=0x12000))
            case['expected'] = None if result is None else str(result)
            cases.append(case)
    for name, getter, fault in [('unknown', 0x18000, False), ('null', 0, False), ('unreadable-int', addresses['param_get_int'], True)]:
        case = dict(id=name, getter=getter, type='int', size=4, signed=True, value=42, fault=fault)
        result = Modules._get_param_val(context, 'kernel', integer_map, getters,
                                        SimpleNamespace(vol=SimpleNamespace(offset=0x10000)),
                                        SimpleNamespace(get=getter, arg=0x12000))
        case['expected'] = None if result is None else str(result)
        cases.append(case)
    source = 'volatility3/framework/symbols/linux/utilities/modules.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout/source).read_bytes()).hexdigest()},
                handlers=addresses, scope='Actual _get_param_handlers and _get_param_val handler-to-type selection, integer values, boolean truth tables, unknown/null and scalar-read failure branches with supplied Python integer reads. Reference integer width/sign decoding is not exercised. Does not establish aliases, getter-read faults, array/string/name faults or the full Lsmod contract.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/module-parameters.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2)+'\n')
