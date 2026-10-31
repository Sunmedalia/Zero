#!/usr/bin/env python3
"""Pinned module base/core-size layout precedence using field adapters (VSL 1.0)."""
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
    from volatility3.framework.symbols.linux.extensions import module

    class Module(SimpleNamespace):
        def has_member(self, name):
            return hasattr(self, name)

        def _get_mem_base(self, name):
            return self.mem_values[name][0]

        def _get_mem_size(self, name):
            return self.mem_values[name][1]

    cases = []
    for layout in ['legacy', 'core-layout-and-legacy', 'mem-and-legacy', 'all-layouts']:
        value = Module(module_core=0x18000, core_size=4096)
        if layout in ['core-layout-and-legacy', 'all-layouts']:
            value.core_layout = SimpleNamespace(base=0x1a000, size=3072)
        if layout in ['mem-and-legacy', 'all-layouts']:
            value.mem = True
            value.mem_values = {'MOD_TEXT': (0x19000, 1024), 'MOD_DATA': (0, 1024),
                                'MOD_RODATA': (0, 0), 'MOD_RO_AFTER_INIT': (0, 0)}
        cases.append(dict(id=layout, base=module.get_module_base(value),
                          core_size=module.get_core_size(value)))
    source = 'volatility3/framework/symbols/linux/extensions/__init__.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout/source).read_bytes()).hexdigest()},
                scope='Actual module.get_module_base/get_core_size methods; synthetic members and memory-index adapters isolate layout priority. No real ISF reads, list faults, init sizes, six-column display or dump contract are established.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--output', type=Path, default=Path('tests/reference/parity/fixtures/module-layouts.json'))
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2)+'\n')
