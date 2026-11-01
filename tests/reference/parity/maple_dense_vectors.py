#!/usr/bin/env python3
"""Execute pinned maple dense-node traversal with synthetic context objects."""
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
    from volatility3.framework.symbols.linux.extensions import maple_tree
    cases = []
    for width, slots in [(4, [0x12004, 0x12104, 0, 0x12204]), (8, [0x12000, 0x12100, 0, 0x12200])]:
        def object_at(name, **kwargs):
            if name.endswith('!pointer'):
                return 0xb000
            assert name.endswith('!maple_node')
            return SimpleNamespace(alloc=SimpleNamespace(slot=slots))
        mock = SimpleNamespace(
            vol=SimpleNamespace(offset=0xb028, native_layer_name='memory', layer_name='memory'),
            _context=SimpleNamespace(object=object_at), get_symbol_table_name=lambda: 'kernel',
        )
        for attr in ['MAPLE_NODE_TYPE_SHIFT', 'MAPLE_NODE_TYPE_MASK', 'MAPLE_NODE_POINTER_MASK', 'MAPLE_DENSE', 'MAPLE_LEAF_64', 'MAPLE_RANGE_64', 'MAPLE_ARANGE_64']:
            setattr(mock, attr, getattr(maple_tree, attr))
        found = list(maple_tree._parse_maple_tree_node(mock, 0x11002, 0xb000, 1))
        cases.append(dict(width=width, root=0x11002, slots=slots, found=found))
    source = 'volatility3/framework/symbols/linux/extensions/__init__.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout / source).read_bytes()).hexdigest()}, scope='Actual pinned dense-node iteration with mocked typed slots; no real image or complete VMA validity claim.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
