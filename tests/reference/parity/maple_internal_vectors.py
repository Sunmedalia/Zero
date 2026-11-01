#!/usr/bin/env python3
"""Execute pinned internal maple traversal with synthetic typed nodes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace, MethodType

PIN = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'


def generate(checkout):
    assert subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    sys.path.insert(0, str(checkout))
    from volatility3.framework.symbols.linux.extensions import maple_tree
    cases = []
    for width in [4, 8]:
        for kind in [2, 3]:
            leaves = [0x14004, 0x14104] if width == 4 else [0x14000, 0x14100]
            nodes = {0x11000: [0x1200c, 0, 0x1300c, 0], 0x12000: [leaves[0], 0, 0, 0], 0x13000: [leaves[1], 0, 0, 0]}
            parents = {0x11000: 0xb029, 0x12000: 0x11006, 0x13000: 0x11006}
            def object_at(name, **kwargs):
                at = kwargs['offset']
                if name.endswith('!pointer'):
                    return parents[at]
                assert name.endswith('!maple_node')
                return SimpleNamespace(mr64=SimpleNamespace(slot=nodes[at]), ma64=SimpleNamespace(slot=nodes[at]))
            mock = SimpleNamespace(vol=SimpleNamespace(offset=0xb028, native_layer_name='memory', layer_name='memory'), _context=SimpleNamespace(object=object_at), get_symbol_table_name=lambda: 'kernel')
            for attr in ['MAPLE_NODE_TYPE_SHIFT', 'MAPLE_NODE_TYPE_MASK', 'MAPLE_NODE_POINTER_MASK', 'MAPLE_DENSE', 'MAPLE_LEAF_64', 'MAPLE_RANGE_64', 'MAPLE_ARANGE_64']:
                setattr(mock, attr, getattr(maple_tree, attr))
            mock._parse_maple_tree_node = MethodType(maple_tree._parse_maple_tree_node, mock)
            root = 0x11002 | (kind << 3)
            for mismatch in [False, True]:
                parents[0x13000] = 0x16006 if mismatch else 0x11006
                for duplicate in [False, True]:
                    nodes[0x11000][1] = 0x1200c if duplicate else 0
                    found = list(mock._parse_maple_tree_node(root, 0xb000, 2))
                    cases.append(dict(width=width, kind=kind, parent_mismatch=mismatch, duplicate=duplicate, root=root, nodes=[dict(address=at, parent=parents[at], slots=list(slots)) for at, slots in nodes.items()], found=found))
    source = 'volatility3/framework/symbols/linux/extensions/__init__.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout / source).read_bytes()).hexdigest()}, scope='Actual pinned RANGE64/ARANGE64 recursion and parent validation with mocked typed slots; no real-image claim.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
