#!/usr/bin/env python3
"""Execute pinned hidden-module scan with a synthetic layer and module objects."""
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
    cases = []
    for width, candidate, known, lower in [
        (4, 0x35104, 0x34100, 0x34000),
        (4, 0x35105, 0x34101, 0x34000),
        (8, 0x35105, 0x34101, 0x34000),
        (4, 0x35105, 0x34100, 0x34001),
        (8, 0x35109, 0x34100, 0x34001),
    ]:
        reads = []
        payload = candidate.to_bytes(width, 'little') + b'\xef\xbe\xad\xde'
        def read(at, count):
            reads.append((at, count))
            return bytes(payload[at - candidate - 88:at - candidate - 88 + count]) if candidate + 88 <= at and at + count <= candidate + 88 + len(payload) else bytes(count)
        def get_type(name):
            if name == 'pointer':
                return SimpleNamespace(size=width)
            if name == 'module':
                return SimpleNamespace(relative_child_offset=lambda _: 56)
            assert name == 'module_kobject'
            return SimpleNamespace(relative_child_offset=lambda _: 32, child_template=lambda _: SimpleNamespace(size=width, data_format=SimpleNamespace(byteorder='little', signed=False)))
        def make_object(_type, offset, absolute):
            return SimpleNamespace(vol=SimpleNamespace(offset=offset), is_valid=lambda: offset == candidate)
        kernel = SimpleNamespace(layer_name='memory', get_type=get_type, object=make_object)
        context = SimpleNamespace(modules={'kernel': kernel}, layers={'memory': SimpleNamespace(read=read)})
        found = [m.vol.offset for m in Modules.get_hidden_modules(context, 'kernel', {known}, (lower, 0x37000))]
        cases.append(dict(width=width, candidate=candidate, known=known, lower=lower, upper=0x37000, found=found, first_read=reads[0], read_count=len(reads)))
    source = 'volatility3/framework/symbols/linux/utilities/modules.py'
    return dict(reference_commit=PIN, source_sha256={source: hashlib.sha256((checkout / source).read_bytes()).hexdigest()}, scope='Actual pinned get_hidden_modules alignment, member-width prefilter and candidate sequence with mocked validity only.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(generate(args.checkout.resolve()), indent=2) + '\n')
