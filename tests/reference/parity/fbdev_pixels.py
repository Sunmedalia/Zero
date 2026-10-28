#!/usr/bin/env python3
"""Test-only pixel/RAW comparison against the pinned fbdev conversion functions.

Uses only generated synthetic bytes. This is not a real-image plugin parity case.
Reference code is loaded from the pinned checkout, never copied into the runtime.
"""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace


def run(checkout, cases):
    checkout = checkout.resolve()
    commit = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != '881e970121c16f0932fb9d16fbd5fb258cbcbf75':
        raise ValueError('unexpected reference commit')
    if subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip():
        raise ValueError('reference source modified')
    sys.path.insert(0, str(checkout))
    from PIL import Image
    from volatility3.plugins.linux.graphics.fbdev import Fbdev, Framebuffer
    results = []
    for case in cases:
        raw = Path(case['raw']).read_bytes()
        def read(address, length):
            assert address == 0 and length == len(raw)
            return raw
        context = SimpleNamespace(modules={'kernel': SimpleNamespace(layer_name='memory')},
                                  layers={'memory': SimpleNamespace(read=read)})
        fields = {name: tuple(channel) for name, channel in zip('RGBA', case['channels'])}
        fb = Framebuffer('synthetic', case['width'], case['height'], case['stride'], case['bpp'],
                         len(raw), fields, SimpleNamespace(screen_base=0))
        if case['format'] == 'PNG':
            reference = Fbdev.convert_fb_raw_buffer_to_image(context, 'kernel', fb)
            with Image.open(case['native']) as native:
                native.load()
                assert native.format == 'PNG' and native.mode == 'RGBA' and native.size == reference.size
                actual, expected = native.tobytes(), reference.tobytes()
        else:
            class Output(io.BytesIO):
                preferred_filename = 'synthetic.raw'
                def __exit__(self, *_):
                    self.saved = self.getvalue()
            output = Output()
            Fbdev.dump_fb(context, 'kernel', lambda _: output, fb, False)
            actual, expected = Path(case['native']).read_bytes(), output.saved
        equal = actual == expected
        assert equal == case['expect_equal'], case['id']
        results.append({'id': case['id'], 'format': case['format'], 'equal': equal,
                        'expected_equal': case['expect_equal'],
                        'compared_bytes': len(actual), 'native_sha256': hashlib.sha256(actual).hexdigest(),
                        'reference_sha256': hashlib.sha256(expected).hexdigest()})
    print(json.dumps({'reference_commit': commit, 'scope': 'synthetic conversion functions only', 'cases': results}))


if __name__ == '__main__':
    run(Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text()))
