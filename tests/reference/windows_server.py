#!/usr/bin/env python3
"""Reference-only Volatility 3 bootstrap adapters; analysis stays in stock plugins.

Use --pae-dtb ADDRESS --kernel-base ADDRESS for a validated small x86 PAE
page table rejected by Volatility's populated-entry heuristic. Use
--bitmap-type6 for SDMPDUMP type 6 (Volatility 3 2.28 only enables types 1/5).
Pass the remaining arguments unchanged to vol. No image or ISF is modified.
"""
import argparse
import sys
from volatility3 import cli
from volatility3.framework.automagic import windows
from volatility3.framework.layers import crash, intel, physical

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--pae-dtb', type=lambda v: int(v, 0))
parser.add_argument('--kernel-base', type=lambda v: int(v, 0))
parser.add_argument('--bitmap-type6', action='store_true')
args, remaining = parser.parse_known_args()
if bool(args.pae_dtb) != bool(args.kernel_base):
    parser.error('--pae-dtb and --kernel-base must be supplied together')
if args.pae_dtb:
    def stack(cls, context, layer_name, progress_callback=None):
        if not isinstance(context.layers[layer_name], physical.FileLayer):
            return None
        path = 'ExplicitServerPAE'
        context.config[path + '.memory_layer'] = layer_name
        context.config[path + '.page_map_offset'] = args.pae_dtb
        layer = intel.WindowsIntelPAE(context, path,
            context.layers.free_layer_name('ServerPAE'), metadata={'os': 'Windows'})
        layer.config['kernel_virtual_offset'] = args.kernel_base
        return layer
    windows.WindowsIntelStacker.stack = classmethod(stack)
if args.bitmap_type6:
    original = crash.WindowsCrashDump64Layer
    class BitmapType6(original):
        supported_dumptypes = original.supported_dumptypes + [6]
        def _load_segments(self):
            dump_type = self.dump_type
            if dump_type == 6:
                signature = self.context.layers[self._base_layer].read(0x2000, 8)
                if signature != b'SDMPDUMP':
                    raise ValueError('Type 6 adapter requires an SDMPDUMP bitmap')
                self.dump_type = 5
            try:
                super()._load_segments()
            finally:
                self.dump_type = dump_type
    crash.WindowsCrashDump64Layer = BitmapType6
sys.argv = [sys.argv[0]] + remaining
cli.main()
