#!/usr/bin/env python3
"""Actual pinned selected-range Intel mappings and reads (VSL 1.0)."""
import argparse
import json
from pathlib import Path
from windows_layer_read_vectors import generate

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checkout',type=Path,default=Path('target/reference/volatility3'))
    p.add_argument('--output',type=Path,default=Path('tests/reference/parity/fixtures/intel-scan.json'))
    a=p.parse_args();data=generate(a.checkout.resolve(),extended=True)
    data['scope']='Actual Intel32e/WindowsIntel/WindowsIntelPAE/WindowsIntel32e selected-range mapping and read, including explicit swap layers, physical backing holes and table uniformity. Linux32/ARM64, discovery, all layer bounds/overflow, container and exception/resource contracts remain unverified.'
    a.output.write_text(json.dumps(data,indent=2)+'\n')
