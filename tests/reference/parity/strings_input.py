#!/usr/bin/env python3
"""Create a bounded, deterministic external strings file from public RAW test data.
No synthetic text is represented as recovered image content. Output stays local.
"""
import argparse
import hashlib
from pathlib import Path
import re

def generate(image, output):
    size = image.stat().st_size
    # Low addresses exercise the reference's process-key domain; tail pages give
    # captured strings whose physical frames may have no live kernel mapping.
    ranges = [(0, min(size, 8 << 20)), (max(0, size - (1 << 20)), size)]
    lines = []
    seen = set()
    with image.open('rb') as stream:
        for begin, end in ranges:
            stream.seek(begin)
            data = stream.read(end - begin)
            for page in range(0, len(data), 4096):
                match = re.search(rb'[A-Za-z_][\x20-\x7e]{5,63}', data[page:page + 4096])
                if not match:
                    continue
                address = begin + page + match.start()
                if address in seen:
                    continue
                seen.add(address)
                lines.append(str(address).encode('ascii') + b' ' + match[0] + b'\n')
    # Intentional exact duplicate verifies input multiplicity, not ownership dedup.
    if lines:
        lines.append(lines[0])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b''.join(lines))
    return {'image_bytes': size, 'records': len(lines),
            'strings_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(generate(args.image, args.output))
