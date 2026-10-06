#!/usr/bin/env python3
"""Package native release binaries without local images, symbols or runtime data."""
import argparse
import hashlib
import subprocess
import tarfile
import tomllib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    host = next(line.removeprefix('host: ') for line in
                subprocess.check_output(['rustc', '-vV'], text=True).splitlines()
                if line.startswith('host: '))
    if args.target != host:
        parser.error('target must match the native build host')
    version = tomllib.loads((root / 'Cargo.toml').read_text())['package']['version']
    name = f'zero-{version}-{host}'
    files = [root / 'target/release' / binary for binary in ('zero', 'zero-tui', 'zero-mcp')]
    files.append(root / 'README.md')
    for source in files:
        if not source.is_file():
            parser.error(f'missing release file: {source}')
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f'{name}.tar.gz'
    with tarfile.open(archive, 'w:gz') as package:
        for source in files:
            package.add(source, arcname=f'{name}/{source.name}', recursive=False)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + '.sha256').write_text(f'{digest}  {archive.name}\n')
    print(archive)


if __name__ == '__main__':
    main()
