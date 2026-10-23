#!/usr/bin/env python3
"""Package the native zero executable and its TypeScript interface without local evidence."""
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
    files = [root / 'target/release/zero', root / 'README.md']
    # The terminal interface is TypeScript; ship its sources, lockfile and the
    # build output so a release runs without a build step on the target host.
    files.extend([root / 'ts/package.json', root / 'ts/package-lock.json'])
    for source in files:
        if not source.is_file():
            parser.error(f'missing release file: {source}')
    if not (root / 'ts/dist').is_dir():
        parser.error('missing ts/dist; run `cd ts && npm install && npm run build` first')
    if not (root / 'docs/tui.md').is_file():
        parser.error('missing docs/tui.md')
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f'{name}.tar.gz'
    with tarfile.open(archive, 'w:gz') as package:
        for source in files:
            package.add(source, arcname=f'{name}/{source.name}', recursive=False)
        package.add(root / 'ts/dist', arcname=f'{name}/ts/dist')
        package.add(root / 'ts/src', arcname=f'{name}/ts/src')
        package.add(root / 'docs/tui.md', arcname=f'{name}/docs/tui.md')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + '.sha256').write_text(f'{digest}  {archive.name}\n')
    print(archive)


if __name__ == '__main__':
    main()
