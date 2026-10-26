#!/usr/bin/env python3
"""Package zero with a native Node runtime and isolated production dependencies."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path


NODE_TARGETS = {
    'x86_64-unknown-linux-gnu': ('linux', 'x64'),
    'aarch64-unknown-linux-gnu': ('linux', 'arm64'),
    'x86_64-apple-darwin': ('darwin', 'x64'),
    'aarch64-apple-darwin': ('darwin', 'arm64'),
}


def validate_symlinks(directory):
    """Keep npm's relative links, but reject links that escape the shipped tree."""
    directory = directory.resolve()
    for path in directory.rglob('*'):
        if path.is_symlink():
            target = path.readlink()
            if target.is_absolute() or not path.resolve(strict=True).is_relative_to(directory):
                raise ValueError(f'unsafe dependency symlink: {path} -> {target}')
        elif not (path.is_file() or path.is_dir()):
            raise ValueError(f'unsupported dependency file: {path}')


def validate_node(node, license_path, host):
    if host not in NODE_TARGETS:
        raise ValueError(f'unsupported Node release target: {host}')
    metadata = json.loads(subprocess.check_output([
        str(node), '-p', 'JSON.stringify({version:process.versions.node,'
        'platform:process.platform,arch:process.arch,name:process.release.name,'
        'shared:process.config.variables.node_shared})',
    ], text=True))
    if (metadata['platform'], metadata['arch']) != NODE_TARGETS[host]:
        raise ValueError(f'Node platform/architecture does not match {host}: {metadata}')
    if int(metadata['version'].split('.')[0]) < 22 or metadata['name'] != 'node':
        raise ValueError(f'Node 22 or newer is required: {metadata}')
    if metadata['shared']:
        raise ValueError('Node must be self-contained, not linked to a shared libnode')
    # setup-node's official distribution only needs OS libraries. In particular,
    # do not silently ship a Homebrew/system build linked to local dependencies.
    if metadata['platform'] == 'darwin':
        libraries = subprocess.check_output(['otool', '-L', str(node)], text=True)
        for line in libraries.splitlines()[1:]:
            library = line.strip().split(' (', 1)[0]
            if not library.startswith(('/usr/lib/', '/System/Library/')):
                raise ValueError(f'Node requires a non-system library: {library}')
    else:
        libraries = subprocess.check_output(['ldd', str(node)], text=True)
        allowed = re.compile(r'^(?:linux-vdso\.so|ld-linux[^/]*\.so|lib(?:c|m|dl|rt|pthread|stdc\+\+|gcc_s|atomic)\.so)(?:\.|$)')
        for line in libraries.splitlines():
            library = line.strip().split()[0]
            if 'not found' in line or not allowed.match(Path(library).name):
                raise ValueError(f'Node requires an unsupported library: {line.strip()}')
    if not license_path.is_file() or 'Node.js' not in license_path.read_text():
        raise ValueError(f'missing Node distribution LICENSE: {license_path}')
    return metadata


def production_dependencies(root, staging, npm, node):
    lock = json.loads((root / 'ts/package-lock.json').read_text())
    packages = lock.get('packages')
    if lock.get('lockfileVersion', 0) < 2 or not isinstance(packages, dict):
        raise ValueError('a package-lock with package metadata is required')
    for name, package in packages.items():
        if name and not package.get('dev') and (package.get('hasInstallScript') or package.get('link')):
            raise ValueError(f'production dependency needs an installation review: {name}')
    for name in ('package.json', 'package-lock.json'):
        shutil.copy2(root / 'ts' / name, staging / name)
    env = os.environ.copy()
    # npm's env-node shebang must use the exact runtime selected for packaging.
    env['PATH'] = str(node.parent) + os.pathsep + env.get('PATH', '')
    env.pop('NODE_ENV', None)
    env.pop('NODE_OPTIONS', None)
    subprocess.run([
        str(npm), 'ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund',
    ], cwd=staging, env=env, check=True)
    dependencies = staging / 'node_modules'
    validate_symlinks(dependencies)
    for manifest in dependencies.rglob('package.json'):
        package = json.loads(manifest.read_text())
        scripts = package.get('scripts', {})
        if any(script in scripts for script in ('preinstall', 'install', 'postinstall')):
            raise ValueError(f'production dependency has disabled install scripts: {manifest}')
    if next(dependencies.rglob('binding.gyp'), None) or next(dependencies.rglob('*.node'), None):
        raise ValueError('native production modules require an explicit build/packaging review')
    for name, package in packages.items():
        if name and package.get('dev') and (staging / name).exists():
            raise ValueError(f'development dependency leaked into production staging: {name}')
    return dependencies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    parser.add_argument('--node', type=Path, required=True,
                        help='native self-contained Node 22+ executable (CI: setup-node)')
    parser.add_argument('--node-license', type=Path,
                        help='LICENSE from the same Node distribution (default: ../LICENSE)')
    parser.add_argument('--npm', type=Path, default=Path(shutil.which('npm') or 'npm'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    host = next(line.removeprefix('host: ') for line in
                subprocess.check_output(['rustc', '-vV'], text=True).splitlines()
                if line.startswith('host: '))
    if args.target != host:
        parser.error('target must match the native build host')
    node = args.node.resolve(strict=True)
    npm = args.npm.resolve(strict=True)
    license_path = args.node_license or node.parent.parent / 'LICENSE'
    version = tomllib.loads((root / 'Cargo.toml').read_text())['package']['version']
    name = f'zero-{version}-{host}'
    files = [root / 'target/release/zero', root / 'README.md',
             root / 'ts/package.json', root / 'ts/package-lock.json', root / 'docs/tui.md']
    for source in files:
        if not source.is_file():
            parser.error(f'missing release file: {source}')
    for directory in ('ts/dist', 'ts/src'):
        if not (root / directory).is_dir():
            parser.error(f'missing {directory}; run make ui-build first')
    try:
        metadata = validate_node(node, license_path, host)
        with tempfile.TemporaryDirectory(prefix='zero-release-deps-') as temporary:
            dependencies = production_dependencies(root, Path(temporary), npm, node)
            args.output.mkdir(parents=True, exist_ok=True)
            archive = args.output / f'{name}.tar.gz'
            # TarFile preserves npm's relative symlinks instead of dereferencing them.
            with tarfile.open(archive, 'w:gz', dereference=False) as package:
                for source in files:
                    relative = Path('zero') if source == files[0] else source.relative_to(root)
                    package.add(source, arcname=f'{name}/{relative}', recursive=False)
                package.add(root / 'ts/dist', arcname=f'{name}/ts/dist')
                package.add(root / 'ts/src', arcname=f'{name}/ts/src')
                package.add(dependencies, arcname=f'{name}/ts/node_modules')
                package.add(node, arcname=f'{name}/runtime/node', recursive=False)
                package.add(license_path, arcname=f'{name}/runtime/LICENSE', recursive=False)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    archive.with_suffix(archive.suffix + '.sha256').write_text(f'{digest}  {archive.name}\n')
    print(f'{archive} (Node {metadata["version"]}, {metadata["platform"]}/{metadata["arch"]})')


if __name__ == '__main__':
    main()
