#!/usr/bin/env python3
"""Run explicitly selected offline cases against Zero and pinned Volatility.

Reference tools and their test wrappers are distributed under VSL 1.0:
https://www.volatilityfoundation.org/license/vsl-v1.0
No image or recovered content is uploaded. Downloads are a separate preparation step.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
from compare import compare
from inventory import COMMIT, VERSION


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def compare_artifacts(native, reference):
    left = {str(p.relative_to(native)): p for p in native.rglob('*') if p.is_file()}
    right = {str(p.relative_to(reference)): p for p in reference.rglob('*') if p.is_file()}
    records = []
    for name in sorted(left.keys() | right.keys()):
        n, r = left.get(name), right.get(name)
        record = {'name': name, 'zero_sha256': digest(n) if n else None,
                  'reference_sha256': digest(r) if r else None,
                  'zero_bytes': n.stat().st_size if n else None,
                  'reference_bytes': r.stat().st_size if r else None}
        record['passed'] = bool(n and r and record['zero_bytes'] > 0 and record['zero_sha256'] == record['reference_sha256'])
        records.append(record)
    return records


def execute(command, output, log, timeout):
    started = time.monotonic()
    with output.open('wb') as stdout, log.open('wb') as stderr:
        try:
            code = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=timeout, check=False).returncode
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'elapsed_seconds': time.monotonic() - started, 'command': command}
    return {'status': 'completed', 'exit_code': code, 'elapsed_seconds': time.monotonic() - started,
            'command': command, 'output_sha256': digest(output), 'log_sha256': digest(log)}


def run(config, output, zero, checkout, python, timeout):
    if subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip() != COMMIT:
        raise ValueError('reference checkout must match pinned commit')
    if subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=no'], text=True).strip():
        raise ValueError('reference tracked source was modified')
    output.mkdir(parents=True, exist_ok=True)
    cache = (output / 'reference-cache').resolve()
    cache.mkdir(exist_ok=True)
    prepared = {}
    for sample in config['samples']:
        image = Path(sample['image']).resolve(strict=True)
        if digest(image) != sample['image_sha256']:
            raise ValueError(f"image SHA256 mismatch: {sample['id']}")
        for symbol in sample['symbol_files']:
            if digest(Path(symbol['path']).resolve(strict=True)) != symbol['sha256']:
                raise ValueError(f"symbol SHA256 mismatch: {symbol['path']}")
        prepared[sample['id']] = sample
    records = []
    for index, case in enumerate(config['cases']):
        sample = prepared[case['sample']]
        destination = output / f'{index:03d}'
        destination.mkdir(exist_ok=True)
        native_output = destination / 'zero.json'
        reference_output = destination / 'reference.json'
        artifacts = case.get('artifact_dump', False)
        zero_files, ref_files = destination / 'zero-files', destination / 'reference-files'
        if artifacts:
            # Every run gets fresh evidence paths; never reuse prior binary dumps.
            zero_files.mkdir()
            ref_files.mkdir()
        zero_cmd = [str(zero), '--offline', 'analyze', '--image', str(Path(sample['image']).resolve()),
                    '--symbols', str(Path(sample['zero_symbols']).resolve()), '--plugin', case['zero_plugin'],
                    '--no-cache', '--output', str(native_output.resolve()), *case.get('zero_args', [])]
        if artifacts:
            zero_cmd += ['--dump-dir', str(zero_files)]
        # Zero exports JSON itself; console output is kept separately.
        native = execute(zero_cmd, destination / 'zero.stdout', destination / 'zero.stderr', timeout)
        ref_cmd = [str(python), str(checkout / 'vol.py'), '--offline', '--cache-path', str(cache),
                   '-s', str(Path(sample['reference_symbols']).resolve()), '-f', str(Path(sample['image']).resolve()),
                   '-r', 'json', case['reference_plugin'], *case.get('reference_args', [])]
        if artifacts:
            ref_cmd[2:2] = ['-o', str(ref_files)]
        reference = execute(ref_cmd, reference_output, destination / 'reference.stderr', timeout)
        record = {'sample': sample['id'], 'sample_source': sample.get('source'),
                  'case_id': case.get('id', str(index)),
                  'zero_args': case.get('zero_args', []), 'reference_args': case.get('reference_args', []), 'image_sha256': sample['image_sha256'],
                  'reference_plugin': case['reference_plugin'], 'zero_plugin': case['zero_plugin'],
                  'zero': native, 'reference': reference, 'passed': False}
        try:
            if native['status'] != 'completed' or reference['status'] != 'completed':
                raise ValueError('one or both engines timed out')
            if reference['exit_code'] != 0:
                raise ValueError('reference engine failed; not comparable')
            mapping_path = Path(case['mapping'])
            mapping = json.loads(mapping_path.read_text())
            record['mapping_sha256'] = digest(mapping_path)
            n = json.loads(native_output.read_text())
            if native['exit_code'] != 0 and (n['complete'] or not mapping.get('allow_partial', False)):
                raise ValueError('native engine failed without an explicitly accepted partial result')
            record['comparison'] = compare(n, json.loads(reference_output.read_text()), mapping)
            record['passed'] = record['comparison']['passed']
            if artifacts:
                record['artifacts'] = compare_artifacts(zero_files, ref_files)
                record['passed'] = record['passed'] and bool(record['artifacts']) and all(item['passed'] for item in record['artifacts'])
            record['native_output_sha256'] = digest(native_output)
        except (OSError, ValueError, KeyError) as error:
            record['error'] = str(error)
        (destination / 'comparison.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
        records.append(record)
    report = {'schema_version': 1, 'reference_version': VERSION, 'reference_commit': COMMIT,
              'zero_executable_sha256': digest(zero), 'cases': records, 'passed': bool(records) and all(r['passed'] for r in records)}
    (output / 'summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--zero', type=Path, default=Path('target/release/zero'))
    parser.add_argument('--reference', type=Path, default=Path('target/reference/volatility3'))
    parser.add_argument('--python', type=Path, default=Path('target/reference/venv/bin/python'))
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    report = run(json.loads(args.config.read_text()), args.output.resolve(), args.zero.resolve(strict=True),
                 args.reference.resolve(strict=True), args.python.absolute(), args.timeout)
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
