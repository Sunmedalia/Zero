#!/usr/bin/env python3
"""Validate the frozen inventory and report honest full-parity coverage."""
import argparse
from collections import Counter
import json
from pathlib import Path
from inventory import COMMIT, VERSION


def audit(manifest, evidence, contracts=None):
    if manifest['reference_version'] != VERSION or manifest['reference_commit'] != COMMIT:
        raise ValueError('unexpected reference version')
    names = [p['reference'] for p in manifest['plugins']]
    if len(names) != len(set(names)):
        raise ValueError('duplicate reference plugin')
    canonical = {p['reference'] for p in manifest['plugins'] if not p['replacement']}
    for item in manifest['plugins']:
        if item['replacement'] and item['replacement'] not in names:
            raise ValueError(f"unresolved alias {item['reference']}")
        if len(item['source_sha256']) != 64:
            raise ValueError('missing reference source digest')
    verified = set()
    passed_cases = {}
    contracts = contracts or {}
    for item in evidence:
        if item['reference_plugin'] not in canonical:
            raise ValueError('evidence must name a canonical plugin')
        if item['reference_commit'] != COMMIT:
            raise ValueError('evidence is for a different reference version')
        if item['passed']:
            proof = item['comparison']
            if not proof['passed'] or not proof['positive_evidence'] or not proof['all_columns_mapped']:
                raise ValueError('claimed parity lacks a positive full-field comparison')
            if not item.get('sample_source') or len(item.get('image_sha256', '')) != 64:
                raise ValueError('claimed parity lacks reproducible sample identity')
            identity = (item['reference_plugin'], item['case_id'])
            if identity in passed_cases:
                raise ValueError('duplicate case evidence')
            passed_cases[identity] = item
    # A successful default invocation proves one case, never all plugin behavior.
    # Contracts are reviewed parameter/field/failure matrices, not inferred aliases.
    for plugin, contract in contracts.items():
        if plugin not in canonical:
            raise ValueError('contract must name a canonical plugin')
        required = contract['required_cases']
        if not required or len(set(required)) != len(required):
            raise ValueError('empty or duplicate contract cases')
        if not contract.get('requirements_reviewed') or not contract.get('failure_cases_reviewed'):
            continue
        source = next(p['source_sha256'] for p in manifest['plugins'] if p['reference'] == plugin)
        if contract['source_sha256'] != source:
            raise ValueError('contract source has changed')
        if all((plugin, case) in passed_cases for case in required):
            verified.add(plugin)
    return {'reference_version': VERSION, 'reference_commit': COMMIT,
            'plugin_entries': len(names), 'canonical_plugins': len(canonical),
            'aliases': len(names) - len(canonical),
            'platforms': dict(Counter(p['platform'] for p in manifest['plugins'] if not p['replacement'])),
            'passed_cases': len(passed_cases), 'verified_plugins': len(verified), 'outstanding': sorted(canonical - verified),
            'complete': canonical == verified}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, default=Path(__file__).with_name('inventory.json'))
    parser.add_argument('--evidence', type=Path, default=Path(__file__).with_name('evidence.json'))
    parser.add_argument('--contracts', type=Path, default=Path(__file__).with_name('contracts.json'))
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args()
    result = audit(json.loads(args.inventory.read_text()), json.loads(args.evidence.read_text()),
                   json.loads(args.contracts.read_text()))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(1 if args.require_complete and not result['complete'] else 0)


if __name__ == '__main__':
    main()
