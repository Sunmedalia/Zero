#!/usr/bin/env python3
"""Strict, declarative comparison of native and reference JSON artifacts."""
import argparse
import datetime
from collections import defaultdict
import json
from pathlib import Path


def normalize(value, kind):
    # Some optional text fields mean an empty value (e.g. no module taints),
    # not a failed read. Use this only in a reviewed per-field mapping; native
    # partial results are still rejected unless separately allowed.
    if kind == 'na_text':
        if value == 'N/A' or value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f'invalid optional text: {value!r}')
        return value
    if kind == 'empty_text':
        if value is None:
            return ''
        if not isinstance(value, str):
            raise ValueError(f'invalid optional text: {value!r}')
        return value
    if value is None or (value == '' and kind != 'text'):
        return None
    if kind in ('integer', 'address', 'address48'):
        if isinstance(value, bool):
            raise ValueError('boolean is not an integer/address')
        if isinstance(value, int):
            result = value
        elif isinstance(value, str):
            result = int(value, 16 if value.lower().startswith('0x') else 10)
        else:
            raise ValueError(f'invalid {kind}: {value!r}')
        if kind == 'address48' and 0 <= result < 1 << 48 and result & (1 << 47):
            result |= ((1 << 64) - 1) ^ ((1 << 48) - 1)
        return result
    if kind == 'boolean':
        if isinstance(value, bool):
            return value
        if value in ('true', 'false'):
            return value == 'true'
        raise ValueError(f'invalid boolean: {value!r}')
    if kind == 'timestamp':
        value = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if value.tzinfo is None:
            raise ValueError('timestamp lacks timezone')
        delta = value - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    if kind == 'text':
        if not isinstance(value, str):
            raise ValueError(f'invalid text: {value!r}')
        return value
    raise ValueError(f'unknown normalization: {kind}')


def reference_rows(rows):
    for row in rows:
        yield {k: v for k, v in row.items() if k != '__children'}
        yield from reference_rows(row.get('__children', []))


def compare(native, reference, mapping):
    columns = native['columns']
    if len(columns) != len(set(columns)):
        raise ValueError('duplicate native columns')
    fields = mapping['fields']
    keys = mapping['keys']
    if not keys or not set(keys) <= fields.keys():
        raise ValueError('keys must name mapped fields')
    for spec in fields.values():
        if spec['zero'] not in columns:
            raise ValueError(f"missing native column {spec['zero']}")
    selection = mapping.get('record_selection')
    selected = {}
    if selection:
        if selection.get('field') not in fields or not selection.get('include') or not selection.get('scope'):
            raise ValueError('record selection needs a mapped field, include values and explicit scope')
    sides = []
    for side, rows in [('zero', [dict(zip(columns, r, strict=True)) for r in native['rows']]),
                       ('reference', list(reference_rows(reference)))]:
        indexed = defaultdict(list)
        excluded = 0
        for row in rows:
            normalized = {}
            for name, spec in fields.items():
                source = spec[side]
                if source not in row:
                    raise ValueError(f'missing {side} field {source}')
                kind = spec.get(side + '_type', spec.get('type', 'text'))
                normalized[name] = normalize(row[source], kind)
            if selection and normalized[selection['field']] not in selection['include']:
                excluded += 1
                continue
            key = tuple(normalized[name] for name in keys)
            if None in key:
                raise ValueError('unavailable record identity')
            indexed[key].append(normalized)
        sides.append(indexed)
        selected[side + '_excluded'] = excluded
    ns, rs = sides
    missing = [list(k) for k in sorted(rs.keys() - ns.keys(), key=repr)]
    extra = [list(k) for k in sorted(ns.keys() - rs.keys(), key=repr)]
    duplicates = [{'side': side, 'key': list(k), 'count': len(v)}
                  for side, values in [('zero', ns), ('reference', rs)]
                  for k, v in values.items() if len(v) != 1]
    conflicts, unavailable, matched_absent = [], [], defaultdict(int)
    for key in sorted(ns.keys() & rs.keys(), key=repr):
        if len(ns[key]) != 1 or len(rs[key]) != 1:
            continue
        n, r = ns[key][0], rs[key][0]
        for field in fields:
            if n[field] is None and r[field] is None and fields[field].get('allow_absent', False):
                matched_absent[field] += 1
            elif n[field] is None or r[field] is None:
                unavailable.append({'key': list(key), 'field': field, 'zero': n[field], 'reference': r[field]})
            elif n[field] != r[field]:
                conflicts.append({'key': list(key), 'field': field, 'zero': n[field], 'reference': r[field]})
    nonempty = bool(ns) and bool(rs)
    all_columns = set(columns) == {spec['zero'] for spec in fields.values()}
    ref_columns = {k for row in reference_rows(reference) for k in row}
    all_columns = all_columns and ref_columns <= {spec['reference'] for spec in fields.values()}
    return {
        'schema_version': 1, 'mapping_version': mapping['version'],
        **({'record_selection': {**selection, **selected}} if selection else {}),
        'zero_records': sum(map(len, ns.values())), 'reference_records': sum(map(len, rs.values())),
        'missing': missing, 'extra': extra, 'duplicates': duplicates,
        'conflicts': conflicts, 'unverifiable': unavailable, 'matched_absent': dict(matched_absent),
        'all_columns_mapped': all_columns, 'positive_evidence': nonempty,
        'zero_complete': native['complete'], 'zero_diagnostics': native['diagnostics'],
        'passed': not (missing or extra or duplicates or conflicts or unavailable)
                  and all_columns and (nonempty or mapping.get('allow_empty', False))
                  and (native['complete'] or mapping.get('allow_partial', False)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zero', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--mapping', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare(json.loads(args.zero.read_text()), json.loads(args.reference.read_text()),
                     json.loads(args.mapping.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
