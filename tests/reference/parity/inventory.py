#!/usr/bin/env python3
"""Extract plugin metadata without importing or executing reference plugins.

Reference metadata: Volatility Foundation, VSL 1.0:
https://www.volatilityfoundation.org/license/vsl-v1.0
The pinned checkout remains a test-only dependency, never packaged with Zero.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess

VERSION = 'v2.28.2'
COMMIT = '881e970121c16f0932fb9d16fbd5fb258cbcbf75'
ROOT = Path(__file__).resolve().parents[3]
OUTPUT = Path(__file__).with_name('inventory.json')


def literal(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return {'expression': ast.unparse(node)}


def inventory(checkout):
    actual = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != COMMIT:
        raise ValueError(f'reference commit mismatch: {actual}')
    base = checkout / 'volatility3/framework/plugins'
    classes = {}
    for platform in ('linux', 'windows'):
        for path in sorted((base / platform).rglob('*.py')):
            module = '.'.join(path.relative_to(base).with_suffix('').parts)
            tree = ast.parse(path.read_text())
            imports = {}
            for node in tree.body:
                if isinstance(node, ast.ImportFrom) and node.module:
                    for alias in node.names:
                        imports[alias.asname or alias.name] = node.module + '.' + alias.name
            def resolve(node):
                expression = ast.unparse(node)
                first, *rest = expression.split('.')
                return '.'.join([imports.get(first, module + '.' + first), *rest]).removeprefix('volatility3.plugins.')
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                name = module + '.' + node.name
                replacement = next((resolve(k.value) for k in node.keywords if k.arg == 'replacement_class'), None)
                requirements = []
                columns = []
                methods = {}
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        methods[method.name] = method
                for call in ast.walk(methods.get('get_requirements', ast.Pass())):
                    if isinstance(call, ast.Call) and ast.unparse(call.func).endswith('Requirement'):
                        requirements.append({'type': ast.unparse(call.func).split('.')[-1], **{
                            k.arg: literal(k.value) for k in call.keywords if k.arg
                        }})
                for call in ast.walk(methods.get('run', ast.Pass())):
                    if isinstance(call, ast.Call) and ast.unparse(call.func).endswith('TreeGrid') and call.args:
                        expression = call.args[0]
                        if isinstance(expression, ast.Name):
                            for assignment in ast.walk(methods['run']):
                                if isinstance(assignment, ast.Assign) and any(isinstance(t, ast.Name) and t.id == expression.id for t in assignment.targets):
                                    expression = assignment.value
                                    break
                        if isinstance(expression, (ast.List, ast.Tuple)):
                            for item in expression.elts:
                                if isinstance(item, (ast.List, ast.Tuple)) and item.elts and isinstance(item.elts[0], ast.Constant):
                                    columns.append(item.elts[0].value)
                classes[name] = {
                    'reference': name, 'platform': platform,
                    'source': str(path.relative_to(checkout)),
                    'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'bases': [resolve(b) for b in node.bases],
                    'replacement': replacement,
                    'declared_requirements': requirements,
                    'declared_columns': columns,
                }
    selected = {name for name, item in classes.items() if any(b.endswith('.PluginInterface') for b in item['bases'])}
    while True:
        inherited = {name for name, item in classes.items() if any(b in selected for b in item['bases'])}
        extended = selected | inherited
        if selected == extended:
            break
        selected = extended
    entries = []
    import re
    zero = re.findall(r'\bname: "([^"]+)"', (ROOT / 'src/plugin.rs').read_text())
    overrides = {'linux.kallsyms.Kallsyms': 'linux.kallsyms.Kallsyms', 'linux.module_extract.ModuleExtract': 'linux.module_extract.ModuleExtract', 'linux.malware.modxview.Modxview': 'linux.malware.modxview.Modxview', 'linux.malware.process_spoofing.ProcessSpoofing': 'linux.malware.process_spoofing.ProcessSpoofing', 'linux.pslist.PsList': 'linux.pslist.PsList', 'linux.ip.Addr': 'ip_addr', 'linux.ip.Link': 'ip_link', 'linux.proc.Maps': 'maps', 'linux.kmsg.Kmsg': 'dmesg',
                 'linux.kthreads.Kthreads': 'kthreads', 'windows.info.Info': 'windows.systeminfo',
                 'windows.registry.hashdump.Hashdump': 'windows.hashdump',
                 'windows.registry.lsadump.Lsadump': 'windows.lsadump',
                 'windows.registry.cachedump.Cachedump': 'windows.cachedump',
                 'windows.registry.hivelist.HiveList': 'windows.hivelist',
                 'windows.registry.printkey.PrintKey': 'windows.printkey'}
    def normalized(name):
        return name.replace('_', '').lower()
    for name in sorted(selected):
        item = classes[name]
        target = item['replacement'] or name
        prefix = 'windows.' if item['platform'] == 'windows' else ''
        module_leaf = target.split('.')[-2]
        candidates = [z for z in zero if normalized(z) == normalized(prefix + module_leaf)]
        if target in overrides:
            candidates = [overrides[target]] if overrides[target] in zero else []
        item['zero_candidates'] = sorted(set(candidates))
        item['status'] = 'alias' if item['replacement'] else ('mapped_unverified' if candidates else 'missing')
        item['evidence'] = []
        entries.append(item)
    return {'schema_version': 1, 'reference_version': VERSION, 'reference_commit': COMMIT,
            'reference_url': 'https://github.com/volatilityfoundation/volatility3',
            'reference_license': 'https://www.volatilityfoundation.org/license/vsl-v1.0',
            'plugins': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=ROOT / 'target/reference/volatility3')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    text = json.dumps(inventory(args.checkout), ensure_ascii=False, indent=2) + '\n'
    if args.check:
        if OUTPUT.read_text() != text:
            raise SystemExit('Reference inventory changed; regenerate and review it')
    else:
        OUTPUT.write_text(text)


if __name__ == '__main__':
    main()
