#!/usr/bin/env python3
"""Render/check the README coverage summary from the engine's manifest."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = '<!-- windows-compatibility:start -->'
END = '<!-- windows-compatibility:end -->'


def render():
    matrix = json.loads((ROOT / 'src/windows/compatibility.json').read_text())
    lines = [START, '| 系统 | 构建 | 架构：真实 / 合成 / 待验证 / 不支持插件数 | 真实样本范围 |',
             '| --- | --- | --- | --- |']
    for target in matrix['targets']:
        counts = []
        for arch, plugins in target['plugins'].items():
            counts.append(arch + ': ' + ' / '.join(str(list(plugins.values()).count(level))
                          for level in ('real', 'synthetic', 'pending', 'unsupported')))
        evidence = ', '.join(f"{e['build']} {e['architecture']} {e['container']}"
                             for e in target['evidence']) or '待采集'
        lines.append(f"| {target['name']} | {', '.join(map(str, target['builds']))} | {'; '.join(counts)} | {evidence} |")
    return '\n'.join(lines + [END])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'README.md'
    text = path.read_text()
    if START not in text or END not in text:
        raise SystemExit('README compatibility markers are missing')
    begin = text.index(START)
    end = text.index(END, begin) + len(END)
    expected = render()
    if args.check:
        if text[begin:end] != expected:
            raise SystemExit('Run python3 scripts/windows_compatibility.py to update README')
    else:
        path.write_text(text[:begin] + expected + text[end:])


if __name__ == '__main__':
    main()
