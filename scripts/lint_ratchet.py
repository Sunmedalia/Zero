#!/usr/bin/env python3
"""Fail when production code gains indexing or truncating-cast sites.

Both lints have too many reviewed sites to deny globally, so each count may only
fall. Run with --update after lowering one to record the new baseline.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "lint-baseline.json"
MESSAGES = {"indexing_slicing": "may panic", "cast_possible_truncation": "truncate"}
LINTS = tuple(MESSAGES)


def count(lint: str) -> int:
    os.utime(ROOT / "src" / "lib.rs")
    os.utime(ROOT / "src" / "main.rs")
    output = subprocess.run(
        ["cargo", "clippy", "--locked", "--lib", "--bins", "--message-format=short",
         "--", f"-Wclippy::{lint}"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stderr
    pattern = MESSAGES[lint]
    return len({line.split(": ")[0] for line in output.splitlines()
                if line.startswith("src/") and pattern in line})


def main() -> int:
    current = {lint: count(lint) for lint in LINTS}
    if "--update" in sys.argv:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n")
        print(current)
        return 0
    baseline = json.loads(BASELINE.read_text())
    failed = False
    for lint, value in current.items():
        limit = baseline[lint]
        print(f"{lint}: {value} (limit {limit})")
        if value > limit:
            failed = True
    if not failed and current != baseline:
        print("counts fell; run scripts/lint_ratchet.py --update to lock them in")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
