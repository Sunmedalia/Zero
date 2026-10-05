#!/usr/bin/env python3
"""Compare Zero exports with independent Volatility 3 v2.28 JSON exports.

Usage: python3 tests/reference/windows.py /tmp/zero-win11- /tmp/zero-ref-win11-
Reference symbols must come from Volatility's converter, not Zero's generated ISF.
Missing rows are reported because damaged lists/pages and rejection rules differ.
Any conflicting fields in matching records fail validation.
"""
import json
import sys

native_prefix, reference_prefix = sys.argv[1:]
MASK = (1 << 48) - 1


def address(text):
    return int(text.removeprefix("physical:"), 16) & MASK


def check(plugin, native, reference):
    n = json.load(open(f"{native_prefix}windows.{plugin}.json"))
    r = json.load(open(f"{reference_prefix}{plugin}.json"))
    ns = dict(native(row) for row in n["rows"])
    rs = dict(reference(row) for row in r)
    shared = ns.keys() & rs.keys()
    def agrees(a, b):
        if b is None:
            return True  # Reference couldn't read this field.
        if isinstance(b, tuple):
            return all(agrees(x, y) for x, y in zip(a, b))
        if isinstance(b, str):
            return a.split("\0")[0] == b.split("\0")[0]
        return a == b
    errors = [(k, ns[k], rs[k]) for k in shared if not agrees(ns[k], rs[k])]
    print(f"{plugin}: native={len(ns)} reference={len(rs)} shared={len(shared)} conflicts={len(errors)} complete={n['complete']}")
    assert shared, f"no comparable records: {plugin}"
    assert not errors, errors[:5]


check("pslist", lambda x: (int(x[0]), (int(x[1]), x[2], address(x[3]), int(x[4]))),
      lambda x: (x["PID"], (x["PPID"], x["ImageFileName"], x["Offset(V)"] & MASK, x["Threads"])))
check("modules", lambda x: (address(x[1]), (x[0], int(x[2]), x[3])),
      lambda x: (x["Base"] & MASK, (x["Name"], x["Size"], x["Path"])))
check("hivelist", lambda x: (address(x[0]), x[1]),
      lambda x: (x["Offset"] & MASK, x["FileFullPath"]))
check("vadinfo", lambda x: ((int(x[0]), address(x[2])), (address(x[3]) - 1, x[4], x[5] == "true")),
      lambda x: ((x["PID"], x["Start VPN"]), (x["End VPN"], x["Protection"], bool(x["PrivateMemory"]))))
check("dlllist", lambda x: ((int(x[0]), address(x[2])), (int(x[3]), x[4])),
      lambda x: ((x["PID"], x["Base"] & MASK), (x["Size"], x["Path"])))


def endpoint(addr, port, proto):
    if addr == "*":
        addr = "::" if proto.endswith("6") else "0.0.0.0"
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


n = json.load(open(f"{native_prefix}windows.netscan.json"))
r = json.load(open(f"{reference_prefix}netscan.json"))
ns = {tuple(row[1:7]) for row in n["rows"]}
rs = {(row["Proto"], endpoint(row["LocalAddr"], row["LocalPort"], row["Proto"]),
       endpoint(row["ForeignAddr"], row["ForeignPort"], row["Proto"]), row["State"],
       str(row["PID"]), row["Owner"]) for row in r if row["PID"] is not None}
print(f"netscan: native={len(ns)} reference={len(rs)} shared={len(ns & rs)}")
assert rs <= ns, list(rs - ns)[:5]
