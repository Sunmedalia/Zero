#!/usr/bin/env python3
"""Compare new native Windows artifacts with independently prepared Volatility JSON.
Usage: windows_artifacts.py NATIVE_PREFIX REFERENCE_PREFIX [plugins comma-separated]
"""
import json
import sys

native_prefix, reference_prefix = sys.argv[1:3]
plugins = sys.argv[3].split(",") if len(sys.argv) > 3 else ["threads", "envars", "driverscan", "svcscan"]
MASK = (1 << 48) - 1

def addr(value):
    return int(value, 16) & MASK

def native(plugin, row):
    if plugin == "threads":
        return (int(row[0]), int(row[2])), (addr(row[3]), addr(row[5]))
    if plugin == "envars":
        return (int(row[0]), row[3]), (row[4],)
    if plugin == "driverscan":
        return addr(row[0]), (row[1], addr(row[2]), int(row[3]))
    return (addr(row[1]), row[2]), (row[3], row[0], row[7])

def reference(plugin, row):
    if plugin == "threads":
        return (row["PID"], row["TID"]), (row["Offset"] & MASK, None if row["StartAddress"] is None else row["StartAddress"] & MASK)
    if plugin == "envars":
        return (row["PID"], row["Variable"]), (row["Value"],)
    if plugin == "driverscan":
        return row["Offset"] & MASK, (row["Name"], row["Start"] & MASK, row["Size"])
    return (row["Offset"] & MASK, row["Name"]), (row["Display"], None if row["PID"] is None else str(row["PID"]), row["Binary"])

for plugin in plugins:
    assert plugin in {"threads", "envars", "driverscan", "svcscan"}, plugin
    n = json.load(open(f"{native_prefix}windows.{plugin}.json"))
    r = json.load(open(f"{reference_prefix}{plugin}.json"))
    ns = dict(native(plugin, row) for row in n["rows"] if plugin != "envars" or row[2] == "native")
    rs = dict(reference(plugin, row) for row in r)
    shared = ns.keys() & rs.keys()
    errors = [(key, ns[key], rs[key]) for key in shared if any(b is not None and a != b for a, b in zip(ns[key], rs[key]))]
    print(f"{plugin}: native={len(ns)} reference={len(rs)} shared={len(shared)} conflicts={len(errors)} complete={n['complete']}")
    assert shared, f"no comparable records: {plugin}"
    assert not errors, errors[:5]
