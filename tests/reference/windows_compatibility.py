#!/usr/bin/env python3
"""Compare common Windows compatibility artifacts, reporting missing evidence separately.
Usage: windows_compatibility.py NATIVE_PREFIX REFERENCE_PREFIX PLUGINS
Reference symbols must be prepared independently from Zero's converter.
"""
import argparse
import datetime
import json

MASK = (1 << 48) - 1


def address(value):
    return int(value.removeprefix("physical:"), 16) & MASK


def filetime(value):
    delta = datetime.datetime.fromisoformat(value) - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return delta.days * 86400 + delta.seconds  # Volatility JSON renders whole seconds.


def native(plugin, row, pool_space):
    if plugin == "getsids":
        return (int(row[0]), row[2]), (row[1],)
    if plugin == "unloadedmodules":
        return (row[0], address(row[1])), (address(row[2]), int(row[3]) // 10000000)
    if plugin == "callbacks":
        return (row[0], address(row[2])), (address(row[2]),)
    if plugin in {"filescan", "mutantscan"}:
        return address(row[0] if pool_space=="physical" else row[1]), (row[2] or None,)
    if plugin == "pslist":
        return int(row[0]), (int(row[1]), row[2], address(row[3]), int(row[4]))
    if plugin == "modules":
        return address(row[1]), (row[0], int(row[2]))
    if plugin == "vadinfo":
        return (int(row[0]), address(row[7])), (int(row[2],16), int(row[3],16), row[4], row[5] == "true", row[6] or None)
    if plugin == "threads":
        return (int(row[0]), int(row[2])), (address(row[3]), address(row[5]) if row[5] else None)
    if plugin == "handles":
        return (int(row[0]), int(row[2],16)), (row[3], address(row[4]), int(row[5],16))
    if plugin == "svcscan":
        return (address(row[1]), row[2]), (row[3] or None, row[0] or None, row[7] or None)
    raise ValueError(plugin)


def reference(plugin, row):
    if plugin == "getsids":
        return (row["PID"], row["SID"]), (row["Process"],)
    if plugin == "unloadedmodules":
        return (row["Name"], row["StartAddress"] & MASK), (row["EndAddress"] & MASK, filetime(row["Time"]))
    if plugin == "callbacks":
        return (row["Type"], row["Callback"] & MASK), (row["Callback"] & MASK,)
    if plugin in {"filescan", "mutantscan"}:
        return row["Offset"] & MASK, (row["Name"],)
    if plugin == "pslist":
        return row["PID"], (row["PPID"], row["ImageFileName"], row["Offset(V)"] & MASK, row["Threads"])
    if plugin == "modules":
        return row["Base"] & MASK, (row["Name"], row["Size"])
    if plugin == "vadinfo":
        return (row["PID"], row["Offset"] & MASK), (row["Start VPN"], row["End VPN"]+1, row["Protection"], bool(row["PrivateMemory"]), row["File"])
    if plugin == "threads":
        return (row["PID"], row["TID"]), (row["Offset"] & MASK, None if row["StartAddress"] is None else row["StartAddress"] & MASK)
    if plugin == "handles":
        return (row["PID"], row["HandleValue"]), (row["Type"], row["Offset"] & MASK, row["GrantedAccess"])
    if plugin == "svcscan":
        return (row["Offset"] & MASK, row["Name"]), (row["Display"], None if row["PID"] is None else str(row["PID"]), row["Binary"])
    raise ValueError(plugin)


def compare_network(native_prefix,reference_prefix,expected_missing=0):
    with open(f"{native_prefix}windows.netscan.json") as stream:
        n=json.load(stream)
    with open(f"{reference_prefix}netscan.json") as stream:
        r=json.load(stream)
    def endpoint(a,p,proto):
        if a=="*": a="::" if proto.endswith("6") else "0.0.0.0"
        return f"[{a}]:{p}" if ":" in a else f"{a}:{p}"
    fields=["Proto","LocalAddr","LocalPort","ForeignAddr","ForeignPort","State","PID","Owner"]
    valid=[row for row in r if all(row[key] is not None for key in fields)]
    ns={tuple(row[1:7]) for row in n["rows"]}
    rs={(row["Proto"],endpoint(row["LocalAddr"],row["LocalPort"],row["Proto"]),endpoint(row["ForeignAddr"],row["ForeignPort"],row["Proto"]),row["State"],str(row["PID"]),row["Owner"]) for row in valid}
    missing = rs - ns
    print(f"netscan: native_unique={len(ns)} reference_unique={len(rs)} shared={len(ns&rs)} unreadable_reference_rows={len(r)-len(valid)} missing_reference_connections={len(missing)} complete={n['complete']}")
    if not rs or not ns & rs or len(missing) != expected_missing:
        raise AssertionError(f"missing comparable network evidence: {list(missing)[:5]}")
    if missing:
        print(f"Known missing network evidence (not counted as equality): {sorted(missing)}")


def compare(native_prefix, reference_prefix, plugin, pool_space):
    with open(f"{native_prefix}windows.{plugin}.json") as stream:
        result = json.load(stream)
    with open(f"{reference_prefix}{plugin}.json") as stream:
        ref = json.load(stream)
    ns = dict(native(plugin, row, pool_space) for row in result["rows"])
    rs = dict(reference(plugin, row) for row in ref)
    shared = ns.keys() & rs.keys()
    conflicts = []
    compared = 0
    unreadable = 0
    for key in shared:
        for a, b in zip(ns[key], rs[key]):
            if a is None or b is None:
                unreadable += 1
                continue
            compared += 1
            if a != b:
                conflicts.append((key, a, b))
    print(f"{plugin}: native={len(ns)} reference={len(rs)} shared={len(shared)} compared_fields={compared} unreadable_fields={unreadable} conflicts={len(conflicts)} complete={result['complete']}")
    if not shared or not compared:
        raise AssertionError(f"no comparable evidence: {plugin}")
    if conflicts:
        raise AssertionError(conflicts[:5])


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native_prefix")
    parser.add_argument("reference_prefix")
    parser.add_argument("plugins")
    parser.add_argument("--pool-space",choices=["physical","virtual"],default="virtual",help="Address domain of reference pool offsets; pre-Windows 8 Volatility scans use physical offsets")
    parser.add_argument("--expected-missing-network", type=int, default=0,
                        help="Exact recorded missing-connection count; default requires all readable reference connections")
    args=parser.parse_args()
    for plugin in args.plugins.split(","):
        if plugin=="netscan":
            compare_network(args.native_prefix,args.reference_prefix,args.expected_missing_network)
        else:
            compare(args.native_prefix,args.reference_prefix,plugin,args.pool_space)
