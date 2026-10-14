#!/usr/bin/env python3
"""snmpd pass_persist handler for the e2e fake NAS: answers get and getnext
from a data file written by build-data.py (OID <tab> type <tab> value).

  pass_persist .1.3.6.1.4.1.55062 /usr/bin/python3 pass-persist.py qnap.data
"""
import sys


def key(oid):
    return tuple(int(p) for p in oid.strip(".").split("."))


def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            oid, t, v = line.rstrip("\n").split("\t", 2)
            rows.append((key(oid), t, v))
    rows.sort()
    return rows


def lookup(rows, op, oid):
    """(oid, type, value) or None."""
    k = key(oid)
    if op == "get":
        for r in rows:
            if r[0] == k:
                return r
        return None
    for r in rows:
        if r[0] > k:
            return r
    return None


def serve(rows, inp, out):
    while True:
        cmd = inp.readline()
        if not cmd:
            return
        cmd = cmd.strip()
        if cmd == "PING":
            out.write("PONG\n")
        elif cmd in ("get", "getnext"):
            r = lookup(rows, cmd, inp.readline().strip())
            if r is None:
                out.write("NONE\n")
            else:
                out.write("." + ".".join(map(str, r[0])) + f"\n{r[1]}\n{r[2]}\n")
        elif cmd == "set":
            inp.readline()
            inp.readline()
            out.write("not-writable\n")
        elif cmd == "":
            return
        out.flush()


if __name__ == "__main__":
    serve(load(sys.argv[1]), sys.stdin, sys.stdout)
