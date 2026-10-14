"""The 30ops command. v0.2 has `drill record` and `drill migrate`; validate,
render and the rest arrive with site.yaml in v0.3."""
import argparse
import json
import sys

from . import drills, jsonl, rfc3339, version


def _value(s):
    """--extra k=v: JSON numbers, true, false and null keep their type."""
    try:
        v = json.loads(s)
    except ValueError:
        return s
    return v if v is None or isinstance(v, (bool, int, float)) else s


def _pair(s):
    if "=" not in s:
        raise argparse.ArgumentTypeError(f"expected key=value, got {s!r}")
    return tuple(s.split("=", 1))


def cmd_drill_record(a):
    checks = []
    for name, rest in a.check:
        res, _, detail = rest.partition(":")
        c = {"name": name, "result": res}
        if detail:
            c["detail"] = detail
        checks.append(c)
    rec = drills.new(a.kind, a.label, a.t0, a.result,
                     t1=a.t1, site=a.site, host=a.host, rto_s=a.rto_s, rpo_s=a.rpo_s, bytes=a.bytes,
                     rate_bps=a.rate_bps, cr=a.cr, rollback_of=a.rollback_of, operator=a.operator,
                     checks=checks, extra={k: _value(v) for k, v in a.extra})
    try:
        drills.append(a.file, rec)
    except drills.DrillError as e:
        print(f"30ops drill record: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_drill_migrate(a):
    recs, skipped = drills.load(a.input, a.hint)
    for r in recs:
        sys.stdout.write(jsonl.dumps(r) + "\n")
    if skipped:
        print(f"30ops drill migrate: skipped {skipped} line(s) without a usable t0 or not JSON objects", file=sys.stderr)
    bad = [e for r in recs for e in drills.validate(r)]
    if bad:
        print(f"30ops drill migrate: {len(bad)} problem(s), first: {bad[0]}", file=sys.stderr)
        return 1
    return 0


def _nonneg_int(s):
    if s in ("", "-", "null"):
        return None
    n = int(s)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _nonneg_float(s):
    if s in ("", "-", "null"):
        return None
    n = float(s)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def parser():
    ap = argparse.ArgumentParser(prog="30ops", description="30ops on-prem operations platform")
    ap.add_argument("--version", action="version", version=f"30ops {version()}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("drill", help="drill records (drills.jsonl v1)").add_subparsers(dest="sub", required=True)
    r = d.add_parser("record", help="append one v1 record")
    r.add_argument("--file", required=True)
    r.add_argument("--kind", required=True, choices=drills.KINDS)
    r.add_argument("--label", required=True)
    r.add_argument("--t0", default=None, help="RFC 3339; default now")
    r.add_argument("--t1", default=None, help="RFC 3339; default now")
    r.add_argument("--result", required=True, choices=drills.RESULTS)
    for k in ("--rto-s", "--rpo-s", "--bytes"):
        r.add_argument(k, type=_nonneg_int, default=None)
    r.add_argument("--rate-bps", type=_nonneg_float, default=None)
    for k in ("--site", "--host", "--cr", "--rollback-of", "--operator"):
        r.add_argument(k, default=None)
    r.add_argument("--check", type=_pair, action="append", default=[], metavar="NAME=RESULT[:DETAIL]")
    r.add_argument("--extra", type=_pair, action="append", default=[], metavar="KEY=VALUE")
    r.set_defaults(f=cmd_drill_record)

    m = d.add_parser("migrate", help="print a v1 copy of an old drills.jsonl; the file is not changed")
    m.add_argument("input")
    m.add_argument("--hint", choices=sorted(drills.HINTS), help="which tool wrote the file")
    m.set_defaults(f=cmd_drill_migrate)
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    if a.cmd == "drill" and a.sub == "record":
        now = rfc3339.format(rfc3339.now())
        a.t0 = a.t0 or now
        a.t1 = a.t1 or now
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())
