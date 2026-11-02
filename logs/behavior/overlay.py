#!/usr/bin/env python3
"""overlay: semi-synthetic labels for a site that has real background and no
injection schedule. Events of known scenarios are added to the pseudonymized
stream, so the question becomes whether the signal survives that site's real
noise. It does not show that a real insider would look like this: the same author
wrote these events and the rules that read them, and a report built on this file
has to say so.

    overlay.py --in events.p.jsonl --out events.o.jsonl --schedule schedule.o.tsv \
        --from 2026-08-01 --to 2026-10-29 --per-scenario 6 --seed 7 [--tz +08:00]

Scenarios the sources of a SIEM's server alerts can carry: S3, S4, S5. Half of
each are `obvious`, off hours and loud; half `subtle`, working hours and just over
the line, the kind the row counts are no help with. The real events are copied
through unchanged; added lines look like the rest (same pseudonym shape, the time
floored to the minute). The label is in the schedule, not in the event.

Standard library only.
"""
import argparse, collections, datetime as dt, json, os, random, sys

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "lib", "python"))
from ops30 import rfc3339  # noqa: E402
from summarize import parse_tz  # noqa: E402


def hexid(rnd, prefix):
    return f"{prefix}-" + "".join(rnd.choice("0123456789abcdef") for _ in range(10))


def rand_ip(rnd):
    return ".".join(str(rnd.randrange(1, 255)) for _ in range(4))


def base(ts, asset, **kw):
    return {"ts": ts, "kind": kw.pop("kind"), "user": kw.pop("user", ""), "src_host": kw.pop("src_host", asset), "asset": asset, "source": "wazuh", **kw}


def at(day, hour, minute, tz):
    return rfc3339.format(dt.datetime(day.year, day.month, day.day, hour, minute, tzinfo=tz).astimezone(dt.timezone.utc))


def s3(rnd, asset, day, tz, variant, accounts):
    """an internal machine the host has not seen logs on and looks around"""
    hour = rnd.choice((1, 2, 22, 23)) if variant == "obvious" else rnd.choice((10, 11, 14, 15))
    srcs = [rand_ip(rnd) for _ in range(4 if variant == "obvious" else 1)]
    acct = rnd.choice(accounts) if accounts else hexid(rnd, "u")
    out = []
    for i, src in enumerate(srcs):
        ts = at(day, hour, (5 + i * 7) % 60, tz)
        out.append(base(ts, asset, kind="auth.logon", user=acct, src_host=src, src_ip=src, src_scope="internal", dst=asset, logon_type="ssh", result="success", method="sshd", rule_id="5715", rule_level=3))
        for j in range(12 if variant == "obvious" else 0):
            out.append(base(at(day, hour, (6 + i * 7 + j) % 60, tz), asset, kind="sec.alert", src_ip=src, src_scope="internal", rule_id="31151", rule_level=10, rule_group="recon", mitre=""))
    return out, acct, hour


def s4(rnd, asset, day, tz, variant, accounts):
    """failures then a success, one source, from somewhere new"""
    hour = rnd.choice((0, 3, 21, 23)) if variant == "obvious" else rnd.choice((9, 13, 16))
    src, new_acct = rand_ip(rnd), variant == "obvious" or not accounts
    acct = hexid(rnd, "u") if new_acct else rnd.choice(accounts)
    scope = rnd.choice(("internal", "external")) if variant == "obvious" else "internal"
    out = []
    for i in range(8 if variant == "obvious" else 3):
        out.append(base(at(day, hour, i, tz), asset, kind="auth.logon", user=acct, src_host=src, src_ip=src, src_scope=scope, dst=asset, logon_type="ssh", result="failure", method="sshd", rule_id="5710", rule_level=5))
    out.append(base(at(day, hour, 12, tz), asset, kind="auth.logon", user=acct, src_host=src, src_ip=src, src_scope=scope, dst=asset, logon_type="ssh", result="success", method="sshd", rule_id="5715", rule_level=3))
    return out, acct, hour


def s5(rnd, asset, day, tz, variant, accounts):
    """a tunnel tool appears, and on the loud version a USB disk and edited files"""
    hour = rnd.choice((1, 2, 22)) if variant == "obvious" else rnd.choice((10, 14, 15))
    acct = rnd.choice(accounts) if accounts else hexid(rnd, "u")
    out = [base(at(day, hour, 10, tz), asset, kind="pkg.change", dst=asset, action="installed", category="evasion", rule_id="2902", rule_level=7)]
    if variant == "obvious":
        out.append(base(at(day, hour, 11, tz), asset, kind="priv.exec", user=acct, dst=asset, target=hexid(rnd, "u"), category="evasion", rule_id="5402", rule_level=3))
        out.append(base(at(day, hour, 15, tz), asset, kind="usb.attach", device="usb"))
        for i in range(6):
            out.append(base(at(day, hour, 20 + i, tz), asset, kind="file.integrity", dst=asset, path="etc/*", action="modified", rule_id="550", rule_level=7))
    return out, acct, hour


GEN = {"S3": s3, "S4": s4, "S5": s5}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="inp", required=True); ap.add_argument("--out", required=True); ap.add_argument("--schedule", required=True)
    ap.add_argument("--from", dest="start", required=True, help="first local date of the test period"); ap.add_argument("--to", required=True)
    ap.add_argument("--per-scenario", type=int, default=6); ap.add_argument("--seed", type=int, default=7); ap.add_argument("--tz", default="+08:00")
    ap.add_argument("--exclude-kinds", default="malware.detect", help="assets seen only through these are not targets")
    ap.add_argument("--min-host-days", type=int, default=20, help="an asset with fewer days has no baseline worth the name")
    a = ap.parse_args()
    tz = parse_tz(a.tz)
    start, end = dt.date.fromisoformat(a.start), dt.date.fromisoformat(a.to)
    exclude = {x for x in a.exclude_kinds.split(",") if x}
    days_of, accounts = collections.defaultdict(set), collections.defaultdict(collections.Counter)
    with open(a.inp, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            d = rfc3339.parse(e.get("ts", ""))
            asset = e.get("asset")
            if d is None or not asset or e.get("kind") in exclude:
                continue
            local = d.astimezone(tz).date()
            days_of[asset].add(local)
            if e.get("kind") == "auth.logon" and e.get("result") == "success" and e.get("user") and local < start:
                accounts[asset][e["user"]] += 1
    targets = sorted(x for x, ds in days_of.items() if sum(1 for d in ds if start <= d <= end) >= a.min_host_days)
    if not targets:
        sys.exit("overlay: no asset has enough days in the test period")
    rnd = random.Random(a.seed)
    used, added, rows = set(), [], []
    for sc in sorted(GEN):
        for i in range(a.per_scenario):
            variant = "obvious" if i % 2 == 0 else "subtle"
            for _try in range(500):
                asset = targets[i % len(targets)] if _try < 50 else rnd.choice(targets)
                pool = sorted(d for d in days_of[asset] if start <= d <= end)
                day = rnd.choice(pool)
                if (asset, day) not in used:
                    break
            else:
                sys.exit("overlay: cannot place an injection; fewer host-days than injections")
            used.add((asset, day))
            evs, acct, hour = GEN[sc](rnd, asset, day, tz, variant, sorted(accounts[asset]))
            added += evs
            stamp = f"{day.isoformat()}T{hour:02d}:00{a.tz}"
            rows.append((stamp, stamp, asset, asset, sc, variant))
    n = 0
    with open(a.inp, encoding="utf-8") as fi, os.fdopen(os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as fo:
        for line in fi:
            fo.write(line); n += 1
        for e in added:
            fo.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")
    with open(a.schedule, "w", encoding="utf-8") as f:
        f.write("start\tend\tuser\thost\tscenario\tnote\n")
        for r in sorted(rows):
            f.write("\t".join(r) + "\n")
    print(f"overlay: {n} real events + {len(added)} added, {len(rows)} injections on {len({r[2] for r in rows})} of {len(targets)} target assets -> {a.out}")


if __name__ == "__main__":
    main()
