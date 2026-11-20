#!/usr/bin/env python3
"""cert: the CERT Insider Threat Test Dataset (CMU SEI, releases r4.2 and r6.2)
through the same pipeline as a site, as the external benchmark.

    cert.py load   --dir r4.2/ --release r4.2 --out events.jsonl [--shards 4] [--answers answers/] --stats load-stats.json
    cert.py labels --answers answers/ --release r4.2 --out schedule.tsv
    cert.py sample --summaries summaries.p.jsonl --schedule schedule.p.tsv --normal 130 --seed 7 --out sample.jsonl [--users-out users.txt]

load reads logon, device, file, http and email CSVs of an extracted release
and writes the event schema of events.py, one line per kept row, in file
order (summarize.py does not need time order). The mapping is fixed from the
dataset's own documentation, before anything is scored:

    logon.csv   Logon -> auth.logon (src_host = dst = pc, success); Logoff dropped
    device.csv  Connect -> usb.attach; Disconnect dropped
    file.csv    -> file.access; r4.2 rows are copies to removable media (write);
                r6.2 File Open/Write/Copy/Delete -> read/write/copy/delete, share
                "removable" when to/from_removable_media, else "local"
    http.csv    -> net.conn to the url's host (no byte counts in the dataset);
                r6.2 activity is kept as `action`
    email.csv   sent mail with a recipient outside the organisation's domain ->
                net.file up, bytes = size, dst_name = first outside domain;
                internal-only mail and r6.2 View rows dropped
    LDAP/*.csv  role per user (the last month the user appears in)

Content, subject, url path and the psychometric file are never read into an
event. Times have no zone in the dataset; they are written as UTC and
summarize.py and evaluate.py run with --tz +00:00, so a local hour stays the
hour the dataset wrote.

--shards N writes events.sNN.jsonl, a user to one shard by a stable hash, so a
large release is summarized a shard at a time. --answers counts, per insider,
how many of the dataset's malicious event ids were seen and kept.

labels turns the answers into the schedule evaluate.py reads: one row per
insider and day that has a malicious event (not the whole start to end span),
the scenario mapped once to the thesis' S1 to S6:

    1 wikileaks upload after hours with a new thumb drive   -> S1 data exfiltration
    2 job search, then data theft by thumb drive before leaving -> S6 departure
    3 keylogger, logs on as the supervisor, mass email      -> S4 credential misuse
    4 logs on to others' machines, searches files, mails home -> S2 out-of-role access
    5 uploads documents to Dropbox after layoffs            -> S1 data exfiltration

sample keeps every insider and N other users drawn with a fixed seed, all of
their user-days: the model layer reads the sample, the rules read everything.

Standard library only.
"""
import argparse, collections, csv, datetime as dt, glob, hashlib, json, os, random, sys, urllib.parse

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
import events as ev  # noqa: E402

RELEASES = ("r4.2", "r6.2")
SCENARIO = {"1": "S1", "2": "S6", "3": "S4", "4": "S2", "5": "S1"}
ORG_DOMAIN = "dtaa.com"
FILES = ("logon", "device", "file", "http", "email")
TIME_FMTS = ("%m/%d/%Y %H:%M:%S",)


def ts(s):
    s = s.strip()
    for f in TIME_FMTS:
        try:
            return dt.datetime.strptime(s, f).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


def rows(path):
    """header-indexed rows; the content columns can be long"""
    csv.field_size_limit(1 << 30)
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        r = csv.reader(f)
        head = [h.strip().lower() for h in next(r)]
        idx = {h: i for i, h in enumerate(head)}
        for row in r:
            yield idx, row


def col(idx, row, name, default=""):
    i = idx.get(name)
    return row[i].strip() if i is not None and i < len(row) else default


def roles(d):
    out = {}
    for p in sorted(glob.glob(os.path.join(d, "LDAP", "*.csv"))):
        for idx, row in rows(p):
            u, r = col(idx, row, "user_id"), col(idx, row, "role")
            if u:
                out[u] = r
    return out


def host_of(url):
    try:
        u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    except ValueError:
        return "", ""
    return (u.hostname or "").lower(), u.scheme.lower()


def domain(addr):
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def convert(kind, idx, row, release):
    """-> (event or None, reason it was dropped)"""
    t = ts(col(idx, row, "date"))
    user, pc = col(idx, row, "user"), col(idx, row, "pc")
    if t is None or not user:
        return None, "bad time or user"
    base = {"ts": t, "user": user, "src_host": pc, "source": "cert"}
    act = col(idx, row, "activity")
    if kind == "logon":
        if act != "Logon":
            return None, "logoff"
        return dict(base, kind="auth.logon", dst=pc, logon_type=2, result="success", method="interactive"), None
    if kind == "device":
        if act != "Connect":
            return None, "disconnect"
        return dict(base, kind="usb.attach", device="removable"), None
    if kind == "file":
        name = col(idx, row, "filename")
        if release == "r4.2":
            action, share = "write", "removable"
        else:
            action = {"file open": "read", "file write": "write", "file copy": "copy", "file delete": "delete"}.get(act.lower())
            if action is None:
                return None, "file activity unknown"
            rem = "true" in (col(idx, row, "to_removable_media").lower(), col(idx, row, "from_removable_media").lower())
            share = "removable" if rem else "local"
        return dict(base, kind="file.access", dst=pc, share=share, path=name, action=action, bytes=0), None
    if kind == "http":
        host, scheme = host_of(col(idx, row, "url"))
        if not host:
            return None, "url without host"
        e = dict(base, kind="net.conn", dst_name=host, dst_port=443 if scheme == "https" else 80, proto="tcp",
                 service="ssl" if scheme == "https" else "http", bytes_out=0, bytes_in=0, category="")
        if act:
            e["action"] = act.lower().replace("www ", "")
        return e, None
    if kind == "email":
        if act and act.lower() != "send":
            return None, "mail viewed, not sent"
        rcpt = [x for f in ("to", "cc", "bcc") for x in col(idx, row, f).split(";") if x.strip()]
        outside = [domain(x) for x in rcpt if domain(x) and domain(x) != ORG_DOMAIN]
        if not outside:
            return None, "internal mail"
        try:
            size = int(float(col(idx, row, "size") or 0))
        except ValueError:
            size = 0
        return dict(base, kind="net.file", dst_name=outside[0], filename="", bytes=size, direction="up"), None
    return None, "unknown file"


def shard_of(user, n):
    return int(hashlib.sha256(user.encode()).hexdigest()[:8], 16) % n


def answer_ids(adir, release):
    """{event id: (insider user, scenario)} from the observables files"""
    out = {}
    for r in insiders(adir, release):
        for p in detail_files(adir, release, r):
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in csv.reader(f):
                    if len(line) >= 3:
                        out[line[1].strip().strip('"')] = (r["user"], r["scenario"])
    return out


def insiders(adir, release):
    num = release.lstrip("r")
    with open(os.path.join(adir, "insiders.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["dataset"].strip() == num:
                yield {k: v.strip() for k, v in r.items()}


def detail_files(adir, release, r):
    """r4.2 keeps one directory per scenario (r4.2-1/r4.2-1-USER.csv), r6.2 one file per incident"""
    p = os.path.join(adir, r["details"])
    if os.path.isfile(p):
        return [p]
    return sorted(glob.glob(os.path.join(adir, f"{release}-{r['scenario']}", f"{release}-{r['scenario']}-{r['user']}.csv")))


def load(a):
    role = roles(a.dir)
    want = answer_ids(a.answers, a.release) if a.answers else {}
    seen = collections.Counter()
    stats = {"release": a.release, "dir": os.path.abspath(a.dir), "files": {}, "roles": len(role), "time_zone": "dataset local time written as UTC"}
    if a.shards > 1:
        stem = a.out[:-6] if a.out.endswith(".jsonl") else a.out
        outs = [open(f"{stem}.s{k:02d}.jsonl", "w", encoding="utf-8") for k in range(a.shards)]
    else:
        outs = [open(a.out, "w", encoding="utf-8")]
    try:
        for kind in FILES:
            p = os.path.join(a.dir, kind + ".csv")
            if not os.path.exists(p):
                stats["files"][kind] = {"missing": True}
                continue
            st = {"rows": 0, "events": 0, "dropped": collections.Counter()}
            for idx, row in rows(p):
                st["rows"] += 1
                e, why = convert(kind, idx, row, a.release)
                rid = col(idx, row, "id")
                if e is not None and not ev.valid(e):
                    e, why = None, "invalid event"
                if e is None:
                    st["dropped"][why] += 1
                    if rid in want:
                        seen[("dropped", want[rid])] += 1
                    continue
                if role.get(e["user"]):
                    e["role"] = role[e["user"]]
                outs[shard_of(e["user"], len(outs))].write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")
                st["events"] += 1
                if rid in want:
                    seen[("kept", want[rid])] += 1
            st["dropped"] = dict(st["dropped"])
            st["balanced"] = st["rows"] == st["events"] + sum(st["dropped"].values())
            stats["files"][kind] = st
            print(f"cert: {kind}: {st['rows']} rows, {st['events']} events, dropped {st['dropped']}", flush=True)
    finally:
        for o in outs:
            o.close()
    if want:
        per = collections.defaultdict(lambda: {"ids": 0, "kept": 0, "dropped": 0})
        for (u, sc) in want.values():
            per[(u, sc)]["ids"] += 1
        for (state, key), n in seen.items():
            per[key][state] += n
        stats["answers"] = {"ids": len(want), "kept": sum(v["kept"] for v in per.values()), "dropped": sum(v["dropped"] for v in per.values()),
                            "not_found": sum(v["ids"] - v["kept"] - v["dropped"] for v in per.values()), "insiders": len(per)}
        print(f"cert: answers {stats['answers']}")
    stats["shards"] = a.shards
    with open(a.stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    if not all(v.get("balanced", True) for v in stats["files"].values()):
        sys.exit("cert: rows in != events out + dropped")


def labels(a):
    days = {}
    n_ins = 0
    for r in insiders(a.answers, a.release):
        n_ins += 1
        sc = SCENARIO[r["scenario"]]
        for p in detail_files(a.answers, a.release, r):
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in csv.reader(f):
                    if len(line) < 5:
                        continue
                    t = ts(line[2])
                    if t is None:
                        continue
                    k = (r["user"], t[:10])
                    d = days.setdefault(k, {"start": t, "end": t, "host": line[4].strip(), "sc": sc, "n": 0, "cert": r["scenario"]})
                    d["start"], d["end"] = min(d["start"], t), max(d["end"], t)
                    d["n"] += 1
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("start\tend\tuser\thost\tscenario\tnote\n")
        for (u, _), d in sorted(days.items(), key=lambda kv: (kv[1]["start"], kv[0][0])):
            f.write(f"{d['start']}\t{d['end']}\t{u}\t{d['host']}\t{d['sc']}\tCERT {a.release} scenario {d['cert']}, {d['n']} events\n")
    print(f"cert: {n_ins} insiders, {len(days)} labelled user-days -> {a.out}")


def sample(a):
    pos = set()
    with open(a.schedule, encoding="utf-8") as f:
        head = None
        for line in f:
            cols = line.rstrip("\n").split("\t")
            if line.startswith("#") or not line.strip():
                continue
            if head is None:
                head = cols
                continue
            pos.add(dict(zip(head, cols))["user"])
    users = set()
    with open(a.summaries, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                users.add(json.loads(line)["user"])
    others = sorted(users - pos)
    pick = set(random.Random(a.seed).sample(others, min(a.normal, len(others))))
    keep = (pos & users) | pick
    n = 0
    with open(a.summaries, encoding="utf-8") as f, open(a.out, "w", encoding="utf-8") as fo:
        for line in f:
            if line.strip() and json.loads(line)["user"] in keep:
                fo.write(line); n += 1
    if a.users_out:
        with open(a.users_out, "w", encoding="utf-8") as fo:
            fo.write("".join(u + "\n" for u in sorted(keep)))
    print(f"cert: {len(pos & users)} insiders (of {len(pos)} in the schedule) + {len(pick)} others, {n} user-days -> {a.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("load")
    p.add_argument("--dir", required=True); p.add_argument("--release", choices=RELEASES, required=True)
    p.add_argument("--out", required=True); p.add_argument("--shards", type=int, default=1)
    p.add_argument("--answers"); p.add_argument("--stats", required=True)
    p = sub.add_parser("labels")
    p.add_argument("--answers", required=True); p.add_argument("--release", choices=RELEASES, required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("sample")
    p.add_argument("--summaries", required=True); p.add_argument("--schedule", required=True)
    p.add_argument("--normal", type=int, required=True); p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", required=True); p.add_argument("--users-out")
    a = ap.parse_args()
    {"load": load, "labels": labels, "sample": sample}[a.cmd](a)


if __name__ == "__main__":
    main()
