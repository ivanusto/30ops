"""The 30ops command: validate, render, import-legacy (v0.3), drill
record / migrate (v0.2), textfile, install, doctor (v0.5). readiness
arrives later."""
import argparse
import difflib
import json
import os
import shutil
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
                     checks=checks, extra={**{k: _value(v) for k, v in a.extra}, **dict(a.extra_str)})
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


def _site(a):
    """(resolved site, sha256, errors printed): None when site.yaml is unusable."""
    from . import site
    from .render import site_sha
    try:
        doc = site.load(a.site)
    except site.SiteError as e:
        print(f"30ops: {e}", file=sys.stderr)
        return None
    base = os.path.dirname(os.path.abspath(a.site))
    errs, warns = site.validate(doc, base, strict=getattr(a, "strict", False), secrets=getattr(a, "secrets", False))
    for w in warns:
        print(f"{a.site}: warning: {w}", file=sys.stderr)
    for e in errs:
        print(f"{a.site}: error: {e}", file=sys.stderr)
    if errs:
        return None
    return site.resolve(doc, base), site_sha(a.site)


def cmd_validate(a):
    r = _site(a)
    if r is None:
        return 1
    print(f"{a.site}: ok ({len(r[0]['hosts'])} hosts)")
    return 0


def _installed_diff(tree, root, owners=False, out=None):
    """Differences between the tree and what is installed under root:
    content (secret values masked), mode, and with owners also owner.
    nodes/ is what install node ships, not part of the collector."""
    from .legacy import _mask
    from . import yamlio
    from .install import deploy
    from .install.ops import Ops
    out = out or sys.stdout
    ops = Ops(root)
    n = 0
    for p in deploy.collector_paths(tree):
        o = tree[p]
        dst = os.path.join(root, p)
        raw = ops.read(p)
        if raw is None:
            print(f"30ops render --diff: {dst} is not installed", file=out)
            n += 1
            continue
        old = raw.decode("utf-8", "replace")
        bad = []
        if o.secret:
            try:
                same = _mask(yamlio.loads(old, dst)) == _mask(yamlio.loads(o.text, p))
            except yamlio.YamlError:
                same = False
            if not same:
                bad.append("differs (secret values not shown)")
        elif old != o.text:
            out.writelines(difflib.unified_diff(old.splitlines(True), o.text.splitlines(True),
                                                f"installed/{p}", f"rendered/{p}"))
            bad.append("")
        st = ops.stat(p)
        if st.st_mode & 0o7777 != o.mode:
            bad.append(f"mode {st.st_mode & 0o7777:04o}, rendered {o.mode:04o}")
        if owners:
            try:
                want = ops.ids(o.owner)
            except LookupError as e:
                want = str(e)
            if ops.owner(p) != want:
                bad.append(f"owner {st.st_uid}:{st.st_gid}, rendered {o.owner}")
        for b in [b for b in bad if b]:
            print(f"30ops render --diff: {dst} {b}", file=out)
        n += bool(bad)
    return n


def cmd_render(a):
    from . import render
    r = _site(a)
    if r is None:
        return 1
    tree = render.render(*r)
    rc = 0
    if a.out:
        render.write(tree, a.out)
        print(f"30ops render: {len(tree)} files under {a.out}", file=sys.stderr)
    if a.diff:
        n = _installed_diff(tree, a.root, owners=a.owners or os.geteuid() == 0)
        if n:
            print(f"30ops render --diff: {n} file(s) differ from {a.root}", file=sys.stderr)
            rc = 1
    if a.compare_legacy:
        from . import legacy
        notes = []
        diffs = legacy.compare(tree, a.compare_legacy, r[0], notes)
        for d in diffs:
            print(d)
        for n in notes:
            print(f"note: new in 30ops: {n}", file=sys.stderr)
        print(f"30ops render --compare-legacy: {len(diffs)} difference(s) from {a.compare_legacy}", file=sys.stderr)
        rc = rc or (1 if diffs else 0)
    if not (a.out or a.diff or a.compare_legacy):
        for p, o in tree.items():
            print(f"{o.mode:04o} {o.owner:<16} {p}")
    return rc


def cmd_import_legacy(a):
    from . import legacy_import, site
    if not os.path.isdir(a.src):
        print(f"30ops import-legacy: {a.src} is not a directory", file=sys.stderr)
        return 2
    doc, todo, assets = legacy_import.draft(a.src)
    text = legacy_import.dumps(doc, todo, a.src)
    if not a.output:
        sys.stdout.write(text)
        base = None
    else:
        if os.path.exists(a.output) and not a.force:
            print(f"30ops import-legacy: {a.output} exists (--force to overwrite)", file=sys.stderr)
            return 2
        base = os.path.dirname(os.path.abspath(a.output))
        os.makedirs(base, exist_ok=True)
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
        if assets:
            dst = os.path.join(base, "assets.tsv")
            if os.path.exists(dst) and not a.force:
                print(f"30ops import-legacy: kept the existing {dst}", file=sys.stderr)
            else:
                shutil.copyfile(os.path.join(a.src, assets), dst)
    print(f"30ops import-legacy: {len(doc['hosts'])} hosts, {len(todo)} TODO line(s)", file=sys.stderr)
    if base:
        errs, warns = site.validate(site.load(a.output), base)
        for e in errs + warns:
            print(f"{a.output}: {e}", file=sys.stderr)
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


def cmd_install_collector(a):
    from . import render
    from .install import collector
    from .install.ops import Ops
    r = _site(a)
    if r is None:
        return 2
    tree = render.render(*r)
    return collector.install(r[0], tree, Ops(a.root), dry_run=a.dry_run, create_volumes=a.create_volumes,
                             out=lambda line: print(line, flush=True))


def cmd_install_node(a):
    from . import render
    from .install import node
    from .install.ops import Ops
    r = _site(a)
    if r is None:
        return 2
    tree = render.render(*r)
    return node.install(r[0], tree, a.host, Ops(), bundle=a.bundle, ssh=a.ssh, out=lambda line: print(line, flush=True))


def cmd_doctor(a):
    from . import doctor, render
    from .install.ops import Ops
    r = _site(a)
    if r is None:
        return 2
    d = doctor.Doctor(r[0], render.render(*r), Ops(a.root))
    res = d.run(skip=set(a.skip))
    sys.stdout.write(doctor.report(res, a.format))
    return 1 if any(x["status"] == doctor.FAIL for x in res) else 0


def cmd_textfile(a):
    from . import collect
    return collect.run(a.name, a.targets, out=a.out, local=a.local,
                       stdin=sys.stdin if a.name == "pve-quorum" and not a.targets else None)


def parser():
    ap = argparse.ArgumentParser(prog="30ops", description="30ops on-prem operations platform")
    ap.add_argument("--version", action="version", version=f"30ops {version()}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    site_default = os.environ.get("OPS30_SITE", "site.yaml")

    v = sub.add_parser("validate", help="check site.yaml")
    v.add_argument("--site", default=site_default, help="default ./site.yaml or $OPS30_SITE")
    v.add_argument("--strict", action="store_true", help="warnings are errors")
    v.add_argument("--secrets", action="store_true", help="also check the credentials files (on the collector)")
    v.set_defaults(f=cmd_validate)

    r = sub.add_parser("render", help="generate the configuration from site.yaml")
    r.add_argument("--site", default=site_default, help="default ./site.yaml or $OPS30_SITE")
    r.add_argument("--out", help="write the files under this directory")
    r.add_argument("--diff", action="store_true", help="compare with the installed files; 1 if any differs")
    r.add_argument("--root", default="/", help="where --diff looks for the installed files (default /)")
    r.add_argument("--owners", action="store_true", help="--diff also compares owners (the default as root)")
    r.add_argument("--compare-legacy", metavar="DIR",
                   help="compare with an old collector's files (a fetch-legacy.sh snapshot); 1 if any differs")
    r.set_defaults(f=cmd_render)

    i = sub.add_parser("import-legacy", help="draft a site.yaml from an old collector's files")
    i.add_argument("--from", dest="src", required=True, metavar="DIR", help="snapshot from scripts/fetch-legacy.sh")
    i.add_argument("-o", "--output", help="write here (and assets.tsv next to it); default stdout")
    i.add_argument("--force", action="store_true", help="overwrite existing files")
    i.set_defaults(f=cmd_import_legacy)

    ins = sub.add_parser("install", help="install the rendered site on this host").add_subparsers(
        dest="sub", required=True)
    c = ins.add_parser("collector", help="this host is the collector (docs/install.md)")
    c.add_argument("--site", default=site_default, help="default ./site.yaml or $OPS30_SITE")
    c.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    c.add_argument("--create-volumes", action="store_true",
                   help="create missing docker volumes (a new site; a moved collector names its old ones)")
    c.add_argument("--root", default="/", help=argparse.SUPPRESS)
    c.set_defaults(f=cmd_install_collector)
    n = ins.add_parser("node", help="install a node's roles over ssh, or write its bundle (docs/install.md)")
    n.add_argument("host", help="the host's name in site.yaml")
    n.add_argument("--site", default=site_default, help="default ./site.yaml or $OPS30_SITE")
    n.add_argument("--bundle", metavar="PATH", help="write the bundle (a file, or a directory for it) and stop")
    n.add_argument("--ssh", metavar="USER@HOST", help="log in as this user (with sudo) instead of hosts[].ssh")
    n.set_defaults(f=cmd_install_node)

    dr = sub.add_parser("doctor", help="check the installed collector against site.yaml (read-only)")
    dr.add_argument("--site", default=site_default, help="default ./site.yaml or $OPS30_SITE")
    dr.add_argument("--format", choices=["text", "json"], default="text")
    dr.add_argument("--skip", action="append", default=[], metavar="CHECK", help="leave a check out (repeatable)")
    dr.add_argument("--root", default="/", help=argparse.SUPPRESS)
    dr.set_defaults(f=cmd_doctor)

    t = sub.add_parser("textfile", help="collect one node_exporter textfile through its adapter (cron)")
    t.add_argument("name", choices=["nas", "pve-quorum"])
    t.add_argument("targets", nargs="*", metavar="LABEL=user@host[,user@host...]",
                   help="pve-quorum without targets reads a pvecm status transcript on stdin")
    t.add_argument("--out", help="write here atomically instead of stdout")
    t.add_argument("--local", action="store_true", help="nas: run on the NAS itself; the targets are bare labels")
    t.set_defaults(f=cmd_textfile)

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
    r.add_argument("--extra", type=_pair, action="append", default=[], metavar="KEY=VALUE",
                   help="extra field; numbers, true, false and null keep their JSON type")
    r.add_argument("--extra-str", type=_pair, action="append", default=[], metavar="KEY=TEXT",
                   help="extra field that is always a string (paths, notes, error texts)")
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
