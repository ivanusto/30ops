"""30ops doctor: is the installed collector the rendered site, and is it
working. Read-only; every check reports ok, warn or fail with what it saw.

  images     every service runs the image digest compose.yml pins
  targets    every Prometheus target is up
  textfiles  every textfile a cron job writes is younger than its stale
             alert allows, says no *_up 0, and node_exporter parses them
  cron       the cron daemon runs (the file itself is part of render)
  worm       the WORM share is mounted nfs4 rw and the collector user can
             write to it; nothing is written, a file there cannot be removed
  clock      NTP synchronised and the zone is site.timezone (cron times are
             local; a wrong zone archives a UTC day before it has closed)
  disk       /, the docker root and the textfile directory below 80 % (warn)
             and 90 % (fail)
  secrets    owner and mode of every credentials file, by its reader
  grafana    the admin password works and is not the default
  accounts   the collector user is in node-exporter
  render     the installed files are the rendered ones, mode and owner too
"""
import json
import os
import re
import time

from . import site as S
from .install import collector as IC, deploy
from .render import compose as RC
from .render.cron import TEXTFILES

OK, WARN, FAIL = "ok", "warn", "fail"


class Doctor:
    def __init__(self, site, tree, ops, now=None):
        self.site, self.tree, self.ops = site, tree, ops
        self.now = time.time() if now is None else now
        self.results = []
        self.ctx = IC.Ctx(site, tree, ops, IC.Run(True, lambda x: None))

    def add(self, check, status, detail):
        self.results.append({"check": check, "status": status, "detail": detail})

    # ---------- checks ----------
    def images(self):
        ops, want = self.ops, self.ctx.services()
        running = self.ctx.containers()
        bad = []
        for svc, img in sorted(want.items()):
            pin = img.split("@", 1)[1] if "@" in img else None
            if svc not in running or running[svc][1] != "running":
                bad.append(f"{svc} is not running")
                continue
            p = ops.run([*ops.docker, "inspect", "--format", "{{.Image}}", running[svc][0]])
            q = ops.run([*ops.docker, "image", "inspect", "--format", "{{json .RepoDigests}}", p.stdout.strip()])
            try:
                digests = {d.split("@", 1)[1] for d in json.loads(q.stdout or "[]")}
            except ValueError:
                digests = set()
            if pin not in digests:
                bad.append(f"{svc} runs {', '.join(sorted(digests)) or 'an image without a digest'}, compose.yml pins {pin}")
        self.add("images", FAIL if bad else OK, "; ".join(bad) or f"{len(want)} services on their pinned digests")

    def _query(self, q):
        import urllib.parse
        code, body = self.ops.http("http://127.0.0.1:9090/api/v1/query?query=" + urllib.parse.quote(q))
        if code != 200:
            return None
        try:
            return json.loads(body)["data"]["result"]
        except (ValueError, KeyError):
            return None

    def targets(self):
        code, body = self.ops.http("http://127.0.0.1:9090/api/v1/targets?state=active")
        if code != 200:
            self.add("targets", FAIL, f"Prometheus did not answer ({code})")
            return
        ts = json.loads(body)["data"]["activeTargets"]
        name = lambda t: f"{t['labels'].get('job')}/{t['labels'].get('instance')}"   # noqa: E731
        down = [f"{name(t)}: {t.get('lastError') or t['health']}" for t in ts if t["health"] == "down"]
        new = [name(t) for t in ts if t["health"] not in ("up", "down")]
        if down:
            self.add("targets", FAIL, "; ".join(down))
        elif new:
            self.add("targets", WARN, f"not scraped yet (just started?): {', '.join(new)}")
        else:
            self.add("targets", OK, f"{len(ts)} targets up")

    def textfiles(self):

        text = self.tree[IC.CRON].text if IC.CRON in self.tree else ""
        for user, _, _, path in IC.textfile_jobs(text):
            name = os.path.basename(path)
            prefix, max_age = TEXTFILES.get(name, (None, 3600))
            raw = self.ops.read(path)
            if raw is None:
                self.add(f"textfile {name}", FAIL, f"{path} does not exist (its job runs as {user})")
                continue
            body = raw.decode("utf-8", "replace")
            stamps = [float(m) for m in re.findall(rf"^{prefix}_last_run_timestamp(?:\{{[^}}]*\}})? (\S+)$", body, re.M)]
            age = self.now - (min(stamps) if stamps else self.ops.stat(path).st_mtime)
            down = re.findall(r"^(\w+_up(?:\{[^}]*\})?) 0$", body, re.M)
            if age > max_age:
                self.add(f"textfile {name}", FAIL, f"{int(age)} s old, its alert fires after {max_age} s")
            elif down:
                self.add(f"textfile {name}", WARN, f"{int(age)} s old; down: {', '.join(down)}")
            else:
                self.add(f"textfile {name}", OK, f"{int(age)} s old")
        r = self._query("node_textfile_scrape_error")
        if not r:
            self.add("textfile scrape", WARN, "Prometheus has no node_textfile_scrape_error yet (not scraped, or no node_exporter)")
        else:
            bad = [x["metric"].get("instance", "?") for x in r if x["value"][1] != "0"]
            self.add("textfile scrape", FAIL if bad else OK,
                     f"node_exporter could not parse a textfile on {', '.join(bad)}" if bad else
                     f"node_exporter parses every textfile ({len(r)} instance(s))")


    def cron(self):
        sc = self.ops.systemctl
        ok = any(self.ops.run([*sc, "is-active", "--quiet", u]).returncode == 0 for u in ("cron", "crond"))
        self.add("cron", OK if ok else FAIL, "the cron daemon runs" if ok else "neither cron nor crond is active")

    def worm(self):
        w = self.site.get("worm")
        if not w:
            self.add("worm", OK, "no WORM share in site.yaml")
            return
        m = w["mount"]
        p = self.ops.run(["findmnt", "-n", "-o", "FSTYPE,OPTIONS", "--mountpoint", m])
        f = p.stdout.split()
        if p.returncode != 0 or len(f) < 2:
            self.add("worm", FAIL, f"{m} is not mounted")
            return
        why = []
        if f[0] != "nfs4":
            why.append(f"type {f[0]}, not nfs4")
        if "rw" not in f[1].split(","):
            why.append("mounted read-only")
        user = self.site["collector"]["user"]
        if self.ops.run(["runuser", "-u", user, "--", "test", "-w", self.ops.path(m)]).returncode != 0:
            why.append(f"{user} cannot write to it")
        self.add("worm", FAIL if why else OK, "; ".join(why) or f"{m} nfs4 rw, writable by {user}")

    def clock(self):
        tz = self.site["site"]["timezone"]
        p = self.ops.run(["timedatectl", "show", "-p", "NTPSynchronized", "-p", "Timezone"])
        kv = dict(x.split("=", 1) for x in p.stdout.split() if "=" in x)
        link = os.path.realpath(self.ops.path("/etc/localtime"))
        have = kv.get("Timezone") or (link.split("zoneinfo/", 1)[1] if "zoneinfo/" in link else "?")
        if have != tz:
            self.add("clock", FAIL, f"time zone {have}, site.timezone {tz} (cron runs in local time)")
        elif kv.get("NTPSynchronized") != "yes":
            self.add("clock", WARN, f"time zone {tz}; NTP is not synchronised")
        else:
            self.add("clock", OK, f"NTP synchronised, {tz}")

    def disk(self):
        p = self.ops.run([*self.ops.docker, "info", "--format", "{{.DockerRootDir}}"])
        paths = ["/", p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else "/var/lib/docker",
                 self.site["collector"]["textfile_dir"]]
        seen = {}
        for path in paths:
            st = self.ops.statvfs(path)
            if st is None or st.f_blocks == 0:
                continue
            pct = 100.0 * (st.f_blocks - st.f_bavail) / st.f_blocks
            seen.setdefault(st.f_fsid if hasattr(st, "f_fsid") else path, (path, pct))
        worst = max(seen.values(), key=lambda x: x[1], default=None)
        if worst is None:
            self.add("disk", WARN, "no file system to look at")
            return
        status = FAIL if worst[1] >= 90 else WARN if worst[1] >= 80 else OK
        self.add("disk", status, ", ".join(f"{p} {pct:.0f} %" for p, pct in seen.values()))

    def secrets(self):
        ops, bad = self.ops, []
        try:
            want = IC.readers(self.site)
        except ValueError as e:
            self.add("secrets", FAIL, str(e))
            return
        want = {S.secret_file(self.site, n): v for n, v in want.items()}
        want[RC.GRAFANA_ADMIN] = (str(IC.GRAFANA_UID), 0o400)
        for f, (owner, mode) in sorted(want.items()):
            st = ops.stat(f)
            if st is None:
                bad.append(f"{f} is missing")
                continue
            try:
                ids = ops.ids(owner if ":" in owner else f"{owner}:{owner}")
            except LookupError as e:
                bad.append(f"{f}: {e}")
                continue
            if st.st_mode & 0o7777 != mode or ops.owner(f) != ids:
                bad.append(f"{f} is {st.st_uid}:{st.st_gid} {st.st_mode & 0o7777:04o}, want {owner} {mode:04o}")
        for name, c in (self.site.get("credentials") or {}).items():
            st = ops.stat(c["file"])
            if st and st.st_mode & 0o077 and c["file"] not in want:
                bad.append(f"{c['file']} (credentials.{name}) is readable by others")
        self.add("secrets", FAIL if bad else OK, "; ".join(bad) or f"{len(want)} secret files, owner and mode as their readers need")

    def grafana(self):
        port = self.site["collector"]["grafana_port"]
        url = f"http://127.0.0.1:{port}/api/user"
        raw = self.ops.read(RC.GRAFANA_ADMIN)
        if raw is None:
            self.add("grafana", FAIL, f"{RC.GRAFANA_ADMIN} is missing")
            return
        code, _ = self.ops.http(url, auth="admin:" + raw.decode().strip())
        if code == 200:
            self.add("grafana", OK, "the admin password from the secret file works")
            return
        # one try with the default only: Grafana locks a user after a few failed logins
        code2, _ = self.ops.http(url, auth="admin:admin") if code == 401 else (0, "")
        if code2 == 200:
            self.add("grafana", FAIL, "the admin password is still 'admin' (the file was unreadable on the first "
                     "start); reset it, docs/install.md")
        else:
            self.add("grafana", WARN, f"the admin password from the file does not work ({code}); "
                     "it was changed in Grafana, or Grafana keeps an older one (docs/install.md)")

    def accounts(self):
        u = self.site["collector"]["user"]
        g = self.ops.groups_of(u)
        if not self.ops.user(u):
            self.add("accounts", FAIL, f"no user {u}")
        elif "node-exporter" not in g:
            self.add("accounts", FAIL, f"{u} is not in node-exporter, so its jobs cannot write the textfiles")
        else:
            self.add("accounts", OK, f"{u} is in node-exporter")

    def render(self):
        bad = []
        try:
            fs = deploy.files(self.tree, self.site, self.ops)
        except LookupError as e:
            self.add("render", FAIL, str(e))
            return
        for f in fs:
            why = deploy.differs(f, self.ops)
            if why:
                bad.append(f"/{f.path}: {why}")
        self.add("render", FAIL if bad else OK,
                 "; ".join(bad[:10]) + (f" (and {len(bad) - 10} more)" if len(bad) > 10 else "") if bad
                 else f"{len(fs)} installed files are the rendered ones (content, mode, owner)")

    CHECKS = ("images", "targets", "textfiles", "cron", "worm", "clock", "disk", "secrets", "grafana",
              "accounts", "render")

    def run(self, skip=()):
        for c in self.CHECKS:
            if c not in skip:
                try:
                    getattr(self, c)()
                except Exception as e:      # a broken check is a failed check, not a traceback
                    self.add(c, FAIL, f"the check itself failed: {type(e).__name__}: {e}")
        return self.results


def report(results, fmt="text"):
    if fmt == "json":
        return json.dumps({"results": results, "fail": sum(r["status"] == FAIL for r in results),
                           "warn": sum(r["status"] == WARN for r in results)}, ensure_ascii=False, indent=2) + "\n"
    out = [f"{r['status']:<5} {r['check']}: {r['detail']}" for r in results]
    n = {s: sum(r["status"] == s for r in results) for s in (OK, WARN, FAIL)}
    out.append(f"30ops doctor: {n[OK]} ok, {n[WARN]} warn, {n[FAIL]} fail")
    return "\n".join(out) + "\n"
