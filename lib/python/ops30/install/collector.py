"""30ops install collector: the rendered site on the collector host.

  preflight   root, docker compose v2, the checkout is collector.root, no
              pre-30ops cron files or compose projects still running, every
              volume exists (or --create-volumes) and no other project uses
              it, the credentials files exist, no credential has two readers
  accounts    node-exporter, metrics (in node-exporter, which owns the
              textfile directory), agent-gate when the gate has targets
  node_exporter  collector/install-node.sh --collector, only when the version,
              the unit or its state differ
  directories every directory a cron job writes, owned by its user
  ssh keys    metrics' own key and the pcap pull key, only when missing
  changes     the change-record clone, from changes.remote, when missing
  secrets     owner and mode of each credentials file by who reads it; the
              Grafana admin password, only when missing
  files       the rendered tree except nodes/ and the cron file, with owner
              and mode, secrets filled in; a replaced or removed file is
              kept under /etc/30ops/.backup/<time>/
  units       daemon-reload, the allowlist service and the WORM mount
  volumes     created with --create-volumes, never otherwise
  images      pulled by digest when one is missing
  stack       docker compose up -d, then the handlers for what changed
              under a container that compose did not recreate
  health      Prometheus, Alertmanager, Grafana, VictoriaLogs answer
  cron        /etc/cron.d/30ops, last, so no job runs before the stack
  prime       each textfile job that has no file yet runs once as its user

Each step acts only on a difference, so a second run makes no change.
"""
import json
import os
import re
import secrets as pysecrets
import time

from .. import site as S, yamlio
from ..render import compose as RC, nodes as RN
from . import deploy

CRON = "etc/cron.d/30ops"
COMPOSE_ENV = "/etc/30ops/compose.env"
SECRETS_DIR = "/etc/30ops/secrets"
GRAFANA_UID = 472           # the grafana image's user
NOBODY = 65534              # alertmanager runs as nobody
LEGACY_PROJECTS = ("onprem-metrics", "onprem-logs")
UNIT_DIR = "etc/systemd/system/"
# service -> the rendered files it reads through a single-file bind mount;
# a rename does not reach the container, so a change means a recreate
FILE_MOUNTS = {
    "pve-exporter": ("etc/30ops/prometheus/pve.yml",),
    "snmp-exporter": ("etc/30ops/prometheus/snmp-auth.yml",),
    "alertmanager": ("etc/30ops/alertmanager/alertmanager.yml",),
}
HEALTH = {"prometheus": "http://127.0.0.1:9090/-/ready", "alertmanager": "http://127.0.0.1:9093/-/ready",
          "victorialogs": "http://127.0.0.1:9428/health"}


class Run:
    """Collects what changed; prints each change as it happens."""

    def __init__(self, dry_run, out):
        self.dry, self.out = dry_run, out
        self.changes, self.warnings, self.failed = [], [], []

    def change(self, what, fn=None):
        self.changes.append(what)
        self.out(f"{'would ' if self.dry else ''}{what}")
        if self.dry or fn is None:
            return True
        try:
            r = fn()
        except (OSError, LookupError, RuntimeError) as e:
            self.fail(f"{what}: {e}")
            return False
        if r is False:
            return False
        return True

    def warn(self, msg):
        self.warnings.append(msg)
        self.out(f"warning: {msg}")

    def fail(self, msg):
        self.failed.append(msg)
        self.out(f"error: {msg}")

    def check(self, p):
        """p is a CompletedProcess; RuntimeError when it failed."""
        if p.returncode != 0:
            raise RuntimeError(f"{' '.join(p.args)}: rc {p.returncode}: {(p.stderr or p.stdout).strip()[-400:]}")
        return p


class Ctx:
    def __init__(self, site, tree, ops, run):
        self.site, self.tree, self.ops, self.r = site, tree, ops, run
        c = site["collector"]
        self.user = c["user"]
        self.env = RC.env(site)
        self.profiles = [p for p in self.env["COMPOSE_PROFILES"].split(",") if p]
        self.compose = [*ops.docker, "compose", "--env-file", ops.path(COMPOSE_ENV),
                        "-f", os.path.join(S.REPO, "collector", "compose.yml")]
        self.changed = []           # rendered paths written or removed this run
        self.volumes_before = set()

    # ---------- compose ----------
    def services(self):
        """{service: image} that run with this site's profiles."""
        doc = yamlio.load(os.path.join(S.REPO, "collector", "compose.yml"))
        return {n: s["image"] for n, s in doc["services"].items()
                if not s.get("profiles") or set(s["profiles"]) & set(self.profiles)}

    def volumes(self):
        vols = ["prometheus", "alertmanager", "grafana"] + (["victorialogs"] if "logs" in self.profiles else [])
        return [self.site["collector"]["volumes"][v] for v in vols]

    def containers(self):
        p = self.ops.run([*self.compose, "ps", "-a", "--format", "{{.Service}} {{.ID}} {{.State}}"])
        out = {}
        for line in p.stdout.splitlines() if p.returncode == 0 else []:
            f = line.split()
            if len(f) >= 3:
                out[f[0]] = (f[1], f[2])
        return out


# ---------- preflight ----------

def readers(site):
    """credential name -> (owner, mode) of the one process that reads it."""
    want = {}

    def put(name, owner, mode, why):
        if name in want and want[name][:2] != (owner, mode):
            raise ValueError(f"credentials.{name} is read by {want[name][2]} and by {why}; "
                             "give each its own credentials entry")
        want[name] = (owner, mode, why)
    for h in site["hosts"]:
        if h.get("api") and "firewall" in h["roles"]:
            put(h["api"]["token"], site["collector"]["user"], 0o400, f"eol-textfile ({h['name']})")
    if (site["logs"].get("pcap") or {}).get("key"):
        put(site["logs"]["pcap"]["key"], site["collector"]["user"], 0o600, "pcap-pull (ssh key)")
    ex = (site.get("pve") or {}).get("exporter")
    if ex:
        put(ex["token"], "root", 0o400, "install (pve.yml)")
    for name, a in ((site.get("snmp") or {}).get("auths") or {}).items():
        for k in ("password", "priv_password"):
            if a.get(k):
                put(a[k], "root", 0o400, "install (snmp-auth.yml)")
    smtp = (site["alerting"].get("smtp") or {}).get("password")
    if smtp:
        put(smtp, str(NOBODY), 0o400, "alertmanager (compose secret)")
    hc = (site["alerting"].get("deadman") or {}).get("healthchecks")
    if hc:
        put(hc, str(NOBODY), 0o400, "alertmanager (compose secret deadman_url)")
    return {k: v[:2] for k, v in want.items()}


def preflight(ctx, create_volumes):
    ops, site, errs = ctx.ops, ctx.site, []
    if ops.root == "/" and ops.euid() != 0:
        errs.append("run as root")
    p = ops.run([*ops.docker, "compose", "version", "--short"])
    m = re.match(r"v?(\d+)", p.stdout.strip()) if p.returncode == 0 else None
    if not m or int(m.group(1)) < 2:
        errs.append("docker compose v2 is required (apt install docker-compose-v2, or Docker's compose plugin)")
    if os.path.realpath(S.REPO) != os.path.realpath(site["collector"]["root"]):
        errs.append(f"this checkout is {S.REPO}, site.yaml collector.root is {site['collector']['root']}; "
                    "cron runs the scripts from collector.root")
    for f in ops.glob("/etc/cron.d/onprem-*"):
        errs.append(f"{f} is a pre-30ops cron file; its jobs would run twice (move it away first, docs/install.md)")
    if m:
        for proj in LEGACY_PROJECTS:
            q = ops.run([*ops.docker, "ps", "-q", "--filter", f"label=com.docker.compose.project={proj}"])
            if q.returncode == 0 and q.stdout.strip():
                errs.append(f"compose project {proj} is running; stop it first (docker compose down, without -v)")
        for v in ctx.volumes():
            if ops.run([*ops.docker, "volume", "inspect", v]).returncode == 0:
                ctx.volumes_before.add(v)
                q = ops.run([*ops.docker, "ps", "-a", "--filter", f"volume={v}",
                             "--format", '{{.Label "com.docker.compose.project"}}'])
                others = sorted({x for x in q.stdout.split() if x != "30ops"}) if q.returncode == 0 else []
                if others:
                    errs.append(f"volume {v} is used by compose project {', '.join(others)}")
            elif not create_volumes:
                errs.append(f"volume {v} does not exist; a new site creates it with --create-volumes, "
                            "a moved collector names its old volume in collector.volumes")
    try:
        want = readers(site)
    except ValueError as e:
        errs.append(str(e))
        want = {}
    pcap_key = (site["logs"].get("pcap") or {}).get("key")
    for name, c in (site.get("credentials") or {}).items():
        if name != pcap_key and not ops.exists(c["file"]):
            errs.append(f"credentials.{name}: {c['file']} does not exist")
    ctx.readers = want
    return errs


# ---------- accounts ----------

def accounts(ctx):
    ops, r = ctx.ops, ctx.r
    if not ops.group("node-exporter"):
        r.change("add group node-exporter", lambda: r.check(ops.run(["groupadd", "--system", "node-exporter"])))
    if not ops.user("node-exporter"):
        r.change("add user node-exporter", lambda: r.check(ops.run(
            ["useradd", "--system", "-g", "node-exporter", "-s", "/usr/sbin/nologin", "-M", "node-exporter"])))
    users = [(ctx.user, f"/var/lib/{ctx.user}", "/usr/sbin/nologin")]
    if ctx.site["gate"]["targets"]:
        users.append(("agent-gate", ctx.site["gate"]["home"], "/bin/sh"))
    for name, home, shell in users:
        if not ops.user(name):
            r.change(f"add user {name} (home {home})", lambda n=name, h=home, s=shell: r.check(ops.run(
                ["useradd", "--system", "--user-group", "--create-home", "--home-dir", h, "-s", s, n])))
        if r.dry and not ops.user(name):
            r.change(f"add {name} to group node-exporter")
        elif "node-exporter" not in ops.groups_of(name):
            r.change(f"add {name} to group node-exporter",
                     lambda n=name: r.check(ops.run(["usermod", "-aG", "node-exporter", n])))


# ---------- node_exporter ----------

def node_exporter(ctx):
    ops, r = ctx.ops, ctx.r
    ver = RN.NODE_EXPORTER
    p = ops.run([ops.path("/usr/local/bin/node_exporter"), "--version"])
    have = re.search(r"version (\S+)", p.stdout + p.stderr) if p.returncode == 0 else None
    with open(os.path.join(S.REPO, "collector", "systemd", "node_exporter.service"), "rb") as f:
        unit = f.read()
    why = []
    if not have or have.group(1) != ver:
        why.append(f"version {have.group(1) if have else 'none'} != {ver}")
    if ops.read("/etc/systemd/system/node_exporter.service") != unit:
        why.append("unit differs")
    for q in ("is-enabled", "is-active"):
        if ops.run([*ops.systemctl, q, "--quiet", "node_exporter"]).returncode != 0:
            why.append(f"not {q[3:]}")
    if why:
        r.change(f"install node_exporter {ver} ({'; '.join(why)})", lambda: r.check(ops.run(
            ["sh", os.path.join(S.REPO, "collector", "install-node.sh"), "--collector", ver], timeout=900)))


# ---------- directories ----------

def dir_list(ctx):
    s, c, u = ctx.site, ctx.site["collector"], ctx.user
    out = [("/etc/30ops", "root:root", 0o755), (SECRETS_DIR, f"root:{u}", 0o750),
           (c["textfile_dir"], "node-exporter:node-exporter", 0o2775),
           (c["log_dir"], f"{u}:{u}", 0o755), (c["reports_dir"], f"{u}:{u}", 0o755),
           (c["eol_cache"], f"{u}:{u}", 0o755), (s["changes"]["state_dir"], f"{u}:{u}", 0o755)]
    for p in sorted({os.path.dirname(v) for v in c["drills"].values()}):
        out.append((p, f"{u}:{u}", 0o755))
    if s["worm"] and s["logs"].get("archive") is not None:
        out.append(("/var/tmp/onprem-logs-stage", f"{u}:{u}", 0o755))
    if S.with_role(s, "pcap") and s["worm"]:
        out.append(("/var/lib/onprem-pcap", f"{u}:{u}", 0o755))
    if s["gate"]["targets"]:
        out.append((s["gate"]["home"], "agent-gate:agent-gate", 0o750))
    seen, uniq = set(), []
    for d in out:
        if d[0] not in seen:
            seen.add(d[0])
            uniq.append(d)
    return uniq


def ids(ctx, owner):
    """(uid, gid), or None in a dry run where the account is still to be added."""
    try:
        return ctx.ops.ids(owner)
    except LookupError:
        if ctx.r.dry:
            return None
        raise


def ensure_dir(ctx, path, owner, mode):
    ops, r = ctx.ops, ctx.r
    st = ops.stat(path)
    want = ids(ctx, owner)
    if r.dry and (st is None or want is None):
        r.change(f"{'create' if st is None else 'fix'} {path} ({owner} {mode:04o})")
        return
    if st is None or not os.path.isdir(ops.path(path)):
        r.change(f"create {path} ({owner} {mode:04o})", lambda: ops.mkdir(path, mode, *want))
    elif st.st_mode & 0o7777 != mode or ops.owner(path) != want:
        r.change(f"fix {path} ({owner} {mode:04o})", lambda: ops.mkdir(path, mode, *want))


def directories(ctx):
    for path, owner, mode in dir_list(ctx):
        ensure_dir(ctx, path, owner, mode)


# ---------- ssh keys, changes clone ----------

def ssh_keys(ctx):
    ops, r, u = ctx.ops, ctx.r, ctx.user
    acct = ops.user(u)
    home = acct.pw_dir if acct else f"/var/lib/{u}"
    keys = [f"{home}/.ssh/id_ed25519"]
    pk = (ctx.site["logs"].get("pcap") or {}).get("key")
    if pk:
        keys.append(S.secret_file(ctx.site, pk))
    for k in keys:
        if ops.exists(k):
            continue
        d = os.path.dirname(k)
        if not r.dry and not ops.exists(d):
            ensure_dir(ctx, d, f"{u}:{u}", 0o700)
        r.change(f"generate ssh key {k} for {u}", lambda k=k: r.check(ops.run(
            ["runuser", "-u", u, "--", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{u}@30ops",
             "-f", ops.path(k)])))


def changes_clone(ctx):
    ops, r, u = ctx.ops, ctx.r, ctx.user
    clone, remote = ctx.site["changes"]["clone"], ctx.site["changes"].get("remote")
    if ops.exists(f"{clone}/.git"):
        return
    if not remote:
        r.warn(f"{clone} is not a git clone and site.yaml has no changes.remote; changes.prom stays absent")
        return
    if not r.dry:
        ensure_dir(ctx, clone, f"{u}:{u}", 0o755)
    r.change(f"clone {remote} into {clone} as {u}", lambda: r.check(ops.run(
        ["runuser", "-u", u, "--", "git", "clone", "-q", remote, ops.path(clone)], timeout=300)))


# ---------- secrets ----------

def secret_files(ctx):
    ops, r = ctx.ops, ctx.r
    for name, (owner, mode) in sorted(ctx.readers.items()):
        f = S.secret_file(ctx.site, name)
        st = ops.stat(f)
        if st is None:
            continue    # the pcap key in a dry run
        want = ids(ctx, owner if ":" in owner else f"{owner}:{owner}")
        if want is None:
            r.change(f"set {f} to {owner} {mode:04o} (credentials.{name})")
            continue
        if st.st_mode & 0o7777 != mode or ops.owner(f) != want:
            def fix(f=f, want=want, mode=mode):
                ops.chown(f, *want)
                ops.chmod(f, mode)
            r.change(f"set {f} to {owner} {mode:04o} (credentials.{name})", fix)
    g = RC.GRAFANA_ADMIN
    if not ops.exists(g):
        r.change(f"generate the Grafana admin password in {g}", lambda: ops.write(
            g, (pysecrets.token_urlsafe(24) + "\n").encode(), 0o400, GRAFANA_UID, GRAFANA_UID))
        vol = ctx.site["collector"]["volumes"]["grafana"]
        if vol in ctx.volumes_before:
            r.warn(f"Grafana keeps the admin password of its first start in volume {vol}; to use the new one: "
                   f"docker compose --env-file {COMPOSE_ENV} -f {S.REPO}/collector/compose.yml exec -T grafana "
                   f"grafana cli admin reset-admin-password --password-from-stdin < {g}")
        ctx.changed.append(g.lstrip("/"))
    else:
        st = ops.stat(g)
        if st.st_mode & 0o7777 != 0o400 or ops.owner(g) != (GRAFANA_UID, GRAFANA_UID):
            def fixg():
                ops.chown(g, GRAFANA_UID, GRAFANA_UID)
                ops.chmod(g, 0o400)
            r.change(f"set {g} to {GRAFANA_UID}:{GRAFANA_UID} 0400", fixg)
            ctx.changed.append(g.lstrip("/"))


# ---------- files ----------

def backup(ctx, path, stamp):
    ops = ctx.ops
    raw = ops.read(path)
    if raw is None:
        return
    st = ops.stat(path)
    ops.write(f"/etc/30ops/.backup/{stamp}/{path}", raw, st.st_mode & 0o7777 & ~0o077 | 0o600, 0, 0)


def deploy_files(ctx, only=None, skip=()):
    ops, r = ctx.ops, ctx.r
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    paths = [p for p in deploy.collector_paths(ctx.tree) if p not in skip and (only is None or p in only)]
    previous = deploy.installed_manifest(ops)
    try:
        fs = deploy.files(ctx.tree, ctx.site, ops, paths)
    except LookupError as e:
        r.fail(str(e))
        return
    for f in fs:
        if ids(ctx, f.owner) is None:
            r.change(f"write /{f.path} (its owner {f.owner} is still to be added)")
            continue
        why = deploy.differs(f, ops)
        if why is None:
            continue
        uid, gid = ops.ids(f.owner)

        def put(f=f, uid=uid, gid=gid, why=why):
            if why != "missing" and "content" in why:
                backup(ctx, f.path, stamp)
            ops.write(f.path, f.data, f.mode, uid, gid)
        label = "secret values not shown" if f.secret else why
        if r.change(f"write /{f.path} ({label})", put):
            ctx.changed.append(f.path)
    if only is None:
        keep = set(deploy.collector_paths(ctx.tree))
        for old in previous:
            if old.startswith("nodes/") or old in keep or not ops.exists(old):
                continue

            def rm(old=old):
                backup(ctx, old, stamp)
                ops.remove(old)
            if r.change(f"remove /{old} (no longer rendered)", rm):
                ctx.changed.append(old)


# ---------- units ----------

def units(ctx):
    ops, r, sc = ctx.ops, ctx.r, ctx.ops.systemctl
    if any(p.startswith(UNIT_DIR) for p in ctx.changed):
        r.change("systemctl daemon-reload", lambda: r.check(ops.run([*sc, "daemon-reload"])))
    for p in ctx.tree:
        if not p.startswith(UNIT_DIR):
            continue
        unit = os.path.basename(p)
        enabled = ops.run([*sc, "is-enabled", "--quiet", unit]).returncode == 0
        active = ops.run([*sc, "is-active", "--quiet", unit]).returncode == 0
        if unit.endswith(".mount"):
            if not enabled:
                r.change(f"enable {unit}", lambda u=unit: r.check(ops.run([*sc, "enable", u])))
            if not active:
                # hard NFS: --no-block, so an unreachable share cannot hang install
                r.change(f"start {unit} (no-block)", lambda u=unit: r.check(ops.run([*sc, "start", "--no-block", u])))
            continue
        if not enabled or not active:
            r.change(f"enable --now {unit}", lambda u=unit: r.check(ops.run([*sc, "enable", "--now", u])))
        elif p in ctx.changed or "etc/default/30ops-allowlist" in ctx.changed:
            r.change(f"restart {unit}", lambda u=unit: r.check(ops.run([*sc, "restart", u])))


# ---------- docker ----------

def volumes(ctx):
    ops, r = ctx.ops, ctx.r
    for v in ctx.volumes():
        if v not in ctx.volumes_before:
            r.change(f"create docker volume {v}", lambda v=v: r.check(ops.run([*ops.docker, "volume", "create", v])))


def images(ctx):
    ops, r = ctx.ops, ctx.r
    missing = [img for img in sorted(set(ctx.services().values()))
               if ops.run([*ops.docker, "image", "inspect", "--format", "{{.Id}}", img]).returncode != 0]
    if missing:
        r.change(f"docker compose pull ({len(missing)} image(s): {', '.join(i.split('@')[0] for i in missing)})",
                 lambda: r.check(ops.run([*ctx.compose, "pull", "--quiet"], timeout=1800)))


def stack(ctx):
    ops, r = ctx.ops, ctx.r
    want = ctx.services()
    before = ctx.containers()
    if r.dry:
        down = [s for s in want if before.get(s, ("", ""))[1] != "running"]
        if down or ctx.changed:
            r.change("docker compose up -d" + (f" (not running: {', '.join(down)})" if down else ""))
        return
    p = ops.run([*ctx.compose, "up", "-d", "--remove-orphans"], timeout=900)
    if p.returncode != 0:
        r.fail(f"docker compose up -d: {(p.stderr or p.stdout).strip()[-400:]}")
        return
    after = ctx.containers()
    new = sorted(s for s in want if before.get(s, ("",))[0] != after.get(s, ("",))[0])
    gone = sorted(set(before) - set(after))
    if new or gone:
        r.change(f"docker compose up -d (created or recreated: {', '.join(new) or '-'}"
                 + (f"; removed: {', '.join(gone)}" if gone else "") + ")")
    # handlers for files a running container did not get through up -d
    for svc, paths in FILE_MOUNTS.items():
        if svc in want and svc not in new and any(p in ctx.changed for p in paths):
            r.change(f"recreate {svc} (its config is a single-file mount)", lambda s=svc: r.check(ops.run(
                [*ctx.compose, "up", "-d", "--force-recreate", "--no-deps", s], timeout=300)))
    env = RC.env(ctx.site)
    secrets = {env[k].lstrip("/") for k in ("OPS30_SMTP_PASSWORD_FILE", "OPS30_DEADMAN_URL_FILE")}
    if "alertmanager" not in new and secrets & set(ctx.changed):
        r.change("recreate alertmanager (smtp or deadman_url secret)", lambda: r.check(ops.run(
            [*ctx.compose, "up", "-d", "--force-recreate", "--no-deps", "alertmanager"], timeout=300)))
    if "grafana" not in new and any(p.startswith("etc/30ops/grafana/") or p == RC.GRAFANA_ADMIN.lstrip("/")
                                    for p in ctx.changed):
        r.change("restart grafana (provisioning)", lambda: r.check(ops.run([*ctx.compose, "restart", "grafana"])))
    if "prometheus" not in new and any(p.startswith("etc/30ops/prometheus/") and p not in FILE_MOUNTS["pve-exporter"]
                                       + FILE_MOUNTS["snmp-exporter"] for p in ctx.changed):
        def reload():
            code, _ = ops.http("http://127.0.0.1:9090/-/reload", method="POST", timeout=30)
            if code != 200:
                raise RuntimeError(f"POST /-/reload answered {code}")
        r.change("reload prometheus", reload)


def health(ctx, timeout=180):
    ops, r = ctx.ops, ctx.r
    if r.dry:
        return
    urls = {k: v for k, v in HEALTH.items() if k in ctx.services()}
    urls["grafana"] = f"http://127.0.0.1:{ctx.site['collector']['grafana_port']}/api/health"
    t0 = time.monotonic()
    while True:
        bad = [k for k, u in urls.items() if ops.http(u)[0] != 200]
        if not bad:
            ctx.r.out(f"ok    {', '.join(sorted(urls))} answer")
            return
        if time.monotonic() - t0 > timeout:
            r.fail(f"not healthy after {timeout}s: {', '.join(bad)}")
            return
        ops.sleep(3)


# ---------- prime ----------

PROM = re.compile(r"(?:--out|--textfile) (\S+\.prom)\b|&& mv \S+ (\S+\.prom)$")


def textfile_jobs(cron_text):
    """[(user, env, command, textfile)] for every cron line that writes a
    .prom, with the file-level variables it sees."""
    out, glob_env = [], {}
    for line in cron_text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if m:
            glob_env[m.group(1)] = m.group(2).strip('"')
            continue
        f = line.split(None, 6)
        if len(f) < 7:
            continue
        p = PROM.search(f[6])
        if p:
            out.append((f[5], dict(glob_env), f[6].replace("\\%", "%"), p.group(1) or p.group(2)))
    return out


def prime(ctx):
    ops, r = ctx.ops, ctx.r
    text = ctx.tree[CRON].text if CRON in ctx.tree else ""
    for user, env, cmd, tf in textfile_jobs(text):
        if ops.exists(tf):
            continue
        envs = [f"{k}={v}" for k, v in env.items()]

        def go(user=user, envs=envs, cmd=cmd, tf=tf):
            p = ops.run(["runuser", "-u", user, "--", "env", *envs, "sh", "-c", cmd], timeout=600)
            if p.returncode != 0 or not ops.exists(tf):
                r.warn(f"first run of the job for {tf} did not write it (rc {p.returncode}): "
                       f"{(p.stderr or p.stdout).strip()[-300:]}")
        r.change(f"run the {os.path.basename(tf)} job once as {user}", go)


# ---------- main ----------

def install(site, tree, ops, dry_run=False, create_volumes=False, out=print):
    """Exit code: 0 done (or nothing to do), 1 a step failed, 2 refused."""
    r = Run(dry_run, out)
    ctx = Ctx(site, tree, ops, r)
    errs = preflight(ctx, create_volumes)
    for e in errs:
        out(f"refused: {e}")
    if errs and not dry_run:
        return 2
    for step in (accounts, node_exporter, directories, ssh_keys, changes_clone, secret_files):
        step(ctx)
        if r.failed:
            break
    if not r.failed:
        deploy_files(ctx, skip=(CRON,))
    for step in (units, volumes, images, stack, health):
        if r.failed:
            break
        step(ctx)
    if not r.failed:
        deploy_files(ctx, only=(CRON,))
        prime(ctx)
    n = len(r.changes)
    if dry_run:
        out(f"30ops install collector --dry-run: {n} change(s) to make")
    else:
        out(f"30ops install collector: {n} change(s), {len(r.warnings)} warning(s)"
            + (f", {len(r.failed)} failed" if r.failed else ""))
    manual(ctx)
    return 2 if errs else 1 if r.failed else 0


def manual(ctx):
    """What install cannot do from the collector: printed every run, short."""
    ops, out = ctx.ops, ctx.r.out
    acct = ops.user(ctx.user)
    pub = ops.read(f"{acct.pw_dir if acct else '/var/lib/' + ctx.user}/.ssh/id_ed25519.pub")
    nas = [h for h in S.with_role(ctx.site, "nas") if h.get("ssh")]
    pve = [h for h in S.with_role(ctx.site, "hypervisor") if h.get("pve") and h.get("ssh")]
    if not (nas or pve):
        return
    out("next, outside this host (docs/install.md):")
    if pub:
        out(f"  key of {ctx.user}: {pub.decode().strip()}")
    for h in nas:
        out(f"  {h['name']}: authorize that key for {h['ssh']['user']}, then as {ctx.user}: "
            f"ssh-keyscan {h['address']} and compare the fingerprint with the NAS before adding it to known_hosts")
    for h in pve:
        out(f"  {h['name']}: 30ops install node {h['name']} (pins the quorum key with command=\"/usr/bin/pvecm status\")")
