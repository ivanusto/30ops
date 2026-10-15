"""30ops install collector against a fake host: a temporary root for the
files, and a FakeOps that answers docker, systemctl and the account
commands from an in-memory state. The property that matters: the second
run makes no change."""
import copy
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))

from ops30 import site as S  # noqa: E402
from ops30 import render  # noqa: E402
from ops30.install import collector  # noqa: E402
from ops30.install.ops import Ops  # noqa: E402

SAMPLE = ROOT / "examples" / "sample-site"


class Acct:
    def __init__(self, name, uid, gid, home="/"):
        self.pw_name, self.pw_uid, self.pw_gid, self.pw_dir = name, uid, gid, home


class Grp:
    def __init__(self, name, gid):
        self.gr_name, self.gr_gid, self.gr_mem = name, gid, []


class FakeOps(Ops):
    def __init__(self, root):
        super().__init__(root)
        self.docker, self.systemctl = ["docker"], ["systemctl"]
        self.users = {"root": Acct("root", 0, 0, "/root")}
        self.groups_ = {"root": Grp("root", 0), "101": Grp("101", 101)}
        self.owners = {}
        self.volumes = set()
        self.images = set()
        self.containers = {}            # service -> id
        self.units = {}                 # unit -> {"enabled", "active"}
        self.ne_version = None
        self.log = []
        self.next = 1000

    # accounts
    def user(self, name):
        return self.users.get(name)

    def group(self, name):
        return self.groups_.get(name)

    def groups_of(self, name):
        u = self.users.get(name)
        if not u:
            return set()
        return {g.gr_name for g in self.groups_.values() if name in g.gr_mem or g.gr_gid == u.pw_gid}

    # ownership is recorded, not applied (the tests do not run as root)
    def chown(self, p, uid, gid):
        self.owners[p.lstrip("/")] = (uid, gid)

    def fchown(self, fd, uid, gid, p):
        self.owners[p.lstrip("/")] = (uid, gid)

    def owner(self, p):
        if not self.exists(p):
            return None
        return self.owners.get(p.lstrip("/"), (0, 0))

    def euid(self):
        return 0

    def http(self, url, method="GET", timeout=5, auth=None):
        self.log.append(("http", method, url))
        return 200, ""

    def sleep(self, s):
        pass

    def _id(self):
        self.next += 1
        return f"c{self.next}"

    def run(self, argv, input=None, timeout=600, env=None):
        import subprocess
        self.log.append(tuple(argv))
        ok = lambda out="": subprocess.CompletedProcess(argv, 0, out, "")    # noqa: E731
        no = lambda: subprocess.CompletedProcess(argv, 1, "", "no")          # noqa: E731
        a = list(argv)
        if a[:2] == ["docker", "compose"]:
            rest = a[2:]
            while rest and rest[0] in ("--env-file", "-f"):
                rest = rest[2:]
            if rest[:2] == ["version", "--short"]:
                return ok("2.29.1\n")
            if rest[:1] == ["ps"]:
                return ok("".join(f"{s} {i} running\n" for s, i in sorted(self.containers.items())))
            if rest[:1] == ["pull"]:
                self.images |= set(self.want_images)
                return ok()
            if rest[:2] == ["up", "-d"]:
                if "--force-recreate" in rest:
                    self.containers[rest[-1]] = self._id()
                    return ok()
                for svc in self.want_services:
                    if svc not in self.containers:
                        self.containers[svc] = self._id()
                return ok()
            if rest[:1] == ["restart"]:
                return ok()
            raise AssertionError(f"unexpected compose call {argv}")
        if a[0] == "docker":
            if a[1:3] == ["volume", "inspect"]:
                return ok() if a[3] in self.volumes else no()
            if a[1:3] == ["volume", "create"]:
                self.volumes.add(a[3])
                return ok()
            if a[1:3] == ["image", "inspect"]:
                return ok() if a[-1] in self.images else no()
            if a[1] == "ps":
                return ok()
            raise AssertionError(f"unexpected docker call {argv}")
        if a[0] == "systemctl":
            verb, unit = a[1], a[-1]
            st = self.units.setdefault(unit, {"enabled": False, "active": False})
            if verb == "is-enabled":
                return ok() if st["enabled"] else no()
            if verb == "is-active":
                return ok() if st["active"] else no()
            if verb in ("enable", "start", "restart", "daemon-reload"):
                if verb == "enable":
                    st["enabled"] = True
                    st["active"] = st["active"] or "--now" in a
                if verb == "start":
                    st["active"] = True
                return ok()
            raise AssertionError(f"unexpected systemctl call {argv}")
        if a[0].endswith("/usr/local/bin/node_exporter"):
            return ok(f"node_exporter, version {self.ne_version}\n") if self.ne_version else no()
        if a[0] == "sh" and a[1].endswith("install-node.sh"):
            self.ne_version = a[-1]
            unit = (ROOT / "collector" / "systemd" / "node_exporter.service").read_bytes()
            self.write("/etc/systemd/system/node_exporter.service", unit, 0o644, 0, 0)
            self.units["node_exporter"] = {"enabled": True, "active": True}
            return ok()
        if a[0] == "groupadd":
            self.groups_[a[-1]] = Grp(a[-1], 900 + len(self.groups_))
            return ok()
        if a[0] == "useradd":
            name = a[-1]
            if "--user-group" in a:
                self.groups_[name] = Grp(name, 900 + len(self.groups_))
                gid = self.groups_[name].gr_gid
            else:
                gid = self.groups_[a[a.index("-g") + 1]].gr_gid
            home = a[a.index("--home-dir") + 1] if "--home-dir" in a else "/"
            self.users[name] = Acct(name, 800 + len(self.users), gid, home)
            if "--create-home" in a:
                os.makedirs(self.path(home), exist_ok=True)
            return ok()
        if a[0] == "usermod":
            self.groups_[a[2]].gr_mem.append(a[3])
            return ok()
        if a[0] == "runuser":
            cmd = a[a.index("--") + 1:]
            if cmd[0] == "ssh-keygen":
                f = cmd[cmd.index("-f") + 1]
                Path(f).parent.mkdir(parents=True, exist_ok=True)
                Path(f).write_text("key\n")
                Path(f + ".pub").write_text("ssh-ed25519 AAAA metrics@30ops\n")
                os.chmod(f, 0o600)
                return ok()
            if cmd[0] == "git":
                os.makedirs(os.path.join(cmd[-1], ".git"), exist_ok=True)
                return ok()
            if cmd[0] == "env":
                m = collector.PROM.search(cmd[-1])
                self.write(m.group(1) or m.group(2), b"# fake\n", 0o644, 0, 0)
                return ok()
        raise AssertionError(f"unexpected command {argv}")


def site_for(root):
    doc = S.load(SAMPLE / "site.yaml")
    doc["collector"]["root"] = str(ROOT)
    doc["changes"]["remote"] = "https://git.example.net/site.git"
    s = S.resolve(doc, str(SAMPLE))
    return s


def credentials(ops, s):
    for name, c in s["credentials"].items():
        if name != s["logs"]["pcap"]["key"]:
            ops.write(c["file"], f"value-of-{name}:#x\n".encode(), 0o644, 0, 0)


def host(tmp, s):
    ops = FakeOps(tmp)
    credentials(ops, s)
    ops.volumes = {s["collector"]["volumes"][v] for v in ("prometheus", "alertmanager", "grafana", "victorialogs")}
    ctx = collector.Ctx(s, {}, ops, collector.Run(True, lambda x: None))
    ops.want_services = list(ctx.services())
    ops.want_images = list(ctx.services().values())
    return ops


class InstallCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.site = site_for(self.tmp)
        self.tree = render.render(self.site, "x")
        self.ops = host(self.tmp, self.site)
        self.lines = []

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def install(self, **kw):
        self.lines = []
        return collector.install(self.site, self.tree, self.ops, out=self.lines.append, **kw)

    def changes(self):
        return [x for x in self.lines if not x.startswith(("ok ", "warning:", "30ops install", "next,", "  "))]

    def test_second_run_changes_nothing(self):
        self.assertEqual(self.install(), 0, self.lines)
        first = self.changes()
        self.assertTrue(any(x.startswith("add user metrics") for x in first), first)
        self.assertIn("docker compose pull (6 image(s): " + ", ".join(sorted(
            i.split("@")[0] for i in self.ops.want_images)) + ")", first)
        self.assertEqual(self.install(), 0, self.lines)
        self.assertEqual(self.changes(), [])
        self.assertIn("30ops install collector: 0 change(s), 0 warning(s)", self.lines)

    def test_files_owner_mode_and_secrets(self):
        self.assertEqual(self.install(), 0, self.lines)
        pve = Path(self.ops.path("etc/30ops/prometheus/pve.yml"))
        self.assertEqual(pve.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.ops.owners["etc/30ops/prometheus/pve.yml"], (0, 101))
        # the value as a JSON string: the ':' and '#' do not break the YAML
        self.assertIn('token_value: "value-of-pve-exporter:#x"', pve.read_text())
        self.assertNotIn("@secret", pve.read_text())
        self.assertFalse(self.ops.exists("nodes"))
        smtp = self.site["credentials"]["smtp"]["file"]
        self.assertEqual(self.ops.owners[smtp.lstrip("/")], (65534, 65534))
        self.assertEqual(Path(self.ops.path(smtp)).stat().st_mode & 0o777, 0o400)
        tok = self.site["credentials"]["fortigate-api"]["file"]
        self.assertEqual(self.ops.owners[tok.lstrip("/")][0], self.ops.users["metrics"].pw_uid)
        g = Path(self.ops.path("etc/30ops/secrets/grafana-admin.pass"))
        self.assertEqual((g.stat().st_mode & 0o777, self.ops.owners["etc/30ops/secrets/grafana-admin.pass"]),
                         (0o400, (472, 472)))
        self.assertIn("node-exporter", self.ops.groups_of("metrics"))
        # cron last, then each textfile job once
        names = [x for x in self.changes() if x.startswith(("write /etc/cron.d", "run the"))]
        self.assertTrue(names[0].startswith("write /etc/cron.d/30ops"), names)
        self.assertTrue(self.ops.exists("var/lib/node_exporter/textfile/eol.prom"))

    def test_changed_file_recreates_its_service(self):
        self.install()
        am = Path(self.ops.path("etc/30ops/alertmanager/alertmanager.yml"))
        am.write_text(am.read_text() + "# local edit\n")
        before = dict(self.ops.containers)
        self.assertEqual(self.install(), 0, self.lines)
        ch = self.changes()
        self.assertIn("write /etc/30ops/alertmanager/alertmanager.yml (content)", ch)
        self.assertIn("recreate alertmanager (its config is a single-file mount)", ch)
        self.assertNotEqual(before["alertmanager"], self.ops.containers["alertmanager"])
        self.assertEqual(before["prometheus"], self.ops.containers["prometheus"])
        backups = self.ops.glob("/etc/30ops/.backup/*/etc/30ops/alertmanager/alertmanager.yml")
        self.assertEqual(len(backups), 1)

    def test_prometheus_reload_and_orphan(self):
        self.install()
        tree = dict(self.tree)
        del tree["etc/30ops/prometheus/targets/gb10.yml"]
        tree["etc/30ops/manifest.json"] = render.Output(render.manifest(
            {k: v for k, v in tree.items() if k != "etc/30ops/manifest.json"}, "x"))
        self.tree = tree
        self.install()
        ch = self.changes()
        self.assertIn("remove /etc/30ops/prometheus/targets/gb10.yml (no longer rendered)", ch)
        self.assertIn("reload prometheus", ch)
        self.assertFalse(self.ops.exists("etc/30ops/prometheus/targets/gb10.yml"))

    def test_dry_run_changes_nothing(self):
        self.assertEqual(self.install(dry_run=True), 0, self.lines)
        self.assertTrue(all(x.startswith(("would ", "warning:", "30ops install", "next,", "  ", "ok "))
                            for x in self.lines), self.lines)
        self.assertFalse(self.ops.exists("etc/30ops/compose.env"))
        self.assertNotIn("metrics", self.ops.users)

    def test_refusals(self):
        self.ops.write("/etc/cron.d/onprem-metrics", b"x\n", 0o644, 0, 0)
        self.ops.volumes.discard(self.site["collector"]["volumes"]["grafana"])
        self.assertEqual(self.install(), 2)
        txt = "\n".join(self.lines)
        self.assertIn("/etc/cron.d/onprem-metrics is a pre-30ops cron file", txt)
        self.assertIn(f"volume {self.site['collector']['volumes']['grafana']} does not exist", txt)
        self.assertFalse(self.ops.exists("etc/30ops/compose.env"))

    def test_create_volumes(self):
        self.ops.volumes = set()
        self.assertEqual(self.install(create_volumes=True), 0, self.lines)
        self.assertIn(f"create docker volume {self.site['collector']['volumes']['grafana']}", self.changes())
        self.assertEqual(self.install(), 0)
        self.assertEqual(self.changes(), [])

    def test_two_readers_of_one_credential(self):
        s = copy.deepcopy(self.site)
        s["alerting"]["smtp"]["password"] = s["pve"]["exporter"]["token"]
        with self.assertRaisesRegex(ValueError, "is read by install .pve.yml. and by alertmanager"):
            collector.readers(s)

    def test_textfile_jobs(self):
        jobs = collector.textfile_jobs(self.tree["etc/cron.d/30ops"].text)
        files = [os.path.basename(j[3]) for j in jobs]
        self.assertEqual(files, ["nas.prom", "drills.prom", "pve-quorum.prom", "eol.prom", "fw.prom", "aup.prom",
                                 "audit.prom", "changes.prom", "agent-gate.prom", "readiness.prom"])
        fw = next(j for j in jobs if j[3].endswith("fw.prom"))
        self.assertEqual(fw[1].get("FW_EXPECT"), "fortigate:fgt-edge")
        self.assertEqual(jobs[-2][0], "agent-gate")
        self.assertTrue(jobs[-1][2].endswith("|| true"), jobs[-1][2])


if __name__ == "__main__":
    unittest.main()
