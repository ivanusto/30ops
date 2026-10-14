"""30ops install node: the bundle is deterministic and carries what the
host's roles need; appliances get their adapter's steps instead."""
import hashlib
import io
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lib" / "python"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ops30 import render  # noqa: E402
from ops30.install import node  # noqa: E402
from test_install import FakeOps, site_for  # noqa: E402


class Bundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.site = site_for(self.tmp)
        self.tree = render.render(self.site, "x")
        self.ops = FakeOps(self.tmp)
        self.ops.write("/var/lib/metrics/.ssh/id_ed25519.pub", b"ssh-ed25519 AAAAquorum metrics@30ops\n", 0o644, 0, 0)
        self.ops.write("/var/lib/metrics/.ssh/id_pcap.pub", b"ssh-ed25519 AAAApull metrics@30ops\n", 0o644, 0, 0)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def names(self, host):
        entries, warns = node.contents(self.site, self.tree, next(h for h in self.site["hosts"] if h["name"] == host),
                                       self.ops)
        self.assertEqual(warns, [])
        return entries, [e[0] for e in entries]

    def test_deterministic(self):
        e1, _ = self.names("pve1")
        e2, _ = self.names("pve1")
        self.assertEqual(hashlib.sha256(node.build(e1)).hexdigest(), hashlib.sha256(node.build(e2)).hexdigest())
        with tarfile.open(fileobj=io.BytesIO(node.build(e1))) as t:
            m = t.getmembers()
        self.assertEqual({(x.mtime, x.uid, x.gid) for x in m}, {(0, 0, 0)})
        self.assertEqual([x.name for x in m], sorted(x.name for x in m))

    def test_pve_node(self):
        entries, names = self.names("pve1")
        p = "30ops-node-pve1/"
        for f in ("node-install.sh", "install.env", "logs/node/install-journal-upload.sh", "logs/pcap/install-pcap.sh",
                  "etc/pcap/corosync.env", "etc/sudoers.d/pcap", "keys/quorum.pub", "keys/pcap-pull.pub"):
            self.assertIn(p + f, names)
        self.assertNotIn(p + "collector/install-node.sh", names)      # no node role
        mode = dict((e[0], e[2]) for e in entries)
        self.assertEqual(mode[p + "node-install.sh"], 0o755)
        self.assertEqual(mode[p + "etc/sudoers.d/pcap"], 0o440)

    def test_gb10_node(self):
        _, names = self.names("spark01")
        self.assertIn("30ops-node-spark01/collector/textfile/gb10-textfile.py", names)
        self.assertNotIn("30ops-node-spark01/etc/pcap/corosync.env", names)   # not a hypervisor
        self.assertNotIn("30ops-node-spark01/keys/quorum.pub", names)

    def test_bundle_file_and_appliances(self):
        lines = []
        rc = node.install(self.site, self.tree, "pve1", self.ops, bundle=self.tmp, out=lines.append)
        self.assertEqual(rc, 0, lines)
        data = (Path(self.tmp) / "30ops-node-pve1.tar.gz").read_bytes()
        self.assertIn(hashlib.sha256(data).hexdigest(), lines[0])
        lines = []
        self.assertEqual(node.install(self.site, self.tree, "nas-primary", self.ops, out=lines.append), 0)
        self.assertTrue(lines[0].startswith("nas-primary is a nas served by the qnap adapter"))
        self.assertTrue(any("SNMP V3 only" in x for x in lines), lines)
        lines = []
        self.assertEqual(node.install(self.site, self.tree, "admin1", self.ops, out=lines.append), 2)
        self.assertEqual(node.install(self.site, self.tree, "nope", self.ops, out=lines.append), 2)


if __name__ == "__main__":
    unittest.main()
