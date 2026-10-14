"""30ops install node: what a node needs from the site, as one bundle.

The bundle is a tar.gz that unpacks to 30ops-node-<host>/ with
node-install.sh (collector/node/), the installers for the host's roles, the
rendered nodes/<host>/ files and the collector's public keys. It is built
deterministically (sorted entries, mtime 0, uid 0, gzip mtime 0), so the
same site gives the same bytes and its sha256 says what was installed.

Without --bundle it is copied over ssh and run with sudo: one upload, then
an interactive session for sudo, over one ControlMaster connection. The
node's host key is read over that session and pinned in the collector
user's known_hosts (the pcap pull and the quorum check log in to it).

A host whose roles are served by an appliance adapter (nas, firewall,
network) gets no bundle; its adapter's manual steps are printed instead.
"""
import gzip
import hashlib
import io
import os
import tarfile
import tempfile

from .. import site as S
from ..adapters import registry

DRIVER = "collector/node/node-install.sh"
NODE = ["collector/install-node.sh", "collector/systemd/node_exporter.service"]
GB10 = ["collector/textfile/gb10-textfile.py", "collector/systemd/gb10-textfile.service",
        "collector/systemd/gb10-textfile.timer"]
JOURNAL = ["logs/node/install-journal-upload.sh"]
PCAP = ["logs/pcap/install-pcap.sh", "logs/pcap/pcap-run.sh", "logs/pcap/pcap-seal.sh", "logs/pcap/pcap@.service",
        "logs/pcap/sudoers-pcap"]


def kinds(site, h):
    """{kind: (kind, vendor)} of the adapters serving the host's roles."""
    out = {}
    for r in h["roles"]:
        kv = registry.for_role(h.get("vendor"), r)
        if kv:
            out.setdefault(kv[0], kv)
    return out


def _home(ops, user):
    a = ops.user(user)
    return a.pw_dir if a else f"/var/lib/{user}"


def contents(site, tree, h, ops):
    """[(path in bundle, bytes, mode)] and warnings."""
    roles, warns = set(h["roles"]), []
    name = f"30ops-node-{h['name']}"
    files = [DRIVER]
    if "node" in roles:
        files += NODE + (GB10 if "gb10-ops" in h["plugins"] else [])
    if "journal" in roles:
        files += JOURNAL
    if "pcap" in roles:
        files += PCAP + sorted(f"logs/pcap/profiles/{f}" for f in os.listdir(f"{S.REPO}/logs/pcap/profiles")
                               if f.endswith(".env"))
    out = []
    for f in files:
        with open(os.path.join(S.REPO, f), "rb") as fh:
            data = fh.read()
        bpath = "node-install.sh" if f == DRIVER else f
        out.append((f"{name}/{bpath}", data, 0o755 if f.endswith((".sh", ".py")) else 0o644))
    pre = f"nodes/{h['name']}/"
    for p in sorted(tree):
        if p.startswith(pre):
            o = tree[p]
            out.append((f"{name}/{p[len(pre):]}", o.text.encode(), o.mode))
    user = site["collector"]["user"]
    if "pcap" in roles:
        key = S.secret_file(site, site["logs"]["pcap"]["key"]) + ".pub"
        raw = ops.read(key)
        if raw:
            out.append((f"{name}/keys/pcap-pull.pub", raw, 0o644))
        else:
            warns.append(f"{key} is missing (install collector first); the node gets no pull key")
    if "hypervisor" in roles and h.get("pve"):
        key = f"{_home(ops, user)}/.ssh/id_ed25519.pub"
        raw = ops.read(key)
        if raw:
            out.append((f"{name}/keys/quorum.pub", raw, 0o644))
        else:
            warns.append(f"{key} is missing (install collector first); the node gets no quorum key")
    return sorted(out), warns


def build(entries):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, filename="") as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for path, data, mode in entries:
                ti = tarfile.TarInfo(path)
                ti.size, ti.mode, ti.mtime = len(data), mode, 0
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = "root"
                tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def manual(site, h, kv):
    kind, vendor = kv
    mod = registry.module(kind, vendor) if (registry.directory(kind, vendor) / "adapter.py").exists() else None
    fn = getattr(mod, "manual_steps", None) if mod else None
    return fn(site, h) if fn else [f"no install steps for {kind}/{vendor} yet"]


def install(site, tree, name, ops, bundle=None, ssh=None, out=print):
    """0 done, 1 failed, 2 refused (unknown host, nothing to install)."""
    try:
        h = S.host(site, name)
    except (KeyError, LookupError, StopIteration):
        h = None
    if not h:
        out(f"refused: no host {name} in site.yaml")
        return 2
    ks = kinds(site, h)
    appliance = [kv for k, kv in ks.items() if k in ("nas", "firewall", "network")]
    for kv in appliance:
        out(f"{h['name']} is a {kv[0]} served by the {kv[1]} adapter; set it up on the device:")
        for i, step in enumerate(manual(site, h, kv), 1):
            out(f"  {i}. {step}")
    if not any(k in ks for k in ("os", "hypervisor")) or f"nodes/{h['name']}/install.env" not in tree:
        if not appliance:
            out(f"refused: {h['name']} has no role a node bundle serves (node, journal, pcap, hypervisor)")
            return 2
        return 0
    entries, warns = contents(site, tree, h, ops)
    for w in warns:
        out(f"warning: {w}")
    data = build(entries)
    digest = hashlib.sha256(data).hexdigest()
    fname = f"30ops-node-{h['name']}.tar.gz"
    if bundle:
        path = os.path.join(bundle, fname) if os.path.isdir(bundle) else bundle
        with open(path, "wb") as f:
            f.write(data)
        dest = ssh or (f"{h['ssh']['user']}@{h['address']}" if h.get("ssh") else f"<user>@{h['address']}")
        out(f"{path}: {len(entries)} files, sha256 {digest}")
        out("on the node, as a user with sudo:")
        out(f"  scp {path} {dest}:/tmp/ && ssh -t {dest} "
            f"'tar xzf /tmp/{fname} -C /tmp && sudo sh /tmp/30ops-node-{h['name']}/node-install.sh'")
        return 0
    dest = ssh or (f"{h['ssh']['user']}@{h['address']}" if h.get("ssh") else None)
    if not dest:
        out(f"refused: {h['name']} has no ssh in site.yaml; give --ssh user@host (a user with sudo there)")
        return 2
    return _over_ssh(site, h, dest, data, digest, fname, ops, out)


def _over_ssh(site, h, dest, data, digest, fname, ops, out):
    d = f"/tmp/30ops-node-{h['name']}"
    sudo = "" if dest.startswith("root@") else "sudo "
    with tempfile.TemporaryDirectory() as tmp:
        cm = ["-o", "ControlMaster=auto", "-o", f"ControlPath={tmp}/cm-%C", "-o", "ControlPersist=60"]
        p = ops.pipe(["ssh", *cm, dest, f"cat > /tmp/{fname}"], data)
        if p.returncode != 0:
            out(f"error: copying the bundle to {dest}: {p.stderr.strip()}")
            return 1
        out(f"copied {fname} (sha256 {digest}) to {dest}")
        rc = ops.run_tty(["ssh", "-t", *cm, dest,
                          f"rm -rf {d} && tar xzf /tmp/{fname} -C /tmp && {sudo}sh {d}/node-install.sh; "
                          f"rc=$?; rm -rf {d} /tmp/{fname}; exit $rc"])
        if rc != 0:
            out(f"error: node-install.sh on {dest} exited {rc}")
            return 1
        if set(h["roles"]) & {"pcap", "hypervisor"}:
            k = ops.run(["ssh", *cm, dest, "cat /etc/ssh/ssh_host_ed25519_key.pub"])
            pin_host_key(site, h, k.stdout.strip() if k.returncode == 0 else "", ops, out)
        ops.run(["ssh", *cm, "-O", "exit", dest])
    return 0


def pin_host_key(site, h, pub, ops, out):
    """The node's host key into the collector user's known_hosts, read over
    the session the operator authenticated, so the cron jobs never trust a
    key on first use."""
    f = pub.split()
    if len(f) < 2:
        out(f"warning: could not read {h['name']}'s host key; add it to known_hosts before the first pull")
        return
    user = site["collector"]["user"]
    kh = f"{_home(ops, user)}/.ssh/known_hosts"
    line = f"{h['address']} {f[0]} {f[1]}\n"
    cur = (ops.read(kh) or b"").decode()
    if line in cur.splitlines(keepends=True):
        return
    if ops.euid() != 0:
        out(f"next, as root on the collector: printf '%s' '{line.strip()}' | sudo -u {user} tee -a {kh}")
        return
    a = ops.user(user)
    ops.write(kh, (cur + line).encode(), 0o644, a.pw_uid, a.pw_gid)
    out(f"pinned {h['name']}'s host key in {kh}")

