"""Golden outputs of every collector-side textfile writer.

Each writer runs on fixed inputs and its output is compared with
tests/golden/textfile/<name>.prom. Metric names, labels and values must not
change in v1 (TSDB continuity), so a refactor that moves code into
lib/python/ops30 has to leave these files byte for byte the same.

Values that depend on the wall clock (*_last_run_timestamp, cache ages) are
masked. Writers in SORTED print the samples of one family in an order that
depends on awk's hash order (nas, pve-quorum), so their samples are sorted
within each family before the comparison. Regenerate after an intended change with:

    GOLDEN_UPDATE=1 python3 -m unittest tests/test_golden.py
"""
import datetime as dt
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests" / "golden" / "textfile"
FIX = ROOT / "tests" / "fixtures"
NOW = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.timezone.utc)
MASK = re.compile(r"^((?:\w+_last_run_timestamp|asset_eol_source_age_seconds)(?:\{[^}]*\})?) \d+$", re.M)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(*args):
    p = subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True)
    if p.returncode != 0:
        raise AssertionError(f"{args[0]} rc={p.returncode}\n{p.stderr}")
    return p.stdout


def changes(tmp):
    d = ROOT / "changes" / "tests" / "fixtures"
    return run(ROOT / "changes/scripts/changes-textfile.py", "--dir", d, "--drills", d / "drills.jsonl")


def drills(tmp):
    src = [f"{k}={FIX / 'drills' / f'legacy-{k}.jsonl'}" for k in ("pve", "nas", "cloud", "logs", "changes")]
    return run(ROOT / "collector/textfile/drills-textfile.py", *src)


def eol(tmp):
    fx = ROOT / "collector" / "tests" / "fixtures" / "eol"
    cache = os.path.join(tmp, "cache")
    shutil.copytree(fx, cache)
    return run(ROOT / "collector/textfile/eol-textfile.py", "--offline", "--cache", cache,
               "--licence-file", fx / "fortigate-license-status.json")


def aup(tmp):
    out = os.path.join(tmp, "aup.prom")
    run(ROOT / "logs/firewall/aup-report.py", "--from-file", ROOT / "logs/tests/fixtures/fortigate-webfilter.log",
        "--expect", "fgt-edge,fgt-silent", "--textfile", out, "--out", os.devnull)
    return Path(out).read_text()


def fw(tmp):
    m = load("logs/firewall/fw-report.py", "fw_report")
    results = {
        "pve": {"host_field": "hostname",
                "total": [{"hostname": "pve1", "n": 42}, {"hostname": "pve2", "n": 7}],
                "by_src": [{"hostname": "pve1", "src": "198.51.100.23", "n": 30},
                           {"hostname": "pve1", "src": "198.51.100.24", "n": 12},
                           {"hostname": "pve2", "src": "203.0.113.5", "n": 7}]},
        "fortigate": {"host_field": "devname", "total": [{"devname": "fgt-edge", "n": 1200}],
                      "by_src": [{"devname": "fgt-edge", "src": "203.0.113.9", "n": 800}]},
    }
    new_sources = {"pve": [("pve1", "198.51.100.23"), ("pve1", "198.51.100.24")]}
    nas = {"fails_by_ip": {("nas1", "192.0.2.50"): 3, ("nas1", "192.0.2.51"): 6}}
    out = os.path.join(tmp, "fw.prom")
    m.write_textfile(out, results, new_sources, nas, NOW, expect=[("pve", "pve3")])
    return Path(out).read_text()


def audit(tmp):
    m = load("logs/audit/audit-report.py", "audit_report")
    src = list(m.SOURCES)
    rows = [{"source": src[0], "cr": "CR-2026-0001", "quiet": False},
            {"source": src[0], "cr": "", "quiet": False},
            {"source": src[-1], "cr": "", "quiet": True}]
    out = os.path.join(tmp, "audit.prom")
    m.write_textfile(out, rows, ["CR-2026-0002"], NOW)
    return Path(out).read_text()


def gate(tmp):
    gdir = ROOT / "gate"
    sys.path.insert(0, str(gdir / "gate"))
    try:
        import core
        import textfile
    finally:
        sys.path.pop(0)
    gfx = gdir / "tests" / "fixtures"
    env = {"LOGGER_LOG": os.path.join(tmp, "logger.log"), "FAKE_SSH_LOG": os.path.join(tmp, "ssh.log"),
           "GATE_NOW": "2026-10-13T12:30:00Z"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        cfg = dict(core.DEFAULTS)
        state = os.path.join(tmp, "state")
        os.makedirs(state)
        cfg.update({"principal": "agent:ops", "changes_dir": str(gfx / "changes"), "state_dir": state,
                    "tools": str(gfx / "tools.json"), "audit": os.path.join(tmp, "audit.jsonl"),
                    "approvals_dir": os.path.join(tmp, "approvals"), "stop_file": os.path.join(tmp, "STOP"),
                    "ssh": [str(gfx / "fake-ssh"), "-o", "BatchMode=yes"],
                    "targets": {"qdevice/Debian": "gate@qdevice", "pve1/Proxmox VE": "gate@pve1",
                                "collector/Ubuntu": "local"},
                    "logger": str(gfx / "fake-logger"), "approval_ttl_s": 600})
        g = core.Gate(cfg)
        with open(os.path.join(state, "CR-2026-0015.state"), "w") as f:
            f.write("annotation=1\n")
        g.call("CR-2026-0015", "pve.quorum_status", {})
        g.call("CR-2026-0015", "nope", {})
        g.call("CR-2026-0015", "qdevice.reboot", {})
        return textfile.render(g, int(NOW.timestamp()))
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _exe(path, text):
    path.write_text(text)
    path.chmod(0o755)


def nas(tmp):
    """Two NAS through a fake ssh that runs the piped script locally, and a
    third that does not answer. Snapshot times are fixed, not relative."""
    t = Path(tmp)
    b = t / "bin"
    b.mkdir()
    now = int(NOW.timestamp())
    _exe(b / "zpool", "#!/bin/sh\nprintf 'zpool1\\t24855000000000\\t6500000000000\\t26%%\\tONLINE\\n'\n")
    _exe(b / "zfs", f"""#!/bin/sh
case "$*" in
  *"-t snapshot"*)
    printf 'zpool1/zfs263@snapshot:init:\\t{now - 8640000}\\t0\\n'
    printf 'zpool1/zfs263@GMT-2026.10.01-01.00.00\\t{now - 7200}\\t123456789\\n'
    printf 'zpool1/zfs263@GMT-2026.10.01-02.00.00\\t{now - 3600}\\t2345678\\n'
    printf 'zpool1/zfs264@snapshot:init:\\t{now - 8640000}\\t0\\n'
    printf 'zpool1/zfs265@daily-1\\t{now - 86400}\\t4096\\n' ;;
  *"-t filesystem,volume"*)
    printf 'zpool1/zfs263\\t3640000000000\\n'
    printf 'zpool1/zfs264\\t24000000000\\n'
    printf 'zpool1/zfs265\\t8192\\n' ;;
esac
""")
    _exe(b / "getcfg", '#!/bin/sh\n[ "$1 $2" = "HybridBackup Version" ] && echo 26.4.4.788\n')
    _exe(b / "ssh", """#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -o) shift 2 ;; *@down) exit 255 ;; sh) shift 2; break ;; *) shift ;; esac; done
exec sh -s "$@"
""")
    (t / "buddyinfo").write_text(
        "Node 0, zone      DMA      0      0      0      0      0      0      0      0      1      1      3\n"
        "Node 0, zone    DMA32    313    255    172    113     55   2180    611    207     50      1      0\n"
        "Node 0, zone   Normal 425257  74031  93543  77921  12561  30507    259      0      0      0      0\n")
    (t / "stat").write_text("cpu  1 2 3 4\nbtime 1791196320\nprocesses 5\n")
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}",
           "NAS_BUDDYINFO": str(t / "buddyinfo"), "NAS_PROC_STAT": str(t / "stat")}
    p = subprocess.run(["sh", str(ROOT / "collector/textfile/nas-textfile.sh"),
                        "primary=ops30@nas1", "secondary=ops30@nas2", "third=ops30@down"],
                       capture_output=True, text=True, env=env)
    if p.returncode != 0:
        raise AssertionError(f"nas-textfile rc={p.returncode}\n{p.stderr}")
    return p.stdout


def pve_quorum(tmp):
    """Cluster lab from the field transcript, first node down so the second
    is tried; cluster dr has the QDevice stopped. One cluster per run, which
    is what the field has."""
    fx = ROOT / "collector" / "tests"
    fake = Path(tmp) / "ssh"
    _exe(fake, f"""#!/bin/sh
for a; do host=$a; done
while [ $# -gt 0 ]; do case $1 in root@*) host=$1;; esac; shift; done
case $host in root@n2) cat {fx / "pvecm-status.txt"} ;; *) exit 255 ;; esac
""")
    env = {**os.environ, "SSH": str(fake)}
    p = subprocess.run(["sh", str(ROOT / "collector/textfile/pve-quorum-textfile.sh"), "lab=root@n1,root@n2"],
                       capture_output=True, text=True, env=env)
    if p.returncode != 0:
        raise AssertionError(f"pve-quorum-textfile rc={p.returncode}\n{p.stderr}")
    return p.stdout


def pve_quorum_qdevice_down(tmp):
    fx = ROOT / "collector" / "tests" / "pvecm-status-qdevice-down.txt"
    p = subprocess.run(["sh", str(ROOT / "collector/textfile/pve-quorum-textfile.sh")],
                       input=fx.read_text(), capture_output=True, text=True)
    if p.returncode != 0:
        raise AssertionError(f"pve-quorum-textfile rc={p.returncode}\n{p.stderr}")
    return p.stdout


def sort_families(text):
    """Sort the sample lines inside each run of samples; HELP and TYPE lines
    and the order of the families stay where they are."""
    out, run_ = [], []
    for line in text.splitlines(keepends=True):
        if line.startswith("#"):
            out.extend(sorted(run_))
            run_ = []
            out.append(line)
        else:
            run_.append(line)
    out.extend(sorted(run_))
    return "".join(out)


WRITERS = {"changes": changes, "drills": drills, "eol": eol, "aup": aup, "fw": fw, "audit": audit, "gate": gate,
           "nas": nas, "pve-quorum": pve_quorum, "pve-quorum-qdevice-down": pve_quorum_qdevice_down}
SORTED = {"nas", "pve-quorum", "pve-quorum-qdevice-down"}


class Golden(unittest.TestCase):
    def test_textfile_outputs(self):
        update = os.environ.get("GOLDEN_UPDATE") == "1"
        for name, fn in WRITERS.items():
            with self.subTest(writer=name):
                tmp = tempfile.mkdtemp()
                try:
                    got = MASK.sub(r"\1 X", fn(tmp))
                    if name in SORTED:
                        got = sort_families(got)
                finally:
                    shutil.rmtree(tmp)
                path = GOLDEN / f"{name}.prom"
                if update:
                    GOLDEN.mkdir(parents=True, exist_ok=True)
                    path.write_text(got)
                    continue
                self.assertEqual(got, path.read_text(), f"{name}: output differs from {path.relative_to(ROOT)}")


if __name__ == "__main__":
    unittest.main()
