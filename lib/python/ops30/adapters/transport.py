"""How an adapter reaches a device: ssh, local commands, HTTP GET, or a
recorded fixture.

Every transport answers run(dest, argv, stdin) and get(url, headers,
insecure) with a Result, so a capability is written once and tested against
Replay with the requests a real device answered. Errors are results, not
exceptions: a host that does not answer is rc 255 from ssh or rc 0 with an
error from HTTP, which is how the textfiles report a device as down.
"""
import hashlib
import json
import os
import shlex
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Result:
    rc: int
    out: bytes
    err: bytes = b""


SSH_OPTS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2")


class Ssh:
    """ssh with BatchMode, a connect timeout and keepalives, and a hard
    timeout so a hung session cannot pile up behind the next cron run.
    $SSH and $SSH_OPTS replace the command and its options (tests, or a
    site that needs -i or a port)."""

    def __init__(self, timeout=40, ssh=None, opts=None):
        self.ssh = shlex.split(ssh if ssh is not None else os.environ.get("SSH", "ssh"))
        env_opts = os.environ.get("SSH_OPTS")
        self.opts = list(opts) if opts is not None else (shlex.split(env_opts) if env_opts else list(SSH_OPTS))
        self.timeout = timeout

    def run(self, dest, argv, stdin=None):
        cmd = [*self.ssh, *self.opts, dest, *argv]
        try:
            p = subprocess.run(cmd, input=stdin, capture_output=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            return Result(124, e.stdout or b"", b"timeout")
        except OSError as e:
            return Result(127, b"", str(e).encode())
        return Result(p.returncode, p.stdout, p.stderr)

    def get(self, url, headers=None, insecure=False):
        return _http_get(url, headers, insecure, self.timeout)


class Local(Ssh):
    """Runs argv on this host and ignores dest (on the device itself)."""

    def run(self, dest, argv, stdin=None):
        try:
            p = subprocess.run(list(argv), input=stdin, capture_output=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            return Result(124, e.stdout or b"", b"timeout")
        return Result(p.returncode, p.stdout, p.stderr)


def _http_get(url, headers, insecure, timeout):
    ctx = None
    if url.startswith("https:") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return Result(r.status, r.read())
    except urllib.error.HTTPError as e:
        return Result(e.code, e.read() or b"")
    except (urllib.error.URLError, OSError) as e:
        return Result(0, b"", str(e).encode())


def sha256(b):
    return hashlib.sha256(b or b"").hexdigest()


class ReplayError(AssertionError):
    pass


class Replay:
    """Answers from a recorded case directory, strictly in order.

    requests.jsonl has one request per line:
      {"op": "run", "dest": "...", "argv": [...], "stdin_sha256": "...", "rc": 0, "out": "001.out"}
      {"op": "get", "url": "...", "rc": 200, "out": "002.out"}
    stdin_sha256 is optional; when present the request must send exactly that
    stdin (the remote script did not change behind the fixture's back).
    "out" names a file in the case directory; a missing "out" is no output.
    done() raises if a recorded request was never made.
    """

    def __init__(self, case_dir):
        self.dir = Path(case_dir)
        p = self.dir / "requests.jsonl"
        self.reqs = [json.loads(line) for line in p.read_text().splitlines() if line.strip()] if p.exists() else []
        self.i = 0

    def _next(self, op, what):
        if self.i >= len(self.reqs):
            raise ReplayError(f"{self.dir.name}: unexpected {op} {what}, nothing left to replay")
        r = self.reqs[self.i]
        self.i += 1
        if r["op"] != op:
            raise ReplayError(f"{self.dir.name}: request {self.i} is {r['op']}, got {op} {what}")
        return r

    def _result(self, r):
        out = (self.dir / r["out"]).read_bytes() if r.get("out") else b""
        return Result(r.get("rc", 0), out)

    def run(self, dest, argv, stdin=None):
        r = self._next("run", f"{dest} {argv}")
        if r["dest"] != dest or r["argv"] != list(argv):
            raise ReplayError(f"{self.dir.name}: request {self.i} is {r['dest']} {r['argv']}, got {dest} {list(argv)}")
        if "stdin_sha256" in r and r["stdin_sha256"] != sha256(stdin):
            raise ReplayError(f"{self.dir.name}: request {self.i} stdin changed (sha256 {sha256(stdin)})")
        return self._result(r)

    def get(self, url, headers=None, insecure=False):
        r = self._next("get", url)
        if r["url"] != url:
            raise ReplayError(f"{self.dir.name}: request {self.i} is {r['url']}, got {url}")
        return self._result(r)

    def done(self):
        if self.i != len(self.reqs):
            raise ReplayError(f"{self.dir.name}: {len(self.reqs) - self.i} recorded requests were not made")


class Record:
    """Wraps a transport and writes what it answered in the Replay layout.
    The recording is raw; anonymise it before it goes into tests/fixtures
    (docs/adapters.md)."""

    def __init__(self, inner, case_dir):
        self.inner, self.dir, self.n = inner, Path(case_dir), 0
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log = (self.dir / "requests.jsonl").open("w")

    def _save(self, entry, res):
        self.n += 1
        name = f"{self.n:03d}.out"
        (self.dir / name).write_bytes(res.out)
        self.log.write(json.dumps({**entry, "rc": res.rc, "out": name}) + "\n")
        self.log.flush()
        return res

    def run(self, dest, argv, stdin=None):
        return self._save({"op": "run", "dest": dest, "argv": list(argv), "stdin_sha256": sha256(stdin)},
                          self.inner.run(dest, argv, stdin))

    def get(self, url, headers=None, insecure=False):
        return self._save({"op": "get", "url": url}, self.inner.get(url, headers, insecure))
