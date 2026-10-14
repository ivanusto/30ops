"""Everything install and doctor do to the host, in one place.

Ops.root prefixes every file path, so tests install into a temporary
directory. Commands go through run(); the docker and systemctl commands
come from $OPS30_DOCKER and $OPS30_SYSTEMCTL when set. Tests subclass Ops
and answer run(), the account lookups and chown themselves.
"""
import grp
import os
import pwd
import shlex
import subprocess
import tempfile
import urllib.error
import urllib.request


class Ops:
    def __init__(self, root="/"):
        self.root = root
        self.docker = shlex.split(os.environ.get("OPS30_DOCKER", "docker"))
        self.systemctl = shlex.split(os.environ.get("OPS30_SYSTEMCTL", "systemctl"))

    # ---------- files ----------
    def path(self, p):
        return os.path.join(self.root, p.lstrip("/"))

    def read(self, p):
        try:
            with open(self.path(p), "rb") as f:
                return f.read()
        except OSError:
            return None

    def stat(self, p):
        try:
            return os.lstat(self.path(p))
        except OSError:
            return None

    def owner(self, p):
        st = self.stat(p)
        return (st.st_uid, st.st_gid) if st else None

    def chown(self, p, uid, gid):
        os.lchown(self.path(p), uid, gid)

    def fchown(self, fd, uid, gid, p):
        """chown of an open file that will become p (tests record p)."""
        os.fchown(fd, uid, gid)

    def write(self, p, data, mode, uid, gid):
        """Atomic: the temp file has its mode and owner before the rename,
        so a secret is never readable by others, not even for a moment."""
        dst = self.path(p)
        d = os.path.dirname(dst)
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(dst) + ".")
        try:
            os.fchmod(fd, mode)
            self.fchown(fd, uid, gid, p)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dst)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def mkdir(self, p, mode, uid, gid):
        os.makedirs(self.path(p), exist_ok=True)
        os.chmod(self.path(p), mode)
        self.chown(p, uid, gid)

    def chmod(self, p, mode):
        os.chmod(self.path(p), mode)

    def remove(self, p):
        os.unlink(self.path(p))

    def exists(self, p):
        return os.path.lexists(self.path(p))

    def glob(self, pattern):
        import glob
        n = len(self.root.rstrip("/"))
        return sorted(x[n:] if self.root != "/" else x for x in glob.glob(self.path(pattern)))

    # ---------- accounts ----------
    def user(self, name):
        try:
            return pwd.getpwnam(name)
        except KeyError:
            return None

    def group(self, name):
        try:
            return grp.getgrnam(name)
        except KeyError:
            return None

    def groups_of(self, name):
        u = self.user(name)
        if not u:
            return set()
        return {g.gr_name for g in grp.getgrall() if name in g.gr_mem} | {grp.getgrgid(u.pw_gid).gr_name}

    def uid(self, name):
        if name.isdigit():
            return int(name)
        u = self.user(name)
        if not u:
            raise LookupError(f"no user {name}")
        return u.pw_uid

    def gid(self, name):
        if name.isdigit():
            return int(name)
        g = self.group(name)
        if not g:
            raise LookupError(f"no group {name}")
        return g.gr_gid

    def ids(self, owner):
        """'root:101' -> (0, 101); digits are ids, names are looked up."""
        u, _, g = owner.partition(":")
        return self.uid(u), self.gid(g or u)

    # ---------- commands ----------
    def run(self, argv, input=None, timeout=600, env=None):
        try:
            return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout,
                                  env={**os.environ, **(env or {})})
        except FileNotFoundError as e:
            return subprocess.CompletedProcess(argv, 127, "", str(e))
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(argv, 124, "", f"timeout after {timeout}s")

    def http(self, url, method="GET", timeout=5, auth=None):
        req = urllib.request.Request(url, method=method)
        if auth:
            import base64
            req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except (urllib.error.URLError, OSError):
            return 0, ""

    def euid(self):
        return os.geteuid()

    def sleep(self, s):
        import time
        time.sleep(s)
