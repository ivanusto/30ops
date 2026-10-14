"""30ops textfile: run one adapter collect capability for cron.

Each name is one textfile and the capability that writes it. The arguments
stay explicit on the cron line (LABEL=user@host ...), so the host list is
part of the rendered cron file that render --diff and --compare-legacy see.
A lock per name keeps a run that hangs on a dead host from stacking up
under the next one: the second run exits 75 without output, and the cron
line's `> tmp && mv` keeps the last good file.
"""
import fcntl
import os
import sys
import tempfile
import time

from . import textfile
from .adapters import registry
from .adapters.base import Target
from .adapters.transport import Local, Ssh

TEXTFILES = {
    "nas": ("nas", "qnap", "health"),
    "pve-quorum": ("hypervisor", "pve", "quorum"),
}


def lock_dir():
    d = os.environ.get("OPS30_LOCK_DIR")
    if d:
        return d
    return "/run/lock" if os.access("/run/lock", os.W_OK) else tempfile.gettempdir()


def run(name, specs, out=None, local=False, stdin=None, now=None):
    """Returns the exit code; writes the textfile to out or stdout."""
    kind, vendor, cap = TEXTFILES[name]
    now = time.time() if now is None else now
    lk = open(os.path.join(lock_dir(), f"30ops-textfile-{name}.lock"), "a")
    try:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"30ops textfile {name}: the previous run is still going", file=sys.stderr)
        return 75
    try:
        mod = registry.module(kind, vendor)
        if local:
            targets = [Target(s, ("local",)) for s in specs]
            transport = Local()
        else:
            try:
                targets = [Target.parse(s) for s in specs]
            except ValueError as e:
                print(f"30ops textfile {name}: {e}", file=sys.stderr)
                return 2
            transport = Ssh()
        if not targets:
            if name == "pve-quorum" and stdin is not None:
                text = mod.quorum_from_text(stdin.read(), now)
            else:
                print(f"30ops textfile {name}: give at least one LABEL=user@host", file=sys.stderr)
                return 2
        else:
            text = getattr(mod, cap)(targets, transport, now)
        if out:
            textfile.write(out, text)
        else:
            sys.stdout.write(text)
        return 0
    finally:
        lk.close()
