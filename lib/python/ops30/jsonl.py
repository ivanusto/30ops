"""Append-only JSON Lines files.

Writers take an exclusive flock on the file itself, so two cron jobs or a
cron job and a person running a drill by hand cannot interleave lines.
"""
import contextlib
import fcntl
import json
import os


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


@contextlib.contextmanager
def lock(path):
    """Exclusive append handle; read what you need, then write_line()."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    f = open(path, "a", encoding="utf-8")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        yield f
    finally:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()


def write_line(f, line):
    f.write(line + "\n")
    f.flush()
    os.fsync(f.fileno())


def append(path, obj, dumps=dumps):
    with lock(path) as f:
        write_line(f, dumps(obj))


def read(path):
    """-> (records, skipped). Blank lines are ignored; lines that are not a
    JSON object are counted in skipped. A missing file is ([], 0)."""
    recs, skipped = [], 0
    try:
        f = open(path, encoding="utf-8")
    except FileNotFoundError:
        return recs, skipped
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                skipped += 1
                continue
            if isinstance(r, dict):
                recs.append(r)
            else:
                skipped += 1
    return recs, skipped
