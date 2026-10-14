"""Prometheus textfile output for node_exporter's textfile collector."""
import os
import tempfile


def esc(v):
    """Label value escaping per the exposition format: backslash, quote, newline."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def family(lines, name, help, type="gauge"):
    lines.append(f"# HELP {name} {help}")
    lines.append(f"# TYPE {name} {type}")


def write(path, text):
    """Atomic write: temp file in the same directory, 0644, fsync, rename.

    mkstemp makes 0600 and node_exporter runs as another user, so the mode is
    set before the rename. The temp file is removed if anything fails.
    """
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".")
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
