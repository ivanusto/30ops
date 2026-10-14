"""The rendered tree on the host: what each file should be, how the
installed one differs, and writing it.

nodes/<host>/ is not installed on the collector (install node ships it),
so it is left out here and in render --diff. Secret placeholders
'@secret:<name>' are replaced by the value of that credentials file,
written as a JSON string, which is also a valid double-quoted YAML scalar,
so a token with ':' or '#' in it cannot break the file.
"""
import json
import re
from dataclasses import dataclass

from .. import site as S

PLACEHOLDER = re.compile(r"""(['"]?)@secret:([A-Za-z0-9_.-]+)\1""")
MANIFEST = "etc/30ops/manifest.json"


@dataclass
class File:
    path: str           # relative to /
    data: bytes
    mode: int
    owner: str          # as rendered, e.g. root:101
    secret: bool


def collector_paths(tree):
    return [p for p in tree if not p.startswith("nodes/")]


def fill(text, site, ops):
    def sub(m):
        f = S.secret_file(site, m.group(2))
        raw = ops.read(f) if f else None
        if raw is None:
            raise LookupError(f"credentials.{m.group(2)}: {f} cannot be read")
        return json.dumps(raw.decode("utf-8").strip())
    return PLACEHOLDER.sub(sub, text)


def files(tree, site, ops, paths=None):
    out = []
    for p in paths if paths is not None else collector_paths(tree):
        o = tree[p]
        text = fill(o.text, site, ops) if o.secret else o.text
        out.append(File(p, text.encode("utf-8"), o.mode, o.owner, o.secret))
    return out


def differs(f, ops, owners=True):
    """None when the installed file is f, else what differs."""
    st = ops.stat(f.path)
    if st is None:
        return "missing"
    why = []
    if ops.read(f.path) != f.data:
        why.append("content")
    if st.st_mode & 0o7777 != f.mode:
        why.append(f"mode {st.st_mode & 0o7777:04o} != {f.mode:04o}")
    if owners:
        want = ops.ids(f.owner)
        have = ops.owner(f.path)
        if have != want:
            why.append(f"owner {have[0]}:{have[1]} != {f.owner}")
    return ", ".join(why) or None


def installed_manifest(ops):
    raw = ops.read(MANIFEST)
    try:
        return [x["path"] for x in json.loads(raw)["files"]] if raw else []
    except (ValueError, KeyError, TypeError):
        return []
