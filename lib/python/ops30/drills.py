"""drills.jsonl version 1: one record per restore or rollback drill.

Every drill tool writes through append() (or `30ops drill record` from sh),
so the fields, types and escaping are the same everywhere. Readers call
normalise(), which also understands the five formats written before v1;
old files are never rewritten (`30ops drill migrate` prints a v1 copy).
See docs/drills-jsonl.md.
"""
import re

from . import jsonl, rfc3339, version

KINDS = ("pve-backup", "nas-backup", "cloud-offload", "change-rollback", "logs-restore", "qdevice")
RESULTS = ("pass", "fail", "partial")
KEYS = ("v", "t0", "t1", "kind", "label", "site", "host", "result", "rto_s", "rpo_s", "bytes", "rate_bps",
        "checks", "cr", "rollback_of", "operator", "tool", "extra")
CR_RE = re.compile(r"^CR-\d{4}-\d{4}$")
MIB = 1048576

# source names used by the collector cron (drills-textfile.py name=path) -> kind
HINTS = {"pve": "pve-backup", "nas": "nas-backup", "cloud": "cloud-offload",
         "logs": "logs-restore", "changes": "change-rollback", "qdevice": "qdevice"}


class DrillError(ValueError):
    pass


def new(kind, label, t0, result, **fields):
    rec = {k: None for k in KEYS}
    rec.update(v=1, kind=kind, label=label, t0=t0, result=result, checks=[], extra={},
               tool=f"30ops {version()}")
    for k, v in fields.items():
        if k not in KEYS:
            raise DrillError(f"unknown field {k}")
        rec[k] = v
    return rec


def _int_or_none(rec, k, errs):
    v = rec.get(k)
    if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
        errs.append(f"{k} must be a non-negative integer or null")


def validate(rec):
    """-> list of problems; empty when rec is a valid v1 record."""
    errs = []
    if not isinstance(rec, dict):
        return ["not an object"]
    for k in rec:
        if k not in KEYS:
            errs.append(f"unknown field {k}")
    if rec.get("v") != 1:
        errs.append("v must be 1")
    if rfc3339.parse(rec.get("t0")) is None:
        errs.append("t0 must be RFC 3339 with an offset")
    if rec.get("t1") is not None and rfc3339.parse(rec.get("t1")) is None:
        errs.append("t1 must be RFC 3339 with an offset or null")
    if rec.get("kind") not in KINDS:
        errs.append(f"kind must be one of {', '.join(KINDS)}")
    if not isinstance(rec.get("label"), str) or not rec.get("label").strip():
        errs.append("label must be a non-empty string")
    if rec.get("result") not in RESULTS:
        errs.append(f"result must be one of {', '.join(RESULTS)}")
    for k in ("rto_s", "rpo_s", "bytes"):
        _int_or_none(rec, k, errs)
    r = rec.get("rate_bps")
    if r is not None and (isinstance(r, bool) or not isinstance(r, (int, float)) or r < 0):
        errs.append("rate_bps must be a non-negative number or null")
    for k in ("cr", "rollback_of"):
        if rec.get(k) is not None and not CR_RE.match(str(rec.get(k))):
            errs.append(f"{k} must look like CR-YYYY-NNNN or be null")
    for k in ("site", "host", "operator", "tool"):
        if rec.get(k) is not None and not isinstance(rec.get(k), str):
            errs.append(f"{k} must be a string or null")
    checks = rec.get("checks", [])
    if not isinstance(checks, list):
        errs.append("checks must be a list")
    else:
        for c in checks:
            if not isinstance(c, dict) or not isinstance(c.get("name"), str) or c.get("result") not in RESULTS \
                    or set(c) - {"name", "result", "detail"}:
                errs.append(f"bad check {c!r}")
    if not isinstance(rec.get("extra", {}), dict):
        errs.append("extra must be an object")
    return errs


def append(path, rec):
    errs = validate(rec)
    if errs:
        raise DrillError("; ".join(errs))
    jsonl.append(path, {k: rec.get(k) for k in KEYS})


# ---------- reading, including the formats written before v1 ----------

def _num(v):
    """118, '118', '118s', '47.7 MiB/s', '-', '?', '' -> float or None."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    for suffix in (" MiB/s", "MiB/s", " MB/s", "MB/s", "s"):
        if s.endswith(suffix):
            s = s[: -len(suffix)].strip()
    try:
        return float(s)
    except ValueError:
        return None


def _int(v):
    n = _num(v)
    return int(n) if n is not None else None


def _whole(x):
    return int(x) if float(x).is_integer() else x


def _first(rec, *keys):
    for k in keys:
        if k in rec:
            return rec[k]
    return None


def _guess(rec):
    if "rollback_of" in rec:
        return "change-rollback"
    if "vmid" in rec or "t_ping" in rec:
        return "pve-backup"
    if "mib" in rec or "seconds" in rec:
        return "cloud-offload"
    if "appear" in rec or "rate_mbs" in rec or "rto" in rec:
        return "nas-backup"
    if "live" in rec or "selection" in rec:
        return "logs-restore"
    return None


# legacy fields that become v1 fields; the rest go to extra
_MAPPED = {"t0", "label", "result", "host", "cr", "rollback_of", "rto", "rto_s", "seconds", "rpo", "rpo_s",
           "rate", "rate_mbs", "mib"}


def normalise(rec, hint=None):
    """Any drills.jsonl line (already json-decoded) -> v1 dict, or None when
    it has no usable t0. v1 records pass through with defaults filled in."""
    if not isinstance(rec, dict):
        return None
    if rec.get("v") == 1:
        out = {k: None for k in KEYS}
        out.update(checks=[], extra={})
        out.update({k: v for k, v in rec.items() if k in KEYS})
        return out if rfc3339.parse(out.get("t0")) is not None else None
    if rfc3339.parse(rec.get("t0")) is None:
        return None
    kind = HINTS.get(hint) or _guess(rec)
    raw = str(rec.get("result", ""))
    rate = _num(rec.get("rate_mbs", rec.get("rate")))
    out = {k: None for k in KEYS}
    out.update(
        v=1, t0=rec["t0"], kind=kind,
        label=str(rec.get("label", "")).strip() or "unlabeled",
        result="pass" if raw.upper() == "OK" else "fail",
        host=rec.get("host") or None,
        rto_s=_int(_first(rec, "rto", "rto_s", "seconds")),
        rpo_s=_int(_first(rec, "rpo", "rpo_s")),
        bytes=int(rec["mib"]) * MIB if isinstance(rec.get("mib"), int) else None,
        # nas rate_mbs is du -sk / 1024 per second, so MiB/s like the others
        rate_bps=_whole(rate * MIB) if rate is not None else None,
        cr=rec.get("cr") or None, rollback_of=rec.get("rollback_of") or None,
        checks=[], extra={k: v for k, v in rec.items() if k not in _MAPPED},
    )
    if raw.upper() not in ("OK", "FAIL"):
        out["extra"]["result_raw"] = raw
    return out


def load(path, hint=None):
    """-> (v1 records in file order, skipped line count)."""
    recs, skipped = jsonl.read(path)
    out = []
    for r in recs:
        n = normalise(r, hint)
        if n is None:
            skipped += 1
        else:
            out.append(n)
    return out, skipped


def epoch(rec):
    return rfc3339.to_epoch(rec["t0"])
