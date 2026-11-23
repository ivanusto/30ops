#!/usr/bin/env python3
"""pseudonymize: the privacy step between the site's events and anything
that reasons about them. Nothing downstream (summaries, the models, the
detections, the report) ever sees a real account, host, address or path.

    pseudonymize.py --key-file /etc/30ops/behavior.key --level standard \
        --in events.jsonl --out events.p.jsonl --schedule schedule.tsv --schedule-out schedule.p.tsv \
        --timing timing.jsonl [--vault /path/held/by/someone/else/vault.jsonl]

Levels (each includes the ones before it):

    minimal   accounts and hostnames replaced by HMAC-SHA256 pseudonyms (u-xxxx, h-xxxx);
              every key outside the event schema dropped
    standard  addresses rewritten prefix-preserving (same prefix in, same prefix
              out, octet by octet, keyed; the idea of Crypto-PAn at octet
              granularity); names cut to the registered domain; paths cut to
              share and first directory, file names to their extension; time
              floored to the minute
    strict    names replaced by their category only; paths cut to the share;
              file names dropped; byte counts rounded to two significant
              figures; time floored to the hour

The key is never in this repository, never in the output, and never printed.
--demo-key is for tests and prints a warning. --vault writes the real to
pseudonym table for the person who holds it (ISO/IEC 27701: the additional
information kept separately); without --vault nothing can be reversed.

The wall time of the batch goes to --timing as one JSON line
({"stage":"pseudonymize","level":...,"events":n,"ms":...}), the measurement
the latency breakdown is built from.

Standard library only.
"""
import argparse, hashlib, hmac, ipaddress, json, math, os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "lib", "python"))
from ops30 import rfc3339  # noqa: E402

LEVELS = ("minimal", "standard", "strict")
COMMON = {"ts", "kind", "user", "src_host", "src_ip", "src_scope", "asset", "source", "role", "host_class"}
PER_KIND = {
    "net.conn": {"dst", "dst_name", "dst_port", "proto", "service", "bytes_out", "bytes_in", "duration_s", "category", "action"},
    "net.file": {"dst", "dst_name", "filename", "bytes", "direction"},
    "auth.logon": {"dst", "logon_type", "result", "method", "rule_id", "rule_level"},  # SIEM-derived logons carry rule fields
    "file.access": {"dst", "share", "path", "action", "bytes"},
    "print.job": {"dst", "pages", "filename"},
    "usb.attach": {"device"},
    "fw.utm": {"dst", "dst_name", "category", "app", "action"},
    "sec.alert": {"rule_id", "rule_level", "rule_group", "mitre"},
    "priv.exec": {"dst", "target", "category", "rule_id", "rule_level"},
    "file.integrity": {"dst", "path", "action", "rule_id", "rule_level"},
    "pkg.change": {"dst", "action", "category", "rule_id", "rule_level"},
    "malware.detect": {"dst", "rule_level", "category", "incident"},
}
HOST_KEYS = ("user", "src_host", "dst")
NAME_KEYS = ("dst_name",)
TWO_LEVEL_TLD = {"com.tw", "org.tw", "edu.tw", "gov.tw", "net.tw", "co.uk", "co.jp", "com.cn", "com.au", "com.hk"}


# dictionary kinds and the letter their pseudonyms start with
# (org: an organisation's name without a TLD; a domain is dotted)
KIND_PREFIX = {"user": "u", "host": "h", "domain": "d", "org": "o", "file": "f", "path": "p", "hash": "x", "device": "m"}


class Pseudonymizer:
    def __init__(self, key, level, vault=None):
        if level not in LEVELS:
            raise ValueError(level)
        self.key, self.level, self.vault = key, level, vault
        self.seen = {}
        self.ipc = {}
        self.term_rx, self.term_map = None, {}
        self.dropped_keys = 0

    def mac(self, kind, value, n=10):
        return hmac.new(self.key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:n]

    def name(self, kind, value, prefix):
        if value in (None, ""):
            return value
        out = f"{prefix}-{self.mac(kind, value)}"
        self.remember(kind, value, out)
        return out

    def remember(self, kind, real, pseud):
        if self.vault is not None and (kind, real) not in self.seen:
            self.seen[(kind, real)] = pseud
            self.vault.write(json.dumps({"kind": kind, "real": real, "pseudonym": pseud}, ensure_ascii=False) + "\n")

    def ip(self, value):
        """Prefix preserving, octet by octet: the substitution of octet i is a
        keyed function of octets 0..i-1, so two addresses that share a prefix
        share the rewritten prefix, and nothing else is preserved."""
        try:
            a = ipaddress.ip_address(value)
        except ValueError:
            return self.name("host", value, "h")
        if a.version != 4:
            return self.name("ip6", value, "i6")
        cached = self.ipc.get(value)
        if cached:
            return cached
        octs, out, prefix = [int(x) for x in value.split(".")], [], ""
        for i, o in enumerate(octs):
            k = hmac.new(self.key, f"ip:{i}:{prefix}".encode(), hashlib.sha256).digest()[0]
            out.append(o ^ k)
            prefix += f"{o}."
        res = ".".join(str(x) for x in out)
        self.ipc[value] = res
        self.remember("ip", value, res)
        return res

    def host_or_ip(self, value):
        if value in (None, ""):
            return value
        try:
            ipaddress.ip_address(value)
            return self.ip(value)
        except ValueError:
            return self.name("host", value, "h")

    def domain(self, value, category):
        if value in (None, ""):
            return value
        if self.level == "strict":
            return f"[{category}]" if category else "[domain]"
        if self.level == "minimal":
            return value
        try:
            ipaddress.ip_address(value)
            return self.ip(value)
        except ValueError:
            pass
        labels = value.lower().rstrip(".").split(".")
        keep = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_TLD else 2
        return ".".join(labels[-keep:])

    def set_terms(self, terms, rx):
        """The site dictionary from scrub.py: a kept path segment can still name a host or an account."""
        self.term_map = {t["real"].lower(): self.name(t["kind"], t["real"].lower(), KIND_PREFIX.get(t["kind"], "h")) for t in terms}
        self.term_rx = rx

    def path(self, value, share):
        if value in (None, ""):
            return value
        parts = [p for p in str(value).replace("\\", "/").split("/") if p]
        if self.level == "minimal":
            return "/".join(parts)
        for i in range(len(parts) - 1):      # a home directory is an account name
            if parts[i].lower() in ("home", "users"):
                parts[i + 1] = "<user>"
        if self.level == "strict" or len(parts) < 2:
            return share or (parts[0] if parts else "")
        if self.term_rx:
            parts = [self.term_rx.sub(lambda m: self.term_map.get(m.group(0).lower(), "<term>"), x) for x in parts]
        ext = os.path.splitext(parts[-1])[1].lower() if len(parts) > 1 else ""
        return "/".join(parts[:2]) + (f"/*{ext}" if ext else "")

    def filename(self, value):
        if value in (None, ""):
            return value
        if self.level == "minimal":
            return value
        if self.level == "strict":
            return ""
        return "*" + os.path.splitext(str(value))[1].lower()

    def when(self, ts):
        d = rfc3339.parse(ts)
        if d is None:
            return ts
        if self.level == "standard":
            d = d.replace(second=0)
        elif self.level == "strict":
            d = d.replace(minute=0, second=0)
        return rfc3339.format(d)

    def bytes_(self, n):
        if self.level != "strict" or not isinstance(n, int) or n <= 0:
            return n
        mag = 10 ** (int(math.log10(n)) - 1) if n >= 10 else 1
        return int(round(n / mag) * mag)

    @staticmethod
    def scope(value):
        """internal or external, read before the address is rewritten: the
        rewrite keeps prefixes but not what they mean."""
        try:
            a = ipaddress.ip_address(value)
        except ValueError:
            return ""
        b = a.packed
        if a.version == 4:      # by number: is_private also says yes to the documentation and benchmark ranges
            inner = b[0] in (10, 127) or (b[0] == 172 and 16 <= b[1] <= 31) or (b[0] == 192 and b[1] == 168) or (b[0] == 100 and 64 <= b[1] <= 127) or (b[0] == 169 and b[1] == 254)
        else:
            inner = a.is_loopback or a.is_link_local or (b[0] & 0xfe) == 0xfc
        return "internal" if inner else "external"

    def event(self, e):
        allowed = COMMON | PER_KIND.get(e.get("kind", ""), set())
        out = {}
        for k, v in e.items():
            if k not in allowed:
                self.dropped_keys += 1
                continue
            out[k] = v
        out["ts"] = self.when(out.get("ts", ""))
        if out.get("src_ip") and not out.get("src_scope"):
            out["src_scope"] = self.scope(out["src_ip"])
        if out.get("user"):
            out["user"] = self.name("user", out["user"], "u")
        if out.get("target"):
            out["target"] = self.name("user", out["target"], "u")
        if out.get("incident"):
            out["incident"] = self.name("incident", out["incident"], "i")
        for k in ("src_host", "dst", "asset"):
            if out.get(k):
                out[k] = self.host_or_ip(out[k])
        if out.get("src_ip"):
            out["src_ip"] = self.ip(out["src_ip"]) if self.level != "minimal" else self.host_or_ip(out["src_ip"])
        if "dst_name" in out:
            out["dst_name"] = self.domain(out["dst_name"], out.get("category", ""))
        if out.get("share"):
            out["share"] = self.name("share", out["share"], "s")
        if "path" in out:
            out["path"] = self.path(out["path"], out.get("share", ""))
        if "filename" in out:
            out["filename"] = self.filename(out["filename"])
        for k in ("bytes", "bytes_out", "bytes_in"):
            if k in out:
                out[k] = self.bytes_(out[k])
        return out


def load_key(a):
    if a.demo_key:
        print("pseudonymize: DEMO KEY, output is not protected", file=sys.stderr)
        return b"30ops-behavior-demo-key-not-for-real-data"
    path = a.key_file or os.environ.get("BEHAVIOR_KEY_FILE")
    if not path:
        sys.exit("pseudonymize: --key-file (or BEHAVIOR_KEY_FILE) is required; --demo-key only for tests")
    with open(path, "rb") as f:
        key = f.read().strip()
    if len(key) < 32:
        sys.exit("pseudonymize: key must be at least 32 bytes (openssl rand -hex 32 > file)")
    return key


def schedule_rows(path):
    with open(path, encoding="utf-8") as f:
        header = None
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if header is None:
                header = cols
                yield header, None
                continue
            yield header, dict(zip(header, cols))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--level", choices=LEVELS, default="standard")
    ap.add_argument("--key-file"); ap.add_argument("--demo-key", action="store_true")
    ap.add_argument("--vault", help="real to pseudonym table, for the key holder only")
    ap.add_argument("--schedule", help="injection schedule (tsv) to pseudonymize with the same key")
    ap.add_argument("--schedule-out")
    ap.add_argument("--timing", help="append one JSON line with the batch wall time")
    ap.add_argument("--terms", help="site dictionary from scrub.py dict; also replaced inside kept path segments")
    a = ap.parse_args()
    key = load_key(a)
    vault = open(a.vault, "a", encoding="utf-8") if a.vault else None
    p = Pseudonymizer(key, a.level, vault)
    if a.terms:
        from scrub import load_terms, term_regex     # scrub imports this module, so not at the top
        terms = load_terms(a.terms)
        p.set_terms(terms, term_regex({t["real"].lower(): t["kind"] for t in terms}))
    n = 0
    t0 = time.perf_counter()
    with open(a.inp, encoding="utf-8") as fi, open(a.out, "w", encoding="utf-8") as fo:
        for line in fi:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            fo.write(json.dumps(p.event(e), ensure_ascii=False, separators=(",", ":")) + "\n")
            n += 1
    ms = (time.perf_counter() - t0) * 1000
    if a.schedule:
        with open(a.schedule_out or (a.schedule + ".p"), "w", encoding="utf-8") as fo:
            for header, row in schedule_rows(a.schedule):
                if row is None:
                    fo.write("\t".join(header) + "\n")
                    continue
                for k in ("user",):
                    if row.get(k):
                        row[k] = p.name("user", row[k], "u")
                for k in ("host",):
                    if row.get(k):
                        row[k] = p.host_or_ip(row[k])
                if "note" in row:                      # free text written by a person: may name anything
                    row["note"] = ""
                fo.write("\t".join(row.get(h, "") for h in header) + "\n")
    if vault:
        vault.close()
    if a.timing:
        with open(a.timing, "a", encoding="utf-8") as f:
            f.write(json.dumps({"stage": "pseudonymize", "level": a.level, "events": n, "ms": round(ms, 1),
                                "ts": rfc3339.format(rfc3339.now())}) + "\n")
    print(f"pseudonymize: {n} events, level {a.level}, {ms:.0f} ms ({ms / max(n, 1):.3f} ms/event), {p.dropped_keys} keys outside the schema dropped")


if __name__ == "__main__":
    main()
