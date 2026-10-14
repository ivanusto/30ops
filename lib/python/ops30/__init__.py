"""Shared code for the collector-side tools of 30ops.

Python 3.12 standard library, plus PyYAML (python3-yaml) for site.yaml in
ops30.yamlio, imported only when used. Scripts find this package with a
sys.path entry derived from their own __file__ (see docs/lib.md), so it
works under `python3 -I` as well. Node-side scripts that are copied to
other hosts on their own do not import it.
"""
import os

_VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "VERSION")


def version():
    try:
        with open(_VERSION_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "0.0.0"
