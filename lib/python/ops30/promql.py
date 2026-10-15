"""Prometheus' HTTP API, read only: instant queries and the active targets.

doctor asks the collector's own Prometheus (LOCAL, published on 127.0.0.1
only); readiness may ask any Prometheus (--prometheus), the one of a
collector that does not run 30ops yet included. ops is an install.ops.Ops
or a test double: ops.http(url) -> (status, body), status 0 when nothing
answered.
"""
import json
import urllib.parse

LOCAL = "http://127.0.0.1:9090"


def query(ops, q, base=LOCAL):
    """The result list of an instant query, or None when Prometheus did not
    answer or refused the query."""
    code, body = ops.http(f"{base.rstrip('/')}/api/v1/query?query=" + urllib.parse.quote(q))
    if code != 200:
        return None
    try:
        return json.loads(body)["data"]["result"]
    except (ValueError, KeyError, TypeError):
        return None


def targets(ops, base=LOCAL):
    """(status, active targets): the list is None unless status is 200."""
    code, body = ops.http(f"{base.rstrip('/')}/api/v1/targets?state=active")
    if code != 200:
        return code, None
    try:
        return code, json.loads(body)["data"]["activeTargets"]
    except (ValueError, KeyError, TypeError):
        return code, None
