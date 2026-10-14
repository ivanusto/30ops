#!/usr/bin/env python3
"""HTTP fakes for the e2e LAN, one process, a thread per listener:

  PVE API      https://<pve address>:8006/api2/json/...  (pve-exporter)
  FortiGate    https://<fgt address>:10443/api/v2/monitor/license/status
  webhook sink http://<sink address>:9999/<receiver>     (Alertmanager)

  http.py --state DIR --cert PEM --key PEM \
          --pve pve1=192.0.2.9 --pve pve2=192.0.2.5 --pve-cluster lab \
          --pve-token 'prometheus@pve!exporter=SECRET' \
          --fortigate 192.0.2.99 --fortigate-token SECRET --fortigate-body FILE \
          --sink 192.0.2.250

The PVE API answers a quorate two-node cluster with one storage per node
and no guests. The sink appends {"path", "body"} per POST to
DIR/webhook.jsonl. A wrong token gets 401, as the real APIs do.
"""
import argparse
import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def pve_routes(nodes, local, cluster):
    """{path: data} for the PVE API as seen from node `local`.
    nodes: [(name, address)]."""
    status = [{"type": "cluster", "id": "cluster", "name": cluster, "nodes": len(nodes),
               "quorate": 1, "version": 2}]
    resources = []
    for i, (n, addr) in enumerate(nodes, 1):
        status.append({"type": "node", "id": f"node/{n}", "name": n, "nodeid": i, "ip": addr,
                       "online": 1, "local": int(n == local), "level": ""})
        resources.append({"id": f"node/{n}", "type": "node", "node": n, "status": "online",
                          "cpu": 0.05, "maxcpu": 4, "mem": 4 << 30, "maxmem": 16 << 30,
                          "disk": 8 << 30, "maxdisk": 64 << 30, "uptime": 864000})
        resources.append({"id": f"storage/{n}/local", "type": "storage", "node": n,
                          "storage": "local", "plugintype": "dir", "content": "iso,backup,vztmpl",
                          "status": "available", "disk": 10 << 30, "maxdisk": 100 << 30,
                          "shared": 0})
    routes = {
        "/api2/json/version": {"version": "9.0.3", "release": "9.0", "repoid": "e2e00000"},
        "/api2/json/cluster/status": status,
        "/api2/json/cluster/resources": resources,
    }
    for n, _ in nodes:
        for sub in ("qemu", "lxc", "replication"):
            routes[f"/api2/json/nodes/{n}/{sub}"] = []
    return routes


def pve_get(routes, path, query):
    """(code, body) for a GET on the fake PVE API."""
    p = path.rstrip("/")
    if p not in routes:
        return 404, {"data": None, "errors": {"path": "no such fake endpoint"}}
    data = routes[p]
    if p.endswith("/cluster/resources") and "type" in query:
        want = query["type"][0]
        data = [r for r in data if r["type"] == ("qemu" if want == "vm" else want)
                or (want == "vm" and r["type"] == "lxc")]
    return 200, {"data": data}


def handler(kind, cfg):
    class H(BaseHTTPRequestHandler):
        server_version = "ops30-e2e-fake"

        def log_message(self, fmt, *args):
            if not cfg.get("quiet"):
                sys.stderr.write(f"{kind} {self.client_address[0]} {fmt % args}\n")

        def reply(self, code, body):
            raw = json.dumps(body).encode() if not isinstance(body, bytes) else body
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            u = urlsplit(self.path)
            auth = self.headers.get("Authorization", "")
            if kind == "pve":
                if auth != f"PVEAPIToken={cfg['token']}":
                    return self.reply(401, {"data": None})
                return self.reply(*pve_get(cfg["routes"], u.path, parse_qs(u.query)))
            if kind == "fortigate":
                if auth != f"Bearer {cfg['token']}":
                    return self.reply(401, {"http_status": 401})
                if u.path != "/api/v2/monitor/license/status":
                    return self.reply(404, {"http_status": 404})
                return self.reply(200, cfg["body"])
            return self.reply(404, {})

        def do_POST(self):
            if kind != "sink":
                return self.reply(405, {})
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n)
            try:
                body = json.loads(raw)
            except ValueError:
                body = raw.decode("utf-8", "replace")
            with cfg["lock"]:
                with open(cfg["file"], "a", encoding="utf-8") as f:
                    f.write(json.dumps({"path": self.path, "body": body}) + "\n")
            return self.reply(200, {})
    return H


def listen(addr, port, h, tls=None):
    srv = ThreadingHTTPServer((addr, port), h)
    if tls:
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--pve", action="append", default=[], metavar="NAME=ADDR")
    ap.add_argument("--pve-cluster", default="lab")
    ap.add_argument("--pve-token")
    ap.add_argument("--fortigate")
    ap.add_argument("--fortigate-token")
    ap.add_argument("--fortigate-body")
    ap.add_argument("--sink")
    a = ap.parse_args(argv)
    tls = None
    if a.cert:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(a.cert, a.key)
    servers = []
    nodes = [tuple(x.split("=", 1)) for x in a.pve]
    for n, addr in nodes:
        cfg = {"token": a.pve_token, "routes": pve_routes(nodes, n, a.pve_cluster)}
        servers.append(listen(addr, 8006, handler("pve", cfg), tls))
    if a.fortigate:
        with open(a.fortigate_body, "rb") as f:
            body = f.read()
        servers.append(listen(a.fortigate, 10443, handler("fortigate", {"token": a.fortigate_token, "body": body}), tls))
    if a.sink:
        cfg = {"file": os.path.join(a.state, "webhook.jsonl"), "lock": threading.Lock()}
        servers.append(listen(a.sink, 9999, handler("sink", cfg)))
    sys.stderr.write(f"http fakes: {len(servers)} listener(s)\n")
    threading.Event().wait()


if __name__ == "__main__":
    main()
