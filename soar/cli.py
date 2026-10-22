import argparse
import json
import logging
import secrets
import signal
import sys
import threading
import urllib.request

from . import __version__
from .api import make_server, start_maintenance
from .config import load_config
from .engine import Engine
from .scenarios import sample_config, scenarios
from .store import Store


def _print_incident(inc):
    print(f"  incident {inc['id']}  risk={inc['risk']}  alerts={inc['alert_count']}")
    for a in inc["actions"]:
        print(f"    {a['status']:<17} {a['action']:<17} {a['target']:<42} {a['reason'][:70]}")


def cmd_simulate(args):
    cfg = sample_config(dry_run=args.dry_run)
    eng = Engine(cfg)
    print(f"Auto-Contain SOAR {__version__} simulation (dry_run={cfg['dry_run']}, simulated connectors)\n")
    incidents = []
    for name, expect, alert in scenarios():
        print(f"== {name}\n   expect: {expect}")
        inc = eng.ingest(alert, "simulate")
        incidents.append(inc)
        _print_incident(inc)
        print()
    pending = eng.list_actions("pending_approval")
    print(f"-- {len(pending)} action(s) pending approval; approving the first one as 'analyst1'")
    if pending:
        done = eng.approve(pending[0]["id"], "analyst1")
        print(f"   {done['action']} {done['target']} -> {done['status']}")
    first = incidents[0]["id"]
    print(f"\n-- false positive! rolling back incident {first}")
    print("  ", json.dumps(eng.rollback_incident(first, "analyst1")))
    print("\n-- audit chain:", json.dumps(eng.store.verify_audit()))
    print("-- stats:", json.dumps(eng.stats()))
    return 0


def cmd_serve(args):
    if args.demo:
        import os
        cfg = sample_config(db_path=os.environ.get("SOAR_DB_PATH", "soar-demo.db"))
        print("[demo] sample inventory/threat-intel loaded; ALL connectors are simulated.", file=sys.stderr)
    else:
        cfg = load_config(args.config)
    if args.host:
        cfg["listen_host"] = args.host
    if args.port:
        cfg["listen_port"] = args.port
    if args.dry_run:
        cfg["dry_run"] = True
    keys = cfg["api_keys"]
    for role in ("admin", "ingest"):
        if not keys.get(role):
            keys[role] = secrets.token_urlsafe(32)
            print(f"[!] no {role} API key configured; generated for this run: {keys[role]}", file=sys.stderr)
    if keys["admin"] == keys["ingest"]:
        raise SystemExit("admin and ingest API keys must differ")
    eng = Engine(cfg)
    srv = make_server(eng, cfg["listen_host"], int(cfg["listen_port"]), keys)
    stop = start_maintenance(eng, cfg["maintenance_interval_seconds"])
    if cfg["listen_host"] not in ("127.0.0.1", "localhost", "::1"):
        print("[!] listening on a non-loopback address WITHOUT TLS - put a TLS reverse proxy in front.", file=sys.stderr)
    print(f"Auto-Contain SOAR {__version__} listening on http://{cfg['listen_host']}:{cfg['listen_port']} "
          f"(dry_run={cfg['dry_run']}, db={cfg['db_path']})")
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown).start())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()
    return 0


def cmd_verify(args):
    res = Store(args.db).verify_audit()
    print(json.dumps(res))
    return 0 if res["ok"] else 2


def cmd_send(args):
    sent = 0
    for name, _, alert in scenarios():
        req = urllib.request.Request(args.url.rstrip("/") + "/api/alerts", data=json.dumps(alert).encode(),
                                     headers={"Content-Type": "application/json", "X-API-Key": args.key}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            inc = json.loads(r.read())
        print(f"== {name}")
        _print_incident(inc)
        sent += 1
    print(f"sent {sent} alerts")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="soar", description="Auto-Contain SOAR")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("simulate", help="run the built-in scenarios against simulated connectors")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_simulate)
    s = sub.add_parser("serve", help="run the API server")
    s.add_argument("--config")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--demo", action="store_true", help="sample environment + simulated connectors (safe)")
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("verify-audit", help="verify the audit hash chain in a database")
    s.add_argument("--db", required=True)
    s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("send", help="POST sample scenarios to a running server")
    s.add_argument("--url", default="http://127.0.0.1:8080")
    s.add_argument("--key", required=True, help="ingest or admin API key")
    s.set_defaults(fn=cmd_send)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return args.fn(args)
