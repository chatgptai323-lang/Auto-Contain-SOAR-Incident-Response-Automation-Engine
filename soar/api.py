"""HTTP API (stdlib only). Two roles: `ingest` (POST alerts only) and `admin` (everything)."""
import hmac
import json
import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .engine import EngineError, NotFound
from .models import ValidationError

log = logging.getLogger("soar.api")
MAX_BODY = 1_000_000
ACTOR_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def make_server(engine, host, port, keys):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AutoContainSOAR/" + __version__
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        # ---- helpers -----------------------------------------------------
        def _send(self, code, obj):
            data = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _role(self):
            provided = self.headers.get("X-API-Key") or ""
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                provided = auth[7:].strip()
            if not provided:
                return None
            for role in ("admin", "ingest"):
                key = keys.get(role) or ""
                if key and hmac.compare_digest(provided.encode(), key.encode()):
                    return role
            return None

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ValidationError("request body too large")
            if n == 0:
                return {}
            try:
                return json.loads(self.rfile.read(n))
            except ValueError:
                raise ValidationError("body is not valid JSON") from None

        def _actor(self, body):
            a = body.get("actor") if isinstance(body, dict) else None
            return a if isinstance(a, str) and ACTOR_RE.match(a) else "admin"

        # ---- routing -----------------------------------------------------
        def _dispatch(self, method):
            try:
                self._route(method)
            except ValidationError as e:
                self._send(400, {"error": str(e)})
            except NotFound as e:
                self._send(404, {"error": str(e)})
            except EngineError as e:
                self._send(409, {"error": str(e)})
            except Exception:  # noqa: BLE001
                log.exception("unhandled error")
                self._send(500, {"error": "internal error"})

        def _route(self, method):
            u = urlparse(self.path)
            path = u.path.rstrip("/") or "/"
            qs = parse_qs(u.query)
            if method == "GET" and path == "/health":
                return self._send(200, {"status": "ok", "version": __version__})
            role = self._role()
            if role is None:
                return self._send(401, {"error": "missing or invalid API key"})

            if method == "POST" and path == "/api/alerts":
                body = self._body()
                if isinstance(body, list):
                    if len(body) > 100:
                        raise ValidationError("batch limited to 100 alerts")
                    return self._send(200, [engine.ingest(a, f"api:{role}") for a in body])
                res = engine.ingest(body, f"api:{role}")
                return self._send(200 if res.get("duplicate_alert") else 201, res)

            if role != "admin":
                return self._send(403, {"error": "admin key required"})

            if method == "GET":
                if path == "/api/incidents":
                    return self._send(200, engine.list_incidents((qs.get("status") or [None])[0]))
                if path == "/api/actions":
                    return self._send(200, engine.list_actions((qs.get("status") or [None])[0]))
                if path == "/api/stats":
                    return self._send(200, engine.stats())
                if path == "/api/audit":
                    return self._send(200, engine.store.list_audit(min(int((qs.get("limit") or [100])[0]), 1000)))
                if path == "/api/audit/verify":
                    return self._send(200, engine.store.verify_audit())
                m = re.fullmatch(r"/api/incidents/([A-Za-z0-9-]+)", path)
                if m:
                    return self._send(200, engine.get_incident(m.group(1)))
            if method == "POST":
                body = self._body()
                actor = self._actor(body)
                m = re.fullmatch(r"/api/actions/([A-Za-z0-9-]+)/(approve|deny|rollback)", path)
                if m:
                    aid, verb = m.groups()
                    if verb == "approve":
                        return self._send(200, engine.approve(aid, actor))
                    if verb == "deny":
                        return self._send(200, engine.deny(aid, actor, str(body.get("reason", ""))))
                    return self._send(200, engine.rollback_action(aid, actor))
                m = re.fullmatch(r"/api/incidents/([A-Za-z0-9-]+)/(rollback|close)", path)
                if m:
                    iid, verb = m.groups()
                    if verb == "rollback":
                        return self._send(200, engine.rollback_incident(iid, actor))
                    return self._send(200, engine.close_incident(iid, actor))
                if path == "/api/maintenance":
                    return self._send(200, engine.maintenance())
            self._send(404, {"error": "not found"})

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def start_maintenance(engine, interval):
    stop = threading.Event()

    def loop():
        while not stop.wait(interval):
            try:
                engine.maintenance()
            except Exception:  # noqa: BLE001
                log.exception("maintenance failed")

    threading.Thread(target=loop, name="soar-maintenance", daemon=True).start()
    return stop
