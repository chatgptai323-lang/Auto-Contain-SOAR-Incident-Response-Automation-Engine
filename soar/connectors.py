"""Connectors: the only code that touches the outside world.

* SimulatedConnector - in-memory, for demos/tests/dry integration.
* WebhookConnector   - generic REST adapter. Map any EDR / IdP / firewall / DNS /
  mail / chat / ticketing API to SOAR actions purely through config routes.
"""
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import os


class ConnectorError(Exception):
    pass


class Connector:
    name = "connector"

    def execute(self, action, target, params):
        raise NotImplementedError


class SimulatedConnector(Connector):
    def __init__(self, name="sim"):
        self.name = name
        self.lock = threading.Lock()
        self.calls = []          # every call, in order
        self.active = set()      # (action, target) pairs currently "in force"
        self.fail_next = {}      # action -> number of upcoming failures (fault injection)

    def execute(self, action, target, params):
        with self.lock:
            if self.fail_next.get(action, 0) > 0:
                self.fail_next[action] -= 1
                raise ConnectorError(f"{self.name}: simulated failure for {action}")
            self.calls.append((action, target, dict(params)))
            self.active.add((action, target))
            for undo, do in (("unisolate_host", "isolate_host"), ("enable_account", "disable_account"),
                             ("unblock_ip", "block_ip"), ("unblock_domain", "block_domain"),
                             ("release_file", "quarantine_file"), ("release_email", "quarantine_email")):
                if action == undo:
                    self.active.discard((do, target))
            return {"simulated": True, "connector": self.name, "action": action, "target": target}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):   # never follow redirects (avoids leaking auth headers)
        return None


def _render(template, ctx, quote=False):
    def sub(m):
        v = str(ctx.get(m.group(1), ""))
        return urllib.parse.quote(v, safe="") if quote else v
    return re.sub(r"\{(\w+)\}", sub, template)


def _render_obj(obj, ctx):
    if isinstance(obj, str):
        return _render(obj, ctx)
    if isinstance(obj, dict):
        return {k: _render_obj(v, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render_obj(v, ctx) for v in obj]
    return obj


class WebhookConnector(Connector):
    """Config example:
    {"type": "webhook", "base_url": "https://edr.example.com/api", "token_env": "EDR_TOKEN",
     "routes": {"isolate_host":   {"method": "POST", "path": "/hosts/{target}/isolate"},
                "unisolate_host": {"method": "POST", "path": "/hosts/{target}/release"}}}
    Placeholders: {target} {action} plus any step/param value ({user}, {host}, {message}, {ttl} ...).
    """

    def __init__(self, name, cfg):
        self.name = name
        self.base = cfg["base_url"].rstrip("/")
        if not (self.base.startswith("https://") or cfg.get("allow_insecure_http")):
            raise ValueError(f"connector {name}: base_url must be https:// (or set allow_insecure_http)")
        self.routes = cfg.get("routes", {})
        self.timeout = float(cfg.get("timeout", 10))
        self.headers = {"Content-Type": "application/json", "User-Agent": "auto-contain-soar/1.0"}
        token = os.environ.get(cfg["token_env"]) if cfg.get("token_env") else cfg.get("token")
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.headers.update(cfg.get("headers", {}))
        self.opener = urllib.request.build_opener(_NoRedirect)

    def execute(self, action, target, params):
        route = self.routes.get(action)
        if not route:
            raise ConnectorError(f"{self.name}: no route configured for {action}")
        ctx = {k: str(v) for k, v in params.items() if isinstance(v, (str, int, float, bool))}
        ctx.update(target=target, action=action)
        url = self.base + _render(route.get("path", ""), ctx, quote=True)
        body = route.get("body")
        data = json.dumps(_render_obj(body, ctx)).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=route.get("method", "POST"), headers=self.headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw, status = resp.read(65536), resp.status
        except urllib.error.HTTPError as e:
            raise ConnectorError(f"{self.name}: HTTP {e.code} for {action}") from e
        except (urllib.error.URLError, OSError) as e:
            raise ConnectorError(f"{self.name}: {e}") from e
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:
            parsed = {"raw": raw[:200].decode("utf-8", "replace")}
        return {"status": status, "response": parsed}


def build_connectors(cfg_connectors):
    out = {}
    for cap, c in cfg_connectors.items():
        out[cap] = WebhookConnector(cap, c) if c["type"] == "webhook" else SimulatedConnector(cap)
    return out
