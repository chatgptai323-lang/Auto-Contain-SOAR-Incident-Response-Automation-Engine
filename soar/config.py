"""Configuration: safe defaults, JSON file overlay, environment overrides."""
import copy
import json
import os

CAPABILITIES = ("edr", "idp", "firewall", "dns", "mail", "notify", "ticket")

DEFAULTS = {
    "db_path": "soar.db",
    "listen_host": "127.0.0.1",
    "listen_port": 8080,
    "api_keys": {"ingest": "", "admin": ""},   # blank => random keys generated at `serve`
    "dry_run": False,                          # True => disruptive actions are recorded, never executed
    "retries": 2,
    "retry_backoff_seconds": 0.5,
    "correlation_window_seconds": 3600,
    "approval_ttl_seconds": 3600,
    "maintenance_interval_seconds": 30,
    "thresholds": {
        "monitor": 20,                 # below this risk nothing at all happens
        "min_confidence_auto": 0.7,    # disruptive auto-actions need at least this confidence
        "default": {"approval": 50, "auto": 80},
        "actions": {
            "isolate_host": {"approval": 50, "auto": 85},
            "disable_account": {"approval": 55, "auto": 90},
            "revoke_sessions": {"approval": 45, "auto": 70},
            "block_ip": {"approval": 45, "auto": 75},
            "block_domain": {"approval": 45, "auto": 75},
            "quarantine_file": {"approval": 45, "auto": 70},
            "quarantine_email": {"approval": 35, "auto": 60},
        },
    },
    "blast_radius": {"window_seconds": 3600, "max_per_action": 5, "max_total": 10},
    # Never touched automatically OR via approval. Glob patterns (hosts/users/domains), CIDRs (ips).
    "protected": {"hosts": [], "users": [], "ips": [], "domains": []},
    # Disruptive actions on these always need a human.
    "sensitive": {"hosts": [], "users": []},
    "inventory": {"assets": {}, "users": {}},
    "threat_intel": {"ips": [], "domains": [], "hashes": []},
    "threat_intel_file": None,
    "connectors": {cap: {"type": "simulated"} for cap in CAPABILITIES},
    "playbooks": {},
}


def deep_merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _validate(cfg):
    t = cfg["thresholds"]
    for name, th in list(t["actions"].items()) + [("default", t["default"])]:
        if th["approval"] > th["auto"]:
            raise ValueError(f"thresholds.{name}: approval must be <= auto")
    if not 0 <= t["min_confidence_auto"] <= 1:
        raise ValueError("thresholds.min_confidence_auto must be within 0..1")
    for cap, c in cfg["connectors"].items():
        if cap not in CAPABILITIES:
            raise ValueError(f"unknown connector capability: {cap}")
        if c.get("type") not in ("simulated", "webhook"):
            raise ValueError(f"connectors.{cap}.type must be 'simulated' or 'webhook'")
    int(cfg["listen_port"])


def build_config(overrides=None):
    cfg = deep_merge(DEFAULTS, overrides or {})
    env = os.environ
    if env.get("SOAR_DB_PATH"):
        cfg["db_path"] = env["SOAR_DB_PATH"]
    if env.get("SOAR_HOST"):
        cfg["listen_host"] = env["SOAR_HOST"]
    if env.get("SOAR_PORT"):
        cfg["listen_port"] = int(env["SOAR_PORT"])
    if env.get("SOAR_INGEST_KEY"):
        cfg["api_keys"]["ingest"] = env["SOAR_INGEST_KEY"]
    if env.get("SOAR_ADMIN_KEY"):
        cfg["api_keys"]["admin"] = env["SOAR_ADMIN_KEY"]
    if env.get("SOAR_DRY_RUN"):
        cfg["dry_run"] = env["SOAR_DRY_RUN"].lower() in ("1", "true", "yes")
    _validate(cfg)
    return cfg


def load_config(path=None):
    overrides = {}
    if path:
        with open(path, "r", encoding="utf-8") as f:
            overrides = json.load(f)
    return build_config(overrides)
