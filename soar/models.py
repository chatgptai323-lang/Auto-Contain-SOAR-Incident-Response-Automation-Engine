"""Alert normalisation and strict input validation.

Every value that can later end up in a URL, command or API call is validated
here, so downstream connectors only ever see well-formed targets.
"""
import ipaddress
import re
import time
import uuid
from urllib.parse import urlparse

ALERT_TYPES = ("ransomware", "malware_beacon", "phishing", "credential_compromise", "brute_force")
SEVERITY_NAMES = {"info": 1, "informational": 1, "low": 3, "medium": 5, "moderate": 5,
                  "high": 7, "critical": 10}
ALIASES = {
    "id": ("id", "alert_id", "event_id"),
    "source": ("source", "product", "vendor"),
    "type": ("type", "alert_type", "category"),
    "severity": ("severity", "level", "priority"),
    "confidence": ("confidence",),
    "title": ("title", "name", "rule_name", "description"),
    "host": ("host", "hostname", "computer_name", "device"),
    "ip": ("ip", "host_ip", "asset_ip"),          # the monitored asset's own IP (context only)
    "user": ("user", "username", "account", "user_name"),
    "email_id": ("email_id", "message_id"),
}
ATTACKER_IP_KEYS = ("src_ip", "source_ip", "attacker_ip", "remote_ip")  # adversary IPs -> indicators.ips
MAX_INDICATORS = 50

_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HOST = re.compile(r"^[a-z0-9][a-z0-9._-]{0,252}$")
_USER = re.compile(r"^[a-z0-9][a-z0-9._@+-]{0,127}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
_EMAIL = re.compile(r"^[A-Za-z0-9._:@<>+=/-]{1,256}$")


class ValidationError(ValueError):
    pass


def validate_target(kind, value):
    v = str(value).strip()
    if kind == "incident":
        return v
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            raise ValidationError(f"invalid ip: {v[:64]!r}") from None
    rx = {"host": _HOST, "user": _USER, "domain": _DOMAIN, "hash": _HASH, "email": _EMAIL}.get(kind)
    if rx is None:
        raise ValidationError(f"unknown target kind: {kind}")
    if kind in ("host", "user", "hash"):
        v = v.lower()
    elif kind == "domain":
        v = v.lower().rstrip(".")
    if not rx.match(v):
        raise ValidationError(f"invalid {kind}: {v[:64]!r}")
    return v


def _first(raw, names):
    for n in names:
        if raw.get(n) not in (None, ""):
            return raw[n]
    return None


def _severity(v):
    if v is None:
        return 5.0
    if isinstance(v, str):
        s = v.strip().lower()
        if s in SEVERITY_NAMES:
            return float(SEVERITY_NAMES[s])
        try:
            v = float(s)
        except ValueError:
            raise ValidationError("invalid severity") from None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValidationError("invalid severity")
    v = float(v)
    if v > 10:
        v = v / 10 if v <= 100 else 10.0
    return max(1.0, min(10.0, v))


def _confidence(v):
    if v is None:
        return 0.5
    try:
        v = float(v)
    except (TypeError, ValueError):
        raise ValidationError("invalid confidence") from None
    if v > 1:
        v = v / 100
    return max(0.0, min(1.0, v))


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (str, int)):
        return [v]
    if isinstance(v, (list, tuple)):
        return list(v)[:MAX_INDICATORS]
    raise ValidationError("indicator values must be a string or list")


def normalize_alert(raw, now=None):
    if not isinstance(raw, dict):
        raise ValidationError("alert must be a JSON object")
    now = now or time.time()
    warnings = []

    atype = str(_first(raw, ALIASES["type"]) or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    if atype not in ALERT_TYPES:
        atype = "unknown"

    aid = _first(raw, ALIASES["id"])
    aid = str(aid) if aid is not None else uuid.uuid4().hex
    if not _ID.match(aid):
        raise ValidationError("invalid alert id")

    out = {
        "id": aid,
        "source": str(_first(raw, ALIASES["source"]) or "unknown")[:64],
        "type": atype,
        "severity": _severity(_first(raw, ALIASES["severity"])),
        "confidence": _confidence(_first(raw, ALIASES["confidence"])),
        "title": str(_first(raw, ALIASES["title"]) or f"{atype} alert")[:200],
        "host": None, "ip": None, "user": None, "email_id": None,
        "timestamp": str(raw.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))[:64],
        "details": raw.get("details") if isinstance(raw.get("details"), dict) else {},
    }
    for field, kind in (("host", "host"), ("ip", "ip"), ("user", "user"), ("email_id", "email")):
        val = _first(raw, ALIASES[field])
        if val is not None:
            out[field] = validate_target(kind, val)

    ind_raw = raw.get("indicators") if isinstance(raw.get("indicators"), dict) else {}
    ips = _as_list(ind_raw.get("ips"))
    for k in ATTACKER_IP_KEYS:
        ips += _as_list(raw.get(k))
    domains = _as_list(ind_raw.get("domains"))
    for url in _as_list(ind_raw.get("urls")):
        u = str(url)
        host = urlparse(u if "://" in u else "http://" + u).hostname
        if host:
            domains.append(host)
    hashes = _as_list(ind_raw.get("hashes"))

    indicators = {"ips": [], "domains": [], "hashes": []}
    for kind, key, values in (("ip", "ips", ips), ("domain", "domains", domains), ("hash", "hashes", hashes)):
        for v in values[:MAX_INDICATORS]:
            try:
                nv = validate_target(kind, v)
            except ValidationError as e:
                warnings.append(str(e))
                continue
            if nv not in indicators[key]:
                indicators[key].append(nv)
    out["indicators"] = indicators
    out["warnings"] = warnings
    return out
