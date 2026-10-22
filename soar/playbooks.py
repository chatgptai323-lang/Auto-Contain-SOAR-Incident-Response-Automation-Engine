"""Action catalog and default playbooks (override per alert type in config)."""

ACTIONS = {
    "isolate_host":     {"cap": "edr",      "kind": "host",     "disruptive": True,  "inverse": "unisolate_host"},
    "unisolate_host":   {"cap": "edr",      "kind": "host",     "disruptive": False, "inverse": None, "internal": True},
    "disable_account":  {"cap": "idp",      "kind": "user",     "disruptive": True,  "inverse": "enable_account"},
    "enable_account":   {"cap": "idp",      "kind": "user",     "disruptive": False, "inverse": None, "internal": True},
    "revoke_sessions":  {"cap": "idp",      "kind": "user",     "disruptive": True,  "inverse": None},
    "block_ip":         {"cap": "firewall", "kind": "ip",       "disruptive": True,  "inverse": "unblock_ip"},
    "unblock_ip":       {"cap": "firewall", "kind": "ip",       "disruptive": False, "inverse": None, "internal": True},
    "block_domain":     {"cap": "dns",      "kind": "domain",   "disruptive": True,  "inverse": "unblock_domain"},
    "unblock_domain":   {"cap": "dns",      "kind": "domain",   "disruptive": False, "inverse": None, "internal": True},
    "quarantine_file":  {"cap": "edr",      "kind": "hash",     "disruptive": True,  "inverse": "release_file"},
    "release_file":     {"cap": "edr",      "kind": "hash",     "disruptive": False, "inverse": None, "internal": True},
    "quarantine_email": {"cap": "mail",     "kind": "email",    "disruptive": True,  "inverse": "release_email"},
    "release_email":    {"cap": "mail",     "kind": "email",    "disruptive": False, "inverse": None, "internal": True},
    "notify":           {"cap": "notify",   "kind": "incident", "disruptive": False, "inverse": None},
    "create_ticket":    {"cap": "ticket",   "kind": "incident", "disruptive": False, "inverse": None},
}

SELECTOR_KIND = {"host": "host", "user": "user", "ip": "ip", "email_id": "email", "incident": "incident",
                 "indicators.ips": "ip", "indicators.domains": "domain", "indicators.hashes": "hash"}


def _tail():
    return [{"action": "create_ticket", "target": "incident"}, {"action": "notify", "target": "incident"}]


DEFAULT_PLAYBOOKS = {
    "ransomware": [
        {"action": "isolate_host", "target": "host"},
        {"action": "disable_account", "target": "user"},
        {"action": "revoke_sessions", "target": "user"},
        {"action": "quarantine_file", "target": "indicators.hashes"},
        *_tail()],
    "malware_beacon": [
        {"action": "block_ip", "target": "indicators.ips", "ttl": 86400},
        {"action": "block_domain", "target": "indicators.domains", "ttl": 86400},
        {"action": "isolate_host", "target": "host"},
        {"action": "quarantine_file", "target": "indicators.hashes"},
        *_tail()],
    "phishing": [
        {"action": "quarantine_email", "target": "email_id"},
        {"action": "block_domain", "target": "indicators.domains", "ttl": 604800},
        {"action": "revoke_sessions", "target": "user", "when": {"details.user_clicked": True}},
        *_tail()],
    "credential_compromise": [
        {"action": "revoke_sessions", "target": "user"},
        {"action": "disable_account", "target": "user"},
        *_tail()],
    "brute_force": [
        {"action": "block_ip", "target": "indicators.ips", "ttl": 3600},
        *_tail()],
    "unknown": _tail(),
}


def validate_playbooks(playbooks):
    for name, steps in playbooks.items():
        if not isinstance(steps, list):
            raise ValueError(f"playbook {name}: must be a list of steps")
        for s in steps:
            act = s.get("action")
            if act not in ACTIONS or ACTIONS[act].get("internal"):
                raise ValueError(f"playbook {name}: unknown action {act!r}")
            sel = s.get("target")
            if SELECTOR_KIND.get(sel) != ACTIONS[act]["kind"]:
                raise ValueError(f"playbook {name}: target {sel!r} is not valid for {act}")
            if "ttl" in s and (not isinstance(s["ttl"], (int, float)) or s["ttl"] <= 0):
                raise ValueError(f"playbook {name}: ttl must be a positive number")


def _get_path(d, path):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def resolve_steps(playbook, ctx):
    """Expand playbook steps into concrete (action, target) work items for this alert."""
    items = []
    for step in playbook:
        when = step.get("when") or {}
        if any(_get_path(ctx, k) != v for k, v in when.items()):
            continue
        sel = step["target"]
        if sel == "incident":
            targets = [ctx["incident_id"]]
        elif sel.startswith("indicators."):
            targets = list(ctx["indicators"].get(sel.split(".", 1)[1], []))
        else:
            targets = [ctx[sel]] if ctx.get(sel) else []
        params = {k: ctx[k] for k in ("host", "user") if ctx.get(k)}
        if "ttl" in step:
            params["ttl"] = step["ttl"]
        for t in targets:
            items.append({"step": step, "kind": ACTIONS[step["action"]]["kind"], "target": t, "params": dict(params)})
    return items
