"""Risk scoring and the containment decision policy (the safety brain).

Decision modes:
  auto     - execute now
  approval - queue for a human
  monitor  - record only, do nothing
  deny     - never allowed (protected target)
"""
import fnmatch
import ipaddress
from collections import namedtuple

from .playbooks import ACTIONS

Decision = namedtuple("Decision", "mode reason")

BUILTIN_PROTECTED_CIDRS = ["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8", "::1/128", "ff00::/8"]
TYPE_BONUS = {"ransomware": 10, "malware_beacon": 5, "credential_compromise": 5}


def risk_score(alert, enrichment, alert_count):
    """0-100 score: severity (55) + confidence (25) + threat intel (30) + type + correlation (10)."""
    parts = {
        "severity": round(alert["severity"] / 10 * 55, 1),
        "confidence": round(alert["confidence"] * 25, 1),
        "threat_intel": min(30, 15 * len(enrichment["intel_hits"])),
        "type_bonus": TYPE_BONUS.get(alert["type"], 0),
        "correlation": min(10, 5 * max(0, alert_count - 1)),
    }
    return int(round(min(100, sum(parts.values())))), parts


class Policy:
    def __init__(self, cfg, store, enricher, clock):
        self.cfg, self.store, self.enricher, self.clock = cfg, store, enricher, clock
        cidrs = BUILTIN_PROTECTED_CIDRS + list(cfg["protected"].get("ips", []))
        self.cidrs = [ipaddress.ip_network(c, strict=False) for c in cidrs]
        self.disruptive = [a for a, s in ACTIONS.items() if s["disruptive"]]

    @staticmethod
    def _glob(patterns, value):
        return any(fnmatch.fnmatch(value, p.lower()) for p in patterns)

    def protected_reason(self, kind, target):
        p = self.cfg["protected"]
        if kind == "host":
            if self._glob(p.get("hosts", []), target) or self.enricher.asset(target).get("protected"):
                return f"protected host: {target}"
        elif kind == "user":
            if self._glob(p.get("users", []), target) or self.enricher.user(target).get("protected"):
                return f"protected account: {target}"
        elif kind == "ip":
            ip = ipaddress.ip_address(target)
            if any(ip in net for net in self.cidrs if net.version == ip.version):
                return f"protected address: {target}"
        elif kind == "domain":
            for pat in p.get("domains", []):
                pat = pat.lower()
                if fnmatch.fnmatch(target, pat) or target == pat or target.endswith("." + pat):
                    return f"protected domain: {target}"
        return None

    def sensitive_reason(self, kind, target):
        s = self.cfg["sensitive"]
        if kind == "host":
            if self._glob(s.get("hosts", []), target) or self.enricher.asset(target).get("criticality") == "critical":
                return f"critical asset requires human approval: {target}"
        elif kind == "user":
            if self._glob(s.get("users", []), target) or self.enricher.user(target).get("privileged") \
                    or self.enricher.user(target).get("vip"):
                return f"privileged/VIP account requires human approval: {target}"
        return None

    def blast_reason(self, action):
        br = self.cfg["blast_radius"]
        since = self.clock() - br["window_seconds"]
        total = self.store.count_actions_since(since, self.disruptive)
        if total >= br["max_total"]:
            return f"blast-radius limit: {total} disruptive actions in window (max {br['max_total']})"
        per = self.store.count_actions_since(since, [action])
        if per >= br["max_per_action"]:
            return f"blast-radius limit: {per} x {action} in window (max {br['max_per_action']})"
        return None

    def thresholds(self, action, step):
        t = self.cfg["thresholds"]
        th = t["actions"].get(action, t["default"])
        auto = step.get("min_risk", th["auto"])
        return min(th["approval"], auto), auto

    def decide(self, action, kind, target, risk, confidence, step):
        t = self.cfg["thresholds"]
        if not ACTIONS[action]["disruptive"]:
            if risk >= t["monitor"]:
                return Decision("auto", "non-disruptive")
            return Decision("monitor", f"risk {risk} below monitor threshold {t['monitor']}")
        why = self.protected_reason(kind, target)
        if why:
            return Decision("deny", why)
        approval, auto = self.thresholds(action, step)
        if risk >= auto and confidence >= t["min_confidence_auto"]:
            why = self.sensitive_reason(kind, target) or self.blast_reason(action)
            if why:
                return Decision("approval", why)
            return Decision("auto", f"risk {risk} >= auto threshold {auto}")
        if risk >= approval:
            return Decision("approval", f"risk {risk} / confidence {confidence:.2f} below auto bar "
                                        f"({auto} / {t['min_confidence_auto']})")
        return Decision("monitor", f"risk {risk} below approval threshold {approval}")
