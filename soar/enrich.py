"""Enrichment: threat-intel matching plus asset / identity inventory lookups."""
import fnmatch
import json


class Enricher:
    def __init__(self, cfg):
        self.intel = {"ips": set(), "domains": set(), "hashes": set()}
        sources = [cfg.get("threat_intel") or {}]
        if cfg.get("threat_intel_file"):
            with open(cfg["threat_intel_file"], "r", encoding="utf-8") as f:
                sources.append(json.load(f))
        for s in sources:
            self.intel["ips"].update(str(x).strip() for x in s.get("ips", []))
            self.intel["domains"].update(str(x).strip().lower().rstrip(".") for x in s.get("domains", []))
            self.intel["hashes"].update(str(x).strip().lower() for x in s.get("hashes", []))
        inv = cfg.get("inventory", {})
        self.assets = {k.lower(): v for k, v in inv.get("assets", {}).items()}
        self.users = {k.lower(): v for k, v in inv.get("users", {}).items()}

    @staticmethod
    def _lookup(table, key):
        if not key:
            return {}
        key = key.lower()
        if key in table:
            return table[key]
        for pattern, val in table.items():
            if fnmatch.fnmatch(key, pattern):
                return val
        return {}

    def asset(self, host):
        return self._lookup(self.assets, host)

    def user(self, user):
        return self._lookup(self.users, user)

    def enrich(self, alert):
        hits = []
        ind = alert["indicators"]
        for ip in ind["ips"]:
            if ip in self.intel["ips"]:
                hits.append({"type": "ip", "value": ip})
        for d in ind["domains"]:
            if any(d == bad or d.endswith("." + bad) for bad in self.intel["domains"]):
                hits.append({"type": "domain", "value": d})
        for h in ind["hashes"]:
            if h in self.intel["hashes"]:
                hits.append({"type": "hash", "value": h})
        return {"intel_hits": hits,
                "asset": self.asset(alert.get("host")),
                "user": self.user(alert.get("user"))}
