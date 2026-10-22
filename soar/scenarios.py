"""Sample environment + attack scenarios used by `simulate`, `send` and the tests."""
from .config import build_config


def sample_config(**overrides):
    base = {
        "db_path": ":memory:",
        "retry_backoff_seconds": 0,
        "inventory": {
            "assets": {"dc-*": {"criticality": "critical", "protected": True},
                       "filesrv-*": {"criticality": "critical"}},
            "users": {"administrator": {"privileged": True},
                      "breakglass*": {"protected": True},
                      "svc-*": {"privileged": True}},
        },
        "protected": {"ips": ["10.0.0.53/32"], "domains": ["corp.example.com"]},
        "threat_intel": {"ips": ["203.0.113.50"], "domains": ["evil-c2.example.net"],
                         "hashes": ["44d88612fea8a8f36de82e1278abb02f"]},
        "blast_radius": {"window_seconds": 3600, "max_per_action": 4, "max_total": 12},
    }
    from .config import deep_merge
    cfg = build_config(deep_merge(base, overrides))
    if "db_path" not in overrides:
        cfg["db_path"] = ":memory:"      # never let SOAR_DB_PATH leak into demos/tests
    return cfg


def scenarios():
    """(name, expectation, alert)"""
    s = [
        ("Ransomware on a workstation (known-bad hash)",
         "high risk -> isolate host, disable account, quarantine file AUTOMATICALLY",
         {"id": "a-001", "source": "edr", "type": "ransomware", "severity": "critical", "confidence": 0.95,
          "title": "Mass file encryption detected", "host": "WS-0142", "user": "jdoe",
          "indicators": {"hashes": ["44d88612fea8a8f36de82e1278abb02f"]}}),
        ("C2 beaconing to known-bad IP + domain",
         "block IP/domain and isolate host AUTOMATICALLY (IP/domain auto-expire via TTL)",
         {"id": "a-002", "source": "ndr", "type": "malware_beacon", "severity": "high", "confidence": 0.85,
          "title": "Periodic beaconing to C2", "host": "WS-0201", "user": "asmith",
          "indicators": {"ips": ["203.0.113.50"], "domains": ["evil-c2.example.net"]}}),
        ("Ransomware on a DOMAIN CONTROLLER",
         "isolation is BLOCKED (protected asset); privileged account actions need APPROVAL",
         {"id": "a-003", "source": "edr", "type": "ransomware", "severity": "critical", "confidence": 0.9,
          "title": "Encryption activity on DC", "host": "DC-01", "user": "administrator"}),
        ("Phishing, medium confidence, user clicked",
         "email quarantine goes to APPROVAL; weaker actions only MONITORED",
         {"id": "a-004", "source": "mail", "type": "phishing", "severity": "medium", "confidence": 0.6,
          "title": "Credential-harvest link delivered", "user": "mlee", "email_id": "<msg-8841@mail.example.com>",
          "indicators": {"urls": ["http://login-portal.phish-example.org/verify"]},
          "details": {"user_clicked": True}}),
        ("Credential compromise of a privileged service account",
         "privileged account -> APPROVAL required even though risk is high",
         {"id": "a-005", "source": "idp", "type": "credential_compromise", "severity": "critical", "confidence": 0.95,
          "title": "Impossible travel for svc-backup", "user": "svc-backup"}),
        ("Low-severity noise",
         "below monitor threshold -> NOTHING happens",
         {"id": "a-006", "source": "siem", "type": "brute_force", "severity": "info", "confidence": 0.3,
          "title": "Single failed login burst", "host": "WS-0300", "src_ip": "198.51.100.7"}),
    ]
    for i in range(4):
        s.append((f"Beacon storm host {i + 1}/4 (blast-radius guard)",
                  "first few auto-isolate, then the blast-radius limit forces APPROVAL",
                  {"id": f"storm-{i}", "source": "ndr", "type": "malware_beacon", "severity": "critical",
                   "confidence": 0.9, "title": "Beaconing to C2", "host": f"WS-09{i}0",
                   "indicators": {"ips": ["203.0.113.50"]}}))
    return s
