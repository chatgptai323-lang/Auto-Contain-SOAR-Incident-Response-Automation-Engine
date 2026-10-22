import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from soar.api import make_server                      # noqa: E402
from soar.connectors import ConnectorError, SimulatedConnector, WebhookConnector, build_connectors  # noqa: E402
from soar.engine import Engine, EngineError           # noqa: E402
from soar.models import ValidationError, normalize_alert  # noqa: E402
from soar.scenarios import sample_config, scenarios   # noqa: E402


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_engine(**over):
    clock = Clock()
    cfg = sample_config(**over)
    eng = Engine(cfg, clock=clock)
    return eng, clock


def sim(eng, cap):
    return eng.connectors[cap]


def statuses(inc):
    return {(a["action"], a["target"]): a["status"] for a in inc["actions"]}


RANSOM = {"id": "r1", "type": "ransomware", "severity": "critical", "confidence": 0.95,
          "host": "WS-1", "user": "jdoe", "indicators": {"hashes": ["44d88612fea8a8f36de82e1278abb02f"]}}


class TestValidation(unittest.TestCase):
    def test_rejects_malicious_values(self):
        for bad in ({"host": "a/../b"}, {"host": "x; rm -rf /"}, {"user": "a b"}, {"ip": "1.2.3.4/24"},
                    {"id": "../../etc"}, {"severity": "banana"}):
            with self.assertRaises(ValidationError, msg=str(bad)):
                normalize_alert(bad)

    def test_bad_indicators_dropped_with_warning(self):
        a = normalize_alert({"type": "phishing", "indicators": {"domains": ["evil.com/path", "ok.example.org"],
                                                                "ips": ["999.1.1.1", "8.8.4.4"], "hashes": ["zz"]}})
        self.assertEqual(a["indicators"]["domains"], ["ok.example.org"])
        self.assertEqual(a["indicators"]["ips"], ["8.8.4.4"])
        self.assertEqual(len(a["warnings"]), 3)

    def test_normalisation(self):
        a = normalize_alert({"alert_type": "Malware-Beacon", "level": "HIGH", "confidence": 85, "hostname": "WS-9",
                             "src_ip": "203.0.113.9", "indicators": {"urls": ["http://Evil.Example.com/x?y=1"]}})
        self.assertEqual((a["type"], a["severity"], a["confidence"], a["host"]), ("malware_beacon", 7.0, 0.85, "ws-9"))
        self.assertEqual(a["indicators"]["ips"], ["203.0.113.9"])
        self.assertEqual(a["indicators"]["domains"], ["evil.example.com"])


class TestDecisions(unittest.TestCase):
    def test_ransomware_auto_contained(self):
        eng, _ = make_engine()
        inc = eng.ingest(RANSOM)
        st = statuses(inc)
        self.assertEqual(st[("isolate_host", "ws-1")], "executed")
        self.assertEqual(st[("disable_account", "jdoe")], "executed")
        self.assertIn(("isolate_host", "ws-1"), sim(eng, "edr").active)
        self.assertIn(("disable_account", "jdoe"), sim(eng, "idp").active)

    def test_protected_asset_never_touched_and_cannot_be_approved(self):
        eng, _ = make_engine()
        inc = eng.ingest(dict(RANSOM, id="r2", host="DC-01", user="jdoe"))
        self.assertEqual(statuses(inc)[("isolate_host", "dc-01")], "blocked")
        self.assertNotIn(("isolate_host", "dc-01"), sim(eng, "edr").active)

    def test_protected_ip_and_domain(self):
        eng, _ = make_engine()
        inc = eng.ingest({"id": "b1", "type": "malware_beacon", "severity": "critical", "confidence": 0.95,
                          "host": "ws-2", "indicators": {"ips": ["10.0.0.53", "127.0.0.1", "203.0.113.50"],
                                                         "domains": ["mail.corp.example.com", "evil-c2.example.net"]}})
        st = statuses(inc)
        self.assertEqual(st[("block_ip", "10.0.0.53")], "blocked")
        self.assertEqual(st[("block_ip", "127.0.0.1")], "blocked")
        self.assertEqual(st[("block_domain", "mail.corp.example.com")], "blocked")
        self.assertEqual(st[("block_ip", "203.0.113.50")], "executed")
        self.assertEqual(st[("block_domain", "evil-c2.example.net")], "executed")

    def test_privileged_account_needs_approval_then_approve(self):
        eng, _ = make_engine()
        inc = eng.ingest({"id": "c1", "type": "credential_compromise", "severity": "critical", "confidence": 0.95,
                          "user": "svc-backup"})
        row = [a for a in inc["actions"] if a["action"] == "revoke_sessions"][0]
        self.assertEqual(row["status"], "pending_approval")
        self.assertIn("privileged", row["reason"])
        self.assertNotIn(("revoke_sessions", "svc-backup"), sim(eng, "idp").active)
        done = eng.approve(row["id"], "alice")
        self.assertEqual(done["status"], "executed")
        self.assertEqual(done["approved_by"], "alice")
        with self.assertRaises(EngineError):
            eng.approve(row["id"], "alice")  # not pending any more

    def test_deny_and_low_risk_noop(self):
        eng, _ = make_engine()
        inc = eng.ingest({"id": "p1", "type": "phishing", "severity": "medium", "confidence": 0.6,
                          "user": "mlee", "email_id": "<m1@x.example.com>"})
        row = [a for a in inc["actions"] if a["action"] == "quarantine_email"][0]
        self.assertEqual(row["status"], "pending_approval")
        self.assertEqual(eng.deny(row["id"], "bob", "legit newsletter")["status"], "denied")
        noise = eng.ingest({"id": "n1", "type": "brute_force", "severity": "info", "confidence": 0.3,
                            "host": "ws-3", "src_ip": "198.51.100.7"})
        self.assertTrue(all(a["status"] == "skipped" for a in noise["actions"]))

    def test_unknown_type_only_notifies(self):
        eng, _ = make_engine()
        inc = eng.ingest({"id": "u1", "type": "weird", "severity": "high", "confidence": 0.9, "host": "ws-4"})
        self.assertEqual({a["action"] for a in inc["actions"]}, {"create_ticket", "notify"})

    def test_low_confidence_blocks_auto(self):
        eng, _ = make_engine()
        inc = eng.ingest(dict(RANSOM, id="lc", confidence=0.5, host="ws-5"))
        self.assertEqual(statuses(inc)[("isolate_host", "ws-5")], "pending_approval")


class TestSafetyRails(unittest.TestCase):
    def test_blast_radius_forces_approval(self):
        eng, _ = make_engine(blast_radius={"max_per_action": 2, "max_total": 50})
        res = []
        for i in range(4):
            inc = eng.ingest(dict(RANSOM, id=f"s{i}", host=f"ws-{i + 10}", user=None, indicators={}))
            res.append(statuses(inc)[("isolate_host", f"ws-{i + 10}")])
        self.assertEqual(res, ["executed", "executed", "pending_approval", "pending_approval"])
        row = [a for a in eng.list_actions("pending_approval") if a["action"] == "isolate_host"][0]
        self.assertIn("blast-radius", row["reason"])
        self.assertEqual(eng.approve(row["id"], "alice")["status"], "executed")  # humans may override the cap

    def test_idempotency_and_correlation(self):
        eng, _ = make_engine()
        a = eng.ingest(RANSOM)
        again = eng.ingest(RANSOM)                       # same alert id
        self.assertTrue(again["duplicate_alert"])
        self.assertEqual(len(again["actions"]), len(a["actions"]))
        second = eng.ingest(dict(RANSOM, id="r1b"))      # new alert, same host -> same incident, no duplicate actions
        self.assertEqual(second["id"], a["id"])
        self.assertEqual(second["alert_count"], 2)
        self.assertEqual(len(sim(eng, "edr").calls), 2)  # isolate + quarantine, executed once only

    def test_dry_run_executes_nothing_disruptive(self):
        eng, _ = make_engine(dry_run=True)
        inc = eng.ingest(RANSOM)
        self.assertEqual(statuses(inc)[("isolate_host", "ws-1")], "dry_run")
        self.assertEqual(sim(eng, "edr").calls, [])
        out = eng.rollback_action([a for a in inc["actions"] if a["action"] == "isolate_host"][0]["id"])
        self.assertEqual(out["status"], "rolled_back")

    def test_retry_then_fail(self):
        eng, _ = make_engine(retries=2)
        sim(eng, "edr").fail_next["isolate_host"] = 2     # succeeds on 3rd attempt
        self.assertEqual(statuses(eng.ingest(RANSOM))[("isolate_host", "ws-1")], "executed")
        sim(eng, "edr").fail_next["isolate_host"] = 99    # never succeeds
        inc = eng.ingest(dict(RANSOM, id="r9", host="ws-7", user=None, indicators={}))
        self.assertEqual(statuses(inc)[("isolate_host", "ws-7")], "failed")


class TestRollbackAndExpiry(unittest.TestCase):
    def test_incident_rollback(self):
        eng, _ = make_engine()
        inc = eng.ingest(RANSOM)
        out = eng.rollback_incident(inc["id"])
        self.assertEqual(len(out["rolled_back"]), 3)       # isolate, disable, quarantine
        self.assertEqual(len(out["irreversible"]), 1)      # revoke_sessions
        self.assertNotIn(("isolate_host", "ws-1"), sim(eng, "edr").active)
        self.assertEqual(eng.get_incident(inc["id"])["status"], "closed")

    def test_ttl_expiry_and_approval_timeout(self):
        eng, clock = make_engine(approval_ttl_seconds=600)
        inc = eng.ingest({"id": "t1", "type": "malware_beacon", "severity": "critical", "confidence": 0.95,
                          "host": "ws-8", "indicators": {"ips": ["203.0.113.50"]}})
        self.assertIn(("block_ip", "203.0.113.50"), sim(eng, "firewall").active)
        pend = eng.ingest({"id": "t2", "type": "phishing", "severity": "medium", "confidence": 0.6,
                           "user": "x1", "email_id": "<z@x.example.com>"})
        clock.t += 700
        out = eng.maintenance()
        self.assertEqual(out["approvals_expired"], 1)
        clock.t += 86400
        out = eng.maintenance()
        self.assertEqual(out["auto_rolled_back"], 1)
        self.assertNotIn(("block_ip", "203.0.113.50"), sim(eng, "firewall").active)
        self.assertEqual(statuses(eng.get_incident(inc["id"]))[("block_ip", "203.0.113.50")], "rolled_back")
        self.assertEqual(statuses(eng.get_incident(pend["id"]))[("quarantine_email", "<z@x.example.com>")], "expired")


class TestAudit(unittest.TestCase):
    def test_chain_valid_and_tamper_detected(self):
        eng, _ = make_engine()
        eng.ingest(RANSOM)
        v = eng.store.verify_audit()
        self.assertTrue(v["ok"])
        self.assertGreater(v["entries"], 5)
        eng.store.conn.execute("UPDATE audit SET actor='mallory' WHERE seq=3")
        v = eng.store.verify_audit()
        self.assertFalse(v["ok"])
        self.assertEqual(v["first_bad_seq"], 3)


class _Capture(BaseHTTPRequestHandler):
    log = []

    def _h(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        _Capture.log.append((self.command, self.path, self.headers.get("Authorization"), body))
        if self.path.startswith("/fail"):
            self.send_response(500)
        elif self.path.startswith("/redir"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/")
        else:
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    do_POST = do_GET = do_DELETE = _h

    def log_message(self, *a):
        pass


class TestWebhookConnector(unittest.TestCase):
    def setUp(self):
        _Capture.log = []
        self.srv = HTTPServer(("127.0.0.1", 0), _Capture)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_routes_templating_auth_and_errors(self):
        os.environ["TEST_TOKEN"] = "s3cret"
        c = WebhookConnector("edr", {
            "base_url": self.base, "allow_insecure_http": True, "token_env": "TEST_TOKEN",
            "routes": {"isolate_host": {"method": "POST", "path": "/hosts/{target}/isolate", "body": {"by": "{user}"}},
                       "block_ip": {"method": "DELETE", "path": "/fail/{target}"},
                       "notify": {"method": "POST", "path": "/redir"}}})
        res = c.execute("isolate_host", "ws-1/../x", {"user": "jdoe"})
        self.assertEqual(res["status"], 200)
        method, path, auth, body = _Capture.log[0]
        self.assertEqual((method, path, auth), ("POST", "/hosts/ws-1%2F..%2Fx/isolate", "Bearer s3cret"))
        self.assertEqual(json.loads(body), {"by": "jdoe"})
        with self.assertRaises(ConnectorError):
            c.execute("block_ip", "1.2.3.4", {})
        with self.assertRaises(ConnectorError):
            c.execute("notify", "x", {})                       # redirect is not followed
        with self.assertRaises(ConnectorError):
            c.execute("unknown_action", "x", {})

    def test_https_required_by_default(self):
        with self.assertRaises(ValueError):
            WebhookConnector("edr", {"base_url": "http://insecure.example.com"})

    def test_engine_with_webhook_connector(self):
        cfg = sample_config(connectors={"edr": {"type": "webhook", "base_url": self.base, "allow_insecure_http": True,
                                                "routes": {"isolate_host": {"path": "/hosts/{target}/isolate"},
                                                           "unisolate_host": {"path": "/hosts/{target}/release"},
                                                           "quarantine_file": {"path": "/q/{target}"}}}})
        eng = Engine(cfg, connectors=build_connectors(cfg["connectors"]), clock=Clock())
        inc = eng.ingest(RANSOM)
        self.assertEqual(statuses(inc)[("isolate_host", "ws-1")], "executed")
        eng.rollback_incident(inc["id"])
        paths = [p for _, p, _, _ in _Capture.log]
        self.assertIn("/hosts/ws-1/isolate", paths)
        self.assertIn("/hosts/ws-1/release", paths)


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.eng, _ = make_engine()
        cls.srv = make_server(cls.eng, "127.0.0.1", 0, {"admin": "adm-key", "ingest": "ing-key"})
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def call(self, method, path, body=None, key=None):
        headers = {"Content-Type": "application/json"}
        if key:
            headers["X-API-Key"] = key
        req = urllib.request.Request(self.base + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_auth_and_roles(self):
        self.assertEqual(self.call("GET", "/health")[0], 200)
        self.assertEqual(self.call("POST", "/api/alerts", RANSOM)[0], 401)
        self.assertEqual(self.call("POST", "/api/alerts", RANSOM, "wrong")[0], 401)
        self.assertEqual(self.call("GET", "/api/incidents", key="ing-key")[0], 403)

    def test_full_workflow(self):
        code, inc = self.call("POST", "/api/alerts", {"id": "api-1", "type": "credential_compromise",
                                                      "severity": "critical", "confidence": 0.95, "user": "svc-api"}, "ing-key")
        self.assertEqual(code, 201)
        code, pend = self.call("GET", "/api/actions?status=pending_approval", key="adm-key")
        row = [a for a in pend if a["target"] == "svc-api" and a["action"] == "revoke_sessions"][0]
        code, done = self.call("POST", f"/api/actions/{row['id']}/approve", {"actor": "carol"}, "adm-key")
        self.assertEqual((code, done["status"], done["approved_by"]), (200, "executed", "carol"))
        self.assertEqual(self.call("POST", f"/api/actions/{row['id']}/approve", {}, "adm-key")[0], 409)
        self.assertEqual(self.call("GET", f"/api/incidents/{inc['id']}", key="adm-key")[0], 200)
        self.assertEqual(self.call("GET", "/api/incidents/INC-NOPE", key="adm-key")[0], 404)
        code, v = self.call("GET", "/api/audit/verify", key="adm-key")
        self.assertTrue(v["ok"])
        self.assertEqual(self.call("POST", "/api/alerts", {"host": "bad host!"}, "ing-key")[0], 400)
        code, dup = self.call("POST", "/api/alerts", {"id": "api-1", "type": "credential_compromise",
                                                      "user": "svc-api"}, "ing-key")
        self.assertEqual((code, dup["duplicate_alert"]), (200, True))

    def test_scenarios_all_ingest(self):
        for name, _, alert in scenarios():
            code, _ = self.call("POST", "/api/alerts", dict(alert, id="api-" + alert["id"]), "adm-key")
            self.assertEqual(code, 201, name)
        self.assertGreater(self.call("GET", "/api/stats", key="adm-key")[1]["incidents"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
