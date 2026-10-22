"""Orchestrator: ingest -> normalise -> enrich -> correlate -> score -> playbook -> decide -> act."""
import logging
import threading
import time

from .connectors import build_connectors
from .enrich import Enricher
from .models import normalize_alert
from .playbooks import ACTIONS, DEFAULT_PLAYBOOKS, resolve_steps, validate_playbooks
from .policy import Policy, risk_score
from .store import Store

log = logging.getLogger("soar.engine")

TIME_FIELDS = ("created", "updated", "executed_at", "expires_at", "received")
STATUS_FOR_MODE = {"auto": "approved", "approval": "pending_approval", "deny": "blocked", "monitor": "skipped"}


class EngineError(Exception):
    pass


class NotFound(EngineError):
    pass


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _pub(d):
    out = dict(d)
    for f in TIME_FIELDS:
        if out.get(f) is not None:
            out[f] = _iso(out[f])
    return out


def _entity_key(alert):
    if alert["host"]:
        return f"host:{alert['host']}"
    if alert["user"]:
        return f"user:{alert['user']}"
    if alert["indicators"]["ips"]:
        return f"ip:{alert['indicators']['ips'][0]}"
    return f"alert:{alert['id']}"


class Engine:
    def __init__(self, cfg, store=None, connectors=None, clock=time.time):
        self.cfg = cfg
        self.clock = clock
        self.store = store or Store(cfg["db_path"], clock)
        self.connectors = connectors if connectors is not None else build_connectors(cfg["connectors"])
        self.enricher = Enricher(cfg)
        self.policy = Policy(cfg, self.store, self.enricher, clock)
        validate_playbooks(cfg["playbooks"])
        self.playbooks = {**DEFAULT_PLAYBOOKS, **cfg["playbooks"]}
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ ingest
    def ingest(self, raw, actor="ingest"):
        alert = normalize_alert(raw, self.clock())
        with self.lock:
            dup = self.store.get_alert(alert["id"])
            if dup:
                out = self.get_incident(dup["incident_id"])
                out["duplicate_alert"] = True
                return out
            now = self.clock()
            enrichment = self.enricher.enrich(alert)
            inc = self.store.find_open_incident(_entity_key(alert), now - self.cfg["correlation_window_seconds"])
            count = inc["alert_count"] + 1 if inc else 1
            risk, detail = risk_score(alert, enrichment, count)
            detail["intel_hits"] = enrichment["intel_hits"]
            if inc:
                risk = max(risk, inc["risk"])
                inc_id = inc["id"]
                self.store.update_incident(inc_id, risk=risk, risk_detail=detail, alert_count=count, updated=now)
            else:
                title = alert["title"]
                inc_id = self.store.create_incident(_entity_key(alert), title, alert["type"], risk, detail, count, now)
            self.store.add_alert(alert, raw, inc_id, now)
            self.store.audit(actor, "alert_received", inc_id,
                             {"alert_id": alert["id"], "type": alert["type"], "risk": risk, "intel": len(enrichment["intel_hits"])})

            playbook = self.playbooks.get(alert["type"], self.playbooks["unknown"])
            ctx = dict(alert, incident_id=inc_id)
            pending = []
            for item in resolve_steps(playbook, ctx):
                row = self._handle_step(inc_id, item, alert, risk)
                if row and row["status"] == "pending_approval":
                    pending.append(f"{row['action']}:{row['target']}")
            if pending:
                self._notify_raw(f"[SOAR] {inc_id}: {len(pending)} action(s) awaiting approval -> " + ", ".join(pending))
            return self.get_incident(inc_id)

    def _handle_step(self, inc_id, item, alert, risk):
        step, kind, target = item["step"], item["kind"], item["target"]
        action = step["action"]
        if self.store.find_active_action(action, target):
            self.store.audit("engine", "duplicate_skipped", inc_id, {"action": action, "target": target})
            return None
        decision = self.policy.decide(action, kind, target, risk, alert["confidence"], step)
        params = dict(item["params"], incident_id=inc_id, risk=risk)
        if action in ("notify", "create_ticket"):
            params["title"] = alert["title"]
            params["message"] = (f"[SOAR] {inc_id} {alert['type']} risk={risk} host={alert['host'] or '-'} "
                                 f"user={alert['user'] or '-'} :: {alert['title']}")
        aid = self.store.add_action(inc_id, action, kind, target, STATUS_FOR_MODE[decision.mode],
                                    decision.reason, params, risk, self.clock())
        self.store.audit("engine", f"decision_{decision.mode}", aid,
                         {"action": action, "target": target, "risk": risk, "reason": decision.reason})
        if decision.mode == "auto":
            return self._execute(self.store.get_action(aid), "auto")
        return self.store.get_action(aid)

    # ----------------------------------------------------------------- execute
    def _call(self, conn, action, target, params):
        if conn is None:
            raise EngineError("no connector configured for this action")
        attempts = int(self.cfg["retries"]) + 1
        for i in range(attempts):
            try:
                return conn.execute(action, target, params)
            except Exception as e:  # noqa: BLE001 - connector boundary
                if i == attempts - 1:
                    raise
                log.warning("connector call %s failed (%s); retrying", action, e)
                time.sleep(float(self.cfg["retry_backoff_seconds"]) * (2 ** i))

    def _execute(self, row, actor):
        spec = ACTIONS[row["action"]]
        now = self.clock()
        ttl = row["params"].get("ttl")
        expires = now + ttl if ttl else None
        if self.cfg["dry_run"] and spec["disruptive"]:
            self.store.update_action(row["id"], status="dry_run", result={"dry_run": True},
                                     executed_at=now, expires_at=expires)
            self.store.audit(actor, "action_dry_run", row["id"], {"action": row["action"], "target": row["target"]})
            return self.store.get_action(row["id"])
        try:
            result = self._call(self.connectors.get(spec["cap"]), row["action"], row["target"], row["params"])
        except Exception as e:  # noqa: BLE001
            self.store.update_action(row["id"], status="failed", result={"error": str(e)}, executed_at=now)
            self.store.audit(actor, "action_failed", row["id"], {"action": row["action"], "error": str(e)})
            log.error("action %s failed: %s", row["id"], e)
        else:
            self.store.update_action(row["id"], status="executed", result=result, executed_at=now, expires_at=expires)
            self.store.audit(actor, "action_executed", row["id"], {"action": row["action"], "target": row["target"]})
        return self.store.get_action(row["id"])

    def _notify_raw(self, message):
        conn = self.connectors.get("notify")
        if conn is None:
            return
        try:
            conn.execute("notify", "soar", {"message": message})
        except Exception as e:  # noqa: BLE001
            log.warning("notification failed: %s", e)

    # --------------------------------------------------------------- approvals
    def approve(self, action_id, actor="admin"):
        with self.lock:
            row = self.store.get_action(action_id)
            if not row:
                raise NotFound(f"no such action: {action_id}")
            if row["status"] != "pending_approval":
                raise EngineError(f"action is {row['status']}, not pending_approval")
            why = self.policy.protected_reason(row["kind"], row["target"])
            if why:
                self.store.update_action(action_id, status="blocked", reason=why)
                self.store.audit(actor, "approval_refused", action_id, {"reason": why})
                raise EngineError(f"cannot approve: {why}")
            self.store.update_action(action_id, status="approved", approved_by=actor)
            self.store.audit(actor, "action_approved", action_id, {"action": row["action"], "target": row["target"]})
            return _pub(self._execute(self.store.get_action(action_id), actor))

    def deny(self, action_id, actor="admin", reason=""):
        with self.lock:
            row = self.store.get_action(action_id)
            if not row:
                raise NotFound(f"no such action: {action_id}")
            if row["status"] != "pending_approval":
                raise EngineError(f"action is {row['status']}, not pending_approval")
            self.store.update_action(action_id, status="denied", reason=(reason or "denied by analyst")[:300],
                                     approved_by=actor)
            self.store.audit(actor, "action_denied", action_id, {"reason": reason})
            return _pub(self.store.get_action(action_id))

    # ---------------------------------------------------------------- rollback
    def rollback_action(self, action_id, actor="admin"):
        with self.lock:
            row = self.store.get_action(action_id)
            if not row:
                raise NotFound(f"no such action: {action_id}")
            if row["status"] not in ("executed", "dry_run"):
                raise EngineError(f"cannot roll back an action in status {row['status']}")
            spec = ACTIONS[row["action"]]
            if not spec["inverse"]:
                raise EngineError(f"{row['action']} is not reversible")
            if row["status"] == "dry_run":
                result = {"dry_run": True}
            else:
                try:
                    result = self._call(self.connectors.get(spec["cap"]), spec["inverse"], row["target"], row["params"])
                except Exception as e:  # noqa: BLE001
                    self.store.audit(actor, "rollback_failed", action_id, {"error": str(e)})
                    raise EngineError(f"rollback failed: {e}") from e
            merged = dict(row["result"])
            merged["rollback"] = result
            self.store.update_action(action_id, status="rolled_back", result=merged)
            self.store.audit(actor, "action_rolled_back", action_id, {"action": row["action"], "target": row["target"]})
            return _pub(self.store.get_action(action_id))

    def rollback_incident(self, incident_id, actor="admin"):
        """Undo every reversible containment action of an incident, then close it."""
        with self.lock:
            if not self.store.get_incident(incident_id):
                raise NotFound(f"no such incident: {incident_id}")
            rows = [r for r in self.store.list_actions(incident_id=incident_id) if r["status"] in ("executed", "dry_run")]
            out = {"rolled_back": [], "failed": [], "irreversible": []}
            for r in reversed(rows):
                spec = ACTIONS[r["action"]]
                if not spec["disruptive"]:
                    continue
                if not spec["inverse"]:
                    out["irreversible"].append(r["id"])
                    continue
                try:
                    self.rollback_action(r["id"], actor)
                    out["rolled_back"].append(r["id"])
                except EngineError as e:
                    out["failed"].append({"id": r["id"], "error": str(e)})
            if not out["failed"]:
                self.store.update_incident(incident_id, status="closed")
            self.store.audit(actor, "incident_rolled_back", incident_id, out)
            return out

    def close_incident(self, incident_id, actor="admin"):
        with self.lock:
            if not self.store.get_incident(incident_id):
                raise NotFound(f"no such incident: {incident_id}")
            self.store.update_incident(incident_id, status="closed")
            self.store.audit(actor, "incident_closed", incident_id)
            return self.get_incident(incident_id)

    # ------------------------------------------------------------- maintenance
    def maintenance(self):
        """Expire stale approval requests and auto-roll-back TTL'd containment."""
        with self.lock:
            now = self.clock()
            expired = rolled = 0
            for row in self.store.list_actions(status="pending_approval"):
                if now - row["created"] >= self.cfg["approval_ttl_seconds"]:
                    self.store.update_action(row["id"], status="expired", reason=f"{row['reason']} | approval timed out")
                    self.store.audit("maintenance", "approval_expired", row["id"])
                    expired += 1
            for row in self.store.due_expiries(now):
                try:
                    self.rollback_action(row["id"], "auto-expiry")
                    rolled += 1
                except EngineError as e:
                    log.error("auto-expiry rollback failed for %s: %s", row["id"], e)
            return {"approvals_expired": expired, "auto_rolled_back": rolled}

    # ------------------------------------------------------------------- views
    def get_incident(self, incident_id):
        inc = self.store.get_incident(incident_id)
        if not inc:
            raise NotFound(f"no such incident: {incident_id}")
        out = _pub(inc)
        out["alerts"] = [_pub(a) | {"raw": None} for a in self.store.alerts_for(incident_id)]
        out["actions"] = [_pub(a) for a in self.store.list_actions(incident_id=incident_id)]
        return out

    def list_incidents(self, status=None, limit=50):
        return [_pub(i) for i in self.store.list_incidents(status, limit)]

    def list_actions(self, status=None, limit=200):
        return [_pub(a) for a in self.store.list_actions(status=status, limit=limit)]

    def stats(self):
        incs = self.store.list_incidents(limit=100000)
        return {"incidents": len(incs), "open_incidents": sum(1 for i in incs if i["status"] == "open"),
                "actions_by_status": self.store.action_counts(), "dry_run": self.cfg["dry_run"]}
