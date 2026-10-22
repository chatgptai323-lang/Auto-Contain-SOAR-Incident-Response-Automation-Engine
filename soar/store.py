"""SQLite persistence plus a hash-chained, tamper-evident audit log."""
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents(
  id TEXT PRIMARY KEY, entity_key TEXT, title TEXT, type TEXT, status TEXT, risk INTEGER,
  risk_detail TEXT, alert_count INTEGER, created REAL, updated REAL);
CREATE INDEX IF NOT EXISTS ix_inc_entity ON incidents(entity_key, status, updated);
CREATE TABLE IF NOT EXISTS alerts(
  id TEXT PRIMARY KEY, incident_id TEXT, source TEXT, type TEXT, normalized TEXT, raw TEXT, received REAL);
CREATE TABLE IF NOT EXISTS actions(
  id TEXT PRIMARY KEY, incident_id TEXT, action TEXT, kind TEXT, target TEXT, status TEXT, reason TEXT,
  params TEXT, result TEXT, risk INTEGER, approved_by TEXT, created REAL, updated REAL,
  executed_at REAL, expires_at REAL);
CREATE INDEX IF NOT EXISTS ix_act_status ON actions(status, created);
CREATE INDEX IF NOT EXISTS ix_act_target ON actions(action, target);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, event TEXT, ref TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT);
"""

INCIDENT_COLS = {"title", "risk", "risk_detail", "alert_count", "status", "updated"}
ACTION_COLS = {"status", "reason", "params", "result", "approved_by", "executed_at", "expires_at", "updated"}
JSON_COLS = {"params", "result", "risk_detail", "normalized", "raw"}
ACTIVE_STATUSES = ("pending_approval", "approved", "executed", "dry_run")


def _row(r):
    if r is None:
        return None
    d = dict(r)
    for c in JSON_COLS:
        if c in d:
            d[c] = json.loads(d[c]) if d[c] else {}
    return d


class Store:
    def __init__(self, path=":memory:", clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        if path != ":memory:":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    # ---- low level -------------------------------------------------------
    def _all(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def _one(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def _run(self, sql, args=()):
        with self.lock:
            self.conn.execute(sql, args)

    def _update(self, table, rid, fields, allowed):
        sets, args = [], []
        for k, v in fields.items():
            if k not in allowed:
                raise KeyError(k)
            sets.append(f"{k}=?")
            args.append(json.dumps(v, default=str) if k in JSON_COLS else v)
        if "updated" in allowed and "updated" not in fields:
            sets.append("updated=?")
            args.append(self.clock())
        args.append(rid)
        self._run(f"UPDATE {table} SET {', '.join(sets)} WHERE id=?", args)

    # ---- incidents -------------------------------------------------------
    def create_incident(self, key, title, itype, risk, detail, count, now):
        iid = "INC-" + uuid.uuid4().hex[:8].upper()
        self._run("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (iid, key, title, itype, "open", risk, json.dumps(detail), count, now, now))
        return iid

    def update_incident(self, iid, **f):
        self._update("incidents", iid, f, INCIDENT_COLS)

    def get_incident(self, iid):
        return _row(self._one("SELECT * FROM incidents WHERE id=?", (iid,)))

    def list_incidents(self, status=None, limit=50):
        if status:
            rows = self._all("SELECT * FROM incidents WHERE status=? ORDER BY created DESC LIMIT ?", (status, limit))
        else:
            rows = self._all("SELECT * FROM incidents ORDER BY created DESC LIMIT ?", (limit,))
        return [_row(r) for r in rows]

    def find_open_incident(self, key, since):
        return _row(self._one("SELECT * FROM incidents WHERE entity_key=? AND status='open' AND updated>=? "
                              "ORDER BY updated DESC LIMIT 1", (key, since)))

    # ---- alerts ----------------------------------------------------------
    def add_alert(self, alert, raw, incident_id, now):
        self._run("INSERT INTO alerts VALUES(?,?,?,?,?,?,?)",
                  (alert["id"], incident_id, alert["source"], alert["type"],
                   json.dumps(alert), json.dumps(raw, default=str)[:200000], now))

    def get_alert(self, aid):
        return _row(self._one("SELECT * FROM alerts WHERE id=?", (aid,)))

    def alerts_for(self, incident_id):
        return [_row(r) for r in self._all("SELECT * FROM alerts WHERE incident_id=? ORDER BY received", (incident_id,))]

    # ---- actions ---------------------------------------------------------
    def add_action(self, incident_id, action, kind, target, status, reason, params, risk, now):
        aid = "act-" + uuid.uuid4().hex[:12]
        self._run("INSERT INTO actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (aid, incident_id, action, kind, target, status, reason, json.dumps(params, default=str),
                   "{}", risk, None, now, now, None, None))
        return aid

    def update_action(self, aid, **f):
        self._update("actions", aid, f, ACTION_COLS)

    def get_action(self, aid):
        return _row(self._one("SELECT * FROM actions WHERE id=?", (aid,)))

    def list_actions(self, status=None, incident_id=None, limit=500):
        sql, args = "SELECT * FROM actions WHERE 1=1", []
        if status:
            sql += " AND status=?"
            args.append(status)
        if incident_id:
            sql += " AND incident_id=?"
            args.append(incident_id)
        sql += " ORDER BY created, rowid LIMIT ?"
        args.append(limit)
        return [_row(r) for r in self._all(sql, args)]

    def find_active_action(self, action, target):
        q = ",".join("?" * len(ACTIVE_STATUSES))
        return _row(self._one(f"SELECT * FROM actions WHERE action=? AND target=? AND status IN ({q}) LIMIT 1",
                              (action, target) + ACTIVE_STATUSES))

    def count_actions_since(self, since, actions):
        if not actions:
            return 0
        q = ",".join("?" * len(actions))
        row = self._one(f"SELECT COUNT(*) AS n FROM actions WHERE status IN ('executed','dry_run') "
                        f"AND executed_at>=? AND action IN ({q})", (since,) + tuple(actions))
        return row["n"]

    def due_expiries(self, now):
        return [_row(r) for r in self._all("SELECT * FROM actions WHERE status='executed' "
                                           "AND expires_at IS NOT NULL AND expires_at<=?", (now,))]

    def action_counts(self):
        return {r["status"]: r["n"] for r in self._all("SELECT status, COUNT(*) AS n FROM actions GROUP BY status")}

    # ---- audit chain -----------------------------------------------------
    @staticmethod
    def _hash(prev, ts, actor, event, ref, detail):
        return hashlib.sha256(f"{prev}|{ts!r}|{actor}|{event}|{ref}|{detail}".encode()).hexdigest()

    def audit(self, actor, event, ref="", detail=None):
        with self.lock:
            last = self.conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            ts = float(self.clock())
            d = json.dumps(detail or {}, sort_keys=True, default=str)
            h = self._hash(prev, ts, actor, event, ref, d)
            self.conn.execute("INSERT INTO audit(ts,actor,event,ref,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
                              (ts, actor, event, ref, d, prev, h))

    def list_audit(self, limit=100):
        rows = self._all("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"])
            out.append(d)
        return out

    def verify_audit(self):
        prev, n = GENESIS, 0
        for r in self._all("SELECT * FROM audit ORDER BY seq"):
            expect = self._hash(prev, float(r["ts"]), r["actor"], r["event"], r["ref"], r["detail"])
            if r["prev_hash"] != prev or r["hash"] != expect:
                return {"ok": False, "entries": n, "first_bad_seq": r["seq"]}
            prev, n = r["hash"], n + 1
        return {"ok": True, "entries": n, "first_bad_seq": None}
