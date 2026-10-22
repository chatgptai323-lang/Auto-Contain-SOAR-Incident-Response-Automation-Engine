# Auto-Contain SOAR - Incident Response Automation Engine

Zero-dependency (Python 3.9+ stdlib only) SOAR that ingests security alerts, scores risk, and
**automatically contains threats - with guardrails** - or routes the action to a human.

```
alert -> normalise/validate -> enrich -> correlate -> risk score -> playbook
      -> policy decision (auto | approval | monitor | deny) -> connector action -> audit log
```

## Quick start

```bash
python3 -m unittest discover -s tests -v      # 23 tests
python3 -m soar simulate                      # scripted attack scenarios, simulated connectors
python3 -m soar serve --demo                  # API server, sample environment, simulated connectors
python3 -m soar send --key <ingest key printed at startup>    # fire the sample alerts at it
```

Production-style run (real config, keys from env, file DB):

```bash
export SOAR_ADMIN_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')
export SOAR_INGEST_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')
cp config.example.json config.json            # edit protected assets, connectors, thresholds
python3 -m soar serve --config config.json --dry-run     # START IN DRY-RUN, review, then remove the flag
```
If no API keys are configured, random ones are generated and printed at startup.

## Safety model (why it is safe to automate)

| Guardrail | Behaviour |
|---|---|
| **Protected targets** | Hosts/users/IPs/domains in `protected` (or inventory `protected: true`) are *never* touched - not even by human approval. Loopback/link-local/multicast IPs are always protected. |
| **Sensitive targets** | `critical` assets, privileged/VIP accounts, `sensitive` patterns: disruptive actions always need a human. |
| **Confidence + risk gates** | Auto-execution needs risk >= per-action `auto` threshold *and* confidence >= `min_confidence_auto`. Between `approval` and `auto` -> queued for approval. Below -> recorded only. |
| **Blast-radius limits** | Max disruptive actions per type and in total per window; beyond that everything falls back to human approval (circuit breaker against alert storms / poisoned feeds). |
| **Dry-run** | `dry_run: true` records every would-be disruptive action, executes none. |
| **TTL auto-rollback** | Network blocks carry a TTL and are reverted automatically by the maintenance loop. |
| **Rollback** | Per action or whole incident (reverse order); irreversible actions (session revoke) are reported. |
| **Idempotency** | Same alert id = no-op; same action+target already active = skipped. Correlated alerts join one incident. |
| **Input validation** | Every host/user/IP/domain/hash/email id is regex/ipaddress-validated before it can reach a URL or API call. |
| **Tamper-evident audit** | Every alert, decision, approval, execution and rollback is in a SHA-256 hash chain. `python3 -m soar verify-audit --db soar.db`. |
| **Auth** | `ingest` key can only POST alerts; `admin` key does everything. Constant-time comparison. DB file is chmod 600. Webhook connectors require https, never follow redirects. |

## Risk score (0-100)

`severity/10*55 + confidence*25 + threat-intel hits (15 each, max 30) + type bonus (ransomware +10, beacon/cred +5) + correlation (+5 per extra alert, max 10)`. The breakdown is stored on the incident.

## Alert format

```json
{"id": "a-1", "source": "edr", "type": "ransomware", "severity": "critical", "confidence": 0.95,
 "title": "Mass file encryption", "host": "WS-0142", "user": "jdoe", "email_id": "<msg@x>",
 "indicators": {"ips": [], "domains": [], "hashes": [], "urls": []}, "details": {"user_clicked": true}}
```
Types: `ransomware, malware_beacon, phishing, credential_compromise, brute_force` (others -> ticket+notify).
Severity: 1-10 or info/low/medium/high/critical. Confidence: 0-1 (or 0-100). `src_ip`/`attacker_ip`/`remote_ip` go to
`indicators.ips` (adversary). `ip` is the monitored asset's own IP (context only). Aliases: hostname, username, alert_type, level...

## API (header `X-API-Key`)

| Method & path | Role | |
|---|---|---|
| `GET /health` | none | liveness |
| `POST /api/alerts` | ingest/admin | one alert or a JSON array (max 100) |
| `GET /api/incidents[?status=open]`, `GET /api/incidents/{id}` | admin | |
| `GET /api/actions[?status=pending_approval]` | admin | approval queue |
| `POST /api/actions/{id}/approve` `/deny` `/rollback` | admin | body `{"actor":"alice","reason":"..."}` optional |
| `POST /api/incidents/{id}/rollback` `/close` | admin | rollback undoes all reversible actions and closes |
| `GET /api/stats`, `/api/audit`, `/api/audit/verify`, `POST /api/maintenance` | admin | |

```bash
curl -s -X POST localhost:8080/api/alerts -H "X-API-Key: $SOAR_INGEST_KEY" -d @alert.json
curl -s -H "X-API-Key: $SOAR_ADMIN_KEY" 'localhost:8080/api/actions?status=pending_approval'
curl -s -X POST -H "X-API-Key: $SOAR_ADMIN_KEY" -d '{"actor":"alice"}' localhost:8080/api/actions/act-abc123/approve
```
`actor` is a free-text label for the audit log (not authenticated per user) - put an SSO-aware proxy in front if you need that.

## Connecting real tools

Each capability (`edr, idp, firewall, dns, mail, notify, ticket`) is `simulated` (default) or `webhook`.
A webhook connector maps actions to REST calls - see `config.example.json`. Placeholders: `{target}`, `{action}`, `{host}`,
`{user}`, `{message}`, `{ttl}`, `{incident_id}`, `{risk}` (URL-encoded in paths). Tokens come from env (`token_env`).
Every `isolate_host` etc. needs its inverse route (`unisolate_host`...) so rollback works.
Need non-REST (SDK, SSH, SOAP)? Subclass `soar.connectors.Connector` and implement `execute(action, target, params)`.

## Custom playbooks

Override per type in config; steps run in order:
```json
{"playbooks": {"brute_force": [
  {"action": "block_ip", "target": "indicators.ips", "ttl": 7200, "min_risk": 70},
  {"action": "notify", "target": "incident"}]}}
```
Targets: `host, user, email_id, incident, indicators.ips|domains|hashes`. Optional `when` (e.g. `{"details.user_clicked": true}`), `ttl` (seconds),
`min_risk` (auto threshold override). Actions: isolate_host, disable_account, revoke_sessions, block_ip, block_domain,
quarantine_file, quarantine_email, create_ticket, notify.

## Layout

```
soar/config.py     defaults + overlay + env        soar/policy.py     risk score + decision/guardrails
soar/models.py     normalisation + validation      soar/engine.py     orchestration, approvals, rollback, expiry
soar/enrich.py     threat intel + inventory        soar/store.py      SQLite + audit hash chain
soar/playbooks.py  action catalog + playbooks      soar/connectors.py simulated + webhook connectors
soar/api.py        HTTP API + maintenance loop     soar/cli.py        serve | simulate | send | verify-audit
```

## Before production

Run behind a TLS reverse proxy; start in `dry_run`; fill `protected`/`inventory` first (an empty config protects nothing);
load a real threat-intel feed via `threat_intel_file`; test every connector's rollback route; back up the SQLite DB.
