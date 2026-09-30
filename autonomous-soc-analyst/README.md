# Autonomous SOC Analyst (Tier‑1)

An agent that turns a Defender/SIEM alert into **containment + preliminary evidence + a
human‑readable report in under 28 seconds**, so the on‑call human stops being the first
responder and becomes the strategic overseer.

For every alert it: classifies it against your IR policy → enriches file hashes and IPs
across many real‑time threat feeds → pulls recent account activity and endpoint network
traffic → decides *true positive / false positive / undetermined* and *critical/high/
medium/low* with an auditable reason for every point → contains per policy (isolate
endpoint, stop & quarantine file, block IP, disable account, collect forensics) → writes
a concise report → and **pages** the infra + security on‑call for anything urgent or
drops it **in the queue** if it can wait.

Because it can touch Active Directory, firewalls and endpoints, it ships with a safety
layer built for exactly that: a **kill switch**, hard **capability/scope limits**, and
**out‑of‑band admin alerts if it ever tries to break out of scope or heal itself**.

---

## Quick start (no credentials needed)

```bash
pip install -r requirements.txt
python -m soc_agent check                 # validate policies + config
python -m soc_agent admin seal            # seal code+policy integrity manifest
python -m soc_agent simulate all          # run 7 attack scenarios end to end
python -m soc_agent simulate ransomware --show-report   # see a full report
```

`simulate` runs against a built‑in simulated "Contoso" tenant — real Defender alert
formats, real threat‑intel shapes, simulated endpoints/users/traffic — so you can watch
the whole decision + containment + report flow before wiring anything up.

Run the service (mock mode, safe):

```bash
python -m soc_agent serve                 # http://127.0.0.1:8080
python -m soc_agent export-scenarios /tmp/alerts
curl -X POST 'http://127.0.0.1:8080/webhooks/defender?wait=true' \
     -H 'X-API-Key: dev' -d @/tmp/alerts/ransomware.defender.json
```

---

## How an alert flows

```
alert ─► classify (IR policy) ─► resolve devices ─┬─► FAST‑PATH containment (ransomware…)
                                                  └─► enrich in parallel (28s budget):
                                                       hashes × N feeds · account activity
                                                       network traffic ─► C2 IP intel
      triage (rule‑based, explainable) ◄────────────────────────────────────────────────┘
        ─► response actions (guardrails + safety gate) ─► auto‑release if false positive
        ─► report ─► PAGE on‑call  or  QUEUE  ─► persist + tamper‑evident audit log
```

- **Detection/response inputs:** Defender XDR (Graph *and* legacy MDE), Microsoft
  Sentinel, Splunk, and a generic schema for any other SIEM (QRadar, Elastic, Chronicle…).
- **Every decision is rule‑based** and lives in `ir_policy.yaml`. No AI model makes a
  containment or verdict decision — an optional LLM only *writes the summary paragraph*,
  and its output is screened for prompt‑injection before use.
- **Time budget:** each phase gets a slice of the remaining 28 s while reserving time for
  the phases after it, so a slow feed can never delay containment, the report, or paging.

### What it does as a T1 analyst
Agent flow state (`investigating → contained → remediated / awaiting_approval / closed`),
verdict (`true/false positive`, `undetermined`), severity + alert class · hash malware &
threat‑intel enrichment · recent user‑account activity · endpoint network traffic → C2 ·
endpoint isolation · firewall IP block · AD/Entra account disable · forensic package ·
IR report generation.

---

## Safeguards (it has keys to AD, firewalls, endpoints)

| Control | What it does |
|---|---|
| **Kill switch** | `admin kill` (file), `SOC_KILL_SWITCH` (env), or `POST /admin/kill` (admin key). Checked immediately before **every** action. `actions` level = no changes to any system (it still investigates and **pages a human** for anything that needed containment); `full` = stop ingesting alerts (webhooks return 503 so the SIEM retries). **Fail‑closed:** an unreadable kill file = engaged. |
| **One‑way from inside** | The agent process can *engage* the switch but has **no code path to clear it**, and the runtime guard blocks it from deleting/overwriting the kill file. Only an admin, from a **separate** process, can resume: `python -m soc_agent admin resume --confirm`. There is deliberately **no resume API**. |
| **Capability allow‑list** | `safety.yaml` lists the only action types the agent may ever run. Anything else → blocked + admin alert. |
| **Scope / provenance** | Every action target must appear in *that case's* evidence. Acting on anything else = breakout → blocked, kill switch trips, admin paged. |
| **Self‑protection** | It can never isolate its own hosts, block its own IPs, or disable its own service accounts / named admins. |
| **Runtime breakout guard** | A Python audit hook (can't be uninstalled mid‑process) blocks & reports: spawning a shell/process, writing to its own code/policy, tampering with the kill switch (**self‑heal**), or truncating the audit log. |
| **Integrity monitor** | `admin seal` records SHA‑256 of all code + policies. Drift at runtime, or a mismatch at startup in live mode, forces a full stop. |
| **Restart‑loop / self‑heal detection** | Repeated restarts, unclean shutdown, or starting while killed → admin alert. |
| **Circuit breaker** | Caps containment actions per 10‑min window across all cases; repeated safety denials trip the switch. |
| **Tamper‑evident audit log** | Hash‑chained JSONL of every decision/action/admin op. `admin verify-audit` detects any edit or deletion. Ship it to your SIEM/WORM store. |
| **Out‑of‑band admin channel** | Safety alerts go to a **separate** webhook/PagerDuty from the SOC channels, with a local fallback file if delivery fails. |
| **Egress allow‑list** | The agent may only reach hosts derived from its own config. Any other outbound request is refused *before connecting* and reported. Enforce it at the network layer too. |
| **Not armed by default** | Live mode does nothing until `SOC_ARMED=true`; until then every action is a dry run. |

**When the admin is alerted:** kill‑switch engage/clear, scope/self/capability violation,
attempted self‑modification or self‑heal, process‑spawn or audit‑tamper attempt, restart
loop, integrity drift, circuit breaker, repeated denials, revoked credentials, and a
flood of connector failures.

### Kill it right now
```bash
python -m soc_agent admin kill --level full --reason "investigating agent behaviour"
python -m soc_agent admin status          # see state + recent security events
# ...review admin alerts + audit log, then, only from the host:
python -m soc_agent admin resume --confirm
```

---

## Going live (checklist)

1. `cp .env.example .env` and fill in credentials for the systems you actually use.
2. Set `SOC_API_KEY` and a **different** `SOC_ADMIN_API_KEY`; set an admin alert channel
   (`SOC_ADMIN_WEBHOOK_URL` or `SOC_ADMIN_PAGERDUTY_ROUTING_KEY`).
3. Review `ir_policy.yaml` (protected hosts, privileged accounts, never‑block CIDRs) and
   `safety.yaml` (`self_identities` — the agent's **own** hostnames/accounts/IPs).
4. `python -m soc_agent admin seal` after any code/policy change.
5. Start with `SOC_MOCK_MODE=false` and `SOC_ARMED=false` (dry run). Confirm the reports
   and routing look right, then flip `SOC_ARMED=true`.
6. Grant each integration **least privilege** (see per‑connector notes in
   `connectors/microsoft.py`, `active_directory.py`, `firewall.py`). Run the process as an
   unprivileged user with a read‑only code filesystem, and put the same egress allow‑list
   on the network. Terminate TLS in front of the service.

Send alerts by webhook (`POST /webhooks/{defender|sentinel|splunk|generic}`) or enable
the built‑in Defender poller (`SOC_ENABLE_POLLER=true`).

---

## Human‑in‑the‑loop

Privileged‑account disables, protected‑host isolation, and blast‑radius overflows are
**staged for approval**, not executed:

```
POST /cases/{id}/actions/{action_id}/approve    {"approver": "you@corp"}
POST /cases/{id}/actions/{action_id}/rollback   {"requested_by": "you@corp"}
GET  /cases/{id}/report                          # the Markdown report
GET  /admin/safety                               # kill switch, events, integrity, egress
```

## Tests

```bash
python -m unittest discover -t . -s tests    # 46 tests: pipeline, safety, API, units
ruff check soc_agent && mypy soc_agent --ignore-missing-imports
```

## Layout

```
soc_agent/
  orchestrator.py     28s pipeline               triage.py     rule-based verdict/severity/routing
  normalize.py        Defender/Sentinel/Splunk   actions.py    planning + guarded execution
  policy.py           IR policy engine           intel.py      feed fan-out + consensus
  report.py           Markdown report            notify.py     Teams/Slack/PagerDuty/ticket
  connectors/         Defender, Entra, AD, PAN-OS/FortiGate, 8 intel feeds, mock tenant, LLM
  safety/             killswitch · gate · monitor · egress · integrity · runtime_guard · audit
ir_policy.yaml   safety.yaml   .env.example   tests/
```

> Scope: this is a Tier‑1 autonomous analyst — detection triage, first‑line containment,
> evidence, reporting. Advanced/Tier‑2 investigation is deliberately out of scope for now.
> Nothing here is a substitute for network‑layer egress control, least‑privilege
> credentials, and an OS sandbox around the process.
