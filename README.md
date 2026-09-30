# Enterprise Security Automation Portfolio

**Repository:** `Security_Automation_Projects` — local workspace for security automation engineering, tracked with Git and linked to GitHub.

## Layout

```
.
├── README.md
├── autonomous-soc-analyst/
├── docs/
├── scripts/
├── diagrams/
└── examples/
```

| Path | Purpose |
|------|---------|
| `README.md` | Portfolio overview and how to use this repo |
| `autonomous-soc-analyst/` | Tier-1 autonomous SOC analyst — detect, contain & report on alerts in <28s |
| `docs/` | Design notes, runbooks, ADRs, references |
| `scripts/` | Automation and bootstrap scripts |
| `diagrams/` | Architecture and flow diagrams (source exports) |
| `examples/` | Sample configs, inputs/outputs, snippets |

## Projects

### 🚨 Autonomous SOC Analyst — [`autonomous-soc-analyst/`](./autonomous-soc-analyst/)

Turns a Defender/SIEM alert into **containment + preliminary evidence + a human-readable report in under 28 seconds**, so the on-call engineer becomes the strategic overseer instead of the first responder. Ingests Defender XDR / Sentinel / Splunk / generic SIEM, enriches hashes and IPs across up to 8 threat-intel feeds, makes a rule-based (auditable, non-AI) verdict and severity call, contains per IR policy (isolate endpoint, block IP, disable AD/Entra account, quarantine file, collect forensics), and pages vs. queues per escalation rules. Ships with a full safety layer — fail-closed **kill switch**, capability/scope guardrails, runtime breakout + self-heal detection, tamper-evident audit log, and out-of-band admin alerting. Runs end-to-end in a mock tenant with no credentials; 46 tests, ruff + mypy clean.

```bash
cd autonomous-soc-analyst
pip install -r requirements.txt
python -m soc_agent simulate all          # 7 attack scenarios, end to end
```

## Quick start

- File → Open Folder → `c:\LLM Projects\Security_Automation_Projects`
- **Remote:** [github.com/as70023333/Security_Automation_Projects](https://github.com/as70023333/Security_Automation_Projects) (branch `main`)

Created 2026-05-11.
