#!/usr/bin/env bash
set -euo pipefail

# Creates three flagship FastAPI scaffolds under the current directory.
# Run from an empty parent folder, e.g.:
#   mkdir -p flagship-scaffold && cd flagship-scaffold && bash /path/to/create-flagship-scaffold.sh

create_common_structure() {
  local PROJECT_NAME="$1"

  mkdir -p "$PROJECT_NAME"/{app,app/api,app/core,app/models,app/services,app/utils,docs,diagrams,examples,scripts,tests,.github/workflows}

  touch "$PROJECT_NAME"/app/__init__.py
  touch "$PROJECT_NAME"/app/api/__init__.py
  touch "$PROJECT_NAME"/app/core/__init__.py
  touch "$PROJECT_NAME"/app/models/__init__.py
  touch "$PROJECT_NAME"/app/services/__init__.py
  touch "$PROJECT_NAME"/app/utils/__init__.py

  cat > "$PROJECT_NAME/requirements.txt" <<EOF
fastapi
uvicorn
python-dotenv
requests
pydantic
pytest
httpx
EOF

  cat > "$PROJECT_NAME/Dockerfile" <<EOF
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

  cat > "$PROJECT_NAME/docker-compose.yml" <<EOF
services:
  api:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
EOF

  cat > "$PROJECT_NAME/.env.example" <<EOF
APP_NAME=$PROJECT_NAME
APP_ENV=dev
JIRA_BASE_URL=
JIRA_EMAIL=
JIRA_API_TOKEN=
TEAMS_WEBHOOK_URL=
OPENAI_API_KEY=
MICROSOFT_GRAPH_TENANT_ID=
MICROSOFT_GRAPH_CLIENT_ID=
MICROSOFT_GRAPH_CLIENT_SECRET=
OKTA_DOMAIN=
OKTA_API_TOKEN=
EOF

  cat > "$PROJECT_NAME/.gitignore" <<EOF
.env
__pycache__/
.pytest_cache/
.venv/
*.pyc
.DS_Store
EOF

  cat > "$PROJECT_NAME/.github/workflows/ci.yml" <<EOF
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run tests
        run: pytest
EOF

  cat > "$PROJECT_NAME/app/main.py" <<EOF
from fastapi import FastAPI

app = FastAPI(title="$PROJECT_NAME")

@app.get("/")
def root():
    return {
        "project": "$PROJECT_NAME",
        "status": "running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}
EOF

  cat > "$PROJECT_NAME/tests/test_smoke.py" <<EOF
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["project"] == "$PROJECT_NAME"

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
EOF
}

# -------------------------------------------------------------------
# PROJECT 1: Vulnerability Management Automation Platform
# -------------------------------------------------------------------

create_common_structure "vulnerability-management-automation-platform"

cat > vulnerability-management-automation-platform/README.md <<EOF
# Vulnerability Management Automation Platform

## Purpose

Enterprise security automation platform that ingests vulnerability scan data, prioritizes remediation, scores SLA risk, creates Jira tickets, sends Microsoft Teams notifications, tracks remediation progress, supports executive reporting, and enables auto-close logic.

## Core Features

- Ingest Nessus scan data
- Prioritize CVEs
- SLA scoring
- Create Jira tickets
- Send Microsoft Teams notifications
- Track remediation status
- Generate executive dashboard data
- Auto-close remediated findings

## Technology Stack

- Python
- FastAPI
- Docker
- Jira API
- Microsoft Teams Webhook
- GitHub Actions

## Workflow

\`\`\`
Nessus Finding
    ↓
Normalize Vulnerability Data
    ↓
Prioritize by Severity / CVSS / Asset Criticality
    ↓
Calculate SLA Due Date
    ↓
Create Jira Ticket
    ↓
Notify Teams
    ↓
Track Remediation
    ↓
Auto-Close When Resolved
\`\`\`

## Business Value

This project demonstrates enterprise security automation, vulnerability operations, API integration, workflow orchestration, and executive-ready reporting.
EOF

cat > vulnerability-management-automation-platform/app/services/nessus_ingest.py <<EOF
def ingest_nessus_scan(scan_data: dict) -> list[dict]:
    findings = scan_data.get("findings", [])
    return findings
EOF

cat > vulnerability-management-automation-platform/app/services/sla_scoring.py <<EOF
from datetime import datetime, timedelta

SLA_DAYS = {
    "critical": 7,
    "high": 30,
    "medium": 60,
    "low": 90,
}

def calculate_sla_due_date(severity: str) -> str:
    days = SLA_DAYS.get(severity.lower(), 90)
    due_date = datetime.utcnow() + timedelta(days=days)
    return due_date.date().isoformat()
EOF

cat > vulnerability-management-automation-platform/app/services/jira_client.py <<EOF
def create_jira_ticket(finding: dict) -> dict:
    return {
        "ticket_id": "MOCK-JIRA-001",
        "summary": finding.get("title", "Vulnerability Finding"),
        "status": "created"
    }
EOF

cat > vulnerability-management-automation-platform/app/services/teams_notifier.py <<EOF
def send_teams_notification(message: str) -> dict:
    return {
        "status": "sent",
        "message": message
    }
EOF

cat > vulnerability-management-automation-platform/examples/nessus_sample.json <<EOF
{
  "findings": [
    {
      "plugin_id": "19506",
      "title": "Critical OpenSSL Vulnerability",
      "severity": "critical",
      "cvss": 9.8,
      "asset": "server01",
      "cve": "CVE-2024-0001"
    }
  ]
}
EOF

# -------------------------------------------------------------------
# PROJECT 2: AI Security Copilot
# -------------------------------------------------------------------

create_common_structure "ai-security-copilot"

cat >> ai-security-copilot/requirements.txt <<EOF
openai
langchain
EOF

cat > ai-security-copilot/README.md <<EOF
# AI Security Copilot

## Purpose

AI-assisted security operations workflow that summarizes alerts, recommends remediation, maps activity to MITRE ATT&CK, scores risk, creates tickets, and posts analyst-ready summaries to Microsoft Teams.

## Core Features

- OpenAI integration
- Alert summarization
- Risk scoring
- MITRE ATT&CK mapping
- Response recommendations
- Jira ticket creation
- Microsoft Teams notification
- Vector search planned for future release

## Technology Stack

- Python
- FastAPI
- OpenAI API
- LangChain basics
- Jira API
- Microsoft Teams Webhook
- Vector search later

## Workflow

\`\`\`
Security Alert
    ↓
AI Summary
    ↓
Risk Score
    ↓
MITRE Mapping
    ↓
Recommended Response
    ↓
Create Jira Ticket
    ↓
Post to Teams
\`\`\`

## Business Value

This project demonstrates AI-assisted security operations, analyst acceleration, alert enrichment, remediation guidance, and workflow automation.
EOF

cat > ai-security-copilot/app/services/ai_summarizer.py <<EOF
def summarize_alert(alert: dict) -> dict:
    return {
        "summary": f"Security alert involving {alert.get('user', 'unknown user')}",
        "risk": "medium",
        "recommended_action": "Review activity, validate user behavior, and escalate if suspicious."
    }
EOF

cat > ai-security-copilot/app/services/risk_scoring.py <<EOF
def score_risk(alert: dict) -> str:
    severity = alert.get("severity", "").lower()

    if severity in ["critical", "high"]:
        return "high"

    if alert.get("anomalous_location") or alert.get("new_device"):
        return "medium"

    return "low"
EOF

cat > ai-security-copilot/app/services/mitre_mapper.py <<EOF
def map_to_mitre(alert: dict) -> list[dict]:
    return [
        {
            "technique": "T1078",
            "name": "Valid Accounts",
            "reason": "Alert may involve suspicious authenticated access."
        }
    ]
EOF

cat > ai-security-copilot/examples/sample_alert.json <<EOF
{
  "alert_id": "ALERT-001",
  "user": "jane.doe@example.com",
  "severity": "high",
  "source_ip": "203.0.113.10",
  "new_device": true,
  "anomalous_location": true,
  "description": "User logged in from anomalous location using a new device."
}
EOF

# -------------------------------------------------------------------
# PROJECT 3: Identity Threat Response Automation
# -------------------------------------------------------------------

create_common_structure "identity-threat-response-automation"

cat > identity-threat-response-automation/README.md <<EOF
# Identity Threat Response Automation

## Purpose

Enterprise identity security automation workflow that detects impossible travel, enriches risky sign-ins, performs ASN/IP reputation lookup, supports conditional remediation, and integrates with Microsoft Teams and Jira.

## Core Features

- Impossible travel detection
- Risky sign-in enrichment
- ASN/IP reputation lookup
- Conditional remediation
- Auto-disable account option
- Microsoft Graph integration
- Okta API integration
- Sentinel-ready workflow logic
- Teams and Jira integration

## Technology Stack

- Python
- FastAPI
- Microsoft Graph
- Okta API
- Microsoft Sentinel
- Webhooks
- Jira API
- Microsoft Teams Webhook

## Workflow

\`\`\`
Risky Sign-In
    ↓
Normalize Identity Event
    ↓
Enrich IP / ASN / Geo
    ↓
Impossible Travel Evaluation
    ↓
Risk Score
    ↓
Conditional Remediation Decision
    ↓
Teams + Jira Notification
    ↓
Optional Account Disable Recommendation
\`\`\`

## Business Value

This project demonstrates identity threat automation, enterprise detection workflows, enrichment logic, conditional response, and security operations integration.
EOF

cat > identity-threat-response-automation/app/services/impossible_travel.py <<EOF
def detect_impossible_travel(previous_event: dict, current_event: dict) -> bool:
    previous_country = previous_event.get("country")
    current_country = current_event.get("country")

    previous_time = previous_event.get("timestamp")
    current_time = current_event.get("timestamp")

    if previous_country and current_country and previous_country != current_country:
        return True

    return False
EOF

cat > identity-threat-response-automation/app/services/ip_enrichment.py <<EOF
def enrich_ip_address(ip_address: str) -> dict:
    return {
        "ip": ip_address,
        "asn": "mock-asn",
        "country": "mock-country",
        "reputation": "unknown"
    }
EOF

cat > identity-threat-response-automation/app/services/graph_client.py <<EOF
def get_risky_signins() -> list[dict]:
    return [
        {
            "user": "jane.doe@example.com",
            "ip": "203.0.113.10",
            "risk_level": "high"
        }
    ]
EOF

cat > identity-threat-response-automation/app/services/okta_client.py <<EOF
def get_okta_events() -> list[dict]:
    return [
        {
            "user": "jane.doe@example.com",
            "event_type": "user.session.start",
            "outcome": "success"
        }
    ]
EOF

cat > identity-threat-response-automation/examples/risky_signin_sample.json <<EOF
{
  "user": "jane.doe@example.com",
  "source_ip": "203.0.113.10",
  "country": "Netherlands",
  "city": "Amsterdam",
  "device": "iOS",
  "risk_level": "high",
  "timestamp": "2026-05-11T18:30:00Z"
}
EOF

echo "Flagship project scaffolding created successfully."
