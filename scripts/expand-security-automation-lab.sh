#!/usr/bin/env bash
set -euo pipefail

# Run from the parent of security-automation-lab (e.g. security-portfolio/).
# Expands the lab repo tree and README.

REPO="security-automation-lab"

mkdir -p "$REPO"

cd "$REPO"

mkdir -p \
  docs/architecture \
  docs/workflows \
  docs/ai-security \
  docs/threat-models \
  docs/executive-summaries \
  diagrams/vuln-management \
  diagrams/ai-copilot \
  diagrams/identity-response \
  diagrams/cloud-security \
  scripts/jira \
  scripts/teams \
  scripts/graph-api \
  scripts/okta \
  scripts/sentinel \
  scripts/utility \
  workflows/tines \
  workflows/logic-apps \
  workflows/github-actions \
  workflows/gitlab-ci \
  examples/alerts \
  examples/vulnerabilities \
  examples/incidents \
  examples/risk-scores \
  examples/enrichment \
  projects/vulnerability-management-automation-platform \
  projects/ai-security-copilot \
  projects/identity-threat-response-automation \
  playbooks/incident-response \
  playbooks/vulnerability-response \
  playbooks/identity-response \
  playbooks/ai-security \
  dashboards/executive \
  dashboards/operational \
  dashboards/sla-metrics \
  lab/poc \
  lab/experiments \
  lab/ai-agents \
  .github/workflows

cat > README.md <<'EOF'
# Enterprise Security Automation Portfolio

## Professional Identity

Senior Security Engineer transitioning into Security Automation, AI Security Operations, and Cloud Security Platform Engineering.

## Purpose

This repository is an enterprise security automation lab focused on building practical, scalable, and executive-ready security automation workflows.

It demonstrates how security teams can reduce manual work, accelerate remediation, improve visibility, and modernize operations through automation, AI-assisted workflows, and platform engineering.

## Core Focus Areas

- Security Automation
- AI Security Engineering
- Vulnerability Operations
- Identity Threat Automation
- Cloud Security Architecture
- Detection Engineering
- Workflow Orchestration
- Security Platform Engineering
- Executive Reporting
- Operational Optimization

## Problems This Lab Solves

This lab focuses on solving real enterprise security challenges:

- Alert fatigue
- Manual remediation workflows
- Vulnerability management scaling
- Identity threat response delays
- Telemetry normalization
- Security tooling fragmentation
- Operational inefficiency
- Executive reporting gaps
- Analyst burnout
- AI-assisted remediation workflows

## Featured Projects

### 1. Vulnerability Management Automation Platform

Automates vulnerability ingestion, prioritization, SLA scoring, Jira ticket creation, Teams notifications, remediation tracking, executive reporting, and auto-close logic.

### 2. AI Security Copilot

Uses AI to summarize alerts, recommend remediation, map activity to MITRE ATT&CK, score risk, create tickets, and post analyst-ready summaries to Teams.

### 3. Identity Threat Response Automation

Automates risky sign-in enrichment, impossible travel detection, ASN/IP reputation lookup, conditional remediation, and Teams/Jira integration.

## Repository Structure

```text
security-automation-lab/
├── README.md
├── ROADMAP.md
├── LEARNING-NOTES.md
├── ARCHITECTURE.md
├── docs/
├── diagrams/
├── scripts/
├── workflows/
├── examples/
├── projects/
├── playbooks/
├── dashboards/
└── lab/
```
EOF

cat > ROADMAP.md <<'EOF'
# Roadmap

- Add live workflow exports under `workflows/`
- Link or submodule featured apps under `projects/`
- Add executive dashboard samples under `dashboards/`
- Expand playbooks with decision trees and RACI
EOF

cat > LEARNING-NOTES.md <<'EOF'
# Learning notes

Use this file (or split by topic under `docs/`) for experiments, links, certifications, and lessons learned while building the lab.
EOF

cat > ARCHITECTURE.md <<'EOF'
# Architecture

Document how data flows from sources (scans, IdP, SIEM) through orchestration, ticketing, and notifications. Update as components land in `projects/` and `workflows/`.
EOF

# Track empty directories in Git (excluding .git)
find . -name .git -prune -o -type d -empty -exec touch {}/.gitkeep \;

echo "security-automation-lab structure expanded successfully."
