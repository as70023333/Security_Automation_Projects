#!/usr/bin/env bash
set -euo pipefail

# Requires GitHub CLI:
# https://cli.github.com/
#
# Login first:
# gh auth login

REPOS=(
  "security-automation-lab"
  "vulnerability-remediation-automation"
  "ai-security-operations-copilot"
  "identity-threat-response-automation"
  "cloud-security-optimization"
)

HEADLINE="Senior Security Engineer transitioning into Security Automation, AI Security Operations, and Cloud Security Platform Engineering."

README_TITLE="Enterprise Security Automation Portfolio"

for REPO in "${REPOS[@]}"; do
  echo "Creating repo: $REPO"

  gh repo create "$REPO" \
    --public \
    --description "$HEADLINE" \
    --clone

  cd "$REPO"

  mkdir -p docs scripts diagrams examples
  for d in docs scripts diagrams examples; do
    touch "$d/.gitkeep"
  done

  cat > README.md <<EOF
# $README_TITLE

## Portfolio Headline

$HEADLINE

## Purpose

This repository is part of my enterprise security automation portfolio focused on:

- Security automation engineering
- AI-assisted security operations
- Cloud security platform engineering
- Vulnerability remediation automation
- Identity threat response automation
- Security workflow orchestration

## Repository Focus

**$REPO**

## Structure

\`\`\`
.
├── README.md
├── docs/
├── scripts/
├── diagrams/
└── examples/
\`\`\`

## Roadmap

- Add architecture diagrams
- Add automation scripts
- Add sample inputs and outputs
- Add GitHub Actions workflow
- Add security considerations
- Add executive summary examples
EOF

  git add .
  git commit -m "Initial portfolio repository structure"
  # Local Git may default to master; GitHub expects main.
  git branch -M main
  git push -u origin main

  cd ..

  echo "Completed: $REPO"
done

echo "All portfolio repositories created successfully."
