# Autonomous Vulnerability Management System - Project Context

## Goal

Build a reusable plug-and-play security pipeline for repositories that supports at minimum:

- Node.js
- Python
- Java

The solution should generate SBOMs, scan dependencies, create reports, create GitHub issues, notify Slack, and optionally use AI to attempt dependency remediation.

## Core Workflow

Code Push / Pull Request

1. Build and package the app
2. Generate SBOM first
   - CycloneDX
   - SPDX
3. Feed SBOM into Trivy
4. Run dependency scan
5. Run gate check
   - If no Critical/High CVEs, skip to archival
   - If Critical/High CVEs found, continue to issue creation and AI fix attempt
6. Auto-create GitHub issue
7. AI fix attempt
   - Bump vulnerable dependencies
   - Update lockfiles
   - Modify manifests where needed
8. Run tests
   - If tests pass, commit fix to same PR
   - If tests fail, open a separate draft PR or comment on original PR with attempted fix
9. Re-scan SBOM
   - Record pass/fail result
10. Archive SBOM
   - Attach to release or artifact registry
11. Send Slack notification
   - Overall pass/fail
   - CVE count and severity
   - AI fix attempted yes/no
   - Re-scan result resolved/partial/failed
   - Dependencies changed
   - SBOM artifact link
   - Trivy report link

## Required Features

- Monorepo with intentionally vulnerable Node.js, Python, and Java apps
- SBOM generation for all supported ecosystems
- Trivy scanning from SBOM input
- JSON, HTML, SARIF, and Markdown reports
- GitHub issue creation using GitHub API
- Report management layer with scan history, logs, timestamps, and downloadable reports
- Slack notification integration
- AI-based autonomous remediation workflow
- Re-scan after attempted fixes
- PR update or draft PR fallback

## Recommended Repository Structure

```text
autonomous-vuln-management/
├── apps/
│   ├── node-app/
│   ├── python-app/
│   └── java-app/
├── .github/
│   └── workflows/
│       └── security-pipeline.yml
├── actions/
│   ├── generate-sbom/
│   ├── run-trivy/
│   ├── gate-check/
│   ├── create-github-issue/
│   ├── ai-fix/
│   └── slack-notify/
├── scripts/
│   ├── create-github-issue.sh
│   ├── parse-trivy-report.sh
│   └── slack-payload-builder.sh
└── security-pipeline.config.yml