# CycloGuard SBOM Security Pipeline

## What We Are Building
CycloGuard is a multi-language software supply chain security pipeline that:
- generates SBOMs (Software Bill of Materials),
- scans dependencies with Trivy,
- enforces vulnerability gates,
- and later automates issue creation, notifications, and AI-assisted remediation.

The current target stacks are:
- Node.js: `sbom/apps/vuln_node.js`
- Java/Gradle: `sbom/apps/vuln_java`
- Python: `sbom/apps/vuln_python`

## Why This Is Needed
Modern applications depend on many third-party packages. Without automated SBOM + scanning:
- vulnerable dependencies are hard to track across releases,
- security checks become inconsistent across languages,
- audit/compliance evidence is difficult to produce.

This project creates one repeatable workflow for all three ecosystems so teams can detect and track risk early in CI.

## Phase 1 Scope (Completed)
Phase 1 focused on SBOM + Trivy foundation and report outputs.

Implemented:
1. Monorepo-aligned pipeline in GitHub Actions.
2. SBOM generation for Node/Java/Python in the same run.
3. Trivy scanning of generated SBOMs.
4. Gate parsing logic from Trivy outputs (`high` / `critical` threshold based).
5. Artifact publishing for:
   - consolidated report bundle,
   - separate language-specific Trivy artifacts (node/java/python).

## Current Pipeline Flow
1. Trigger on push/PR/workflow_dispatch.
2. Setup runtimes and tools.
3. Generate SBOMs:
   - CycloneDX JSON per language
   - SPDX file placeholder per language (currently copied from CycloneDX output)
4. Run Trivy scans on generated SBOM files.
5. Parse Trivy output and compute gate result.
6. Upload artifacts.

Note: GitHub issue creation, Slack notifications, and AI fix/re-scan stages are scaffolded but intentionally disabled for current rollout.

## Key Files
- Workflow: `.github/workflows/security-pipeline.yml`
- SBOM action: `sbom/.github/actions/generate-sbom/action.yml`
- Trivy action: `sbom/.github/actions/run-trivy/action.yml`
- Config: `sbom/security-pipeline-config.yml`
- Gate parser: `sbom/scripts/parse_trivy_report.js`

Optional/scaffolded (later phases):
- `sbom/.github/actions/ai-fix/action.yml`
- `sbom/.github/actions/slack-notify/action.yml`
- `sbom/scripts/create_github_issue.js`
- `sbom/scripts/manage_reports.js`
- `sbom/scripts/build_slack_payload.js`

## Artifacts You Should See
Per run, artifacts include:
- `security-reports-<run-id>-<attempt>` (full bundle)
- `trivy-node-<run-id>-<attempt>`
- `trivy-java-<run-id>-<attempt>`
- `trivy-python-<run-id>-<attempt>`

These contain SBOMs and corresponding Trivy reports.

## What Comes Next (Phase 2+)
Planned additions:
1. Re-enable gate enforcement as a strict CI blocker.
2. Auto-create GitHub issues for High/Critical findings.
3. Slack notifications with severity summaries and report links.
4. AI-assisted dependency remediation + validation re-scan loop.
5. Report history/audit indexing for release tracking.
