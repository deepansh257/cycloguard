# CycloGuard SBOM Scanner

CycloGuard SBOM is a repo-driven, local-first SBOM plus Trivy scanner for multi-language repositories.

## What this builds
It accepts a GitHub repository URL or local path, auto-detects supported stacks, generates CycloneDX SBOMs, runs Trivy, evaluates a severity gate, and can optionally create GitHub issues, send Slack notifications, and attempt AI-assisted remediation.

Supported stacks:
- Node.js
- Java (Maven or Gradle)
- Python
- C# (.NET)
- React (detected under Node.js)
- Angular (detected under Node.js)

## Why this is needed
- No vulnerable sample app needs to stay committed in this repo.
- The same flow can run against any user-provided repository.
- Local execution is fast, so you do not need to push every change to test.
- Standardized SBOM, Trivy, and remediation artifacts make auditing easier.

## Core behavior
1. User provides `--source` as a local path or GitHub URL.
2. GitHub sources are cloned once and then refreshed from cache on later runs.
3. The scanner auto-detects stacks from project markers.
4. One detected stack means one scan path; multiple detected stacks means one pass per stack.
5. CycloneDX SBOMs are generated per detected target.
6. Trivy scans the generated SBOMs and can also run optional filesystem scans.
7. A merged report and gate result are written.
8. Optional automation can create issues, send Slack alerts, and run remediation.

## Install
```bash
cd sbom
npm install
```

## Local usage
Scan a GitHub repo:
```bash
npx ts-node src/index.ts --source https://github.com/org/repo.git --branch main --output ./runs
```

Scan a local repo:
```bash
npx ts-node src/index.ts --source ../some-project --output ./runs
```

Optional flags:
- `--threshold high|critical` default `high`
- `--fs-scan true|false` default `true`
- `--secret-scan true|false` default `false`
- `--misconfig-scan true|false` default `false`
- `--workdir <path>` custom persistent clone cache location
- `--create-issues true|false` default `true`
- `--notify-slack true|false` default `true`
- `--enable-remediation true|false` default `false`
- `--create-pr true|false` default `true`
- `--remediation-base-branch <branch>` optional remediation PR base branch override
- `--git-user-name <name>` default `CycloGuard Bot`
- `--git-user-email <email>` default `cycloguard-bot@example.com`
- `--github-repo <owner/repo>` optional issue or PR target override
- `--github-token <token>` optional, otherwise env is used
- `--slack-webhook <url>` optional, otherwise env is used

## Shared environment setup
CycloGuard uses one shared root `.env` file for both `sbom` and `cbom`.

Use the repo root template at `.env.example`, then create `.env` in the repo root.

Typical variables:
```env
API_GITHUB_TOKEN=your_github_token
GITHUB_TOKEN=your_github_token
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
GITHUB_TARGET_REPO=owner/repo
ENABLE_AI_REMEDIATION=false
REMEDIATION_BASE_BRANCH=main
GIT_USER_NAME=CycloGuard Bot
GIT_USER_EMAIL=cycloguard-bot@example.com
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o-mini
```

Notes:
- The real `.env` belongs in the repo root, not inside `sbom/` or `cbom/`.
- `.env` is ignored by Git.
- CLI flags override `.env` values when both are present.

## GitHub issue and Slack behavior
GitHub automation:
- Set `API_GITHUB_TOKEN` or `GITHUB_TOKEN`.
- Optionally set `GITHUB_TARGET_REPO` to send issues or PRs to a repo you control.

Slack automation:
- Set `SLACK_WEBHOOK_URL`.

If credentials are missing, scanning still runs and artifacts are still created. The automation steps are skipped gracefully.

How issue creation works:
- `--source` decides what repository is scanned.
- `GITHUB_TARGET_REPO` decides where the issue is created.
- If `GITHUB_TARGET_REPO` is not set, the tool tries to infer the target from the scanned repo URL or local git remote.
- Only the target repo needs Issues enabled and token access.

## Output folder behavior
Each scan creates a source-specific subfolder under `--output`.

Pattern:
- `<repo-or-folder-name>__<branch>__<YYYYMMDD-HHMMSS>`

Example:
- `./runs/juice-shop__master__20260615-224713/`

## Auto-detection markers
- Node, React, Angular: `package.json`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
- Python: `requirements.txt`, `pyproject.toml`
- C#: `.csproj`, `.sln`

## Artifacts written by SBOM
Inside each scan output folder:
- `detected-projects.json`
- `sbom/<lang>/*-cyclonedx.json`
- `<lang>-<project-id>-trivy.json`
- `trivy-node.json`
- `trivy-java.json`
- `trivy-python.json`
- `trivy-csharp.json`
- `trivy-fs.json`
- `trivy-results.sarif`
- `trivy-merged.json`
- `gate-result.json`
- `issue-result.json` when issue automation runs
- `slack-payload.json` when Slack payload generation runs
- `remediation-plan.json`
- `remediation-applied.json`
- `remediation-validation.json`
- `remediation-rescan-summary.json`
- `remediation-result.json`
- `pr-result.json`
- `remediation-summary.json`

Remediation artifact meaning:
- `remediation-plan.json`: what CycloGuard planned to change
- `remediation-applied.json`: what was actually changed
- `remediation-validation.json`: validation results after changes
- `remediation-rescan-summary.json`: post-remediation re-scan summary
- `remediation-result.json`: final remediation status
- `pr-result.json`: PR creation result
- `remediation-summary.json`: combined user-facing remediation summary

## How AI is used in SBOM remediation
AI is used as a structured remediation planner, not as an unrestricted code-writing agent.

The shared planner lives at:
- `../remediation-core/create_ai_remediation_plan.js`

Flow:
1. The scanner writes machine-readable JSON findings such as `gate-result.json`.
2. The planner reads that JSON from disk using normal file I/O.
3. It extracts structured fields such as package name, installed version, fixed version, severity, and title.
4. It sends only that distilled context to the model, together with repo metadata and remediation rules.
5. The model returns structured JSON, not free-form prose.
6. CycloGuard applies only bounded changes from that plan, validates, rescans, and optionally opens a draft PR.

If `OPENAI_API_KEY` is missing, the remediation layer falls back to non-AI planning based on Trivy fixed-version metadata.

## Source code structure
Main code under `sbom/src`:
- `index.ts`: thin orchestrator entry point
- `types.ts`: shared types
- `cli/args.ts`: CLI argument parsing
- `core/fs.ts`, `core/shell.ts`, `core/env.ts`: shared file, shell, and env utilities
- `source/acquire.ts`: clone or pull cache and source resolution
- `detectors/projects.ts`: auto-detection and language grouping
- `scanner/pipeline.ts`: SBOM generation, Trivy scan, merge, and artifact writing
- `reports/gate.ts`: gate result generation
- `reports/automation.ts`: issue, Slack, remediation, and summary orchestration
- `remediation/*.ts`: remediation planning, dependency update, validation, rescan, and PR workflow
- `tools/bootstrap.ts`: tool checks and auto-install bootstrap

Shared remediation support outside `sbom/src`:
- `../remediation-core/create_ai_remediation_plan.js`: shared AI remediation planner for SBOM and CBOM
- `../remediation-core/build_remediation_summary.js`: shared remediation summary builder

## CI workflow
Workflow:
- `.github/workflows/security-pipeline.yml`

What it does:
- supports manual `workflow_dispatch` inputs
- scans external GitHub repos or the checked-out workspace
- uploads full and per-language artifacts
- can create or update GitHub issues for high or critical findings
- can send Slack summaries for all severities
- can run remediation and open draft PRs for manual review

Manual workflow inputs:
- `source_repo`
- `source_branch`
- `issue_target_repo`
- `threshold`
- `enable_remediation`
- `create_remediation_pr`

How to run it manually:
1. Push the latest workflow changes.
2. Open GitHub Actions.
3. Select `Security Pipeline`.
4. Click `Run workflow`.
5. Provide the inputs.
6. Start the run and download the artifact bundle after completion.

Example manual inputs:
- `source_repo`: `https://github.com/vulnerable-apps/juice-shop.git`
- `source_branch`: `master`
- `issue_target_repo`: `your-username/your-repo`
- `threshold`: `high`
- `enable_remediation`: `true`
- `create_remediation_pr`: `true`

## Phase 3 remediation behavior
When remediation is enabled, SBOM:
- reads high and critical findings from the gate output
- asks the shared planner for a remediation plan when `OPENAI_API_KEY` is available
- falls back to Trivy fixed-version metadata otherwise
- applies direct dependency updates where possible
- validates updated projects with best-effort ecosystem commands
- re-runs SBOM plus Trivy into a remediation rescan flow
- creates a remediation branch
- opens a draft PR for manual review when push access is available

## Severity handling
- `CRITICAL` and `HIGH`
  - participate in gate failure logic
  - are included in GitHub issue creation
  - can trigger AI-assisted remediation when enabled
- `MEDIUM` and `LOW`
  - stay in reports and Slack summaries
  - are alert-only by default

## End-to-end process
1. Parse CLI inputs.
2. Resolve source repo or local path.
3. Ensure tools exist with bootstrap fallback.
4. Auto-detect stack targets.
5. Generate CycloneDX SBOMs.
6. Run Trivy against those SBOMs.
7. Optionally run filesystem, secret, or misconfiguration scans.
8. Merge findings.
9. Write `gate-result.json`.
10. Optionally create issues, send Slack, and run remediation.
11. Save all outputs into a run-isolated artifact folder.

## Source acquisition details
- Windows default cache: `C:\cg-sbom-cache`
- Linux and macOS default cache: temp directory under `cycloguard-sbom-cache`
- First clone honors `--branch` when provided.
- Later runs refresh the cached clone.
- Windows clone uses `core.longpaths=true` to reduce long-path failures.

## Tool bootstrap behavior
If missing, CycloGuard attempts automatic install:
- Windows: `winget` with `choco` fallback
- macOS: `brew`

- Linux: apt-based install path

On Windows, after installing Trivy, the scanner also tries to refresh PATH in-process so the same terminal session can continue.

## Validation checklist
1. Run the scanner against a known single-stack repo.
2. Run it against a known multi-stack repo.
3. Check `detected-projects.json` for expected targets.
4. Verify per-language Trivy reports exist.
5. Verify `trivy-merged.json` and `gate-result.json` exist.
6. If remediation is enabled, verify `remediation-summary.json` and `pr-result.json`.
7. In CI, confirm artifact upload and workflow summary.

## Troubleshooting
- `trivy` not recognized:
  - rerun in a new terminal if PATH refresh was not enough
- Git clone branch not found in CI:
  - confirm the manual input branch exists remotely
- Missing reports:
  - inspect `detected-projects.json` first
- Issue or PR creation failed:
  - confirm token permissions and target repo settings
- No AI plan was generated:
  - confirm `OPENAI_API_KEY` exists in the shared root `.env`

## Current limitations
- Strict SPDX generation per ecosystem is not fully implemented yet.
- GitHub issue creation depends on target repo issue settings and token access.
- Historical indexing exists but can still be expanded.
- Remediation is intentionally constrained to structured planning plus bounded patch application.
- Manual review is still required before merge.

## Note
The old committed vulnerable sample applications under `sbom/apps/` were removed. Scanning is now always performed against a user-provided repo or local path.
