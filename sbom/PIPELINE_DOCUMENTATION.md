# SBOM Security Pipeline - Updated Documentation

## 1. Purpose
This document describes the current CycloGuard SBOM implementation where scanning is **repo-driven**.

Instead of relying on committed sample applications, users provide:
- GitHub repo URL
- optional branch

The scanner then:
1. acquires source code (clone/pull cache behavior),
2. auto-detects language stack(s),
3. generates SBOMs,
4. runs Trivy,
5. produces per-language and merged reports,
6. computes gate output.

Primary stacks supported:
- Node.js
- Java (Maven/Gradle)
- Python

---

## 2. Architecture (Current)

```text
User Input (repo URL + branch) or local path
        |
        v
Source Acquisition (clone first time, pull afterwards)
        |
        v
Auto Detection (node/python/java)
        |
        v
SBOM Generation (CycloneDX)
        |
        v
Trivy SBOM Scan (+ optional fs/secret/misconfig)
        |
        v
Report Merge + Gate Evaluation
        |
        v
Artifacts (per-language + consolidated)
```

---

## 3. Source Acquisition Logic
Implemented in: `sbom/src/index.ts`

Behavior:
- If `--source` is local path:
  - use it directly.
- If `--source` is GitHub URL:
  - first run: clone into cache location.
  - later runs: skip clone, run `git fetch --all --prune`, checkout branch, then pull.

Cache location:
- default: OS temp under `cycloguard-sbom-cache`
- optional override: `--workdir <path>`

---

## 4. Auto Detection Logic
Implemented in: `sbom/src/index.ts`

Detection markers:
- Node.js: `package.json`
- Python: `requirements.txt` or `pyproject.toml`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`

Execution behavior:
- One stack detected -> run only for that stack.
- Multiple stacks detected -> run for all detected stacks.
- Each stack gets separate Trivy report output.

---

## 5. SBOM + Trivy Execution

## 5.1 SBOM generation
- Node/Java: `cdxgen` (CycloneDX spec 1.5)
- Python: `cyclonedx-py` (CycloneDX spec 1.5)

## 5.2 Trivy scanning
- Per-SBOM scans: `trivy sbom <file>`
- Optional filesystem scan: `trivy fs <repo>`
- Optional secret/misconfig scanners controlled via CLI flags

## 5.3 Gate parsing
Implemented in: `sbom/scripts/parse_trivy_report.js`

Input:
- `trivy-merged.json`

Output:
- `gate-result.json` with:
  - `gate_failed`
  - `threshold`
  - `counts`
  - `total_vulnerabilities`
  - flattened vulnerability list

---

## 6. CLI Usage (Local-first)

Install:
```bash
cd sbom
npm install
```

Scan GitHub repository:
```bash
npx ts-node src/index.ts --source https://github.com/org/repo --branch main --output ./runs/repo-scan
```

Scan local repository path:
```bash
npx ts-node src/index.ts --source ../my-project --output ./runs/local-scan
```

Optional flags:
- `--threshold high|critical` (default `high`)
- `--fs-scan true|false` (default `true`)
- `--secret-scan true|false` (default `false`)
- `--misconfig-scan true|false` (default `false`)
- `--workdir <path>` (persistent cache root)

---

## 7. CI Workflow (Wrapper)
File: `.github/workflows/security-pipeline.yml`

What it does:
1. Installs runtime dependencies (Node, Python, Trivy)
2. Installs `sbom` CLI deps
3. Resolves source inputs:
   - manual run: uses provided repo/branch
   - push/PR: defaults to current repo/ref
4. Runs CLI (`sbom/src/index.ts`)
5. Uploads artifacts

Manual dispatch inputs:
- `source_repo`
- `source_branch`
- `threshold`

---

## 8. Artifact Outputs
Generated in the selected output directory (CI uses `sbom/reports/<run>-<attempt>`):

Core files:
- `detected-projects.json`
- `trivy-node.json`
- `trivy-java.json`
- `trivy-python.json`
- `trivy-fs.json`
- `trivy-results.sarif`
- `trivy-merged.json`
- `gate-result.json`

SBOM files:
- `sbom/node/*-cyclonedx.json`
- `sbom/java/*-cyclonedx.json`
- `sbom/python/*-cyclonedx.json`

Per-project Trivy files:
- `<lang>-<project-id>-trivy.json`

CI artifact uploads:
- full bundle: `security-reports-<run>-<attempt>`
- per-language summaries:
  - `trivy-node-<run>-<attempt>`
  - `trivy-java-<run>-<attempt>`
  - `trivy-python-<run>-<attempt>`

---

## 9. Files and Responsibilities

- `sbom/src/index.ts`
  - local scanner orchestration (source acquisition, detection, SBOM, Trivy, merge, gate)
- `sbom/scripts/parse_trivy_report.js`
  - gate evaluation logic
- `sbom/package.json`
  - CLI scripts and dependencies
- `sbom/tsconfig.json`
  - TypeScript configuration
- `.github/workflows/security-pipeline.yml`
  - CI wrapper around the same local scanner behavior

Scaffolded but currently not active in pipeline flow:
- `sbom/.github/actions/ai-fix/action.yml`
- `sbom/.github/actions/slack-notify/action.yml`
- `sbom/scripts/create_github_issue.js`
- `sbom/scripts/manage_reports.js`
- `sbom/scripts/build_slack_payload.js`

---

## 10. Important Changes from Earlier Design

Completed changes:
1. Removed committed vulnerable sample applications under `sbom/apps/`.
2. Shifted from fixed app paths to user-provided source repo/path.
3. Added clone-once then pull update behavior.
4. Added automatic language detection.
5. Added conditional per-stack execution and report generation.
6. Standardized local and CI behavior through the same scanner engine.

---

## 11. Current Limitations / Next Enhancements

1. SPDX output generation is not yet strict per ecosystem in this local CLI flow.
2. GitHub issue creation and Slack notifications are scaffolded but not enabled in active flow.
3. AI remediation and post-fix re-scan loop are not enabled in current workflow path.
4. Report history indexing is scaffolded but not integrated in latest CLI pipeline run path.

---

## 12. Quick Validation Checklist

1. Run CLI against a known mixed-stack repository.
2. Confirm `detected-projects.json` includes expected stacks.
3. Confirm per-language reports (`trivy-node.json`, `trivy-java.json`, `trivy-python.json`) are produced for detected stacks.
4. Confirm `gate-result.json` is generated.
5. In CI, confirm artifact uploads include full bundle + per-language artifacts.
