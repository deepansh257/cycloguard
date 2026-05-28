# Local Scanner Process Guide

## Overview
This document explains the full process executed by the CycloGuard SBOM local scanner.

Primary entrypoint:
- `sbom/src/index.ts`

Main goal:
- Accept a user-provided source repository (GitHub URL or local path)
- Auto-detect stack(s)
- Generate SBOM(s)
- Run Trivy scans
- Produce language-specific + merged security reports
- Compute gate result (`high` or `critical`)

---

## 1. Inputs
CLI command format:
```bash
npx ts-node src/index.ts --source <repo-url-or-local-path> --output <output-dir>
```

For example:
```bash
npx ts-node src/index.ts --source https://github.com/vulnerable-apps/juice-shop.git --branch master --output ./runs/repo-scan
```

Supported arguments:
- `--source` (required): GitHub URL or local path
- `--branch` (optional): branch to checkout when source is GitHub URL
- `--output` (optional): report output directory (default `sbom-output`)
- `--threshold` (optional): `high` or `critical` (default `high`)
- `--fs-scan` (optional): `true|false` (default `true`)
- `--secret-scan` (optional): `true|false` (default `false`)
- `--misconfig-scan` (optional): `true|false` (default `false`)
- `--workdir` (optional): custom cache location for cloned repos

---

## 2. Source Acquisition Flow

## 2.1 Local path source
If `--source` is a local directory:
- scanner validates existence
- scanner uses directory directly

## 2.2 GitHub URL source
If `--source` is a GitHub URL:
1. Build a stable cache directory name from URL.
2. If repo is not already cloned in cache:
   - perform `git clone --depth 1` (branch-aware)
3. If repo already exists in cache:
   - perform `git fetch --all --prune`
   - checkout requested branch (or current)
   - perform pull to refresh latest code

Windows path-length handling:
- scanner uses shorter default cache root (`C:\cg-sbom-cache`)
- clone uses `core.longpaths=true`

---

## 3. Tool Bootstrap (Auto-install)
Before scanning, scanner ensures required tools exist.

Tools:
- `cdxgen`
- `cyclonedx-py`
- `trivy`

Behavior:
- If tool exists -> use it
- If missing -> attempt install automatically

Install strategy:
- Windows: `winget` (fallback `choco`)
- macOS: `brew`
- Linux: apt-based install path

Windows post-install PATH refresh:
- scanner auto-discovers `trivy.exe`
- injects found directory into current process PATH
- avoids requiring terminal restart in most cases

---

## 4. Auto-detection of Technology Stack
Scanner recursively inspects repository files and detects projects by markers:

- Node/JS ecosystem:
  - `package.json`
  - React inferred from dependencies (`react`, `react-dom`)
  - Angular inferred from dependencies (`@angular/core`, `@angular/cli`)
- Python:
  - `requirements.txt`
  - `pyproject.toml`
- Java:
  - `pom.xml`
  - `build.gradle`
  - `build.gradle.kts`
- C#/.NET:
  - `*.csproj`
  - `*.sln`

Execution rule:
- single stack detected -> run only for that stack
- multiple stacks detected -> run for all detected stacks

---

## 5. SBOM Generation Process
For each detected project target:

- Node: `cdxgen -t nodejs`
- Java: `cdxgen -t java`
- C#: `cdxgen -t dotnet` (with generic fallback if needed)
- Python: `cyclonedx-py requirements`

Output location:
- `<output>/sbom/<language>/<project-id>-cyclonedx.json`

CycloneDX version target:
- spec version `1.5`

---

## 6. Trivy Scan Process
For each generated SBOM:
- run `trivy sbom` with configured threshold severity
- write per-project scan output

After per-project scans:
- merge per-project results into per-language reports:
  - `trivy-node.json`
  - `trivy-java.json`
  - `trivy-python.json`
  - `trivy-csharp.json`

Optional repository-wide scan:
- `trivy fs` JSON output -> `trivy-fs.json`
- optional SARIF output -> `trivy-results.sarif`

Final consolidated report:
- `trivy-merged.json`

---

## 7. Gate Evaluation
Gate parser script:
- `sbom/scripts/parse_trivy_report.js`

Input:
- `trivy-merged.json`

Logic:
- flatten vulnerabilities across all report keys
- count severities
- apply threshold (`high` or `critical`)

Output:
- `gate-result.json`
  - `gate_failed`
  - `threshold`
  - `counts`
  - `total_vulnerabilities`
  - flattened `vulnerabilities[]`

---

## 8. Output Artifacts
Typical output directory contents:

- `detected-projects.json`
- `sbom/node/*-cyclonedx.json`
- `sbom/java/*-cyclonedx.json`
- `sbom/python/*-cyclonedx.json`
- `sbom/csharp/*-cyclonedx.json`
- `node-*-trivy.json`
- `java-*-trivy.json`
- `python-*-trivy.json`
- `csharp-*-trivy.json`
- `trivy-node.json`
- `trivy-java.json`
- `trivy-python.json`
- `trivy-csharp.json`
- `trivy-fs.json`
- `trivy-results.sarif`
- `trivy-merged.json`
- `gate-result.json`

---

## 9. CI Relationship
CI workflow (`.github/workflows/security-pipeline.yml`) acts as a wrapper:
- installs runtime prerequisites
- calls same local scanner CLI
- uploads generated reports as artifacts

This keeps local and CI execution paths aligned.

---

## 10. Example Commands
Scan GitHub repository:
```bash
npx ts-node src/index.ts --source https://github.com/vulnerable-apps/juice-shop.git --branch master --output ./runs/repo-scan
```

Scan local repository:
```bash
npx ts-node src/index.ts --source ../my-project --output ./runs/local-scan --threshold high
```

Enable secret + misconfig scans:
```bash
npx ts-node src/index.ts --source ../my-project --output ./runs/full-scan --secret-scan true --misconfig-scan true
```

---

## 11. Troubleshooting Quick Notes
- `trivy not recognized` on Windows:
  - scanner now auto-installs and patches PATH for current process.
  - if still failing once, reopen terminal and rerun.
- clone failures due to long paths on Windows:
  - scanner uses short cache root and long-path git config.
- missing reports:
  - check generated `detected-projects.json` to verify stack detection.
