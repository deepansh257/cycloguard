# CycloGuard SBOM Scanner

CycloGuard SBOM is a repo-driven, local-first SBOM + Trivy scanner.

## What this builds
A local-first security scanner that accepts any GitHub repository URL (or local path), auto-detects tech stack, generates SBOM, runs Trivy, and saves artifacts.

Supported stacks:
- Node.js
- Java (Maven/Gradle)
- Python
- C# (.NET)
- React (auto-detected under Node.js)
- Angular (auto-detected under Node.js)

## Why this is needed
- No hardcoded sample apps needed in repo.
- Same flow can run against any target repository.
- Faster iteration locally (no need to push every change to test).
- Standardized SBOM + Trivy outputs for auditing and gates.

## Core behavior
1. User provides `--source` (`https://github.com/org/repo` or local path).
2. For GitHub URL:
   - First run: clone to temp/cache location.
   - Next runs: skip re-clone, do `git fetch/pull`.
3. Auto-detect project type(s) from repo contents.
4. If one stack detected: run only that stack.
5. If multiple stacks detected: run all detected stacks.
6. Generate separate Trivy reports per detected stack + merged report + gate summary.
7. Save all artifacts under provided output folder.

## Local usage
Install once:
```bash
cd cycloguard
npm install
```

Recommended full scan from the repository root:
```bash
npx cycloguard --source https://github.com/juice-shop/juice-shop --scan all --no-cache
```

This is the recommended top-level command when you want the unified CycloGuard flow. It is preferred over older `npm run scan -- --source ...` usage because it uses the CLI entrypoint directly and avoids shell-specific argument forwarding issues, especially on Windows PowerShell.

Run SBOM only from the `sbom/` package:

Scan GitHub repo:
```bash
cd sbom
npx ts-node src/index.ts --source https://github.com/org/repo --branch main --output ./runs/repo-scan
```

Scan local path:
```bash
npx ts-node src/index.ts --source ../some-project --output ./runs/local-scan
```

Optional flags:
- `--threshold high|critical` (default: `high`)
- `--fs-scan true|false` (default: `true`)
- `--secret-scan true|false` (default: `false`)
- `--misconfig-scan true|false` (default: `false`)
- `--workdir <path>` (custom persistent clone cache location)
- `--create-issues true|false` (default: `true`)
- `--notify-slack true|false` (default: `true`)
- `--github-repo <owner/repo>` (optional override for issue target)
- `--github-token <token>` (optional, otherwise env is used)
- `--slack-webhook <url>` (optional, otherwise env is used)

Local automation credentials:
- GitHub issues:
  - set `API_GITHUB_TOKEN` or `GITHUB_TOKEN`
  - optional `GITHUB_TARGET_REPO` to override target repo
- Slack:
  - set `SLACK_WEBHOOK_URL`
- If credentials are missing, the scanner still runs and produces reports; issue/slack actions are skipped gracefully.

How local issue creation works:
- `--source` or the scanned GitHub URL decides what repository is scanned.
- `GITHUB_TARGET_REPO` decides where the GitHub issue is created.
- If `GITHUB_TARGET_REPO` is not set, the scanner tries to infer the issue target repo from:
  - the provided GitHub source URL, or
  - the local repository `origin` remote URL.
- This means you can:
  - scan an external repo like Juice Shop
  - but create the issue in your own repository by setting `GITHUB_TARGET_REPO=owner/repo`
- Only the issue target repository needs:
  - GitHub Issues enabled
  - token access/permissions to create issues

Using a local `.env` file:
```env
API_GITHUB_TOKEN=your_github_token
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
GITHUB_TARGET_REPO=owner/repo
```

Notes:
- Place `.env` inside the `sbom/` folder for local runs.
- `.env` is ignored by Git and will not be committed.
- CLI flags still override `.env` values when both are provided.

Output isolation behavior:
- Scanner now creates a source-specific subfolder under `--output` automatically.
- Pattern: `<repo-or-folder-name>__<branch>__<YYYYMMDD-HHMMSS>`
- Example: `--output ./runs` with Juice Shop `master` creates:
  - `./runs/juice-shop__master__20260528-184255/`

Auto-detection markers:
- Node/React/Angular: `package.json` (framework inferred from dependencies)
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
- Python: `requirements.txt`, `pyproject.toml`
- C#: `.csproj`, `.sln`

## Outputs (artifacts)
Inside `--output` folder:
- `detected-projects.json`
- `sbom/<lang>/*-cyclonedx.json`
- `<lang>-<project-id>-trivy.json` (per detected project)
- `trivy-node.json`
- `trivy-java.json`
- `trivy-python.json`
- `trivy-csharp.json`
- `trivy-fs.json`
- `trivy-results.sarif`
- `trivy-merged.json`
- `gate-result.json`
- `issue-result.json` (when GitHub issue automation runs)
- `slack-payload.json` (when Slack notification payload is built)

## Source code structure (`sbom/src`)
- `index.ts`: thin orchestrator entrypoint
- `types.ts`: shared types
- `cli/args.ts`: CLI argument parsing
- `core/fs.ts`, `core/shell.ts`: shared file/shell utilities
- `source/acquire.ts`: clone/pull cache and source resolution
- `detectors/projects.ts`: auto-detection and language grouping
- `scanner/pipeline.ts`: SBOM generation + Trivy scan + merge
- `reports/gate.ts`: gate result generation
- `tools/bootstrap.ts`: tool checks + auto-install bootstrap

## CI workflow
- `.github/workflows/security-pipeline.yml`
  - wraps the same scanner flow for CI
  - supports workflow dispatch inputs (`source_repo`, `source_branch`, `issue_target_repo`, `threshold`)
  - creates or updates GitHub issues for `HIGH`/`CRITICAL` findings
  - sends Slack summaries for all severities
  - uploads full and per-language artifacts

Manual CI usage from GitHub Actions:
1. Open the `Security Pipeline` workflow in the repository Actions tab.
2. Click `Run workflow`.
3. Fill the workflow inputs:
   - `source_repo`: GitHub repository URL to scan
   - `source_branch`: branch to scan from that repo
   - `issue_target_repo`: optional `owner/repo` where the issue should be created
   - `threshold`: `high` or `critical`
4. Start the workflow and download the artifact bundle after completion.

Detailed workflow-dispatch steps:
1. Push the latest workflow changes to GitHub so the updated `Security Pipeline` is available.
2. Open the repository on GitHub.
3. Go to the `Actions` tab.
4. Select the `Security Pipeline` workflow from the left panel.
5. Click the `Run workflow` button on the right side.
6. Enter the scan inputs:
   - `source_repo`: full GitHub repo URL such as `https://github.com/vulnerable-apps/juice-shop.git`
   - `source_branch`: branch name such as `master`
   - `issue_target_repo`: optional `owner/repo` where issues should be created
   - `threshold`: choose `high` or `critical`
7. Click the final `Run workflow` button to start the scan.
8. Open the running workflow and check:
   - `Show resolved execution inputs`
   - `Show resolved issue target`
   - `Publish workflow summary`
9. After completion, verify:
   - artifact bundle is uploaded
   - Slack notification is sent
   - GitHub issue is created or updated in the configured target repo

Example manual CI inputs:
- `source_repo`: `https://github.com/vulnerable-apps/juice-shop.git`
- `source_branch`: `master`
- `issue_target_repo`: `your-username/your-repo`
- `threshold`: `high`

## Local full-flow usage
Example with repo URL + GitHub issue + Slack:
```bash
cd sbom
set API_GITHUB_TOKEN=your_token
set SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
set GITHUB_TARGET_REPO=your-username/your-repo
npx ts-node src/index.ts --source https://github.com/org/repo.git --branch main --output ./runs
```

Example behavior:
- scan source repo: `https://github.com/vulnerable-apps/juice-shop.git`
- issue target repo: `your-username/your-repo`
- Slack notification: sent using `SLACK_WEBHOOK_URL`

## Severity handling policy
- `CRITICAL` / `HIGH`:
  - included in gate failure logic
  - used to create or update a GitHub security issue
- `MEDIUM` / `LOW`:
  - included in reports and Slack summary
  - alert-only by default, no separate GitHub ticket created

## End-to-end process
1. Parse CLI inputs (`--source`, `--branch`, `--output`, scan flags).
2. Acquire source code:
   - local path: scan directly
   - GitHub URL: clone first time, then fetch/pull on later runs from cache
3. Ensure required tools exist (`cdxgen`, `cyclonedx-py`, `trivy`) with auto-install fallback.
4. Auto-detect stack(s) from project markers.
5. Generate CycloneDX SBOM per detected target.
6. Run Trivy against generated SBOMs.
7. Optionally run filesystem/secret/misconfig scan based on flags.
8. Merge language reports and build `trivy-merged.json`.
9. Evaluate gate threshold and write `gate-result.json`.
10. Save all outputs into run-isolated artifact folder.

## Source acquisition details
- GitHub source cache:
  - Windows default cache: `C:\\cg-sbom-cache`
  - Linux/macOS default cache: temp directory (`cycloguard-sbom-cache`)
- Branch handling:
  - First time clone honors `--branch` when provided.
  - Subsequent runs update existing clone with fetch + checkout + pull.
- Windows long path mitigation:
  - clone uses `core.longpaths=true`
  - shorter cache root used to reduce path length issues.

## Tool bootstrap behavior
- If missing, scanner attempts automatic install:
  - Windows: `winget` (fallback `choco`)
  - macOS: `brew`
  - Linux: apt-based install flow
- On Windows, after Trivy install, scanner attempts PATH refresh in-process so run can continue without manual restart.

## CI execution model
- Manual (`workflow_dispatch`):
  - uses provided `source_repo` and `source_branch` when set
  - can route issue creation into `issue_target_repo` when provided
- Push/PR:
  - defaults to scanning checked-out workspace (`.`) to avoid PR synthetic branch issues.
- CI artifact uploads:
  - full bundle: `security-reports-<run>-<attempt>`
  - per-language: node/java/python/csharp Trivy summaries.

Local vs CI behavior:
- Local:
  - can scan external GitHub repo URLs directly
  - can create GitHub issues and send Slack using `.env` or CLI-provided credentials
- CI:
  - usually scans the checked-out workspace by default
  - can also scan external repos through manual dispatch inputs
  - uses GitHub Secrets instead of `.env`

## Validation checklist
1. Run scanner against known repo (single-stack and multi-stack examples).
2. Check `detected-projects.json` includes expected targets.
3. Verify per-language reports are present for detected stacks.
4. Verify `trivy-merged.json` and `gate-result.json` are generated.
5. In CI, confirm full bundle + per-language artifacts upload.

## Troubleshooting
- `trivy` not recognized:
  - install may have succeeded but PATH may need refresh; rerun in new terminal if needed.
- Git clone branch not found in CI:
  - ensure manual input branch exists remotely; push/PR scans should use local checkout.
- Missing reports:
  - inspect `detected-projects.json` first to confirm stack detection occurred.

## Current limitations / next enhancements
- Strict SPDX generation per ecosystem is not fully implemented yet.
- GitHub issue creation depends on the target repo having Issues enabled and token access.
- Historical report indexing is enabled, but can be expanded further for richer audit workflows.

## Note
The old committed vulnerable sample applications under `sbom/apps/` were removed per updated approach. Scanning target is now always user-provided source repo/path.
