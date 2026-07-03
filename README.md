# CycloGuard

CycloGuard is a repository security analysis framework that helps scan source code repositories for both:

- **software supply-chain risks** through SBOM generation and dependency vulnerability scanning
- **cryptographic risks** through CBOM generation and crypto misuse detection

It is designed to work against real repositories instead of hardcoded demo apps. A user can provide a local path or a repository URL, and CycloGuard can clone or reuse the source, detect the project stack, run the required scanners, generate reports, and support follow-up automation such as GitHub issues, Slack alerts, and remediation workflows.

## Project Structure

```text
cycloguard/
|-- bin/                    # Cross-platform CLI entrypoints
|-- cbom/                   # Crypto scanning and CBOM generation
|-- common/                 # Shared utilities such as centralized logging
|-- remediation/            # AI planning, approval, and remediation apply flow
|   |-- src/
|   |   |-- providers/      # OpenAI, Anthropic, Gemini provider adapters
|   |   |-- apply.ts        # Deterministic apply engine
|   |   |-- apply-index.ts  # Apply CLI entrypoint
|   |   |-- args.ts         # Planning CLI argument parsing
|   |   |-- apply-args.ts   # Apply CLI argument parsing
|   |   |-- artifact-loader.ts
|   |   |-- context-builder.ts
|   |   |-- env.ts
|   |   |-- index.ts        # Planning entrypoint
|   |   |-- planner.ts
|   |   |-- report-writer.ts
|   |   |-- types.ts
|-- runner/                 # Unified scan orchestration
|-- sbom/                   # Dependency scanning and SBOM generation
|-- cycloguard-output/      # Per-run scan and remediation artifacts
|-- .env.example            # Shared environment reference
|-- package.json            # Root scripts and CLI configuration
`-- README.md               # Root project documentation
```

## What CycloGuard Contains

- `sbom/`
  - Generates Software Bills of Materials
  - Runs Trivy against detected ecosystems
  - Evaluates gate results based on vulnerability severity
  - Supports GitHub issue creation, Slack notification, and remediation flow
- `cbom/`
  - Generates Cryptography Bills of Materials
  - Detects insecure cryptographic usage in code
  - Supports AST-based scanning and optional CodeQL-based deep analysis
  - Supports remediation flow for crypto findings
- `runner/`
  - Acts as the unified entrypoint for running SBOM and CBOM together
  - Creates a common run folder and organizes outputs
- `remediation/`
  - Generates AI-assisted remediation plans from SBOM and CBOM findings
  - Supports provider-based planning through OpenAI, Anthropic, or Gemini
  - Creates human approval files for reviewed remediation items
  - Applies approved deterministic fixes such as exact replacements and dependency upgrades
  - Records remediation apply results per run
- `common/`
  - Stores shared cross-project utilities
  - Currently holds the centralized Pino logger implementation

## Why CycloGuard Is Needed

Modern repositories are risky in more than one way.

- Dependencies can contain known CVEs
- Projects may use weak or insecure cryptography
- Large repositories often contain multiple stacks such as Node.js, Java, Python, and C#
- Security findings need to be reported clearly and consistently
- Teams need the same workflow to work both locally and in CI

CycloGuard addresses this by providing one framework that can:

- accept a real repository as input
- auto-detect the stack
- generate security artifacts
- evaluate the findings
- trigger automation after the scan

## High-Level Flow

At a high level, CycloGuard works like this:

1. User provides a local path or repository URL.
2. CycloGuard resolves the source:
   - local path is scanned directly
   - remote repository is cloned or reused from cache
3. The project structure is inspected to determine which technology stacks are present.
4. SBOM and/or CBOM workflows are executed depending on what the user runs.
5. Reports are generated and stored in an isolated run directory.
6. Optional automation can create issues, notify Slack, or begin remediation steps.

## Overall Flow

CycloGuard now supports both scanning and a controlled remediation workflow.

### 1. Source Resolution

- Local paths are scanned directly
- GitHub repositories are cloned or reused from CycloGuard cache
- `--no-cache` forces a fresh clone for the run

### 2. Stack Detection

- The runner inspects the source tree
- It identifies supported ecosystems such as Node.js, Python, Java, and C#

### 3. SBOM and CBOM Execution

- SBOM generates dependency inventories and vulnerability results
- CBOM detects crypto misuse and related code-level findings
- Outputs are written into a per-run folder under `cycloguard-output/`

### 4. Dashboard and Automation

- A consolidated dashboard is generated for the run
- Slack notification and issue automation can use the generated findings

### 5. AI Remediation Planning

When remediation is enabled, CycloGuard:

- reads SBOM and CBOM findings from the current run
- normalizes them into a common remediation context
- sends that context to the configured AI provider, or falls back to local rule-based planning
- writes remediation outputs into the same run folder

Generated remediation artifacts:

- `remediation/remediation-plan.json`
- `remediation/remediation-summary.md`
- `remediation/remediation-approval.json`

### 6. Human Approval

- Remediation items are initially created as `proposed`
- A reviewer updates `remediation-approval.json`
- Only items marked `approved` are eligible for apply

### 7. Deterministic Remediation Apply

The first apply implementation is intentionally limited to low-risk deterministic operations:

- exact text replacement
- structured dependency upgrades

CycloGuard does not currently allow free-form AI rewriting of source files.

Apply results are written to:

- `remediation/remediation-apply-result.json`

### 8. Next Planned Stage

The current implementation stops after apply-result generation.

The next stage is:

- validation / re-scan after apply
- branch or PR creation
- tighter approval-to-apply workflow automation

## SBOM Capability

The SBOM side of CycloGuard focuses on dependency and supply-chain visibility.

It can:

- detect supported ecosystems automatically
- generate CycloneDX SBOM files
- run Trivy against the generated SBOMs
- merge and summarize vulnerability data
- create gate results such as pass/fail based on threshold
- support issue creation and Slack summaries
- support remediation and re-scan workflows

Supported and commonly handled stacks include:

- Node.js
- Java
- Python
- C#
- frontend frameworks such as React and Angular when detected under Node.js projects

## CBOM Capability

The CBOM side of CycloGuard focuses on insecure cryptographic usage inside the codebase.

It can:

- scan source files for risky crypto patterns
- detect weak algorithms such as MD5, SHA-1, RC4, DES, and related misuse
- detect insecure randomness and hardcoded secrets
- inspect weak TLS and crypto library usage
- optionally run CodeQL to perform deeper taint-flow analysis
- generate a CycloneDX-style CBOM JSON output
- support remediation planning based on generated findings

## Local-First and CI-Friendly

CycloGuard is built so that the same ideas work in both environments:

- **Local usage**
  - faster iteration during development
  - direct scanning of arbitrary repositories
  - easier manual validation of reports and remediation
- **CI usage**
  - repeatable execution in GitHub Actions
  - workflow-dispatch support for repository input
  - automation for issue creation, Slack alerts, and report artifacts

## Shared Environment Configuration

Use [`.env.example`](.env.example) as the reference for the root `.env` file.

Example entries used in the project:

```env
API_GITHUB_TOKEN=your_github_token
GITHUB_TARGET_REPO=owner/repo
SLACK_WEBHOOK_URL=slack_webhook_url
AI_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o-mini
ANTHROPIC_API_KEY=your_anthropic_api_key
ANTHROPIC_MODEL=claude-sonnet-4-20250514
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-2.5-flash
ENABLE_AI_REMEDIATION=true
REMEDIATION_BASE_BRANCH=main
GIT_USER_NAME=CycloGuard Bot
GIT_USER_EMAIL=your-email@example.com
```

AI remediation provider selection currently supports:

- `openai`
- `anthropic`
- `gemini`

## Recommended Scan Command

Use the CycloGuard CLI entrypoint directly when scanning a repository:

```bash
npx cycloguard --source <repo> --scan all --no-cache
```

Example:

```bash
npx cycloguard --source https://github.com/juice-shop/juice-shop --scan all --no-cache
```

This command is now recommended instead of older forms such as:

```bash
npm run scan -- --source <repo> --scan all
```

Why this was changed:

- `npx cycloguard ...` uses the project CLI entrypoint directly
- it avoids shell-specific argument forwarding issues seen with `npm run ... -- ...`, especially on Windows PowerShell
- it keeps the execution path consistent across Windows, macOS, and Linux
- `--no-cache` is useful when validating fresh repository state instead of reusing a previously cached clone

In short, the command was updated for better cross-platform reliability and more predictable argument handling.

To run scanning together with remediation planning:

```bash
npx cycloguard --source <repo> --scan all --no-cache --enable-remediation
```

Example:

```bash
npx cycloguard --source https://github.com/juice-shop/juice-shop --scan all --no-cache --enable-remediation
```

Expected remediation log signals:

```text
Remediation planner: using AI-generated planning via provider 'gemini'.
Remediation planning mode: ai
Remediation planning provider: gemini
```

## SBOM Troubleshooting

In some repositories, especially older Node.js/Angular projects or forks without a committed lockfile, SBOM generation may complete but the dashboard can still show:

- `0 dependency vulnerabilities`
- an empty or very small CycloneDX SBOM
- npm `ERESOLVE unable to resolve dependency tree` messages in the logs

Why this happens:

- `cdxgen` may need to resolve dependencies dynamically when a repository does not provide a usable lockfile
- during that step, npm can fail on peer-dependency conflicts
- when npm dependency resolution fails, the generated SBOM may be empty or lower-precision, so Trivy has little or nothing to scan for dependency CVEs

Likely log signal:

```text
npm install has failed. Generated SBOM will be empty or with a lower precision.
Set the environment variable NPM_INSTALL_ARGS=--legacy-peer-deps to resolve the dependency resolution issue reported.
```

Recommended workaround for that case:

```powershell
$env:NPM_INSTALL_ARGS="--legacy-peer-deps"
npx cycloguard --source <repo> --scan all --no-cache
```

Example:

```powershell
$env:NPM_INSTALL_ARGS="--legacy-peer-deps"
npx cycloguard --source https://github.com/vulnerable-apps/juice-shop.git --scan all --no-cache
```

What `legacy-peer-deps` does:

- it tells npm to ignore strict peer-dependency resolution failures and continue using the older install behavior
- this helps `cdxgen` generate an SBOM for repositories with legacy or inconsistent dependency trees
- it is a compatibility workaround for SBOM generation and does not actually fix the upstream dependency conflict in the scanned repository

## Report and Artifact Model

CycloGuard stores outputs in a run-specific directory so each scan remains isolated.

Typical outputs can include:

- SBOM files
- CBOM files
- Trivy reports
- gate summary files
- automation results such as issue or Slack payload files
- remediation plan, approval, and apply-result artifacts

Typical run folder structure:

```text
cycloguard-output/
`-- <project>__<branch>__<timestamp>/
    |-- cbom/
    |   `-- cbom.json
    |-- sbom/
    |   |-- gate-result.json
    |   `-- ...
    |-- remediation/
    |   |-- remediation-plan.json
    |   |-- remediation-summary.md
    |   |-- remediation-approval.json
    |   `-- remediation-apply-result.json
    `-- dashboard.html
```

This makes the framework easier to audit, debug, and extend.

## Remediation Workflow

### Generate the plan

Run a scan with remediation enabled:

```powershell
npx cycloguard --source https://github.com/juice-shop/juice-shop --scan all --no-cache --enable-remediation
```

### Review and approve items

Open:

- `remediation/remediation-plan.json`
- `remediation/remediation-summary.md`
- `remediation/remediation-approval.json`

Change selected approval entries from `proposed` to `approved`.

### Apply approved remediations

Run the apply command against the run directory:

```powershell
npm run remediation:apply -- --run-dir "C:\Users\RahulSharma\cycloguard\cycloguard-output\<run-folder>"
```

Notes:

- `--run-dir` must point to the run folder itself
- not to the `remediation` folder
- not to `remediation-approval.json`

### Review apply results

Open:

- `remediation/remediation-apply-result.json`

Current apply behavior:

- `applied` means the item was approved and the operation was deterministic and supported
- `skipped` means the item was approved but not safe or supported for auto-apply
- `failed` means CycloGuard attempted the operation but the expected file or text state did not match

Current supported auto-apply operations:

- exact `replace`
- deterministic `upgrade`

Current unsupported auto-apply operations:

- `manual` operations
- broad or ambiguous AI-authored changes

## Central Logging

CycloGuard uses centralized `pino` logging shared across `sbom`, `cbom`, and `runner`.

- Shared implementation:
  - [common/logger.js](common/logger.js)

## Where To Read More

- SBOM details:
  - [sbom/README.md](sbom/README.md)
- CBOM details:
  - [cbom/README.md](cbom/README.md)
