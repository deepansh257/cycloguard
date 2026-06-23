# CycloGuard

CycloGuard is a repository security analysis framework that helps scan source code repositories for both:

- **software supply-chain risks** through SBOM generation and dependency vulnerability scanning
- **cryptographic risks** through CBOM generation and crypto misuse detection

It is designed to work against real repositories instead of hardcoded demo apps. A user can provide a local path or a repository URL, and CycloGuard can clone or reuse the source, detect the project stack, run the required scanners, generate reports, and support follow-up automation such as GitHub issues, Slack alerts, and remediation workflows.

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
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o-mini
ENABLE_AI_REMEDIATION=true
REMEDIATION_BASE_BRANCH=main
GIT_USER_NAME=CycloGuard Bot
GIT_USER_EMAIL=your-email@example.com
```

## Report and Artifact Model

CycloGuard stores outputs in a run-specific directory so each scan remains isolated.

Typical outputs can include:

- SBOM files
- CBOM files
- Trivy reports
- gate summary files
- automation results such as issue or Slack payload files
- remediation and re-scan artifacts

This makes the framework easier to audit, debug, and extend.

## Central Logging

CycloGuard uses centralized `pino` logging shared across `sbom`, `cbom`, and `runner`.

- Shared implementation:
  - [common/logger.js](common/logger.js)

## Where To Read More

- SBOM details:
  - [sbom/README.md](sbom/README.md)
- CBOM details:
  - [cbom/README.md](cbom/README.md)
