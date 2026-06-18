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

CycloGuard uses a centralized `pino` logger implementation shared across `sbom`, `cbom`, and `runner`.

- Shared implementation:
  - [common/logger.js](common/logger.js)
- This is the single source of truth for:
  - log format selection
  - log level handling
  - pretty local output vs JSON CI output
  - shared logger methods

## Pino Usage

The current logger API used across the repo supports these methods:

- `logger.info(message, meta?)`
  - Use for normal execution flow such as scan start, source resolution, generated output paths, and successful steps.
- `logger.warn(message, meta?)`
  - Use for non-blocking problems such as skipped steps, fallback behavior, or partial analysis failures.
- `logger.error(message, meta?)`
  - Use for blocking failures or conditions that lead to process exit.
- `logger.debug(message, meta?)`
  - Use for detailed diagnostics such as resolved paths, calculated inputs, or troubleshooting-only details.
- `logger.raw(message)`
  - Use when terminal-oriented output must be preserved exactly, such as banners, tables, summaries, or progress-friendly output.
- `logger.command(command)`
  - Use when printing shell command execution from scanner utilities.
- `logger.child(component)`
  - Use when a component-scoped logger is needed with attached context.

## Ways To Add Logs

There are multiple practical ways we add logs with `pino` in this project:

1. Plain message log

```js
logger.info('Running SBOM scan...');
```

2. Structured log with metadata

```js
logger.info('Gate summary generated', {
  gate_failed: gate.gate_failed,
  counts: gate.counts
});
```

3. Warning log

```js
logger.warn('Branch not found, cloning default branch instead');
```

4. Error log

```js
logger.error('No supported projects detected');
```

5. Debug log

```js
logger.debug('Resolved CodeQL query directories', {
  jsQueriesDir,
  javaQueriesDir
});
```

6. Raw output log

```js
logger.raw(JSON.stringify(gate, null, 2));
```

7. Shell command log

```js
logger.command('trivy --version');
```

8. Child logger

```js
const scanLogger = logger.child('scanner');
scanLogger.info('Starting stack scan');
```

## Format Control

Local runs default to pretty logs for readability.

CI defaults to JSON logs for machine-friendly output.

Environment variables:

- `CYCLOGUARD_LOG_FORMAT=pretty|json`
- `CYCLOGUARD_LOG_LEVEL=debug|info|warn|error`

Examples:

```bash
set CYCLOGUARD_LOG_FORMAT=pretty
set CYCLOGUARD_LOG_LEVEL=debug
```

## Logging Guidance

- Prefer `info`, `warn`, `error`, and `debug` for operational logging.
- Prefer structured metadata when the values may be useful for CI analysis or troubleshooting.
- Prefer `raw` only when output must remain visually formatted for users.
- Keep messages short and meaningful.
- Use `debug` for verbose internals, not for normal run flow.

## Where To Read More

- SBOM details:
  - [sbom/README.md](sbom/README.md)
- CBOM details:
  - [cbom/README.md](cbom/README.md)
