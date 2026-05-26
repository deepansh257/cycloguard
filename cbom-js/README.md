# cbom-js

A static analysis tool that scans JavaScript/TypeScript codebases for cryptographic vulnerabilities and generates a **Cryptography Bill of Materials (CBOM)** in [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) format.

It combines two scanning engines:
- **AST-based engine** — fast, registry-driven detection using `@typescript-eslint/typescript-estree`
- **CodeQL engine** *(optional)* — deep taint-flow analysis that tracks how secrets and weak algorithms flow through the codebase

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Options](#cli-options)
- [How It Works](#how-it-works)
  - [AST Engine](#ast-engine)
  - [CodeQL Engine](#codeql-engine)
  - [Result Deduplication](#result-deduplication)
- [CodeQL Setup](#codeql-setup)
  - [Download CodeQL](#download-codeql)
  - [Install Query Pack Dependencies](#install-query-pack-dependencies)
  - [Running with CodeQL](#running-with-codeql)
- [Caching](#caching)
  - [Repository Cache](#repository-cache)
  - [CodeQL Database Cache](#codeql-database-cache)
  - [Clearing the Cache](#clearing-the-cache)
- [Output Format](#output-format)
- [Project Structure](#project-structure)
- [Extending the Tool](#extending-the-tool)
- [.gitignore Recommendations](#gitignore-recommendations)

---

## Features

- Detects **weak cryptographic algorithms** — MD5, SHA-1, RC4, DES, and more
- Detects **insecure randomness** — `Math.random()`, `Date.now()` used in security contexts
- Detects **hardcoded secrets** — private keys, passwords, API keys in source code
- Detects **weak TLS configuration** — insecure protocol versions, weak cipher suites, disabled certificate validation
- Detects **JWT vulnerabilities** — weak algorithm selections in `jsonwebtoken`, `jose`
- **CodeQL taint analysis** *(optional)* — tracks data flow from secret sources to crypto sinks across the entire codebase
- Supports scanning **local directories** or **remote GitHub/GitLab/Bitbucket repositories**
- Generates **CycloneDX 1.6 CBOM JSON** with full evidence, CWE mappings, and quantum-safety ratings
- **Persistent caching** for both cloned repositories and CodeQL databases — repeat scans are fast

---

## Installation

```bash
git clone https://github.com/your-org/cbom-js
cd cbom-js
npm install
```

---

## Quick Start

**Scan a local directory:**
```bash
npx ts-node src/index.ts --source ./my-project --output cbom.json
```

**Scan a GitHub repository:**
```bash
npx ts-node src/index.ts --source https://github.com/org/repo --output cbom.json
```

**Scan with CodeQL taint analysis enabled:**
```bash
npx ts-node src/index.ts \
  --source https://github.com/juice-shop/juice-shop \
  --codeql \
  --codeql-path "C:\tools\codeql\codeql.exe" \
  --output cbom.json
```

---

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--source <path\|url>` | Local directory path or remote Git URL to scan | *(required)* |
| `--output <file>` | Output file path for the CBOM JSON | `cbom.json` |
| `--format <format>` | Output format (`cyclonedx`) | `cyclonedx` |
| `--codeql` | Enable CodeQL taint analysis pass | `false` |
| `--codeql-path <path>` | Absolute path to the `codeql` / `codeql.exe` binary | `codeql` (must be on PATH) |
| `--branch <name>` | Git branch to clone for remote sources | default branch |
| `--verbose` | Print every individual finding to the console | `false` |
| `--clear-cache` | Delete all cached repositories and CodeQL databases | `false` |

---

## How It Works

### AST Engine

The AST engine runs on every scan. It:

1. Discovers all `.js`, `.ts`, `.jsx`, `.tsx` files using `glob`
2. Parses each file into an AST using `@typescript-eslint/typescript-estree` with error-tolerant mode
3. Runs a suite of detectors over each AST:

| Detector | What it finds |
|----------|--------------|
| `hardcodedSecrets` | Secret literals assigned to sensitive variable names, insecure RNG (`Math.random`, `Date.now`) |
| `tlsDetector` | Weak TLS versions, cipher suites, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| `nodeCrypto` | Native `crypto` module calls — `createHash`, `createCipheriv`, etc. |
| `jwtDetector` | JWT algorithm selections in `jsonwebtoken`, `jose` |
| `cryptoLibs` | Third-party crypto libraries — `crypto-js`, `bcrypt`, `argon2`, and many more |
| `registryDetector` | Any library listed in `src/registry/libraries.json` |

All detectors return `CryptoFinding[]`. The orchestrator in `src/detectors/index.ts` aggregates and deduplicates them.

### CodeQL Engine

The CodeQL engine is optional and runs after the AST engine. It performs **taint-flow analysis** — rather than just finding where a weak algorithm is used, it tracks whether that value actually flows into a crypto function. This catches vulnerabilities that span multiple files or variable assignments that the AST engine cannot follow.

When `--codeql` is passed, the tool:

1. **Creates a CodeQL database** for the source directory (JavaScript/TypeScript extractor)
2. **Generates two QL queries at runtime** from the registry data in `libraries.json`:
   - `registry-<timestamp>.ql` — tracks hardcoded secrets flowing to any registered crypto sink
   - `weakalgo-<timestamp>.ql` — tracks weak algorithm names flowing into crypto function arguments
3. **Runs any static `.ql` files** found in `queries/` alongside the generated ones
4. **Parses the SARIF output** and converts findings to `CryptoFinding[]` via `bridgeCodeQLResults`
5. **Merges and deduplicates** CodeQL findings with AST findings

The generated queries are written to `queries/_generated/` (which is gitignored) and cleaned up after each run.

### Result Deduplication

When both engines run, findings are deduplicated by matching on `(algorithm, filePath, line)`. If the AST engine and CodeQL engine both find the same algorithm usage at the same location, only one finding is kept — the one with richer metadata (typically the AST finding, since it includes the actual code snippet).

---

## CodeQL Setup

### Download CodeQL

Download the CodeQL CLI bundle for your platform from the official GitHub release page:

👉 https://github.com/github/codeql-action/releases

Choose the `codeql-bundle-*.tar.gz` (Linux/macOS) or `codeql-bundle-win64.tar.gz` (Windows) asset — **not** the source code zip. The bundle includes the CLI and all language extractors including JavaScript.

Extract it to a permanent location, for example:
- Windows: `C:\tools\codeql\`
- macOS/Linux: `~/tools/codeql/`

The binary you need is:
- Windows: `C:\tools\codeql\codeql.exe`
- macOS/Linux: `~/tools/codeql/codeql`

> **Important:** Use the full absolute path when passing `--codeql-path`. Do not rely on adding it to PATH for the first run.

### Install Query Pack Dependencies

The generated queries depend on `codeql/javascript-all`. You need to install this dependency **once** before the first CodeQL scan:

```bash
# Navigate to the queries directory
cd <project-root>/queries

# Run pack install using your CodeQL binary
# Windows:
C:\tools\codeql\codeql.exe pack install

# macOS/Linux:
~/tools/codeql/codeql pack install
```

This creates `queries/codeql-pack.lock.yml` and downloads `codeql/javascript-all` into `~/.codeql/packages/`. You only need to do this once — subsequent runs reuse the cached packages.

Both `queries/qlpack.yml` and `queries/codeql-pack.lock.yml` should be committed to your repository so teammates do not need to run `pack install` themselves.

### Running with CodeQL

```bash
# Windows
npx ts-node src/index.ts \
  --source https://github.com/juice-shop/juice-shop \
  --codeql \
  --codeql-path "C:\tools\codeql\codeql.exe" \
  --output cbom.json

# macOS/Linux
npx ts-node src/index.ts \
  --source https://github.com/juice-shop/juice-shop \
  --codeql \
  --codeql-path "$HOME/tools/codeql/codeql" \
  --output cbom.json
```

> The first run will be slow (2–5 minutes for a large repo) because it builds the CodeQL database. Subsequent runs reuse the cached database and complete much faster — see [Caching](#caching).

---

## Caching

### Repository Cache

When scanning a remote Git URL, the repository is cloned once and cached at:

```
~/.cbom-js/cache/<host>__<org>__<repo>/
```

For example, `https://github.com/juice-shop/juice-shop` is cached at:
```
~/.cbom-js/cache/github.com__juice-shop__juice-shop/
```

On subsequent runs, the cached clone is reused and no network request is made. The cache is keyed by URL and branch, so scanning different branches creates separate cache entries.

If a clone fails midway (network error, disk full), the partial cache directory is automatically deleted so the next run retries from scratch.

### CodeQL Database Cache

CodeQL databases are cached at:

```
~/.cbom-js/codeql-dbs/<projectName>__<fingerprint>/
```

The fingerprint is derived from the **git commit SHA** of the source (for git repos) or a **hash of file modification times** (for local paths). This means:

- Same commit → cached database is reused ✅
- New commit or changed files → new database is built automatically ✅
- Failed database build → partial directory is deleted, next run retries ✅

### Clearing the Cache

To clear all cached repositories and CodeQL databases:

```bash
npx ts-node src/index.ts --clear-cache
```

Or manually delete:
```bash
# All caches
rm -rf ~/.cbom-js/

# Just repository clones
rm -rf ~/.cbom-js/cache/

# Just CodeQL databases
rm -rf ~/.cbom-js/codeql-dbs/
```

---

## Output Format

The output is a **CycloneDX 1.6 CBOM JSON** file. Each cryptographic finding becomes a `cryptoAsset` component with:

- `cryptoProperties` — algorithm primitive, quantum safety level, classical security level, OID
- `evidence.occurrences` — file path, line number, column offset
- `properties` — library source, weak flag, severity, CWE IDs, code snippet, detection source (`ast` or `codeql`)

Findings from the CodeQL engine are tagged with `"cbom-js:library": "codeql"` and `"cbom-js:detectionSource": "codeql"` so you can filter them.

Example component (CodeQL finding):
```json
{
  "type": "cryptoAsset",
  "name": "HARDCODED-SECRET",
  "properties": [
    { "name": "cbom-js:library",         "value": "codeql" },
    { "name": "cbom-js:detectionSource", "value": "codeql" },
    { "name": "cbom-js:severity",        "value": "CRITICAL" },
    { "name": "cbom-js:cwe",             "value": "CWE-321" },
    { "name": "cbom-js:notes",           "value": "CodeQL taint path: hardcoded key flows to crypto sink" },
    { "name": "cbom-js:codeSnippet",     "value": "const hmac = crypto.createHmac('sha256', privateKey)" }
  ]
}
```

---

## Project Structure

```
cbom-js/
├── src/
│   ├── index.ts                    ← CLI entry point, scan orchestration
│   ├── types.ts                    ← Shared TypeScript interfaces (CryptoFinding, ScanOptions, etc.)
│   ├── parser/
│   │   ├── astParser.ts            ← AST parsing and traversal helpers
│   │   └── fileScanner.ts          ← Recursive file discovery
│   ├── detectors/
│   │   ├── index.ts                ← Aggregates all detector results
│   │   ├── hardcodedSecrets.ts     ← Hardcoded secrets and insecure RNG
│   │   ├── tlsDetector.ts          ← Weak TLS configuration
│   │   ├── nodeCrypto.ts           ← Node.js native crypto module
│   │   ├── jwtDetector.ts          ← JWT algorithm detection
│   │   ├── cryptoLibs.ts           ← Third-party crypto libraries
│   │   ├── registryDetector.ts     ← Registry-driven library detection
│   │   └── codeqlBridge.ts         ← Converts CodeQL SARIF results to CryptoFinding[]
│   ├── cbom/
│   │   └── cbomGenerator.ts        ← Serialises findings to CycloneDX 1.6 JSON
│   ├── registry/
│   │   ├── libraries.json          ← Central detection rules and algorithm metadata
│   │   └── registryLoader.ts       ← Singleton registry loader with lookup helpers
│   └── utils/
│       ├── codeqlRunner.ts         ← CodeQL database creation, query generation, SARIF parsing
│       ├── githubSource.ts         ← Git clone with persistent cache
│       ├── reporter.ts             ← Console output (progress bars, tables)
│       └── detectorHelpers.ts      ← Re-exports AST helpers for detectors
├── queries/
│   ├── qlpack.yml                  ← Declares this as a CodeQL pack depending on codeql/javascript-all
│   ├── codeql-pack.lock.yml        ← Lock file generated by `codeql pack install` (commit this)
│   ├── codeql-config.yml           ← Optional: paths to exclude from CodeQL extraction
│   └── _generated/                 ← Runtime-generated .ql files (gitignored)
├── package.json
├── tsconfig.json
└── README.md
```

---

## Extending the Tool

**Add a new AST detector:**
1. Create `src/detectors/<name>.ts` exporting `detect<Name>(ast, filePath, source): CryptoFinding[]`
2. Register it in `src/detectors/index.ts`

**Add detection rules without writing code:**
Edit `src/registry/libraries.json` — add entries under `packages`, `algorithms`, `hardcodedPatterns`, or `tlsPatterns`. The registry loader picks up changes on the next run automatically.

**Add a static CodeQL query:**
Place any `.ql` file in the `queries/` directory. It will be picked up and run alongside the auto-generated queries on every CodeQL scan. The query must import `javascript` and the `qlpack.yml` dependency on `codeql/javascript-all` covers stdlib resolution.

**Exclude paths from CodeQL analysis:**
Edit `queries/codeql-config.yml`:
```yaml
paths-ignore:
  - frontend/src/assets/private   # vendored libraries
  - data/static/codefixes         # intentionally broken fixture files
```

---
