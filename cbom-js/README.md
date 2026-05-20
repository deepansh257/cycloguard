# cycloguard
CycloneDX-native security orchestration platform that generates SBOMs and CBOMs, detects dependency and cryptographic risks, automates remediation workflows, and delivers actionable security intelligence through GitHub and Slack integrations.


**Cryptography Bill of Materials (CBOM) generator for JavaScript, TypeScript, and Node.js projects.**

Scans your source code — or any public GitHub repository — to detect every cryptographic algorithm, library, and pattern in use, then outputs a structured [CycloneDX 1.6](https://cyclonedx.org/) CBOM. Designed to slot directly into your CI/CD pipeline alongside SBOM and vulnerability scanning.

---

## What It Detects

| Category | Examples |
|---|---|
| **Node.js `crypto` module** | `createHash`, `createCipheriv`, `createSign`, `generateKeyPair`, `pbkdf2`, `scrypt` |
| **JWT libraries** | `jsonwebtoken`, `jose`, `jwt-simple` — algorithm extraction (`HS256`, `RS256`, `none`) |
| **Crypto libraries** | `crypto-js`, `node-forge`, `bcrypt`, `argon2`, `elliptic`, `tweetnacl`, `libsodium` |
| **TLS/HTTPS config** | Weak versions (`TLSv1`, `SSLv3`), disabled cert validation, weak cipher suites |
| **Hardcoded secrets** | Keys/secrets assigned to variables, `Math.random()` for crypto, `Date.now()` as entropy |

### Severity Ratings

| Severity | Examples |
|---|---|
| `CRITICAL` | MD5, RC4, DES, `algorithm: 'none'` in JWT, `rejectUnauthorized: false`, hardcoded secrets |
| `HIGH` | SHA-1, 3DES, ECB mode, `Math.random()` for crypto, TLSv1/TLSv1.1 |
| `MEDIUM` | RSA/ECDSA/DH (quantum-vulnerable but classically sound), RSA < 4096-bit |
| `LOW` | Minor configuration concerns |
| `INFO` | Secure algorithms noted for inventory (SHA-256, AES-256-GCM, BCRYPT, ARGON2) |

### CWEs Mapped

- `CWE-327` — Use of a Broken or Risky Cryptographic Algorithm
- `CWE-326` — Inadequate Encryption Strength
- `CWE-338` — Use of Cryptographically Weak PRNG
- `CWE-321` — Use of Hard-coded Cryptographic Key
- `CWE-295` — Improper Certificate Validation
- `CWE-347` — Improper Verification of Cryptographic Signature

---

## Prerequisites

- **Node.js** >= 18.x
- **npm** >= 9.x
- **Git** (required only when scanning GitHub repositories)

Verify:
```bash
node --version   # >= 18.0.0
npm --version    # >= 9.0.0
git --version    # any recent version
```

---

## Installation

### Option A — Run from source (recommended for development)

```bash
# 1. Clone this repository
git clone https://github.com/your-org/cbom-js.git
cd cbom-js

# 2. Install dependencies
npm install

# 3. Run directly with ts-node (no build needed)
npm run scan -- --source ./path/to/project --output cbom.json
```

### Option B — Build and install globally

```bash
# Build TypeScript
npm run build

# Install globally so 'cbom-js' works from anywhere
npm install -g .

# Verify
cbom-js --version
```

---

## Usage

### Basic syntax

```
cbom-js [options]
```

### All options

| Option | Alias | Default | Description |
|---|---|---|---|
| `--source <path-or-url>` | `-s` | *(required)* | Local directory path **or** GitHub URL |
| `--output <file>` | `-o` | `cbom.json` | Output file path |
| `--branch <name>` | `-b` | default branch | Git branch (only used with GitHub URLs) |
| `--fail-on-weak` | | `false` | Exit code 1 if any weak algorithms found |
| `--fail-on-severity <level>` | | none | Exit code 1 if findings at or above this severity (`CRITICAL`, `HIGH`, `MEDIUM`) |
| `--verbose` | `-v` | `false` | Print all findings including INFO |
| `--exclude <patterns>` | | see below | Comma-separated glob patterns to exclude |
| `--include <patterns>` | | `**/*.js,**/*.ts,...` | Comma-separated glob patterns to include |
| `--help` | `-h` | | Show help |
| `--version` | | | Show version |

---

## Scanning a Local Project

### Scan current directory

```bash
cbom-js --source .
```

### Scan a specific folder

```bash
cbom-js --source ./my-node-app
```

### Write output to a specific file

```bash
cbom-js --source ./my-node-app --output ./reports/cbom.json
```

### Verbose output (show all findings including INFO)

```bash
cbom-js --source ./my-node-app --verbose
```

### Fail if any weak algorithms are found (for CI gating)

```bash
cbom-js --source ./my-node-app --fail-on-weak
echo "Exit code: $?"   # 1 if weak crypto found, 0 if clean
```

### Fail if any CRITICAL or HIGH findings exist

```bash
cbom-js --source ./my-node-app --fail-on-severity HIGH
```

### Exclude test files and vendor folders

```bash
cbom-js \
  --source ./my-node-app \
  --exclude "**/test/**,**/vendor/**,**/__mocks__/**"
```

---

## Scanning a GitHub Repository

cbom-js clones the repository into a temporary directory, scans it, then cleans up automatically.

### Scan the default branch

```bash
cbom-js --source https://github.com/juice-shop/juice-shop
```

### Scan a specific branch

```bash
cbom-js \
  --source https://github.com/juice-shop/juice-shop \
  --branch develop
```

### Scan a specific tag or branch by name

```bash
cbom-js \
  --source https://github.com/keycloak/keycloak \
  --branch main \
  --output keycloak-cbom.json
```

### Scan with .git suffix (also works)

```bash
cbom-js --source https://github.com/juice-shop/juice-shop.git
```

### Full example — scan, output, and fail on critical

```bash
cbom-js \
  --source https://github.com/juice-shop/juice-shop \
  --branch master \
  --output ./reports/juiceshop-cbom.json \
  --fail-on-severity CRITICAL \
  --verbose
```

### Private repositories

For private repos, ensure your machine has SSH access configured:

```bash
# Use SSH URL instead of HTTPS
cbom-js --source git@github.com:your-org/private-repo.git --branch main
```

Or set up a GitHub token via git credential helper before running.

---

## Example Output (Console)

```
 ██████╗██████╗  ██████╗ ███╗   ███╗      ██╗███████╗
██╔════╝██╔══██╗██╔═══██╗████╗ ████║      ██║██╔════╝
...

▶ Scan Target:  https://github.com/juice-shop/juice-shop
▶ Cloning repository...
▶ Files Found:  147

  ██████████████████████████████ 100% (147/147)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Severity Breakdown:
    [ CRIT ]    8
    [ HIGH ]   12
    [ MED  ]    6
    [ LOW  ]    0
    [ INFO ]   11

  Total Crypto Assets:    37
  Weak Algorithms:        20
  Quantum Vulnerable:      6
  Files Scanned:         147
  Duration:             3241ms

  Findings Detail:

  [ CRIT ] MD5 · node:crypto
           lib/insecurity.ts:42
           ↳ CWE-327

  [ CRIT ] HARDCODED-SECRET · source-code
           lib/insecurity.ts:7
           ↳ Hardcoded value in variable 'jwtSecret' — use environment variables instead
           ↳ CWE-321, CWE-798

  [ HIGH ] SHA-1 · node:crypto
           routes/vulnCodeSnippet.js:89
           ↳ CWE-327
...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓ CBOM written to: ./juiceshop-cbom.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## CBOM Output Format (CycloneDX 1.6)

The output is a valid [CycloneDX 1.6](https://cyclonedx.org/specification/overview/) CBOM JSON file.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:a1b2c3d4-...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-19T10:30:00.000Z",
    "tools": [{ "name": "cbom-js", "version": "1.0.0" }],
    "component": {
      "type": "application",
      "name": "juice-shop"
    },
    "properties": [
      { "name": "cbom-js:filesScanned", "value": "147" },
      { "name": "cbom-js:totalFindings", "value": "37" },
      { "name": "cbom-js:criticalFindings", "value": "8" },
      { "name": "cbom-js:weakAlgorithms", "value": "20" },
      { "name": "cbom-js:quantumVulnerable", "value": "6" }
    ]
  },
  "components": [
    {
      "type": "cryptoAsset",
      "bom-ref": "crypto:md5:lib/insecurity.ts:42",
      "name": "MD5",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "hash",
          "executionEnvironment": "software",
          "implementationPlatform": "node.js",
          "cryptoFunctions": ["digest"],
          "nistQuantumSecurityLevel": 1,
          "classicalSecurityLevel": 0
        }
      },
      "evidence": {
        "occurrences": [
          {
            "location": "lib/insecurity.ts",
            "line": 42,
            "symbol": "MD5"
          }
        ]
      },
      "properties": [
        { "name": "cbom-js:library", "value": "node:crypto" },
        { "name": "cbom-js:weak", "value": "true" },
        { "name": "cbom-js:severity", "value": "CRITICAL" },
        { "name": "cbom-js:cwe", "value": "CWE-327" },
        { "name": "cbom-js:codeSnippet", "value": "const hash = crypto.createHash('md5')" }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CWE-327",
      "source": {
        "name": "CWE",
        "url": "https://cwe.mitre.org/data/definitions/327.html"
      },
      "ratings": [{ "severity": "critical", "method": "other" }],
      "description": "MD5 is a cryptographically broken hash function vulnerable to collision attacks"
    }
  ]
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/cbom.yml
name: CBOM Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  cbom-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install cbom-js
        run: |
          git clone https://github.com/your-org/cbom-js.git
          cd cbom-js && npm install && npm run build && npm install -g .

      - name: Run CBOM Scan
        run: |
          cbom-js \
            --source . \
            --output cbom.json \
            --fail-on-severity HIGH

      - name: Upload CBOM Artifact
        uses: actions/upload-artifact@v4
        if: always()   # upload even on failure
        with:
          name: cbom-report
          path: cbom.json
          retention-days: 90
```

### Full security pipeline with Trivy + CBOM

```yaml
name: Security Pipeline

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      # Step 1: Generate SBOM + scan with Trivy
      - name: Trivy — SBOM + CVE scan
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
          ./bin/trivy fs . \
            --format cyclonedx \
            --output sbom.json
          ./bin/trivy fs . \
            --format json \
            --output trivy-report.json \
            --severity CRITICAL,HIGH \
            --exit-code 1

      # Step 2: CBOM scan
      - name: Install cbom-js
        run: |
          git clone https://github.com/your-org/cbom-js.git /tmp/cbom-js
          cd /tmp/cbom-js && npm install && npm run build && npm install -g .

      - name: Generate CBOM
        run: |
          cbom-js \
            --source . \
            --output cbom.json \
            --fail-on-severity CRITICAL

      # Step 3: Upload all artifacts
      - name: Upload Security Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: |
            sbom.json
            trivy-report.json
            cbom.json
```

### GitLab CI

```yaml
cbom-scan:
  stage: security
  image: node:20
  script:
    - git clone https://github.com/your-org/cbom-js.git /tmp/cbom-js
    - cd /tmp/cbom-js && npm install && npm run build && npm install -g .
    - cd $CI_PROJECT_DIR
    - cbom-js --source . --output cbom.json --fail-on-severity HIGH
  artifacts:
    paths:
      - cbom.json
    expire_in: 90 days
    when: always
```

---

## Scanning Popular Repositories (Quick Start)

Try cbom-js immediately on well-known open source projects:

```bash
# OWASP Juice Shop — intentionally vulnerable, great for testing
cbom-js --source https://github.com/juice-shop/juice-shop --output juiceshop-cbom.json

# Express.js
cbom-js --source https://github.com/expressjs/express --output express-cbom.json

# Keycloak (Java-heavy but has JS frontend)
cbom-js --source https://github.com/keycloak/keycloak --output keycloak-cbom.json

# Socket.io
cbom-js --source https://github.com/socketio/socket.io --output socketio-cbom.json

# Next.js
cbom-js --source https://github.com/vercel/next.js --branch canary --output nextjs-cbom.json
```

---

## Project Structure

```
cbom-js/
├── src/
│   ├── index.ts                    ← CLI entry point
│   ├── types.ts                    ← shared TypeScript interfaces
│   ├── parser/
│   │   ├── astParser.ts            ← AST parsing + traversal helpers
│   │   └── fileScanner.ts          ← directory walker, file finder
│   ├── detectors/
│   │   ├── index.ts                ← orchestrates all detectors
│   │   ├── nodeCrypto.ts           ← node:crypto built-in detection
│   │   ├── jwtDetector.ts          ← jsonwebtoken / jose detection
│   │   ├── cryptoLibs.ts           ← crypto-js, bcrypt, forge, etc.
│   │   ├── tlsDetector.ts          ← TLS/HTTPS config weaknesses
│   │   └── hardcodedSecrets.ts     ← hardcoded keys, Math.random()
│   ├── cbom/
│   │   └── cbomGenerator.ts        ← CycloneDX 1.6 CBOM output
│   └── utils/
│       ├── githubSource.ts         ← GitHub clone / local path resolver
│       └── reporter.ts             ← console output, tables, progress
├── package.json
├── tsconfig.json
└── README.md
```

---

## How It Works

### 1. Source Resolution
If the input is a GitHub URL, the repository is cloned shallowly (`--depth 1`) into a temp directory. Local paths are resolved as-is. Temp directories are cleaned up automatically after the scan.

### 2. File Discovery
All `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs` files are collected recursively, excluding `node_modules`, `dist`, `build`, test files, and minified bundles by default.

### 3. AST Parsing
Each file is parsed into an Abstract Syntax Tree using `@typescript-eslint/typescript-estree`, which handles both JavaScript and TypeScript natively. Malformed files are skipped with a warning.

### 4. Detection
Five detectors run against every file's AST simultaneously:
- **nodeCrypto** — walks `CallExpression` nodes looking for `crypto.*` calls
- **jwtDetector** — finds JWT library imports and extracts algorithm values
- **cryptoLibs** — recognizes 15+ crypto library import patterns
- **tlsDetector** — checks `Property` nodes for TLS config keys
- **hardcodedSecrets** — matches variable names against secret patterns

### 5. CBOM Generation
Findings are mapped to the [CycloneDX 1.6 `cryptoAsset` component type](https://cyclonedx.org/specification/overview/), with primitive classification, OID mapping, quantum safety level, CWE references, and code location evidence.

---

## Extending cbom-js

### Adding a new detector

Create `src/detectors/myLibrary.ts`:

```typescript
import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import { traverseAST, getStringValue, getSnippet, isMemberCall } from '../parser/astParser';

export function detectMyLibrary(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];

  traverseAST(ast, {
    CallExpression(node) {
      if (isMemberCall(node, 'myLib', 'encrypt')) {
        const algo = getStringValue(node.arguments[0]);
        if (algo) {
          findings.push({
            algorithm: algo.toUpperCase(),
            library: 'my-library',
            location: filePath,
            line: node.loc?.start.line || 0,
            weak: false,
            quantumSafe: true,
            severity: 'INFO',
            context: getSnippet(source, node.loc?.start.line || 0),
            cwe: []
          });
        }
      }
    }
  });

  return findings;
}
```

Then register it in `src/detectors/index.ts`:

```typescript
import { detectMyLibrary } from './myLibrary';

const detectors = [
  // ... existing detectors
  { name: 'my-library', fn: detectMyLibrary }
];
```

---

## Limitations

- **JS/TS only** — no Java, Python, Go, C/C++ support (by design for now)
- **Static analysis only** — cannot detect runtime-constructed algorithm strings like `crypto.createHash(getUserInput())`
- **Import aliasing** — heavily aliased imports may be missed if the alias doesn't match known patterns
- **Minified code** — excluded by default; if included, findings will be less readable
- **Transitive dependencies** — scans source code only, not `node_modules`. Use Trivy/Grype for dependency CVE scanning alongside this tool

---

## Roadmap

- [ ] SPDX output format support
- [ ] `--format sarif` output for GitHub Code Scanning integration
- [ ] Dependency Track upload (`--upload-to <url>`)
- [ ] Config file support (`.cbomrc.json`)
- [ ] Detect `SubtleCrypto` (Web Crypto API) usage in browser-targeted code
- [ ] Detect Webpack/Vite crypto plugin configurations
- [ ] VS Code extension for inline findings

---

## License

Apache 2.0 — see [LICENSE](./LICENSE)

---

## Related Tools

| Tool | Purpose | Relationship to cbom-js |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | CVE + SBOM scanning | Complementary — use for dependency CVEs |
| [IBM CBOMkit](https://github.com/IBM/cbomkit) | Full CBOM platform (Java/Python) | cbom-js fills the JS/TS gap CBOMkit doesn't cover |
| [Syft](https://github.com/anchore/syft) | SBOM generation | SBOM complement — use Syft for library inventory, cbom-js for crypto inventory |
| [Dependency Track](https://dependencytrack.org/) | Continuous SBOM/CBOM monitoring | Feed cbom-js output into Dependency Track for continuous monitoring |
| [Semgrep](https://semgrep.dev/) | SAST with crypto rules | Alternative/complement — Semgrep finds findings, cbom-js produces structured CBOM |