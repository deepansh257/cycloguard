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
cd sbom
npm install
```

Scan GitHub repo:
```bash
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
  - supports workflow dispatch inputs (`source_repo`, `source_branch`, `threshold`)
  - uploads full and per-language artifacts

## Note
The old committed vulnerable sample applications under `sbom/apps/` were removed per updated approach. Scanning target is now always user-provided source repo/path.
