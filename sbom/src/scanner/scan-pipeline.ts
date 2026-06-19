/**
 * SBOM + Trivy scanning pipeline module.
 * Generates per-target SBOMs, runs Trivy scans, and builds merged outputs.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ensureDir, readJson, writeJson } from "../core/file-system-utils";
import { run } from "../core/shell-command-utils";
import { Args, Language, ProjectTarget } from "../types";

type BuildLanguageReportsOptions = {
  persistCycloneDx?: boolean;
};

function generatePythonSbom(target: ProjectTarget, outFile: string): void {
  const requirementsFile = path.join(target.projectPath, "requirements.txt");
  const pyprojectFile = path.join(target.projectPath, "pyproject.toml");

  if (fs.existsSync(requirementsFile)) {
    run(`cyclonedx-py requirements "${requirementsFile}" -o "${outFile}" --of JSON --sv 1.5`);
    return;
  }

  if (fs.existsSync(pyprojectFile)) {
    try {
      run(`npx @cyclonedx/cdxgen -t python --spec-version 1.5 -o "${outFile}" "${target.projectPath}"`);
    } catch {
      run(`npx @cyclonedx/cdxgen --spec-version 1.5 -o "${outFile}" "${target.projectPath}"`);
    }
    return;
  }

  throw new Error(`Python project missing supported dependency source files: ${target.projectPath}`);
}

export function generateSbomForTarget(target: ProjectTarget, outDir: string): string {
  const langDir = path.join(outDir, "cyclonedx", target.language);
  ensureDir(langDir);

  const outFile = path.join(langDir, `${target.id}-cyclonedx.json`);

  if (target.language === "python") {
    generatePythonSbom(target, outFile);
  } else {
    const cdxTypeMap: Record<Exclude<Language, "python">, string> = {
      node: "nodejs",
      java: "java",
      csharp: "dotnet"
    };
    const cdxType = cdxTypeMap[target.language as Exclude<Language, "python">];
    try {
      run(`npx @cyclonedx/cdxgen -t ${cdxType} --spec-version 1.5 -o "${outFile}" "${target.projectPath}"`);
    } catch {
      run(`npx @cyclonedx/cdxgen --spec-version 1.5 -o "${outFile}" "${target.projectPath}"`);
    }
  }

  return outFile;
}

function scanSbom(sbomFile: string, outFile: string, severity: string): void {
  try {
    run(`trivy sbom "${sbomFile}" --format json --output "${outFile}" --severity "${severity}" --ignore-unfixed`);
  } catch {
    writeJson(outFile, {});
  }
}

function mergeReports(scanFiles: string[], outFile?: string): { Results: any[] } {
  const merged = { Results: [] as any[] };
  for (const f of scanFiles) {
    if (!fs.existsSync(f)) continue;
    const report = readJson(f);
    const results = report?.Results || [];
    merged.Results.push(...results);
  }
  if (outFile) {
    writeJson(outFile, merged);
  }
  return merged;
}

function maybeFsScan(repoRoot: string, outDir: string, args: Args): string | null {
  const trivyDir = path.join(outDir, "trivy");
  ensureDir(trivyDir);
  const fsJson = path.join(trivyDir, "filesystem-trivy.json");
  if (!args.fsScan) {
    return null;
  }

  try {
    run(`trivy fs "${repoRoot}" --format json --output "${fsJson}"`);
  } catch {
    writeJson(fsJson, {});
  }
  return fsJson;
}

function createTrivyMerged(outDir: string, reports: Record<string, unknown>): void {
  writeJson(path.join(outDir, "trivy", "merged.json"), {
    scan_prefix: "trivy",
    reports
  });
}

export function buildLanguageReports(
  repoRoot: string,
  outDir: string,
  targetsByLang: Record<Language, ProjectTarget[]>,
  threshold: "critical" | "high",
  args: Args,
  options: BuildLanguageReportsOptions = {}
): void {
  const severity = threshold === "critical" ? "CRITICAL" : "HIGH,CRITICAL";
  const trivyDir = path.join(outDir, "trivy");
  ensureDir(trivyDir);
  const persistCycloneDx = options.persistCycloneDx !== false;
  const reportPayloads: Record<string, unknown> = {};

  for (const lang of ["node", "java", "python", "csharp"] as Language[]) {
    const scanFiles: string[] = [];
    const targets = targetsByLang[lang];
    if (targets.length === 0) {
      continue;
    }

    for (const target of targets) {
      let sbomFile: string;
      let tempDir: string | null = null;
      if (persistCycloneDx) {
        sbomFile = generateSbomForTarget(target, outDir);
      } else {
        tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "cycloguard-remediate-sbom-"));
        sbomFile = generateSbomForTarget(target, tempDir);
      }

      const scanFile = path.join(trivyDir, `${lang}-${target.id}-trivy.json`);
      scanSbom(sbomFile, scanFile, severity);
      scanFiles.push(scanFile);
      if (tempDir) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    }

    reportPayloads[lang] = mergeReports(scanFiles);
  }

  const fsResult = maybeFsScan(repoRoot, outDir, args);
  if (fsResult) {
    reportPayloads.filesystem = readJson(fsResult);
  }
  createTrivyMerged(outDir, reportPayloads);
}
