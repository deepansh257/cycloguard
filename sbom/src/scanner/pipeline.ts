/**
 * SBOM + Trivy scanning pipeline module.
 * Generates per-target SBOMs, runs Trivy scans, and builds merged outputs.
 */
import * as fs from "fs";
import * as path from "path";
import { ensureDir, readJson, writeJson } from "../core/fs";
import { run } from "../core/shell";
import { Args, Language, ProjectTarget } from "../types";

export function generateSbomForTarget(target: ProjectTarget, outDir: string): string {
  const langDir = path.join(outDir, "sbom", target.language);
  ensureDir(langDir);

  const outFile = path.join(langDir, `${target.id}-cyclonedx.json`);

  if (target.language === "python") {
    const req = path.join(target.projectPath, "requirements.txt");
    if (!fs.existsSync(req)) {
      throw new Error(`Python project missing requirements.txt: ${target.projectPath}`);
    }
    run(`cyclonedx-py requirements "${req}" -o "${outFile}" --of JSON --sv 1.5`);
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

function mergeReports(scanFiles: string[], outFile: string): void {
  const merged = { Results: [] as any[] };
  for (const f of scanFiles) {
    if (!fs.existsSync(f)) continue;
    const report = readJson(f);
    const results = report?.Results || [];
    merged.Results.push(...results);
  }
  writeJson(outFile, merged);
}

function maybeFsScan(repoRoot: string, outDir: string, args: Args): { fsJson: string; sarif: string } {
  const fsJson = path.join(outDir, "trivy-fs.json");
  const sarif = path.join(outDir, "trivy-results.sarif");
  if (!args.fsScan) {
    writeJson(fsJson, {});
    writeJson(sarif, { version: "2.1.0", runs: [] });
    return { fsJson, sarif };
  }

  try {
    run(`trivy fs "${repoRoot}" --format json --output "${fsJson}"`);
  } catch {
    writeJson(fsJson, {});
  }

  const scanners = ["vuln"];
  if (args.secretScan) scanners.push("secret");
  if (args.misconfigScan) scanners.push("misconfig");

  try {
    run(`trivy fs "${repoRoot}" --scanners "${scanners.join(",")}" --format sarif --output "${sarif}"`);
  } catch {
    writeJson(sarif, { version: "2.1.0", runs: [] });
  }

  return { fsJson, sarif };
}

function createTrivyMerged(outDir: string, byLangMerged: Record<Language, string>, fsJson: string): void {
  const payload = {
    scan_prefix: "trivy",
    reports: {
      node: readJson(byLangMerged.node),
      java: readJson(byLangMerged.java),
      python: readJson(byLangMerged.python),
      csharp: readJson(byLangMerged.csharp),
      filesystem: readJson(fsJson)
    }
  };
  writeJson(path.join(outDir, "trivy-merged.json"), payload);
}

export function buildLanguageReports(
  repoRoot: string,
  outDir: string,
  targetsByLang: Record<Language, ProjectTarget[]>,
  threshold: "critical" | "high",
  args: Args
): void {
  const severity = threshold === "critical" ? "CRITICAL" : "HIGH,CRITICAL";

  const mergedByLang: Record<Language, string> = {
    node: path.join(outDir, "trivy-node.json"),
    java: path.join(outDir, "trivy-java.json"),
    python: path.join(outDir, "trivy-python.json"),
    csharp: path.join(outDir, "trivy-csharp.json")
  };

  for (const lang of ["node", "java", "python", "csharp"] as Language[]) {
    const scanFiles: string[] = [];

    for (const target of targetsByLang[lang]) {
      const sbomFile = generateSbomForTarget(target, outDir);
      const scanFile = path.join(outDir, `${lang}-${target.id}-trivy.json`);
      scanSbom(sbomFile, scanFile, severity);
      scanFiles.push(scanFile);
    }

    if (scanFiles.length === 0) {
      writeJson(mergedByLang[lang], {});
      continue;
    }

    mergeReports(scanFiles, mergedByLang[lang]);
  }

  const fsResult = maybeFsScan(repoRoot, outDir, args);
  createTrivyMerged(outDir, mergedByLang, fsResult.fsJson);
}
