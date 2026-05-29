/**
 * Main orchestration entrypoint.
 * Wires together argument parsing, source acquisition, stack detection,
 * scanning pipeline execution, and gate evaluation.
 */
import * as path from "path";
import { parseArgs } from "./cli/args";
import { ensureDir, writeJson } from "./core/fs";
import { detectProjects, groupByLanguage } from "./detectors/projects";
import { runGateParser } from "./reports/gate";
import { buildLanguageReports } from "./scanner/pipeline";
import { acquireSource, outputSlugFromSource } from "./source/acquire";
import { ensureTools } from "./tools/bootstrap";

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const outputDir = path.join(path.resolve(args.output), outputSlugFromSource(args.source, args.branch));
  ensureDir(outputDir);

  const { repoRoot, cleanup } = acquireSource(args);
  try {
    console.log(`Using source at: ${repoRoot}`);
    ensureTools();

    const targets = detectProjects(repoRoot);
    if (targets.length === 0) {
      throw new Error("No supported projects detected. Expected package.json, requirements.txt/pyproject.toml, pom.xml or build.gradle.");
    }

    writeJson(path.join(outputDir, "detected-projects.json"), {
      source: args.source,
      repoRoot,
      detected: targets
    });

    const targetsByLang = groupByLanguage(targets);
    buildLanguageReports(repoRoot, outputDir, targetsByLang, args.threshold, args);
    runGateParser(outputDir, args.threshold);

    console.log(`\nDone. Reports available at: ${outputDir}`);
  } finally {
    if (cleanup) cleanup();
  }
}

main();
