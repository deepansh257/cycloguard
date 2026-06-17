/**
 * Main orchestration entrypoint.
 * Wires together argument parsing, source acquisition, stack detection,
 * scanning pipeline execution, and gate evaluation.
 */
import * as path from "path";
import { parseArgs } from "./cli/args";
import { loadLocalEnv } from "./core/env";
import { ensureDir, writeJson } from "./core/fs";
import { detectProjects, groupByLanguage } from "./detectors/projects";
import { runPostScanAutomation } from "./reports/automation";
import { runGateParser } from "./reports/gate";
import { buildLanguageReports } from "./scanner/pipeline";
import { acquireSource, outputSlugFromSource, resolveGithubRepoIdentifier, resolveSourceGithubRepoIdentifier } from "./source/acquire";
import { ensureTools } from "./tools/bootstrap";

async function main(): Promise<void> {
  loadLocalEnv();
  const args = parseArgs(process.argv.slice(2));
  const outputDir = path.join(path.resolve(args.output), outputSlugFromSource(args.source, args.branch));
  ensureDir(outputDir);

  const { repoRoot, cleanup } = acquireSource(args);
  try {
    console.log(`Using source at: ${repoRoot}`);
    ensureTools();
    const sourceGithubRepo = resolveSourceGithubRepoIdentifier(args.source, repoRoot);
    const effectiveGithubRepo = resolveGithubRepoIdentifier(args.source, repoRoot, args.githubRepo);
    const sourceRepoLabel = sourceGithubRepo || args.source;

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
    await runPostScanAutomation({ ...args, githubRepo: effectiveGithubRepo || args.githubRepo }, {
      repoRoot,
      outputDir,
      sourceRepoLabel,
      sourceBranch: args.branch || "default",
      historyFile: path.join(path.resolve(args.output), "history-index.json"),
      targets,
      remediationRepo: sourceGithubRepo || undefined
    });

    console.log(`\nDone. Reports available at: ${outputDir}`);
  } finally {
    if (cleanup) cleanup();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
