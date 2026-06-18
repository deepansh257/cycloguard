/**
 * Main orchestration entrypoint.
 * Wires together argument parsing, source acquisition, stack detection,
 * scanning pipeline execution, and gate evaluation.
 */
import * as path from "path";
import pino from "pino";
import { parseArgs } from "./cli/args";
import { loadLocalEnv } from "./core/env";
import { ensureDir, writeJson } from "./core/fs";
import { detectProjects, groupByLanguage } from "./detectors/projects";
import { runPostScanAutomation } from "./reports/automation";
import { runGateParser } from "./reports/gate";
import { buildLanguageReports } from "./scanner/pipeline";
import { acquireSource, resolveGithubRepoIdentifier } from "./source/acquire";
import { ensureTools } from "./tools/bootstrap";

const { createAppLogger } = require(path.resolve(__dirname, "..", "..", "common", "logger.js")) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    info: (message: string, meta?: Record<string, unknown>) => void;
    warn: (message: string, meta?: Record<string, unknown>) => void;
    error: (message: string, meta?: Record<string, unknown>) => void;
    raw: (message: string) => void;
  };
};
const logger = createAppLogger({ pino });

async function main(): Promise<void> {
  loadLocalEnv();
  const args = parseArgs(process.argv.slice(2));
  const outputDir = path.join(path.resolve(args.output));
  ensureDir(outputDir);

  const { repoRoot, cleanup } = acquireSource(args);
  try {
    logger.info(`Using source at: ${repoRoot}`);
    ensureTools();
    const effectiveGithubRepo = resolveGithubRepoIdentifier(args.source, repoRoot, args.githubRepo);
    const sourceRepoLabel = effectiveGithubRepo || args.source;

    const targets = detectProjects(repoRoot);
    if (targets.length === 0) {
      throw new Error("No supported projects detected. Expected package.json, requirements.txt/pyproject.toml, pom.xml or build.gradle.");
    }
    writeJson(path.join(outputDir, "detected-projects.json"), {
      source: args.source,
      branch: args.branch || "default",
      repo_root: repoRoot,
      projects: targets.map((target) => ({
        language: target.language,
        project_path: target.projectPath,
        id: target.id,
        framework: target.framework,
        source_of_truth_type: target.sourceOfTruthType,
        source_of_truth_files: target.sourceOfTruthFiles,
        supporting_files: target.supportingFiles,
        lockfile_present: target.lockfilePresent,
        lockfile_files: target.lockfileFiles,
        reproducibility: target.reproducibility,
        lockfile_warning: target.lockfileWarning || null
      }))
    });
    const targetsByLang = groupByLanguage(targets);
    buildLanguageReports(repoRoot, outputDir, targetsByLang, args.threshold, args);
    runGateParser(outputDir, args.threshold);
    await runPostScanAutomation({ ...args, githubRepo: effectiveGithubRepo || args.githubRepo }, {
      outputDir,
      sourceRepoLabel,
      sourceBranch: args.branch || "default",
      historyFile: path.join(outputDir, "automation", "history-index.json")
    });

    logger.info(`Done. Reports available at: ${outputDir}`);
  } finally {
    if (cleanup) cleanup();
  }
}

main().catch((err) => {
  logger.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
