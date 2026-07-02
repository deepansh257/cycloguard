import * as path from "path";
import { spawnSync } from "child_process";

type RunRemediationOptions = {
  runDir: string;
  sourcePath: string;
  sourceRepo?: string;
  sourceBranch?: string;
  threshold?: string;
};

export function runRemediation(options: RunRemediationOptions): { error?: string } {
  const repoRoot = path.resolve(__dirname, "..", "..");
  const remediationEntry = path.join(repoRoot, "remediation", "src", "index.ts");
  const remediationTsconfig = path.join(repoRoot, "remediation", "tsconfig.json");
  const tsNodeBin = require.resolve("ts-node/dist/bin.js", { paths: [repoRoot] });

  const args = [
    tsNodeBin,
    "-P",
    remediationTsconfig,
    remediationEntry,
    "--run-dir",
    options.runDir,
    "--source-path",
    options.sourcePath
  ];

  if (options.sourceRepo) {
    args.push("--source-repo", options.sourceRepo);
  }

  if (options.sourceBranch) {
    args.push("--source-branch", options.sourceBranch);
  }

  if (options.threshold) {
    args.push("--threshold", options.threshold);
  }

  const result = spawnSync(process.execPath, args, {
    cwd: repoRoot,
    stdio: "inherit"
  });

  if (result.error) {
    return { error: result.error.message };
  }

  if ((result.status ?? 1) !== 0) {
    return { error: `remediation exited with code ${result.status ?? 1}` };
  }

  return {};
}
