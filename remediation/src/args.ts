/**
 * Parses the remediation CLI arguments passed by the runner.
 * This is the entry point for locating the scan output folder and source path.
 */
import * as path from "path";
import { RemediationArgs } from "./types";

export function parseArgs(argv: string[]): RemediationArgs {
  const args = new Map<string, string>();

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      continue;
    }

    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      args.set(key, "true");
      continue;
    }

    args.set(key, next);
    index += 1;
  }

  const runDir = args.get("run-dir");
  const sourcePath = args.get("source-path");

  if (!runDir) {
    throw new Error("Missing required argument: --run-dir <scan-output-folder>");
  }

  if (!sourcePath) {
    throw new Error("Missing required argument: --source-path <scanned-source-folder>");
  }

  return {
    runDir: path.resolve(runDir),
    sourcePath: path.resolve(sourcePath),
    sourceRepo: args.get("source-repo"),
    sourceBranch: args.get("source-branch"),
    threshold: args.get("threshold")
  };
}
