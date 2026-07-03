/**
 * Parses CLI arguments for the remediation apply command.
 * This resolves the run directory and optional source path override.
 */
import * as path from "path";
import { RemediationApplyArgs } from "./types";

export function parseApplyArgs(argv: string[]): RemediationApplyArgs {
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
  if (!runDir) {
    throw new Error("Missing required argument: --run-dir <scan-output-folder>");
  }

  return {
    runDir: path.resolve(runDir),
    sourcePath: args.get("source-path") ? path.resolve(args.get("source-path") as string) : undefined
  };
}
