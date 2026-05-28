/**
 * CLI argument parser.
 * Converts raw argv tokens into a validated Args object with defaults.
 */
import * as path from "path";
import { Args } from "../types";

export function parseArgs(argv: string[]): Args {
  const map = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      map.set(key, "true");
    } else {
      map.set(key, next);
      i += 1;
    }
  }

  const source = map.get("source") || "";
  if (!source) {
    throw new Error("Missing required argument: --source <github-url-or-local-path>");
  }

  return {
    source,
    output: map.get("output") || path.resolve("sbom-output"),
    threshold: (map.get("threshold") as "critical" | "high") || "high",
    branch: map.get("branch"),
    workdir: map.get("workdir"),
    fsScan: map.get("fs-scan") !== "false",
    secretScan: map.get("secret-scan") === "true",
    misconfigScan: map.get("misconfig-scan") === "true"
  };
}
