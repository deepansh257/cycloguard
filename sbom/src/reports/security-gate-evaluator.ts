/**
 * Report gate module.
 * Executes gate parsing against merged Trivy output and prints summary.
 */
import * as path from "path";
import * as fs from "fs";
import pino from "pino";
import { readJson } from "../core/file-system-utils";
import { run } from "../core/shell-command-utils";

const { createAppLogger } = require(path.resolve(__dirname, "..", "..", "..", "common", "logger.js")) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    info: (message: string, meta?: Record<string, unknown>) => void;
    raw: (message: string) => void;
  };
};
const logger = createAppLogger({ pino });

export function runGateParser(outDir: string, threshold: "critical" | "high"): void {
  const mergedFile = path.join(outDir, "trivy", "merged.json");
  const gateFile = path.join(outDir, "gate-result.json");
  const parserScript = path.resolve(__dirname, "..", "..", "scripts", "parse_trivy_report.js");
  run(`node "${parserScript}" --report-dir "${outDir}" --threshold "${threshold}" --output "${gateFile}"`);
  const gate = readJson(gateFile);
  logger.info("Gate summary generated", {
    gate_failed: gate.gate_failed,
    threshold: gate.threshold,
    total_vulnerabilities: gate.total_vulnerabilities,
    total_secrets: gate.total_secrets,
    total_findings: gate.total_findings,
    reproducibility: gate.reproducibility,
    counts: gate.counts,
    secret_counts: gate.secret_counts,
    finding_counts: gate.finding_counts
  });
  logger.raw(JSON.stringify(gate, null, 2));
  if (!fs.existsSync(mergedFile)) {
    throw new Error(`Expected merged report not found: ${mergedFile}`);
  }
}
