/**
 * Report gate module.
 * Executes gate parsing against merged Trivy output and prints summary.
 */
import * as path from "path";
import * as fs from "fs";
import { readJson } from "../core/fs";
import { run } from "../core/shell";

export function runGateParser(outDir: string, threshold: "critical" | "high"): void {
  const mergedFile = path.join(outDir, "trivy-merged.json");
  const gateFile = path.join(outDir, "gate-result.json");
  const parserScript = path.resolve(__dirname, "..", "..", "scripts", "parse_trivy_report.js");
  run(`node "${parserScript}" --report-dir "${outDir}" --threshold "${threshold}" --output "${gateFile}"`);
  const gate = readJson(gateFile);
  console.log("\nGate summary:");
  console.log(JSON.stringify(gate, null, 2));
  if (!fs.existsSync(mergedFile)) {
    throw new Error(`Expected merged report not found: ${mergedFile}`);
  }
}
