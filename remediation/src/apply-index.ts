/**
 * Entry point for applying approved remediation items.
 * This reads the plan and approval files for a scan run, applies supported
 * remediations, and records the apply results back into the remediation folder.
 */
import { parseApplyArgs } from "./apply-args";
import { loadLocalEnv } from "./env";
import { applyApprovedRemediations } from "./apply";

function summarizeStatuses(items: Array<{ status: string }>): string {
  const counts = new Map<string, number>();
  for (const item of items) {
    counts.set(item.status, (counts.get(item.status) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([status, count]) => `${status}=${count}`)
    .join(", ");
}

function main() {
  loadLocalEnv();
  const args = parseApplyArgs(process.argv.slice(2));
  const result = applyApprovedRemediations(args);
  console.log(`Remediation apply result written to ${result.applyResultPath}`);
  console.log(`Remediation plan updated at ${result.updatedPlanPath}`);
  console.log(`Remediation apply summary: ${summarizeStatuses(result.applyResult.items)}`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown remediation apply failure";
  console.error(message);
  process.exit(1);
}
