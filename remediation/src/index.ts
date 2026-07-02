/**
 * Remediation module entry point.
 * It loads context from scan artifacts, builds a plan, and persists the outputs.
 */
import { parseArgs } from "./args";
import { loadLocalEnv } from "./env";
import { loadRemediationContext } from "./artifact-loader";
import { buildRemediationPlan } from "./planner";
import { writeRemediationOutputs } from "./report-writer";

async function main() {
  loadLocalEnv();
  const args = parseArgs(process.argv.slice(2));
  const context = loadRemediationContext(args);
  const plan = await buildRemediationPlan(context);
  console.log(`Remediation planning mode: ${plan.plannerMode}`);
  const outputs = writeRemediationOutputs(args.runDir, plan);

  console.log(`AI remediation plan written to ${outputs.planPath}`);
  console.log(`AI remediation summary written to ${outputs.summaryPath}`);
}

main().catch((error: Error) => {
  console.error(error.message);
  process.exit(1);
});
