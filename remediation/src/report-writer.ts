/**
 * Writes remediation outputs into the scan result directory.
 * This module produces both machine-readable JSON and a human-readable summary.
 */
import * as fs from "fs";
import * as path from "path";
import { RemediationApprovalDocument, RemediationPlan } from "./types";

function toMarkdown(plan: RemediationPlan): string {
  const lines: string[] = [];
  lines.push("# AI Remediation Summary");
  lines.push("");
  lines.push(`- Planner mode: ${plan.plannerMode}`);
  lines.push(`- Planner provider: ${plan.plannerProvider}`);
  lines.push(`- Created at: ${plan.createdAt}`);
  if (plan.sourceRepo) {
    lines.push(`- Source repo: ${plan.sourceRepo}`);
  }
  if (plan.sourceBranch) {
    lines.push(`- Source branch: ${plan.sourceBranch}`);
  }
  if (plan.threshold) {
    lines.push(`- Threshold: ${plan.threshold}`);
  }
  lines.push(`- Findings with guidance: ${plan.items.length}`);
  lines.push("");

  if (plan.reproducibilityWarnings.length > 0) {
    lines.push("## Reproducibility warnings");
    lines.push("");
    for (const warning of plan.reproducibilityWarnings) {
      lines.push(`- ${warning}`);
    }
    lines.push("");
  }

  for (const item of plan.items) {
    lines.push(`## ${item.title}`);
    lines.push("");
    lines.push(`- Severity: ${item.severity}`);
    lines.push(`- Source type: ${item.sourceType}`);
    lines.push(`- Confidence: ${item.confidence}`);
    if (item.vulnerabilityId) {
      lines.push(`- Advisory: ${item.vulnerabilityId}`);
    }
    if (item.packageName) {
      lines.push(`- Package: ${item.packageName}`);
    }
    if (item.installedVersion) {
      lines.push(`- Installed version: ${item.installedVersion}`);
    }
    if (item.targetVersion) {
      lines.push(`- Target version: ${item.targetVersion}`);
    }
    if (item.targetFile) {
      lines.push(`- Target file: ${item.targetFile}`);
    }
    lines.push("");
    lines.push(item.rationale);
    lines.push("");
    lines.push("Recommended changes:");
    for (const change of item.recommendedChanges) {
      lines.push(`- ${change}`);
    }
    if (item.reviewNotes && item.reviewNotes.length > 0) {
      lines.push("");
      lines.push("Review notes:");
      for (const note of item.reviewNotes) {
        lines.push(`- ${note}`);
      }
    }
    lines.push("");
  }

  return `${lines.join("\n").trim()}\n`;
}

export function writeRemediationOutputs(runDir: string, plan: RemediationPlan) {
  const remediationDir = path.join(runDir, "remediation");
  fs.mkdirSync(remediationDir, { recursive: true });

  const planPath = path.join(remediationDir, "remediation-plan.json");
  const summaryPath = path.join(remediationDir, "remediation-summary.md");
  const approvalPath = path.join(remediationDir, "remediation-approval.json");

  fs.writeFileSync(planPath, JSON.stringify(plan, null, 2));
  fs.writeFileSync(summaryPath, toMarkdown(plan), "utf-8");

  if (!fs.existsSync(approvalPath)) {
    const approvalDocument: RemediationApprovalDocument = {
      createdAt: new Date().toISOString(),
      sourceRepo: plan.sourceRepo,
      sourceBranch: plan.sourceBranch,
      items: plan.items.map((item) => ({
        id: item.id,
        status: item.approvalStatus === "approved" || item.approvalStatus === "rejected"
          ? item.approvalStatus
          : "proposed"
      }))
    };

    fs.writeFileSync(approvalPath, JSON.stringify(approvalDocument, null, 2));
  }

  return {
    remediationDir,
    planPath,
    summaryPath,
    approvalPath
  };
}
