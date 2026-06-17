#!/usr/bin/env node
const fs = require("fs");
const path = require("path");

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function readJsonIfExists(filePath, fallback) {
  return fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, "utf8")) : fallback;
}

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function summarizeSbom(reportDir) {
  const gate = readJsonIfExists(path.join(reportDir, "gate-result.json"), {});
  const issue = readJsonIfExists(path.join(reportDir, "issue-result.json"), {});
  const remediation = readJsonIfExists(path.join(reportDir, "remediation-result.json"), {});
  const pr = readJsonIfExists(path.join(reportDir, "pr-result.json"), {});
  const validation = readJsonIfExists(path.join(reportDir, "remediation-validation.json"), { results: [] });
  const rescan = readJsonIfExists(path.join(reportDir, "remediation-rescan-summary.json"), {});

  return {
    sourceType: "sbom",
    totalVulnerabilities: gate.total_vulnerabilities || 0,
    severityCounts: gate.counts || {},
    gateFailed: Boolean(gate.gate_failed),
    githubIssue: issue.issue_url || null,
    remediationMode: remediation.mode || "not_run",
    remediationBranch: remediation.remediation_branch || null,
    remediationAppliedCount: remediation.applied_fix_count || 0,
    remediationManualReviewRequired: Boolean(remediation.manual_review_required),
    remediationPr: pr.pr_url || null,
    validation: validation.results || [],
    rescanBefore: rescan.before || null,
    rescanAfter: rescan.after || null
  };
}

function summarizeCbom(reportDir, reportFile) {
  const cbom = readJsonIfExists(reportFile, {});
  const remediationDir = path.join(reportDir, "remediation");
  const remediation = readJsonIfExists(path.join(remediationDir, "remediation-result.json"), {});
  const pr = readJsonIfExists(path.join(remediationDir, "pr-result.json"), {});
  const validation = readJsonIfExists(path.join(remediationDir, "ai-remediation-validation.json"), { results: [] });
  const applied = readJsonIfExists(path.join(remediationDir, "ai-remediation-applied.json"), { results: [] });
  const plan = readJsonIfExists(path.join(remediationDir, "ai-remediation-plan.json"), { items: [] });

  return {
    sourceType: "cbom",
    totalFindings: Array.isArray(cbom.components) ? cbom.components.length : 0,
    totalVulnerabilities: Array.isArray(cbom.vulnerabilities) ? cbom.vulnerabilities.length : 0,
    remediationMode: remediation.mode || "not_run",
    remediationAppliedCount: (applied.results || []).filter((item) => item.status === "applied").length,
    remediationPlannedCount: Array.isArray(plan.items) ? plan.items.length : 0,
    remediationManualReviewRequired: Boolean(remediation.manual_review_required),
    remediationPr: pr.pr_url || null,
    validation: validation.results || []
  };
}

function main() {
  const sourceType = getArg("source-type");
  const reportDir = getArg("report-dir");
  const reportFile = getArg("report-file");
  const output = getArg("output");

  if (!sourceType || !reportDir || !output) {
    console.error("Missing required args: --source-type --report-dir --output");
    process.exit(1);
  }

  const summary = sourceType === "sbom"
    ? summarizeSbom(reportDir)
    : summarizeCbom(reportDir, reportFile);

  writeJson(output, {
    generatedAt: new Date().toISOString(),
    ...summary
  });
}

main();
