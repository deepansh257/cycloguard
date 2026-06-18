#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const pino = require('pino');
const { createAppLogger } = require(path.resolve(__dirname, '..', '..', 'common', 'logger.js'));
const logger = createAppLogger({ pino });

const SEVERITY_ORDER = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function flattenVulns(report, appName) {
  const out = [];
  const results = (report && report.Results) || [];
  for (const result of results) {
    const vulns = result.Vulnerabilities || [];
    for (const v of vulns) {
      out.push({
        app: appName,
        severity: v.Severity || 'UNKNOWN',
        cve_id: v.VulnerabilityID || 'N/A',
        package: v.PkgName || 'N/A',
        installed: v.InstalledVersion || 'N/A',
        fixed: v.FixedVersion || 'N/A',
        title: v.Title || ''
      });
    }
  }
  return out;
}

function flattenSecrets(report, appName) {
  const out = [];
  const results = (report && report.Results) || [];
  for (const result of results) {
    const secrets = result.Secrets || [];
    for (const secret of secrets) {
      out.push({
        app: appName,
        severity: secret.Severity || 'UNKNOWN',
        rule_id: secret.RuleID || 'N/A',
        category: secret.Category || 'N/A',
        title: secret.Title || '',
        target: result.Target || 'N/A',
        start_line: secret.StartLine || null,
        end_line: secret.EndLine || null
      });
    }
  }
  return out;
}

function buildSeverityCounts(items) {
  const counts = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const item of items) {
    counts[item.severity] = (counts[item.severity] || 0) + 1;
  }
  return counts;
}

const reportDir = getArg('report-dir');
const threshold = (getArg('threshold', 'high') || 'high').toLowerCase();
const output = getArg('output');

if (!reportDir || !output) {
  logger.error('Missing required args: --report-dir --output');
  process.exit(1);
}

const mergedPath = path.join(reportDir, 'trivy', 'merged.json');
const data = JSON.parse(fs.readFileSync(mergedPath, 'utf8'));

let allVulns = [];
let allSecrets = [];
const reports = ((data || {}).reports || {});
for (const app of Object.keys(reports)) {
  const report = reports[app] || {};
  allVulns = allVulns.concat(flattenVulns(report, app));
  allSecrets = allSecrets.concat(flattenSecrets(report, app));
}

const allowed = threshold === 'critical' ? 'CRITICAL' : 'HIGH';
const allFindings = allVulns.concat(allSecrets);
const gateFailed = allFindings.some((item) => SEVERITY_ORDER.indexOf(item.severity) >= SEVERITY_ORDER.indexOf(allowed));

const counts = buildSeverityCounts(allVulns);
const secretCounts = buildSeverityCounts(allSecrets);
const findingCounts = buildSeverityCounts(allFindings);

const result = {
  gate_failed: gateFailed,
  threshold,
  counts,
  secret_counts: secretCounts,
  finding_counts: findingCounts,
  total_vulnerabilities: allVulns.length,
  total_secrets: allSecrets.length,
  total_findings: allFindings.length,
  vulnerabilities: allVulns,
  secrets: allSecrets
};

fs.writeFileSync(output, JSON.stringify(result, null, 2));

