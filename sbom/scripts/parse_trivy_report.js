#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

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

const reportDir = getArg('report-dir');
const threshold = (getArg('threshold', 'high') || 'high').toLowerCase();
const output = getArg('output');

if (!reportDir || !output) {
  console.error('Missing required args: --report-dir --output');
  process.exit(1);
}

const mergedPath = path.join(reportDir, 'trivy-merged.json');
const data = JSON.parse(fs.readFileSync(mergedPath, 'utf8'));

let allVulns = [];
for (const app of ['node', 'java', 'python', 'filesystem']) {
  const report = (((data || {}).reports || {})[app]) || {};
  allVulns = allVulns.concat(flattenVulns(report, app));
}

const allowed = threshold === 'critical' ? 'CRITICAL' : 'HIGH';
const gateFailed = allVulns.some((v) => SEVERITY_ORDER.indexOf(v.severity) >= SEVERITY_ORDER.indexOf(allowed));

const counts = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
for (const v of allVulns) {
  counts[v.severity] = (counts[v.severity] || 0) + 1;
}

const result = {
  gate_failed: gateFailed,
  threshold,
  counts,
  total_vulnerabilities: allVulns.length,
  vulnerabilities: allVulns
};

fs.writeFileSync(output, JSON.stringify(result, null, 2));
