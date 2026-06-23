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

function dedupeBy(items, makeKey) {
  const seen = new Set();
  return items.filter((item) => {
    const key = makeKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildReproducibilitySummary(reportDir) {
  const detectedProjectsPath = path.join(reportDir, 'detected-projects.json');
  if (!fs.existsSync(detectedProjectsPath)) {
    return {
      deterministic_projects: 0,
      non_deterministic_projects: 0,
      warnings: []
    };
  }

  const detectedProjects = JSON.parse(fs.readFileSync(detectedProjectsPath, 'utf8'));
  const projects = detectedProjects.projects || [];
  const warnings = projects
    .filter((project) => project && project.lockfile_present === false && project.lockfile_warning)
    .map((project) => ({
      language: project.language,
      project_id: project.id,
      project_path: project.project_path,
      source_of_truth_type: project.source_of_truth_type,
      source_of_truth_files: project.source_of_truth_files || [],
      supporting_files: project.supporting_files || [],
      warning: project.lockfile_warning
    }));

  return {
    deterministic_projects: projects.filter((project) => project.lockfile_present !== false).length,
    non_deterministic_projects: projects.filter((project) => project.lockfile_present === false).length,
    source_selection: projects.map((project) => ({
      language: project.language,
      project_id: project.id,
      project_path: project.project_path,
      source_of_truth_type: project.source_of_truth_type,
      source_of_truth_files: project.source_of_truth_files || [],
      supporting_files: project.supporting_files || [],
      reproducibility: project.reproducibility
    })),
    warnings
  };
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

allVulns = dedupeBy(allVulns, (item) => [item.app, item.cve_id, item.package, item.installed].join("|"));
allSecrets = dedupeBy(allSecrets, (item) => [item.app, item.rule_id, item.category, item.target, item.start_line, item.end_line].join("|"));

const allowed = threshold === 'critical' ? 'CRITICAL' : 'HIGH';
const allFindings = allVulns.concat(allSecrets);
const gateFailed = allFindings.some((item) => SEVERITY_ORDER.indexOf(item.severity) >= SEVERITY_ORDER.indexOf(allowed));

const counts = buildSeverityCounts(allVulns);
const secretCounts = buildSeverityCounts(allSecrets);
const findingCounts = buildSeverityCounts(allFindings);
const reproducibility = buildReproducibilitySummary(reportDir);

const result = {
  gate_failed: gateFailed,
  threshold,
  counts,
  secret_counts: secretCounts,
  finding_counts: findingCounts,
  total_vulnerabilities: allVulns.length,
  total_secrets: allSecrets.length,
  total_findings: allFindings.length,
  reproducibility,
  vulnerabilities: allVulns,
  secrets: allSecrets
};

fs.writeFileSync(output, JSON.stringify(result, null, 2));

