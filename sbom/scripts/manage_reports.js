#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function readJsonIfExists(filePath, fallback) {
  return fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf8')) : fallback;
}

const reportDir = getArg('report-dir');
const runId = getArg('run-id');
const runAttempt = getArg('run-attempt');
const sha = getArg('sha');
const ref = getArg('ref');
const actor = getArg('actor');
const sourceRepo = getArg('source-repo', 'unknown-repo');
const sourceBranch = getArg('source-branch', 'unknown-branch');
const historyFile = getArg('history-file');

if (!reportDir || !runId || !runAttempt || !sha || !ref || !actor) {
  console.error('Missing required args');
  process.exit(1);
}

const gate = readJsonIfExists(path.join(reportDir, 'gate-result.json'), {});
const issueResult = readJsonIfExists(path.join(reportDir, 'issue-result.json'), {});
const remediationResult = readJsonIfExists(path.join(reportDir, 'remediation-result.json'), {});
const prResult = readJsonIfExists(path.join(reportDir, 'pr-result.json'), {});
const indexFile = historyFile || path.join(path.dirname(reportDir), 'history-index.json');
let history = [];

if (fs.existsSync(indexFile)) {
  history = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
}

const entry = {
  run_id: runId,
  run_attempt: runAttempt,
  timestamp_utc: new Date().toISOString(),
  sha,
  ref,
  actor,
  source_repo: sourceRepo,
  source_branch: sourceBranch,
  gate_failed: gate.gate_failed,
  total_vulnerabilities: gate.total_vulnerabilities || 0,
  severity_counts: gate.counts || {},
  github_issue: issueResult.issue_url || null,
  github_issue_mode: issueResult.mode || 'not_run',
  alert_only_count: issueResult.alert_only_count || 0,
  remediation_mode: remediationResult.mode || 'not_run',
  remediation_branch: remediationResult.remediation_branch || null,
  remediation_manual_review_required: Boolean(remediationResult.manual_review_required),
  remediation_pr: prResult.pr_url || null,
  remediation_pr_mode: prResult.mode || 'not_run',
  report_path: reportDir.replace(/\\/g, '/')
};

history.push(entry);
fs.writeFileSync(indexFile, JSON.stringify(history, null, 2));
fs.writeFileSync(path.join(reportDir, 'run-summary.json'), JSON.stringify(entry, null, 2));
