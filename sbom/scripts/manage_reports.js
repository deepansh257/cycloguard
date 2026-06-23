#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const pino = require('pino');
const { createAppLogger } = require(path.resolve(__dirname, '..', '..', 'common', 'logger.js'));
const logger = createAppLogger({ pino });

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function readJsonIfExists(filePath, fallback) {
  return fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf8')) : fallback;
}

const reportDir = getArg('report-dir');
const issueResultPath = getArg('issue-result');
const runId = getArg('run-id');
const runAttempt = getArg('run-attempt');
const sha = getArg('sha');
const ref = getArg('ref');
const actor = getArg('actor');
const sourceRepo = getArg('source-repo', 'unknown-repo');
const sourceBranch = getArg('source-branch', 'unknown-branch');
const historyFile = getArg('history-file');
const output = getArg('output');

if (!reportDir || !runId || !runAttempt || !sha || !ref || !actor) {
  logger.error('Missing required args');
  process.exit(1);
}

const gate = readJsonIfExists(path.join(reportDir, 'gate-result.json'), {});
const issueResult = readJsonIfExists(issueResultPath || path.join(reportDir, 'automation', 'issue-result.json'), {});
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
  total_secrets: gate.total_secrets || 0,
  total_findings: gate.total_findings || ((gate.total_vulnerabilities || 0) + (gate.total_secrets || 0)),
  severity_counts: gate.counts || {},
  secret_severity_counts: gate.secret_counts || {},
  finding_severity_counts: gate.finding_counts || {},
  reproducibility: gate.reproducibility || {},
  source_selection: (gate.reproducibility && gate.reproducibility.source_selection) || [],
  github_issue: issueResult.issue_url || null,
  github_issue_mode: issueResult.mode || 'not_run',
  alert_only_count: issueResult.alert_only_count || 0,
  report_path: reportDir.replace(/\\/g, '/')
};

history.push(entry);
fs.writeFileSync(indexFile, JSON.stringify(history, null, 2));
fs.writeFileSync(output || path.join(reportDir, 'automation', 'run-summary.json'), JSON.stringify(entry, null, 2));

