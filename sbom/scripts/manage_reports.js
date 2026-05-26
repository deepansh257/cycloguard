#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

const reportDir = getArg('report-dir');
const runId = getArg('run-id');
const runAttempt = getArg('run-attempt');
const sha = getArg('sha');
const ref = getArg('ref');
const actor = getArg('actor');

if (!reportDir || !runId || !runAttempt || !sha || !ref || !actor) {
  console.error('Missing required args');
  process.exit(1);
}

const gateFile = path.join(reportDir, 'gate-result.json');
const gate = fs.existsSync(gateFile) ? JSON.parse(fs.readFileSync(gateFile, 'utf8')) : {};

const indexFile = 'sbom/reports/history-index.json';
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
  gate_failed: gate.gate_failed,
  total_vulnerabilities: gate.total_vulnerabilities || 0,
  severity_counts: gate.counts || {},
  report_path: reportDir.replace(/\\/g, '/')
};

history.push(entry);
fs.writeFileSync(indexFile, JSON.stringify(history, null, 2));
fs.writeFileSync(path.join(reportDir, 'run-summary.json'), JSON.stringify(entry, null, 2));
