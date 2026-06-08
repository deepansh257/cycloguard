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
const runUrl = getArg('run-url');
const output = getArg('output');
const sourceRepo = getArg('source-repo', 'unknown-repo');
const sourceBranch = getArg('source-branch', 'unknown-branch');

if (!reportDir || !runUrl || !output) {
  console.error('Missing required args: --report-dir --run-url --output');
  process.exit(1);
}

const gate = readJsonIfExists(path.join(reportDir, 'gate-result.json'), {});
const issueResult = readJsonIfExists(path.join(reportDir, 'issue-result.json'), { mode: 'skipped' });
const counts = gate.counts || {};
const status = gate.gate_failed ? 'FAILED' : 'PASSED';
const issueText = issueResult.issue_url
  ? `*GitHub issue:* ${issueResult.issue_url}`
  : '*GitHub issue:* Not created (High/Critical not found or integration disabled)';

const payload = {
  text: `CycloGuard security pipeline ${status}`,
  blocks: [
    { type: 'section', text: { type: 'mrkdwn', text: `*CycloGuard Result:* ${status}` } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Source:* ${sourceRepo} @ ${sourceBranch}` } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Total CVEs:* ${gate.total_vulnerabilities || 0}` } },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Severity Counts:* CRITICAL=${counts.CRITICAL || 0}, HIGH=${counts.HIGH || 0}, MEDIUM=${counts.MEDIUM || 0}, LOW=${counts.LOW || 0}`
      }
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: '*Alerting policy:* High/Critical -> GitHub ticket, Medium/Low -> Slack alert summary only'
      }
    },
    { type: 'section', text: { type: 'mrkdwn', text: issueText } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Run:* ${runUrl}` } },
    { type: 'section', text: { type: 'mrkdwn', text: '*Reports:* Attached in workflow artifacts' } }
  ]
};

fs.writeFileSync(output, JSON.stringify(payload, null, 2));
