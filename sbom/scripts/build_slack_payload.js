#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

const reportDir = getArg('report-dir');
const runUrl = getArg('run-url');
const output = getArg('output');

if (!reportDir || !runUrl || !output) {
  console.error('Missing required args: --report-dir --run-url --output');
  process.exit(1);
}

const gatePath = path.join(reportDir, 'gate-result.json');
const gate = fs.existsSync(gatePath) ? JSON.parse(fs.readFileSync(gatePath, 'utf8')) : {};

const status = gate.gate_failed ? 'FAILED' : 'PASSED';
const counts = gate.counts || {};

const payload = {
  text: `Security pipeline ${status}`,
  blocks: [
    { type: 'section', text: { type: 'mrkdwn', text: `*Security Pipeline:* ${status}` } },
    { type: 'section', text: { type: 'mrkdwn', text: `*Total CVEs:* ${gate.total_vulnerabilities || 0}` } },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Severity Counts:* CRITICAL=${counts.CRITICAL || 0}, HIGH=${counts.HIGH || 0}, MEDIUM=${counts.MEDIUM || 0}, LOW=${counts.LOW || 0}`
      }
    },
    { type: 'section', text: { type: 'mrkdwn', text: `*Run:* ${runUrl}` } },
    { type: 'section', text: { type: 'mrkdwn', text: '*SBOM/Trivy artifacts:* Attached in workflow artifacts' } }
  ]
};

fs.writeFileSync(output, JSON.stringify(payload));
