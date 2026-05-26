#!/usr/bin/env node
const fs = require('fs');
const https = require('https');

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function ghApi(url, token, payload) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(payload));
    const req = https.request(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
        'Content-Length': data.length
      }
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(body ? JSON.parse(body) : {});
          return;
        }
        reject(new Error(`GitHub API failed ${res.statusCode}: ${body}`));
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function main() {
  const repo = getArg('repo');
  const reportPath = getArg('report');
  const runUrl = getArg('run-url');
  const token = getArg('token');

  if (!repo || !reportPath || !runUrl || !token) {
    console.error('Missing args: --repo --report --run-url --token');
    process.exit(1);
  }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  if (!report.gate_failed) return;

  const vulns = (report.vulnerabilities || []).slice(0, 30);
  const rows = vulns.map((v) =>
    `- [${v.severity}] ${v.cve_id} | pkg=${v.package} | installed=${v.installed} | fixed=${v.fixed} | app=${v.app}`
  );

  const title = `Security Gate Failed: ${(report.threshold || 'high').toUpperCase()}+ vulnerabilities detected`;
  const body = [
    'Automated issue from security pipeline.',
    '',
    `Run: ${runUrl}`,
    `Total vulnerabilities: ${report.total_vulnerabilities || 0}`,
    `Severity counts: ${JSON.stringify(report.counts || {})}`,
    '',
    'Top findings:',
    ...rows,
    '',
    'Recommended actions:',
    '1. Update vulnerable dependencies to fixed versions.',
    '2. Re-run pipeline to validate remediation.',
    '3. Track exceptions explicitly if fix is not available.'
  ].join('\n');

  const url = `https://api.github.com/repos/${repo}/issues`;
  await ghApi(url, token, { title, body, labels: ['security', 'automated', 'trivy'] });
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
