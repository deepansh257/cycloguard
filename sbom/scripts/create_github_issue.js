#!/usr/bin/env node
const fs = require('fs');
const https = require('https');
const path = require('path');
const pino = require('pino');
const { createAppLogger } = require(path.resolve(__dirname, '..', '..', 'common', 'logger.js'));
const logger = createAppLogger({ pino });

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function ghApi(method, url, token, payload = null) {
  return new Promise((resolve, reject) => {
    const data = payload ? Buffer.from(JSON.stringify(payload)) : null;
    const req = https.request(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'cycloguard-sbom-scanner',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {})
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
    if (data) req.write(data);
    req.end();
  });
}

function summarize(vulns) {
  return vulns.slice(0, 20).map((v) =>
    `- [${v.severity}] ${v.cve_id} | pkg=${v.package} | installed=${v.installed} | fixed=${v.fixed || 'N/A'} | app=${v.app}`
  );
}

async function main() {
  const repo = getArg('repo');
  const reportPath = getArg('report');
  const runUrl = getArg('run-url');
  const token = getArg('token');
  const output = getArg('output');
  const sourceRepo = getArg('source-repo', repo || 'unknown-repo');
  const sourceBranch = getArg('source-branch', 'unknown-branch');

  if (!repo || !reportPath || !runUrl || !token || !output) {
    logger.error('Missing args: --repo --report --run-url --token --output');
    process.exit(1);
  }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  const allVulns = report.vulnerabilities || [];
  const ticketVulns = allVulns.filter((v) => ['HIGH', 'CRITICAL'].includes(v.severity));
  const alertOnlyVulns = allVulns.filter((v) => ['LOW', 'MEDIUM'].includes(v.severity));
  const marker = `<!-- cycloguard:${sourceRepo}:${sourceBranch} -->`;
  const title = `CycloGuard dependency findings: ${sourceRepo} [${sourceBranch}]`;

  if (ticketVulns.length === 0) {
    fs.writeFileSync(output, JSON.stringify({
      mode: 'skipped',
      reason: 'no_high_or_critical_vulnerabilities',
      total_vulnerabilities: allVulns.length,
      alert_only_count: alertOnlyVulns.length
    }, null, 2));
    return;
  }

  const issueBody = [
    'Automated issue from CycloGuard security pipeline.',
    marker,
    '',
    `Source repo: ${sourceRepo}`,
    `Source branch: ${sourceBranch}`,
    `Run: ${runUrl}`,
    `Gate threshold: ${(report.threshold || 'high').toUpperCase()}`,
    `Total vulnerabilities: ${report.total_vulnerabilities || 0}`,
    `Total secret findings: ${report.total_secrets || 0}`,
    `Total security findings: ${report.total_findings || ((report.total_vulnerabilities || 0) + (report.total_secrets || 0))}`,
    `Severity counts: ${JSON.stringify(report.counts || {})}`,
    `Secret severity counts: ${JSON.stringify(report.secret_counts || {})}`,
    `Overall finding counts: ${JSON.stringify(report.finding_counts || {})}`,
    '',
    'High/Critical findings:',
    ...summarize(ticketVulns),
    '',
    `Medium/Low findings in this run: ${alertOnlyVulns.length}`,
    ...(alertOnlyVulns.length > 0 ? ['', 'Medium/Low findings:', ...summarize(alertOnlyVulns)] : []),
    '',
    'Recommended actions:',
    '1. Review the vulnerable dependencies and available fixed versions.',
    '2. Prioritize Critical and High findings for remediation.',
    '3. Track Medium and Low findings as risk indicators for future updates.'
  ].join('\n');

  const issuesUrl = `https://api.github.com/repos/${repo}/issues?state=open&per_page=100`;
  let existingIssues;
  try {
    existingIssues = await ghApi('GET', issuesUrl, token);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('Issues has been disabled')) {
      fs.writeFileSync(output, JSON.stringify({
        mode: 'skipped',
        reason: 'issues_disabled_for_target_repository',
        total_vulnerabilities: allVulns.length,
        ticket_vulnerability_count: ticketVulns.length,
        alert_only_count: alertOnlyVulns.length
      }, null, 2));
      return;
    }
    throw err;
  }
  const existing = (existingIssues || []).find((issue) =>
    issue && issue.body && issue.body.includes(marker)
  );

  let result;
  if (existing) {
    const commentsUrl = `https://api.github.com/repos/${repo}/issues/${existing.number}/comments`;
    const commentBody = [
      'New CycloGuard scan detected current High/Critical findings.',
      '',
      `Run: ${runUrl}`,
      `Severity counts: ${JSON.stringify(report.counts || {})}`,
      `Secret severity counts: ${JSON.stringify(report.secret_counts || {})}`,
      `Overall finding counts: ${JSON.stringify(report.finding_counts || {})}`,
      '',
      'High/Critical findings:',
      ...summarize(ticketVulns)
      ,
      ...(alertOnlyVulns.length > 0 ? ['', 'Medium/Low findings:', ...summarize(alertOnlyVulns)] : [])
    ].join('\n');
    await ghApi('POST', commentsUrl, token, { body: commentBody });
    result = {
      mode: 'updated',
      issue_number: existing.number,
      issue_url: existing.html_url,
      ticket_vulnerability_count: ticketVulns.length,
      alert_only_count: alertOnlyVulns.length
    };
  } else {
    let created;
    try {
      created = await ghApi('POST', `https://api.github.com/repos/${repo}/issues`, token, {
        title,
        body: issueBody,
        labels: ['security', 'automated', 'trivy', 'cycloguard']
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('Issues has been disabled')) {
        fs.writeFileSync(output, JSON.stringify({
          mode: 'skipped',
          reason: 'issues_disabled_for_target_repository',
          total_vulnerabilities: allVulns.length,
          ticket_vulnerability_count: ticketVulns.length,
          alert_only_count: alertOnlyVulns.length
        }, null, 2));
        return;
      }
      // Some target repos allow issue creation but not automatic label creation.
      if (message.includes('create labels') || message.includes('"field":"label"')) {
        created = await ghApi('POST', `https://api.github.com/repos/${repo}/issues`, token, {
          title,
          body: issueBody
        });
      } else {
        throw err;
      }
    }
    result = {
      mode: 'created',
      issue_number: created.number,
      issue_url: created.html_url,
      ticket_vulnerability_count: ticketVulns.length,
      alert_only_count: alertOnlyVulns.length
    };
  }

  fs.writeFileSync(output, JSON.stringify(result, null, 2));
}

main().catch((err) => {
  logger.error(err.message);
  process.exit(1);
});

