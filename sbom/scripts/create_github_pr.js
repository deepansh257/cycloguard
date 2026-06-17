#!/usr/bin/env node
const fs = require('fs');
const https = require('https');

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
        'User-Agent': 'cycloguard-sbom-remediation',
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

function parseIssueNumber(issueUrl) {
  if (!issueUrl) return null;
  const match = issueUrl.match(/\/issues\/(\d+)$/);
  return match ? Number(match[1]) : null;
}

async function main() {
  const repo = getArg('repo');
  const token = getArg('token');
  const head = getArg('head');
  const base = getArg('base');
  const title = getArg('title');
  const bodyFile = getArg('body-file');
  const output = getArg('output');
  const issueResultPath = getArg('issue-result');

  if (!repo || !token || !head || !base || !title || !bodyFile || !output) {
    console.error('Missing required args: --repo --token --head --base --title --body-file --output');
    process.exit(1);
  }

  const body = fs.readFileSync(bodyFile, 'utf8');
  const repoOwner = repo.split('/')[0];
  const pullsUrl = `https://api.github.com/repos/${repo}/pulls?state=open&head=${repoOwner}:${encodeURIComponent(head)}`;
  const pulls = await ghApi('GET', pullsUrl, token);
  let result;

  if (Array.isArray(pulls) && pulls.length > 0) {
    const existing = pulls[0];
    await ghApi('PATCH', `https://api.github.com/repos/${repo}/pulls/${existing.number}`, token, {
      title,
      body
    });
    result = {
      mode: 'updated',
      pr_number: existing.number,
      pr_url: existing.html_url,
      draft: existing.draft
    };
  } else {
    const created = await ghApi('POST', `https://api.github.com/repos/${repo}/pulls`, token, {
      title,
      head,
      base,
      body,
      draft: true
    });
    result = {
      mode: 'created',
      pr_number: created.number,
      pr_url: created.html_url,
      draft: true
    };
  }

  if (issueResultPath && fs.existsSync(issueResultPath)) {
    const issueResult = JSON.parse(fs.readFileSync(issueResultPath, 'utf8'));
    const issueNumber = parseIssueNumber(issueResult.issue_url);
    if (issueNumber) {
      await ghApi('POST', `https://api.github.com/repos/${repo}/issues/${issueNumber}/comments`, token, {
        body: `CycloGuard remediation PR created for manual review: ${result.pr_url}`
      });
      result.linked_issue = issueResult.issue_url;
    }
  }

  fs.writeFileSync(output, JSON.stringify(result, null, 2));
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
