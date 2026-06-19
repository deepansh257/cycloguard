#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

function loadPino() {
  const candidates = [
    'pino',
    path.resolve(__dirname, '..', 'sbom', 'node_modules', 'pino'),
    path.resolve(__dirname, '..', 'runner', 'node_modules', 'pino'),
    path.resolve(__dirname, '..', 'cbom', 'node_modules', 'pino')
  ];

  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch (error) {
      if (error.code !== 'MODULE_NOT_FOUND') {
        throw error;
      }
    }
  }

  throw new Error('Unable to resolve pino for scripts/build_slack_payload.js');
}

const pino = loadPino();
process.env.CYCLOGUARD_LOG_FORMAT = process.env.CYCLOGUARD_LOG_FORMAT || 'json';
const { createAppLogger } = require(path.resolve(__dirname, '..', 'common', 'logger.js'));
const logger = createAppLogger({ pino });

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function readJsonIfExists(filePath, fallback) {
  return fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf8')) : fallback;
}

function resolvePaths(runDirArg, reportDirArg) {
  if (runDirArg) {
    return {
      runDir: path.resolve(runDirArg),
      sbomDir: path.resolve(runDirArg, 'sbom'),
      cbomFile: path.resolve(runDirArg, 'cbom', 'cbom.json')
    };
  }

  if (!reportDirArg) {
    return null;
  }

  const reportDir = path.resolve(reportDirArg);
  const inferredRunDir = path.basename(reportDir) === 'sbom'
    ? path.dirname(reportDir)
    : reportDir;

  return {
    runDir: inferredRunDir,
    sbomDir: reportDir,
    cbomFile: path.join(inferredRunDir, 'cbom', 'cbom.json')
  };
}

function getCbomSummary(cbom) {
  if (!cbom || !cbom.metadata || !Array.isArray(cbom.metadata.properties)) {
    return null;
  }

  const properties = new Map(
    cbom.metadata.properties
      .filter((entry) => entry && entry.name)
      .map((entry) => [entry.name, entry.value])
  );

  const toNumber = (name) => {
    const value = properties.get(name);
    const parsed = Number.parseInt(value || '0', 10);
    return Number.isFinite(parsed) ? parsed : 0;
  };

  return {
    filesScanned: toNumber('cbom-js:filesScanned'),
    scanDuration: properties.get('cbom-js:scanDuration') || 'unknown',
    totalFindings: toNumber('cbom-js:totalFindings'),
    criticalFindings: toNumber('cbom-js:criticalFindings'),
    highFindings: toNumber('cbom-js:highFindings'),
    weakAlgorithms: toNumber('cbom-js:weakAlgorithms'),
    quantumVulnerable: toNumber('cbom-js:quantumVulnerable'),
    componentName: cbom.metadata.component && cbom.metadata.component.name
      ? cbom.metadata.component.name
      : 'unknown-component'
  };
}

function isLocalRun(runUrlValue) {
  return typeof runUrlValue === 'string' && runUrlValue.startsWith('local-run:');
}

function asSlackLink(label, url) {
  if (!url) {
    return label;
  }
  return `<${url}|${label}>`;
}

function formatSourceRepo(value) {
  if (!value) {
    return 'unknown-repo';
  }

  const githubMatch = value.match(/github\.com[:/]+([^/]+\/[^/.]+)(?:\.git)?$/i);
  if (githubMatch) {
    const repoName = githubMatch[1];
    const normalizedUrl = value.startsWith('http') ? value : `https://github.com/${repoName}`;
    return asSlackLink(repoName, normalizedUrl.replace(/\.git$/i, ''));
  }

  if (value === '.') {
    return 'current-workspace';
  }

  return value;
}

function buildReportsText(runUrlValue, resolved) {
  if (isLocalRun(runUrlValue)) {
    const localPath = resolved.runDir.replace(/\\/g, '/');
    return `*Reports:* local folder \`${localPath}\``;
  }

  return '*Reports:* attached in workflow artifacts';
}

const reportDir = getArg('report-dir');
const runDir = getArg('run-dir');
const issueResultPath = getArg('issue-result');
const runUrl = getArg('run-url');
const output = getArg('output');
const sourceRepo = getArg('source-repo', 'unknown-repo');
const sourceBranch = getArg('source-branch', 'unknown-branch');

if ((!reportDir && !runDir) || !runUrl || !output) {
  logger.error('Missing required args: (--report-dir or --run-dir) --run-url --output');
  process.exit(1);
}

const resolvedPaths = resolvePaths(runDir, reportDir);
if (!resolvedPaths) {
  logger.error('Unable to resolve report paths');
  process.exit(1);
}

const gate = readJsonIfExists(path.join(resolvedPaths.sbomDir, 'gate-result.json'), {});
const cbom = readJsonIfExists(resolvedPaths.cbomFile, null);
const cbomSummary = getCbomSummary(cbom);
const issueResult = readJsonIfExists(
  issueResultPath || path.join(resolvedPaths.sbomDir, 'automation', 'issue-result.json'),
  { mode: 'skipped' }
);
const counts = gate.counts || {};
const secretCounts = gate.secret_counts || {};
const findingCounts = gate.finding_counts || {};
const reproducibility = gate.reproducibility || {};
const reproducibilityWarnings = reproducibility.warnings || [];
const status = gate.gate_failed ? 'FAILED' : 'PASSED';
const sourceText = formatSourceRepo(sourceRepo);
const reportsText = buildReportsText(runUrl, resolvedPaths);
const issueText = issueResult.issue_url
  ? `*GitHub issue:* ${asSlackLink('Open issue', issueResult.issue_url)}`
  : '*GitHub issue:* Not created (High/Critical not found or integration disabled)';

const payload = {
  text: `CycloGuard ${status} | ${sourceRepo} @ ${sourceBranch} | CVEs=${gate.total_vulnerabilities || 0} | Secrets=${gate.total_secrets || 0}${cbomSummary ? ` | CBOM=${cbomSummary.totalFindings}` : ''}`,
  blocks: [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: `CycloGuard Result: ${status}`
      }
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Source*\n${sourceText}` },
        { type: 'mrkdwn', text: `*Branch*\n${sourceBranch}` },
        { type: 'mrkdwn', text: `*Run*\n${runUrl}` },
        { type: 'mrkdwn', text: `*Threshold*\n${gate.threshold || 'high'}` }
      ]
    },
    { type: 'divider' },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: '*SBOM Summary*' }
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Total CVEs*\n${gate.total_vulnerabilities || 0}` },
        { type: 'mrkdwn', text: `*Secret Findings*\n${gate.total_secrets || 0}` },
        { type: 'mrkdwn', text: `*Overall Findings*\n${gate.total_findings || ((gate.total_vulnerabilities || 0) + (gate.total_secrets || 0))}` },
        { type: 'mrkdwn', text: `*Reproducibility*\n${reproducibility.deterministic_projects || 0} deterministic / ${reproducibility.non_deterministic_projects || 0} non-deterministic` }
      ]
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Vulnerability Severity*\nCRITICAL=${counts.CRITICAL || 0}\nHIGH=${counts.HIGH || 0}\nMEDIUM=${counts.MEDIUM || 0}\nLOW=${counts.LOW || 0}` },
        { type: 'mrkdwn', text: `*Secret Severity*\nCRITICAL=${secretCounts.CRITICAL || 0}\nHIGH=${secretCounts.HIGH || 0}\nMEDIUM=${secretCounts.MEDIUM || 0}\nLOW=${secretCounts.LOW || 0}` },
        { type: 'mrkdwn', text: `*Overall SBOM Severity*\nCRITICAL=${findingCounts.CRITICAL || 0}\nHIGH=${findingCounts.HIGH || 0}\nMEDIUM=${findingCounts.MEDIUM || 0}\nLOW=${findingCounts.LOW || 0}` }
      ]
    },
    ...(cbomSummary ? [
      { type: 'divider' },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: '*CBOM Summary*' },
        fields: [
          { type: 'mrkdwn', text: `*Findings*\n${cbomSummary.totalFindings}` },
          { type: 'mrkdwn', text: `*Critical / High*\n${cbomSummary.criticalFindings} / ${cbomSummary.highFindings}` },
          { type: 'mrkdwn', text: `*Weak Algorithms*\n${cbomSummary.weakAlgorithms}` },
          { type: 'mrkdwn', text: `*Quantum Vulnerable*\n${cbomSummary.quantumVulnerable}` },
          { type: 'mrkdwn', text: `*Files Scanned*\n${cbomSummary.filesScanned}` },
          { type: 'mrkdwn', text: `*Duration*\n${cbomSummary.scanDuration}` }
        ]
      },
      {
        type: 'context',
        elements: [
          { type: 'mrkdwn', text: `CBOM component: \`${cbomSummary.componentName}\`` }
        ]
      }
    ] : []),
    ...(reproducibilityWarnings.length > 0 ? [
      { type: 'divider' },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Reproducibility Warning*\n${reproducibilityWarnings[0].warning}`
        }
      },
      {
        type: 'context',
        elements: [
          { type: 'mrkdwn', text: `Selected source: ${(reproducibilityWarnings[0].source_of_truth_files || []).join(', ') || 'fallback manifest'}` },
          { type: 'mrkdwn', text: `Supporting files: ${(reproducibilityWarnings[0].supporting_files || []).join(', ') || 'none'}` }
        ]
      }
    ] : []),
    { type: 'divider' },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: '*Alerting policy:* High/Critical -> GitHub ticket, Medium/Low -> Slack alert summary only'
      }
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: issueText
      }
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: reportsText
      }
    }
  ]
};

fs.writeFileSync(output, JSON.stringify(payload, null, 2));
