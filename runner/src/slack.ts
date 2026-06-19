import * as fs from 'fs';
import * as https from 'https';
import * as path from 'path';
import { spawnSync } from 'child_process';
import pino from 'pino';

const { createAppLogger } = require(path.resolve(__dirname, '..', '..', 'common', 'logger.js')) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    info: (message: string, meta?: Record<string, unknown>) => void;
    warn: (message: string, meta?: Record<string, unknown>) => void;
  };
};
const logger = createAppLogger({ pino });

type SlackOptions = {
  runDir: string;
  sourceRepo: string;
  sourceBranch: string;
  webhookUrl?: string;
};

function buildRunUrl(runDir: string): string {
  return `local-run:${runDir.replace(/\\/g, '/')}`;
}

function buildPayload(runDir: string, sourceRepo: string, sourceBranch: string): string | null {
  const scriptPath = path.resolve(__dirname, '..', '..', 'scripts', 'build_slack_payload.js');
  const outputPath = path.join(runDir, 'slack-payload.json');
  const issueResultPath = path.join(runDir, 'sbom', 'automation', 'issue-result.json');

  const args = [
    scriptPath,
    '--run-dir', runDir,
    '--run-url', buildRunUrl(runDir),
    '--source-repo', sourceRepo,
    '--source-branch', sourceBranch,
    '--output', outputPath
  ];

  if (fs.existsSync(issueResultPath)) {
    args.push('--issue-result', issueResultPath);
  }

  const result = spawnSync(process.execPath, args, {
    cwd: path.resolve(__dirname, '..', '..'),
    stdio: 'inherit',
    timeout: 2 * 60 * 1000
  });

  if (result.error || result.status !== 0) {
    logger.warn('Slack payload generation failed', {
      error: result.error ? result.error.message : `exit_code_${result.status}`
    });
    return null;
  }

  return outputPath;
}

function postJson(url: string, payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(payload));
    const request = https.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': body.length
      }
    }, (response) => {
      let responseText = '';
      response.on('data', (chunk) => { responseText += chunk; });
      response.on('end', () => {
        if (response.statusCode && response.statusCode >= 200 && response.statusCode < 300) {
          resolve();
          return;
        }
        reject(new Error(`Slack webhook failed ${response.statusCode}: ${responseText}`));
      });
    });

    request.on('error', reject);
    request.write(body);
    request.end();
  });
}

export async function notifySlack(opts: SlackOptions): Promise<void> {
  const payloadPath = buildPayload(opts.runDir, opts.sourceRepo, opts.sourceBranch);
  if (!payloadPath) {
    return;
  }

  if (!opts.webhookUrl) {
    logger.info(`Slack payload created at ${payloadPath}`);
    return;
  }

  const payload = JSON.parse(fs.readFileSync(payloadPath, 'utf-8'));
  await postJson(opts.webhookUrl, payload);
  logger.info('Slack notification sent');
}
