import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import pino from 'pino';

const { createAppLogger } = require(path.resolve(__dirname, '..', '..', 'common', 'logger.js')) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    info: (message: string, meta?: Record<string, unknown>) => void;
  };
};
const logger = createAppLogger({ pino });

export interface SbomRunnerOptions {
  localPath: string;
  outputDir: string;
  branch?: string;
}

export interface SbomRunnerResult {
  error?: string;
}

function toWindowsCmdCommand(args: string[]): string {
  return args.map((arg) => {
    if (/[\s"]/u.test(arg)) {
      return `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/g, '$1$1')}"`;
    }
    return arg;
  }).join(' ');
}

export function runSbom(opts: SbomRunnerOptions): Promise<SbomRunnerResult> {
  return new Promise((resolve) => {
    const sbomRoot = path.resolve(__dirname, '..', '..', 'sbom');

    if (!fs.existsSync(sbomRoot)) {
      resolve({ error: `sbom directory not found at ${sbomRoot}` });
      return;
    }

    fs.mkdirSync(opts.outputDir, { recursive: true });

    const args: string[] = [
      'ts-node', 'src/index.ts',
      '--source', opts.localPath,
      '--output', opts.outputDir,
    ];

    if (opts.branch) {
      args.push('--branch', opts.branch);
    }

    logger.info('Running SBOM scan...');
    const result = process.platform === 'win32'
      ? spawnSync('cmd.exe', ['/d', '/s', '/c', toWindowsCmdCommand(['npx.cmd', ...args])], {
        cwd: sbomRoot,
        stdio: 'inherit',
        timeout: 15 * 60 * 1000,
      })
      : spawnSync('npx', args, {
        cwd: sbomRoot,
        stdio: 'inherit',
        timeout: 15 * 60 * 1000,
      });

    if (result.error) {
      resolve({ error: result.error.message });
    } else if (result.status !== 0) {
      resolve({ error: `sbom exited with code ${result.status}` });
    } else {
      resolve({});
    }
  });
}
