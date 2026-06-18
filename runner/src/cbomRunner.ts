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

export interface CbomRunnerOptions {
  localPath: string;
  outputFile: string;
  codeqlPath?: string;
}

export interface CbomRunnerResult {
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

export function runCbom(opts: CbomRunnerOptions): Promise<CbomRunnerResult> {
  return new Promise((resolve) => {
    const cbomRoot = path.resolve(__dirname, '..', '..', 'cbom');

    if (!fs.existsSync(cbomRoot)) {
      resolve({ error: `cbom directory not found at ${cbomRoot}` });
      return;
    }

    const args: string[] = [
      'ts-node', 'src/index.ts',
      '--source', opts.localPath,
      '--output', opts.outputFile,
    ];

    if (opts.codeqlPath) {
      args.push('--codeql', '--codeql-path', opts.codeqlPath);
    }

    logger.info('Running CBOM scan...');
    const result = process.platform === 'win32'
      ? spawnSync('cmd.exe', ['/d', '/s', '/c', toWindowsCmdCommand(['npx.cmd', ...args])], {
        cwd: cbomRoot,
        stdio: 'inherit',
        timeout: 15 * 60 * 1000,
      })
      : spawnSync('npx', args, {
        cwd: cbomRoot,
        stdio: 'inherit',
        timeout: 15 * 60 * 1000,
      });

    if (result.error) {
      resolve({ error: result.error.message });
    } else if (result.status !== 0 && result.status !== 1) {
      resolve({ error: `cbom-js exited with code ${result.status}` });
    } else {
      resolve({});
    }
  });
}
