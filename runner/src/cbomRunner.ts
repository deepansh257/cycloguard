import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export interface CbomRunnerOptions {
  localPath:   string;
  outputFile:  string;
  codeqlPath?: string;
}

export interface CbomRunnerResult {
  error?: string;
}

/**
 * Runs cbom-js pointing at a local path (already cloned by gitSource).
 * Mirrors the working manual command:
 *   npx ts-node src/index.ts --source <localPath> --codeql --codeql-path <path> --output <file>
 */
export function runCbom(opts: CbomRunnerOptions): Promise<CbomRunnerResult> {
  return new Promise(resolve => {
    // Path to cbom package relative to this runner
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

    console.log('  → Running CBOM scan…');

    const result = spawnSync('npx', args, {
      cwd:   cbomRoot,
      stdio: 'inherit',   // stream output directly to terminal
      shell: true,        // needed on Windows
      timeout: 15 * 60 * 1000,
    });

    if (result.error) {
      resolve({ error: result.error.message });
    } else if (result.status !== 0 && result.status !== 1) {
      // cbom-js exits 1 when weak findings present — that is not an error
      resolve({ error: `cbom-js exited with code ${result.status}` });
    } else {
      resolve({});
    }
  });
}
