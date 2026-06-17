import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export interface SbomRunnerOptions {
  localPath:  string;
  outputDir:  string;
  branch?:    string;
}

export interface SbomRunnerResult {
  error?: string;
}

/**
 * Runs sbom pointing at a local path (already cloned by gitSource).
 * Mirrors the working manual command:
 *   npx ts-node src/index.ts --source <localPath> --branch <branch> --output <dir>
 */
export function runSbom(opts: SbomRunnerOptions): Promise<SbomRunnerResult> {
  return new Promise(resolve => {
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

    console.log('  → Running SBOM scan…');

    const result = spawnSync('npx', args, {
      cwd:   sbomRoot,
      stdio: 'inherit',   // stream output directly to terminal
      shell: true,        // needed on Windows
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
