import * as path from 'path';
import * as fs from 'fs';
import pino from 'pino';
import { cloneRepository, resolveLocalSource, isGitHubUrl } from './gitSource';
import { detectTechStack } from './techDetector';
import { runCbom } from './cbomRunner';
import { runSbom } from './sbomRunner';
import { generateDashboard } from './dashboardGenerator';

const { createAppLogger } = require(path.resolve(__dirname, '..', '..', 'common', 'logger.js')) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    info: (message: string, meta?: Record<string, unknown>) => void;
    warn: (message: string, meta?: Record<string, unknown>) => void;
    error: (message: string, meta?: Record<string, unknown>) => void;
    raw: (message: string) => void;
  };
};
const logger = createAppLogger({ pino });

function buildRunFolderName(projectName: string, branch?: string): string {
  const safeProject = projectName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const safeBranch = (branch || 'default').replace(/[^a-zA-Z0-9._-]/g, '_');
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  return `${safeProject}__${safeBranch}__${stamp}`;
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) {
        args[key] = true;
      } else {
        args[key] = next;
        i++;
      }
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const source = args['source'] as string | undefined;
  const branch = args['branch'] as string | undefined;
  const scanMode = (args['scan'] as string) || 'all';
  const outputDir = path.resolve((args['output'] as string) || './cycloguard-output');
  const codeqlPath = args['codeql-path'] as string | undefined;
  const noCache = args['no-cache'] === true;

  if (!source) {
    logger.error('--source is required');
    process.exit(1);
  }

  if (!['cbom', 'sbom', 'all'].includes(scanMode)) {
    logger.error(`--scan must be cbom, sbom, or all (got: ${scanMode})`);
    process.exit(1);
  }

  logger.raw('\n  CycloGuard Runner\n');
  logger.info('Resolving source...');

  let localPath: string;
  let projectName: string;

  if (isGitHubUrl(source)) {
    if (noCache) {
      const { clearRepoCache } = await import('./gitSource');
      clearRepoCache(source, branch);
    }
    const result = await cloneRepository(source, branch, true);
    localPath = result.localPath;
    projectName = result.projectName;
  } else {
    const result = resolveLocalSource(source);
    localPath = result.localPath;
    projectName = result.projectName;
  }

  logger.info(`Source ready: ${projectName} at ${localPath}`);

  const techStack = detectTechStack(localPath);
  logger.info(`Detected: ${techStack.join(', ') || 'unknown'}`);

  const runDir = path.join(outputDir, buildRunFolderName(projectName, branch));
  fs.mkdirSync(runDir, { recursive: true });
  logger.info(`Output: ${runDir}`);

  const runCbomScan = scanMode === 'cbom' || scanMode === 'all';
  const runSbomScan = scanMode === 'sbom' || scanMode === 'all';

  const cbomOutputDir = path.join(runDir, 'cbom');
  const sbomOutputDir = path.join(runDir, 'sbom');
  fs.mkdirSync(cbomOutputDir, { recursive: true });
  fs.mkdirSync(sbomOutputDir, { recursive: true });
  const cbomOutputFile = path.join(cbomOutputDir, 'cbom.json');

  const [cbomResult, sbomResult] = await Promise.all([
    runCbomScan
      ? runCbom({ localPath, outputFile: cbomOutputFile, codeqlPath })
      : Promise.resolve(null),
    runSbomScan
      ? runSbom({ localPath, outputDir: sbomOutputDir, branch })
      : Promise.resolve(null),
  ]);

  logger.raw('\n  Results\n');

  if (cbomResult) {
    if (cbomResult.error) {
      logger.error(`CBOM: ${cbomResult.error}`);
    } else {
      logger.info(`CBOM: output at ${cbomOutputFile}`);
    }
  }

  if (sbomResult) {
    if (sbomResult.error) {
      logger.error(`SBOM: ${sbomResult.error}`);
    } else {
      logger.info(`SBOM: output at ${sbomOutputDir}`);
    }
  }

  try {
    const dashboardFile = generateDashboard({ runDir, projectName, scanMode });
    logger.info(`Dashboard: ${dashboardFile}`);
  } catch (err: any) {
    logger.warn(`Dashboard generation failed: ${err.message}`);
  }

  logger.raw('');
}

main().catch((err) => {
  logger.error(err.message);
  process.exit(1);
});
