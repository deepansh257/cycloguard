import * as path from 'path';
import * as fs from 'fs';
import { cloneRepository, resolveLocalSource, isGitHubUrl } from './gitSource';
import { detectTechStack } from './techDetector';
import { runCbom } from './cbomRunner';
import { runSbom } from './sbomRunner';
import { generateDashboard } from './dashboardGenerator';  // ← new

// ── Parse CLI args ────────────────────────────────────────────────────────────

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

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const source     = args['source'] as string | undefined;
  const branch     = args['branch'] as string | undefined;
  const scanMode   = (args['scan'] as string) || 'all';
  const outputDir  = path.resolve((args['output'] as string) || './cycloguard-output');
  const codeqlPath = args['codeql-path'] as string | undefined;
  const noCache    = args['no-cache'] === true;

  if (!source) {
    console.error('  ✖  --source is required');
    process.exit(1);
  }

  if (!['cbom', 'sbom', 'all'].includes(scanMode)) {
    console.error(`  ✖  --scan must be cbom, sbom, or all (got: ${scanMode})`);
    process.exit(1);
  }

  console.log('\n  🔐 CycloGuard Runner\n');

  // ── 1. Resolve source (clone once, shared by both tools) ──────────────────
  console.log('  → Resolving source…');

  let localPath: string;
  let projectName: string;

  if (isGitHubUrl(source)) {
    if (noCache) {
      const { clearRepoCache } = await import('./gitSource');
      clearRepoCache(source, branch);
    }
    const result = await cloneRepository(source, branch, true);
    localPath   = result.localPath;
    projectName = result.projectName;
  } else {
    const result = resolveLocalSource(source);
    localPath   = result.localPath;
    projectName = result.projectName;
  }

  console.log(`  ✔  Source ready: ${projectName} at ${localPath}`);

  // ── 2. Detect tech stack ──────────────────────────────────────────────────
  const techStack = detectTechStack(localPath);
  console.log(`  ✔  Detected: ${techStack.join(', ') || 'unknown'}`);

  // ── 3. Prepare output dir ─────────────────────────────────────────────────
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const runDir    = path.join(outputDir, `${projectName}-${timestamp}`);
  fs.mkdirSync(runDir, { recursive: true });
  console.log(`  ✔  Output: ${runDir}\n`);

  // ── 4. Run scans ──────────────────────────────────────────────────────────
  const runCbomScan = scanMode === 'cbom' || scanMode === 'all';
  const runSbomScan = scanMode === 'sbom' || scanMode === 'all';

  const cbomOutputFile = path.join(runDir, 'cbom.json');
  const sbomOutputDir  = path.join(runDir, 'sbom');

  const [cbomResult, sbomResult] = await Promise.all([
    runCbomScan
      ? runCbom({ localPath, outputFile: cbomOutputFile, codeqlPath })
      : Promise.resolve(null),
    runSbomScan
      ? runSbom({ localPath, outputDir: sbomOutputDir, branch })
      : Promise.resolve(null),
  ]);

  // ── 5. Print results ──────────────────────────────────────────────────────
  console.log('\n  ── Results ──────────────────────────────────────────');

  if (cbomResult) {
    if (cbomResult.error) {
      console.log(`  ✖  CBOM: ${cbomResult.error}`);
    } else {
      console.log(`  ✔  CBOM: output at ${cbomOutputFile}`);
    }
  }

  if (sbomResult) {
    if (sbomResult.error) {
      console.log(`  ✖  SBOM: ${sbomResult.error}`);
    } else {
      console.log(`  ✔  SBOM: output at ${sbomOutputDir}`);
    }
  }

  // ── 6. Generate dashboard ─────────────────────────────────────────────────
  try {
    const dashboardFile = generateDashboard({ runDir, projectName, scanMode });
    console.log(`  ✔  Dashboard: ${dashboardFile}`);
  } catch (err: any) {
    console.log(`  ⚠  Dashboard generation failed: ${err.message}`);
  }

  console.log('');
}

main().catch(err => {
  console.error(`\n  ✖  ${err.message}`);
  process.exit(1);
});