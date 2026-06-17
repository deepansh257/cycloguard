import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { loadLocalEnv } from './utils/env';
import { runCbomRemediationWorkflow } from './remediation/workflow';
import { ScanOptions } from './types';

function readCbomSourcePath(reportPath: string): string | undefined {
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  const properties = report?.metadata?.properties || [];
  const sourcePathProp = properties.find((item: any) => item.name === 'cbom-js:sourcePath');
  return sourcePathProp?.value;
}

async function main() {
  loadLocalEnv();

  const program = new Command();
  program
    .name('cbom-remediate')
    .description('Run AI-driven remediation against a generated CBOM report')
    .requiredOption('--report <file>', 'Path to generated cbom.json report')
    .option('--repo-root <path>', 'Repository root to patch (defaults to cbom-js:sourcePath from report)')
    .option('--source <path-or-url>', 'Source label used for PR metadata')
    .option('--branch <name>', 'Source branch used for PR metadata', 'main')
    .option('--github-repo <owner/repo>', 'Optional repo where remediation PR should be created')
    .option('--github-token <token>', 'GitHub token for push/PR creation')
    .option('--create-pr <value>', 'Create a draft remediation PR when fixes are applied', 'true')
    .action(async (opts) => {
      const reportPath = path.resolve(opts.report);
      if (!fs.existsSync(reportPath)) {
        throw new Error(`CBOM report not found: ${reportPath}`);
      }

      const repoRoot = path.resolve(opts.repoRoot || readCbomSourcePath(reportPath) || '.');
      const options: ScanOptions = {
        source: opts.source || repoRoot,
        output: reportPath,
        format: 'cyclonedx',
        failOnWeak: false,
        verbose: false,
        enableRemediation: true,
        createPr: String(opts.createPr).toLowerCase() !== 'false',
        githubRepo: opts.githubRepo || process.env.GITHUB_TARGET_REPO || process.env.GITHUB_REPOSITORY,
        githubToken: opts.githubToken || process.env.API_GITHUB_TOKEN || process.env.GITHUB_TOKEN,
        gitUserName: process.env.GIT_USER_NAME || 'CycloGuard Bot',
        gitUserEmail: process.env.GIT_USER_EMAIL || 'cycloguard-bot@example.com',
      };

      await runCbomRemediationWorkflow(options, {
        repoRoot,
        cbomReportPath: reportPath,
        sourceLabel: opts.source || repoRoot,
        sourceBranch: opts.branch || 'main',
        scanSource: opts.source || repoRoot,
        cliCwd: path.resolve(__dirname, '..'),
        projectName: path.basename(repoRoot),
        targetRepo: options.githubRepo,
      });

      const remediationDir = path.join(path.dirname(reportPath), 'remediation');
      console.log(`\nCBOM remediation completed. Artifacts available at: ${remediationDir}`);
    });

  await program.parseAsync(process.argv);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
