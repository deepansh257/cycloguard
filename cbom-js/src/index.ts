import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { ScanOptions, ScanResult } from './types';
import { findFiles, readFile, getRelativePath } from './parser/fileScanner';
import { parseSource } from './parser/astParser';
import { runAllDetectors, runCodeQLPass } from './detectors/index';
import { generateCBOM } from './cbom/cbomGenerator';
import { buildSummary, printBanner, printScanStart, printProgress, printScanComplete, printFindings, printOutput } from './utils/reporter';
import { isGitHubUrl, cloneRepository, resolveLocalSource } from './utils/githubSource';
import { CryptoFinding } from './types';

// ── Java support ──────────────────────────────────────────────────────────────
import { parseJavaSource } from './parser/javaParser';
import { detectJava }      from './detectors/java/javaDetector';

const JAVA_EXTENSIONS = ['.java'];

function isJavaFile(filePath: string): boolean {
  return JAVA_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
}

// ─────────────────────────────────────────────────────────────────────────────

const program = new Command();

program
  .name('cbom-js')
  .description('CBOM generator for JavaScript / TypeScript / Node.js / Java projects')
  .version('1.0.0')
  .requiredOption('-s, --source <path-or-url>', 'Local directory path or GitHub URL to scan')
  .option('-o, --output <file>', 'Output file path for the CBOM JSON', 'cbom.json')
  .option('-b, --branch <name>', 'Git branch to checkout (only used with GitHub URLs)')
  .option('--fail-on-weak', 'Exit with code 1 if any weak algorithms are found', false)
  .option('--fail-on-severity <level>', 'Exit with code 1 if findings exist at or above this severity (CRITICAL, HIGH, MEDIUM)')
  .option('-v, --verbose', 'Print all findings including INFO level', false)
  .option('--exclude <patterns>', 'Comma-separated glob patterns to exclude', '')
  .option('--include <patterns>', 'Comma-separated glob patterns to include', '')
  .option('--codeql',             'Run CodeQL taint analysis after AST scan (requires codeql CLI)')
  .option('--codeql-path <path>', 'Path to codeql binary (default: codeql on PATH)')
  .option('--lang <languages>',   'Comma-separated list of languages to scan: js,java (default: auto-detect)', '')
  .action(async (opts) => {
    printBanner();

    const options: ScanOptions = {
      source:          opts.source,
      output:          opts.output,
      format:          'cyclonedx',
      failOnWeak:      opts.failOnWeak,
      failOnSeverity:  opts.failOnSeverity?.toUpperCase(),
      verbose:         opts.verbose,
      branch:          opts.branch,
      exclude:         opts.exclude ? opts.exclude.split(',').map((s: string) => s.trim()) : [],
      include:         opts.include ? opts.include.split(',').map((s: string) => s.trim()) : [],
      useCodeQL:       opts.codeql   ?? false,
      codeqlPath:      opts.codeqlPath ?? undefined,
    };

    // Parse --lang flag.  Empty = auto-detect (scan both JS and Java files).
    const langFilter: Set<string> = opts.lang
      ? new Set(opts.lang.split(',').map((l: string) => l.trim().toLowerCase()))
      : new Set(); // empty = no filter = scan everything

    const scanJs   = langFilter.size === 0 || langFilter.has('js') || langFilter.has('ts');
    const scanJava = langFilter.size === 0 || langFilter.has('java');

    let sourceResult;
    const startTime = Date.now();

    // ── Step 1: Resolve source ────────────────────────────────────────────────
    try {
      if (isGitHubUrl(options.source)) {
        console.log(`  Cloning repository: ${options.source}`);
        if (options.branch) console.log(`  Branch: ${options.branch}`);
        console.log('');
        sourceResult = await cloneRepository(options.source, options.branch, options.verbose);
      } else {
        sourceResult = resolveLocalSource(options.source);
      }
    } catch (err: any) {
      console.error(`\n  ERROR: Could not resolve source — ${err?.message}`);
      process.exit(1);
    }

    const { localPath, projectName, cleanup } = sourceResult;

    // ── Step 2: Discover files ─────────────────────────────────────────────────
    // Build include globs based on which languages are active.
    const defaultIncludes: string[] = [
      ...(scanJs   ? ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx', '**/*.mjs', '**/*.cjs'] : []),
      ...(scanJava ? ['**/*.java'] : []),
    ];

    const includeGlobs =
      options.include?.length ? options.include : defaultIncludes;

    let files: string[];
    try {
      files = await findFiles(
        localPath,
        includeGlobs,
        options.exclude?.length ? options.exclude : undefined
      );
    } catch (err: any) {
      console.error(`\n  ERROR: File discovery failed — ${err?.message}`);
      cleanup();
      process.exit(1);
    }

    if (files.length === 0) {
      console.error('  ERROR: No supported source files found in the specified source.');
      cleanup();
      process.exit(1);
    }

    // Separate JS and Java file lists for reporting clarity
    const javaFiles = files.filter(isJavaFile);
    const jsFiles   = files.filter(f => !isJavaFile(f));

    if (options.verbose) {
      if (jsFiles.length)   console.log(`  JS/TS files found : ${jsFiles.length}`);
      if (javaFiles.length) console.log(`  Java files found  : ${javaFiles.length}`);
      console.log('');
    }

    printScanStart(options.source, files.length);

    // ── Step 3: Parse + detect ────────────────────────────────────────────────
    const allFindings: CryptoFinding[] = [];
    const allErrors:   string[]        = [];
    let   filesScanned                 = 0;

    for (const filePath of files) {
      filesScanned++;
      printProgress(filesScanned, files.length, getRelativePath(filePath, localPath));

      const source = readFile(filePath);
      if (!source) continue;

      if (isJavaFile(filePath)) {
        // ── Java branch ──────────────────────────────────────────────────────
        try {
          const javaAst  = parseJavaSource(filePath, source);
          const findings = detectJava(javaAst, filePath, source);
          allFindings.push(...findings);
        } catch (err: any) {
          if (options.verbose) {
            allErrors.push(`Java parse error in ${filePath}: ${err.message}`);
          }
        }
      } else {
        const parsed = parseSource(filePath, source);
        if (!parsed.ast) {
          if (options.verbose && parsed.error) {
            allErrors.push(`Parse error in ${filePath}: ${parsed.error}`);
          }
          continue;
        }

        const { findings, errors } = runAllDetectors(parsed.ast, filePath, source);
        allFindings.push(...findings);
        allErrors.push(...errors);
      }
    }

    // ── Step 3b: CodeQL taint pass (JS/TS only — optional) ───────────────────
    if (options.useCodeQL) {
      if (jsFiles.length === 0) {
        console.log('\n  CodeQL skipped — no JS/TS files in this scan.\n');
      } else {
        console.log('\n  Running CodeQL taint analysis…');
        try {
          const withCodeQL = await runCodeQLPass(localPath, allFindings, options);
          const newCount   = withCodeQL.length - allFindings.length;
          allFindings.length = 0;
          allFindings.push(...withCodeQL);
          console.log(`  CodeQL complete — ${newCount} additional finding(s) from taint analysis\n`);
        } catch (err: any) {
          console.warn(`  WARNING: CodeQL skipped — ${err.message}\n`);
        }
      }
    }

    // ── Step 4: Build summary ─────────────────────────────────────────────────
    const duration = Date.now() - startTime;
    const summary  = buildSummary(allFindings);

    const scanResult: ScanResult = {
      findings:    allFindings,
      filesScanned,
      duration,
      projectName,
      projectPath: localPath,
      summary,
    };

    // ── Step 5: Print results ─────────────────────────────────────────────────
    printScanComplete(scanResult);
    printFindings(allFindings, options.verbose);

    if (options.verbose && allErrors.length > 0) {
      console.log(`  Warnings (${allErrors.length}):`);
      allErrors.slice(0, 10).forEach(e => console.log(`    - ${e}`));
      if (allErrors.length > 10) console.log(`    ... and ${allErrors.length - 10} more`);
      console.log('');
    }

    // ── Step 6: Write CBOM ────────────────────────────────────────────────────
    const cbom       = generateCBOM(scanResult);
    const outputPath = path.resolve(options.output);

    try {
      const outputDir = path.dirname(outputPath);
      if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
      fs.writeFileSync(outputPath, JSON.stringify(cbom, null, 2), 'utf-8');
      printOutput(outputPath);
    } catch (err: any) {
      console.error(`\n  ERROR: Could not write output file — ${err?.message}`);
      cleanup();
      process.exit(1);
    }

    // ── Step 7: Cleanup ───────────────────────────────────────────────────────
    cleanup();

    // ── Step 8: Exit codes ────────────────────────────────────────────────────
    if (options.failOnWeak && summary.weak > 0) {
      console.error(`  FAIL: ${summary.weak} weak algorithm(s) found. Exiting with code 1.\n`);
      process.exit(1);
    }

    if (options.failOnSeverity) {
      const severityOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const threshold = severityOrder.indexOf(options.failOnSeverity);
      const hasAboveThreshold =
        (threshold <= severityOrder.indexOf('CRITICAL') && summary.critical > 0) ||
        (threshold <= severityOrder.indexOf('HIGH')     && summary.high     > 0) ||
        (threshold <= severityOrder.indexOf('MEDIUM')   && summary.medium   > 0) ||
        (threshold <= severityOrder.indexOf('LOW')      && summary.low      > 0);

      if (hasAboveThreshold) {
        console.error(`  FAIL: Findings at or above ${options.failOnSeverity} severity detected. Exiting with code 1.\n`);
        process.exit(1);
      }
    }

    process.exit(0);
  });

program.parse(process.argv);