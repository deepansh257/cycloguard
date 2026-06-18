import { CryptoFinding, ScanResult, ScanSummary } from '../types';
import chalk from 'chalk';
import { table } from 'table';
import * as path from 'path';
import pino from 'pino';

const { createAppLogger } = require(path.resolve(__dirname, '..', '..', '..', 'common', 'logger.js')) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    raw: (message: string) => void;
  };
};
const logger = createAppLogger({ pino });

export function buildSummary(findings: CryptoFinding[]): ScanSummary {
  const summary: ScanSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    weak: 0,
    quantumVulnerable: 0,
    byAlgorithm: {},
    byLibrary: {}
  };

  for (const f of findings) {
    switch (f.severity) {
      case 'CRITICAL': summary.critical++; break;
      case 'HIGH': summary.high++; break;
      case 'MEDIUM': summary.medium++; break;
      case 'LOW': summary.low++; break;
      case 'INFO': summary.info++; break;
    }

    if (f.weak) summary.weak++;
    if (!f.quantumSafe) summary.quantumVulnerable++;
    summary.byAlgorithm[f.algorithm] = (summary.byAlgorithm[f.algorithm] || 0) + 1;
    summary.byLibrary[f.library] = (summary.byLibrary[f.library] || 0) + 1;
  }

  return summary;
}

export function printBanner(): void {
  logger.raw(chalk.cyan(`
 ¦¦¦¦¦¦+¦¦¦¦¦¦+  ¦¦¦¦¦¦+ ¦¦¦+   ¦¦¦+      ¦¦+¦¦¦¦¦¦¦+
¦¦+----+¦¦+--¦¦+¦¦+---¦¦+¦¦¦¦+ ¦¦¦¦¦      ¦¦¦¦¦+----+
¦¦¦     ¦¦¦¦¦¦++¦¦¦   ¦¦¦¦¦+¦¦¦¦+¦¦¦      ¦¦¦¦¦¦¦¦¦¦+
¦¦¦     ¦¦+--¦¦+¦¦¦   ¦¦¦¦¦¦+¦¦++¦¦¦ ¦¦   ¦¦¦+----¦¦¦
+¦¦¦¦¦¦+¦¦¦¦¦¦+++¦¦¦¦¦¦++¦¦¦ +-+ ¦¦¦ +¦¦¦¦¦++¦¦¦¦¦¦¦¦
 +-----++-----+  +-----+ +-+     +-+  +----+ +------+
`));
  logger.raw(chalk.gray('  Cryptography Bill of Materials Generator for JS/TS/Node.js\n'));
}

export function printScanStart(source: string, fileCount: number): void {
  logger.raw(`${chalk.blue('? Scan Target:')} ${chalk.white(source)}`);
  logger.raw(`${chalk.blue('? Files Found:')} ${chalk.white(String(fileCount))}`);
  logger.raw('');
}

export function printProgress(current: number, total: number, file: string): void {
  const pct = Math.round((current / total) * 100);
  const bar = buildProgressBar(pct);
  process.stdout.write(`\r  ${bar} ${pct}% (${current}/${total}) ${chalk.gray(truncate(file, 40))}`);
}

export function printScanComplete(result: ScanResult): void {
  const { summary, filesScanned, duration } = result;

  logger.raw('\n');
  logger.raw(chalk.bold('?????????????????????????????????????????????????'));
  logger.raw(chalk.bold('  SCAN RESULTS'));
  logger.raw(chalk.bold('?????????????????????????????????????????????????\n'));

  logger.raw(chalk.bold('  Severity Breakdown:'));
  logger.raw(`    ${severityBadge('CRITICAL')}  ${chalk.red.bold(String(summary.critical).padStart(3))}`);
  logger.raw(`    ${severityBadge('HIGH')}      ${chalk.yellow.bold(String(summary.high).padStart(3))}`);
  logger.raw(`    ${severityBadge('MEDIUM')}    ${chalk.magenta(String(summary.medium).padStart(3))}`);
  logger.raw(`    ${severityBadge('LOW')}       ${chalk.blue(String(summary.low).padStart(3))}`);
  logger.raw(`    ${severityBadge('INFO')}      ${chalk.gray(String(summary.info).padStart(3))}`);
  logger.raw('');
  logger.raw(`  ${chalk.bold('Total Crypto Assets:')}   ${chalk.white.bold(String(summary.total))}`);
  logger.raw(`  ${chalk.bold('Weak Algorithms:')}       ${summary.weak > 0 ? chalk.red.bold(String(summary.weak)) : chalk.green('0')}`);
  logger.raw(`  ${chalk.bold('Quantum Vulnerable:')}    ${summary.quantumVulnerable > 0 ? chalk.yellow.bold(String(summary.quantumVulnerable)) : chalk.green('0')}`);
  logger.raw(`  ${chalk.bold('Files Scanned:')}         ${chalk.white(String(filesScanned))}`);
  logger.raw(`  ${chalk.bold('Duration:')}              ${chalk.white(duration + 'ms')}`);
  logger.raw('');

  if (Object.keys(summary.byAlgorithm).length > 0) {
    logger.raw(chalk.bold('  Algorithms Detected:'));
    const rows = Object.entries(summary.byAlgorithm)
      .sort((a, b) => b[1] - a[1])
      .map(([algo, count]) => [
        '  ' + colorizeAlgorithm(algo),
        chalk.white(String(count))
      ]);

    const output = table([
      [chalk.bold('Algorithm'), chalk.bold('Count')],
      ...rows
    ], {
      border: {
        topBody: '-', topJoin: '-', topLeft: '+', topRight: '+',
        bottomBody: '-', bottomJoin: '-', bottomLeft: '+', bottomRight: '+',
        bodyLeft: '¦', bodyRight: '¦', bodyJoin: '¦',
        joinBody: '-', joinLeft: '+', joinRight: '¦', joinJoin: '+'
      },
      columnDefault: { paddingLeft: 1, paddingRight: 1 }
    });
    logger.raw(output);
  }

  if (Object.keys(summary.byLibrary).length > 0) {
    logger.raw(chalk.bold('  Libraries / Sources:'));
    const rows = Object.entries(summary.byLibrary)
      .sort((a, b) => b[1] - a[1])
      .map(([lib, count]) => [
        '  ' + chalk.cyan(lib),
        chalk.white(String(count))
      ]);

    const output = table([
      [chalk.bold('Library'), chalk.bold('Count')],
      ...rows
    ], {
      border: {
        topBody: '-', topJoin: '-', topLeft: '+', topRight: '+',
        bottomBody: '-', bottomJoin: '-', bottomLeft: '+', bottomRight: '+',
        bodyLeft: '¦', bodyRight: '¦', bodyJoin: '¦',
        joinBody: '-', joinLeft: '+', joinRight: '¦', joinJoin: '+'
      },
      columnDefault: { paddingLeft: 1, paddingRight: 1 }
    });
    logger.raw(output);
  }
}

export function printFindings(findings: CryptoFinding[], verbose: boolean): void {
  if (findings.length === 0) return;

  const interesting = verbose
    ? findings
    : findings.filter((f) => f.severity !== 'INFO' || f.weak);

  if (interesting.length === 0) return;

  logger.raw(chalk.bold('  Findings Detail:'));
  logger.raw('');

  for (const f of interesting.slice(0, verbose ? 999 : 50)) {
    const badge = severityBadge(f.severity);
    const location = chalk.gray(`${f.location}:${f.line}`);
    logger.raw(`  ${badge} ${chalk.bold(f.algorithm)} ${chalk.gray('·')} ${chalk.cyan(f.library)}`);
    logger.raw(`         ${location}`);
    if (f.notes) {
      logger.raw(`         ${chalk.gray('? ' + f.notes)}`);
    }
    if (f.cwe && f.cwe.length > 0) {
      logger.raw(`         ${chalk.gray('? ' + f.cwe.join(', '))}`);
    }
    logger.raw('');
  }

  if (!verbose && interesting.length > 50) {
    logger.raw(chalk.gray(`  ... and ${interesting.length - 50} more. Use --verbose to see all.\n`));
  }
}

export function printOutput(outputPath: string): void {
  logger.raw(chalk.bold('?????????????????????????????????????????????????'));
  logger.raw(`  ${chalk.green('?')} CBOM written to: ${chalk.white.bold(outputPath)}`);
  logger.raw(chalk.bold('?????????????????????????????????????????????????\n'));
}

function severityBadge(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return chalk.bgRed.white.bold(' CRIT ');
    case 'HIGH': return chalk.bgYellow.black.bold(' HIGH ');
    case 'MEDIUM': return chalk.bgMagenta.white(' MED  ');
    case 'LOW': return chalk.bgBlue.white(' LOW  ');
    default: return chalk.bgGray.white(' INFO ');
  }
}

function colorizeAlgorithm(algo: string): string {
  const a = algo.toLowerCase();
  if (['md5', 'sha1', 'rc4', 'des'].some((w) => a.includes(w))) return chalk.red(algo);
  if (['sha-1', '3des', 'rc2'].some((w) => a.includes(w))) return chalk.yellow(algo);
  if (['rsa', 'ecdsa', 'ecdh'].some((w) => a.includes(w))) return chalk.magenta(algo);
  return chalk.green(algo);
}

function buildProgressBar(pct: number): string {
  const width = 30;
  const filled = Math.round((pct / 100) * width);
  const empty = width - filled;
  return chalk.cyan('¦'.repeat(filled)) + chalk.gray('¦'.repeat(empty));
}

function truncate(str: string, len: number): string {
  return str.length > len ? '...' + str.slice(str.length - len + 3) : str;
}
