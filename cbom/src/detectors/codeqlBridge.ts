/**
 * src/detectors/codeqlBridge.ts
 *
 * Transforms SARIF results from CodeQL into CryptoFinding objects.
 * Covers JS/TS, Java, Python, and C# rule IDs.
 */

import { SARIFResult } from '../utils/codeqlRunner';
import { CryptoFinding } from '../types';
import { getAlgorithmMeta } from '../utils/detectorHelpers';

// ─── Rule → Algorithm mappings ────────────────────────────────────────────────

const RULE_TO_ALGORITHM: Record<string, string> = {
  // ── JS / TS ──────────────────────────────────────────────────────────────
  'crypto-taint/registry-driven':           'HARDCODED-SECRET',
  'crypto-taint/weak-algo-flow':            'WEAK-ALGORITHM-FLOW',
  'crypto-taint/env-algo-flow':             'ENV-DRIVEN-ALGORITHM',

  // ── Java ─────────────────────────────────────────────────────────────────
  'crypto-java/weak-algo-flow':             'WEAK-ALGORITHM-FLOW',
  'crypto-java/hardcoded-field-secret':     'HARDCODED-SECRET',
  'crypto-java/weak-secretkeyspec-constant':'WEAK-ALGORITHM-FLOW',
  'crypto-java/hardcoded-secret-flow':      'HARDCODED-SECRET',
  'crypto-java/weak-key-size':              'WEAK-KEY-SIZE',

  // ── Python ────────────────────────────────────────────────────────────────
  'crypto-python/weak-algo-flow':                  'WEAK-ALGORITHM-FLOW',
  'crypto-python/weak-algo-flow-generated':        'WEAK-ALGORITHM-FLOW',
  'crypto-python/hardcoded-secret-flow':           'HARDCODED-SECRET',
  'crypto-python/hardcoded-secret-flow-generated': 'HARDCODED-SECRET',
  'crypto-python/insecure-random':                 'INSECURE-RANDOM',
  'crypto-python/tls-cert-validation-disabled':    'TLS-CERT-VALIDATION',

  // ── C# / .NET ─────────────────────────────────────────────────────────────
  'crypto-csharp/weak-algo-flow':                  'WEAK-ALGORITHM-FLOW',
  'crypto-csharp/weak-algo-flow-generated':        'WEAK-ALGORITHM-FLOW',
  'crypto-csharp/hardcoded-secret-flow':           'HARDCODED-SECRET',
  'crypto-csharp/hardcoded-secret-flow-generated': 'HARDCODED-SECRET',
  'crypto-csharp/weak-key-size':                   'WEAK-KEY-SIZE',
  'crypto-csharp/tls-cert-validation-disabled':    'TLS-CERT-VALIDATION',
};

// ─── WEAK-KEY-SIZE is not in the algorithm registry; define its meta inline ──
const SYNTHETIC_ALGO_META: Record<string, {
  severity: CryptoFinding['severity'];
  weak: boolean;
  quantumSafe: boolean;
  cwe: string[];
}> = {
  'WEAK-ALGORITHM-FLOW': {
    severity: 'HIGH', weak: true, quantumSafe: false, cwe: ['CWE-327'],
  },
  'WEAK-KEY-SIZE': {
    severity: 'HIGH', weak: true, quantumSafe: false, cwe: ['CWE-326'],
  },
  'ENV-DRIVEN-ALGORITHM': {
    severity: 'LOW', weak: false, quantumSafe: true, cwe: [],
  },
  'INSECURE-RANDOM': {
    severity: 'HIGH', weak: true, quantumSafe: false, cwe: ['CWE-338'],
  },
};

// ─── Bridge ───────────────────────────────────────────────────────────────────

export function bridgeCodeQLResults(sarif: SARIFResult[]): CryptoFinding[] {
  return sarif.map((r): CryptoFinding => {
    const algorithm = RULE_TO_ALGORITHM[r.ruleId] ?? r.ruleId.toUpperCase();

    // Try the full registry first; fall back to synthetic meta table
    const registryMeta = getAlgorithmMeta(algorithm);
    const syntheticMeta = SYNTHETIC_ALGO_META[algorithm];

    const severity:    CryptoFinding['severity'] =
      registryMeta?.severity ?? syntheticMeta?.severity ?? 'HIGH';
    const weak:        boolean =
      registryMeta?.weak    ?? syntheticMeta?.weak    ?? false;
    const quantumSafe: boolean =
      registryMeta?.quantumSafe ?? syntheticMeta?.quantumSafe ?? false;
    const cwe: string[] =
      registryMeta?.cwe ?? syntheticMeta?.cwe ?? [];

    return {
      algorithm,
      library:         'codeql',
      location:        r.filePath,
      line:            r.startLine,
      column:          r.startColumn,
      severity,
      weak,
      quantumSafe,
      context:         r.snippet || r.message,
      notes:           `CodeQL: ${r.message}`,
      cwe,
      detectionSource: 'codeql',
      taintPath:       r.codeFlows[0] ?? [],
    };
  });
}

// ─── Deduplication ────────────────────────────────────────────────────────────

/**
 * Merges AST findings with CodeQL findings.
 * CodeQL findings win at any location already covered by AST — they carry
 * richer taint-path context. Any AST finding at a line not touched by CodeQL
 * is kept as-is.
 */
export function deduplicateFindings(
  astFindings:    CryptoFinding[],
  codeqlFindings: CryptoFinding[]
): CryptoFinding[] {
  const codeqlKeys = new Set(
    codeqlFindings.map(f => `${f.location}:${f.line}`)
  );
  const dedupedAst = astFindings.filter(
    f => !codeqlKeys.has(`${f.location}:${f.line}`)
  );
  return [...dedupedAst, ...codeqlFindings];
}