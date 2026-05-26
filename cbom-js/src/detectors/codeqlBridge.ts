import { SARIFResult } from '../utils/codeqlRunner';
import { CryptoFinding } from '../types';
import { getAlgorithmMeta } from '../utils/detectorHelpers';

const RULE_TO_ALGORITHM: Record<string, string> = {
  'crypto-taint/registry-driven':         'HARDCODED-SECRET',
  'crypto-taint/weak-algo-flow':          'WEAK-ALGORITHM-FLOW',
  'crypto-taint/env-algo-flow':           'ENV-DRIVEN-ALGORITHM',
};

export function bridgeCodeQLResults(sarif: SARIFResult[]): CryptoFinding[] {
  return sarif.map((r): CryptoFinding => {
    const algorithm = RULE_TO_ALGORITHM[r.ruleId] ?? r.ruleId.toUpperCase();
    const meta = getAlgorithmMeta(algorithm);

    return {
      algorithm,
      library:         'codeql',
      location:        r.filePath,
      line:            r.startLine,
      column:          r.startColumn,
      severity:        meta.severity ?? 'HIGH',
      weak:            meta.weak ?? false,
      quantumSafe:     meta.quantumSafe ?? false,
      context:         r.snippet || r.message,  
      notes:           `CodeQL taint path detected: ${r.message}`,
      cwe:             meta.cwe ?? [],
      detectionSource: 'codeql',
      taintPath:       r.codeFlows[0] ?? [],
    };
  });
}

export function deduplicateFindings(
  astFindings: CryptoFinding[],
  codeqlFindings: CryptoFinding[]
): CryptoFinding[] {
  // Key on location + line — prefer CodeQL finding when both report the same spot
  const codeqlKeys = new Set(
    codeqlFindings.map(f => `${f.location}:${f.line}`)
  );
  const dedupedAst = astFindings.filter(
    f => !codeqlKeys.has(`${f.location}:${f.line}`)
  );
  return [...dedupedAst, ...codeqlFindings];
}