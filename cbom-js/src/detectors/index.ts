import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import { detectNodeCrypto } from './nodeCrypto';
import { detectJWT } from './jwtDetector';
import { detectCryptoLibs } from './cryptoLibs';
import { detectTLS } from './tlsDetector';
import { detectHardcodedSecrets } from './hardcodedSecrets';

export interface DetectorResult {
  findings: CryptoFinding[];
  errors: string[];
}

export function runAllDetectors(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): DetectorResult {
  const findings: CryptoFinding[] = [];
  const errors: string[] = [];

  const detectors = [
    { name: 'node:crypto', fn: detectNodeCrypto },
    { name: 'jwt', fn: detectJWT },
    { name: 'crypto-libs', fn: detectCryptoLibs },
    { name: 'tls', fn: detectTLS },
    { name: 'hardcoded-secrets', fn: detectHardcodedSecrets }
  ];

  for (const detector of detectors) {
    try {
      const result = detector.fn(ast, filePath, source);
      findings.push(...result);
    } catch (err: any) {
      errors.push(`Detector '${detector.name}' failed on ${filePath}: ${err?.message}`);
    }
  }

  // Global deduplication across all detectors
  const deduped = deduplicateFindings(findings);

  return { findings: deduped, errors };
}

function deduplicateFindings(findings: CryptoFinding[]): CryptoFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.location}:${f.line}:${f.algorithm}:${f.library}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}