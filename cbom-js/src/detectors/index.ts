// src/detectors/index.ts
// Orchestrates all detectors. Registry-driven detector handles all library detection.
// TLS and hardcoded secrets run separately as they have different detection patterns.

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import { detectFromRegistry } from './registryDetector';
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
    // Main detector — reads ALL library/method rules from libraries.json
    { name: 'registry', fn: detectFromRegistry },
    // TLS detector — reads tlsPatterns from libraries.json
    { name: 'tls', fn: detectTLS },
    // Hardcoded secrets — reads hardcodedPatterns + insecureRandomPatterns from libraries.json
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

  return { findings: deduplicateFindings(findings), errors };
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