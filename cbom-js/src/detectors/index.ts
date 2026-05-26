import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding, ScanOptions } from '../types';
import { detectFromRegistry } from './registryDetector';
import { detectTLS } from './tlsDetector';
import { detectHardcodedSecrets } from './hardcodedSecrets';
import { bridgeCodeQLResults } from './codeqlBridge';
import { runCodeQL } from '../utils/codeqlRunner';
import * as path from 'path';
import * as fs from 'fs';

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
    { name: 'registry',          fn: detectFromRegistry    },
    { name: 'tls',               fn: detectTLS             },
    { name: 'hardcoded-secrets', fn: detectHardcodedSecrets },
  ];
  for (const detector of detectors) {
    try {
      const result = detector.fn(ast, filePath, source);
      findings.push(...result);
    } catch (err: any) {
      errors.push(`Detector '${detector.name}' failed on ${filePath}: ${err?.message}`);
    }
  }
  return { findings: deduplicateASTFindings(findings), errors };
}

export async function runCodeQLPass(
  sourceRoot: string,
  astFindings: CryptoFinding[],
  options: ScanOptions
): Promise<CryptoFinding[]> {
  const queriesDir = path.resolve(__dirname, '../../queries');
  console.log('[CodeQL] queriesDir resolved to:', queriesDir);
console.log('[CodeQL] queriesDir exists?', fs.existsSync(queriesDir));
  const sarifResults = runCodeQL({
    codeqlPath: options.codeqlPath,
    sourceRoot,
    queriesDir,
  });
  const codeqlFindings = bridgeCodeQLResults(sarifResults);
  return deduplicateASTFindings([...astFindings, ...codeqlFindings]);
}

function deduplicateASTFindings(findings: CryptoFinding[]): CryptoFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.location}:${f.line}:${f.algorithm}:${f.library}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}