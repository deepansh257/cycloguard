// src/detectors/hardcodedSecrets.ts
// Hardcoded secrets + insecure random — rules driven by libraries.json

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import { traverseAST, getStringValue, getSnippet } from '../utils/detectorHelpers';
import {
  getRegistry,
  getAlgorithmMeta,
  isHardcodedVarName,
  isExcludedHardcodedValue
} from '../registry/registryLoader';

export function detectHardcodedSecrets(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const { insecureRandomPatterns } = getRegistry().registry;

  traverseAST(ast, {

    // Hardcoded variable assignments: const jwtSecret = 'abc123...'
    VariableDeclarator(node) {
      if (node.id.type !== 'Identifier') return;

      const varName = node.id.name;
      if (!isHardcodedVarName(varName)) return;

      const value = getStringValue(node.init as TSESTree.Node);
      if (!value) return;
      if (isExcludedHardcodedValue(value)) return;

      const line = node.loc?.start.line || 0;
      const meta = getAlgorithmMeta('HARDCODED-SECRET');

      findings.push({
        algorithm: 'HARDCODED-SECRET',
        library: 'source-code',
        location: filePath,
        line,
        column: node.loc?.start.column,
        weak: true,
        quantumSafe: false,
        severity: meta.severity,
        context: getSnippet(source, line),
        cwe: meta.cwe,
        notes: `Hardcoded value in variable '${varName}' — use environment variables instead`
      });
    },

    // Insecure random: Math.random(), Date.now() in security context
    CallExpression(node) {
      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      for (const pattern of insecureRandomPatterns.patterns) {
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === pattern.object &&
          node.callee.property.type === 'Identifier' &&
          node.callee.property.name === pattern.method
        ) {
          // For Date.now(), only flag if snippet looks security-related
          if (pattern.contextCheck) {
            const snippetLower = snippet.toLowerCase();
            const { hardcodedPatterns } = getRegistry().registry;
            const isSecurityContext = hardcodedPatterns.variableNames.some(v =>
              snippetLower.includes(v.toLowerCase())
            );
            if (!isSecurityContext) continue;
          }

          const meta = getAlgorithmMeta(pattern.algorithm);
          findings.push({
            algorithm: pattern.algorithm,
            library: 'javascript-builtin',
            location: filePath,
            line, column: col,
            weak: true,
            quantumSafe: false,
            severity: meta.severity,
            context: snippet,
            cwe: meta.cwe,
            notes: pattern.notes
          });
        }
      }
    }
  });

  return findings;
}