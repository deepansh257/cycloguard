// src/detectors/tlsDetector.ts
// TLS/HTTPS configuration detector — rules driven by libraries.json tlsPatterns

import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import { traverseAST, getStringValue, getSnippet, getAlgorithmMeta } from '../utils/detectorHelpers';
import { getRegistry } from '../registry/registryLoader';

export function detectTLS(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const { tlsPatterns } = getRegistry().registry;

  traverseAST(ast, {
    Property(node) {
      if (node.key.type !== 'Identifier') return;

      const propName = node.key.name;
      const rule = tlsPatterns.propertyMap[propName];
      if (!rule) return;

      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      // secureProtocol / minVersion / maxVersion
      if (rule.type === 'version') {
        const val = getStringValue(node.value as TSESTree.Node);
        if (!val) return;

        const isWeak = rule.weakValues?.some(w =>
          val.toLowerCase().includes(w.toLowerCase())
        );

        const algoName = `TLS-${val.replace('_method', '').replace('v', '').replace('TLS', 'TLS-')}`;
        const meta = getAlgorithmMeta(isWeak ? 'TLS-1.0' : 'TLS');

        findings.push({
          algorithm: algoName.toUpperCase(),
          library: 'node:tls',
          location: filePath,
          line, column: col,
          weak: !!isWeak,
          quantumSafe: false,
          severity: isWeak ? meta.severity : 'INFO',
          context: snippet,
          cwe: isWeak ? meta.cwe : [],
          notes: `TLS property '${propName}' = '${val}'`
        });
      }

      // ciphers: 'RC4:...'
      if (rule.type === 'cipherSuite') {
        const val = getStringValue(node.value as TSESTree.Node);
        if (!val) return;

        const weakFound = (rule.weakSubstrings || []).filter(w =>
          val.toUpperCase().includes(w)
        );

        if (weakFound.length > 0) {
          findings.push({
            algorithm: 'WEAK-CIPHER-SUITE',
            library: 'node:tls',
            location: filePath,
            line, column: col,
            weak: true,
            quantumSafe: false,
            severity: 'HIGH',
            context: snippet,
            cwe: ['CWE-327'],
            notes: `Weak ciphers in suite: ${weakFound.join(', ')}`
          });
        }
      }

      // rejectUnauthorized: false
      if (rule.type === 'boolean' && rule.weakValue !== undefined) {
        if (
          node.value.type === 'Literal' &&
          node.value.value === rule.weakValue
        ) {
          const algo = rule.algorithm || 'TLS-CERT-VALIDATION';
          const meta = getAlgorithmMeta(algo);
          findings.push({
            algorithm: algo,
            library: 'node:tls',
            location: filePath,
            line, column: col,
            weak: true,
            quantumSafe: false,
            severity: meta.severity,
            context: snippet,
            cwe: meta.cwe,
            notes: `${propName}: false disables TLS certificate verification`
          });
        }
      }
    },

    // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    AssignmentExpression(node) {
      if (
        node.left.type !== 'MemberExpression' ||
        node.left.object.type !== 'MemberExpression'
      ) return;

      const obj = node.left.object;
      const prop = node.left.property;

      if (
        obj.object.type === 'Identifier' && obj.object.name === 'process' &&
        obj.property.type === 'Identifier' && obj.property.name === 'env' &&
        prop.type === 'Identifier'
      ) {
        const envVarName = prop.name;
        const envRule = tlsPatterns.envVars[envVarName];
        if (!envRule) return;

        const val = getStringValue(node.right);
        if (val === envRule.weakValue) {
          const line = node.loc?.start.line || 0;
          const meta = getAlgorithmMeta(envRule.algorithm);
          findings.push({
            algorithm: envRule.algorithm,
            library: 'node:process',
            location: filePath,
            line,
            weak: true,
            quantumSafe: false,
            severity: meta.severity,
            context: getSnippet(source, line),
            cwe: meta.cwe,
            notes: `${envVarName}=${envRule.weakValue} disables ALL TLS certificate validation globally`
          });
        }
      }
    }
  });

  return findings;
}