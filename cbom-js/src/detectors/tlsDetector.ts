import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import {
  traverseAST,
  getStringValue,
  getSnippet,
  isMemberCall
} from '../parser/astParser';

const WEAK_TLS_VERSIONS = ['TLSv1', 'TLSv1_method', 'TLSv1_1', 'TLSv1_1_method', 'SSLv2', 'SSLv3', 'SSLv3_method'];
const WEAK_CIPHERS = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'aNULL', 'eNULL'];

export function detectTLS(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];

  traverseAST(ast, {
    Property(node) {
      if (node.key.type !== 'Identifier') return;

      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      // secureProtocol: 'TLSv1_method'
      if (node.key.name === 'secureProtocol') {
        const val = getStringValue(node.value as TSESTree.Node);
        if (val && WEAK_TLS_VERSIONS.some(w => val.includes(w))) {
          findings.push({
            algorithm: val.toUpperCase(),
            library: 'tls/https',
            location: filePath,
            line, column: col,
            weak: true,
            quantumSafe: false,
            severity: 'CRITICAL',
            context: snippet,
            cwe: ['CWE-326', 'CWE-327'],
            notes: `Deprecated TLS version: ${val}`
          });
        }
      }

      // minVersion: 'TLSv1'  or maxVersion
      if (node.key.name === 'minVersion' || node.key.name === 'maxVersion') {
        const val = getStringValue(node.value as TSESTree.Node);
        if (val) {
          const isWeak = val === 'TLSv1' || val === 'TLSv1.1';
          findings.push({
            algorithm: `TLS-${val}`,
            library: 'tls/https',
            location: filePath,
            line, column: col,
            weak: isWeak,
            quantumSafe: false,
            severity: isWeak ? 'HIGH' : 'MEDIUM',
            context: snippet,
            cwe: isWeak ? ['CWE-326'] : [],
            notes: `TLS ${node.key.name}: ${val}`
          });
        }
      }

      // ciphers: 'RC4:...' or 'HIGH:!RC4'
      if (node.key.name === 'ciphers') {
        const val = getStringValue(node.value as TSESTree.Node);
        if (val) {
          const weakFound = WEAK_CIPHERS.filter(w => val.toUpperCase().includes(w));
          if (weakFound.length > 0) {
            findings.push({
              algorithm: `CIPHER-SUITE:${val.substring(0, 50)}`,
              library: 'tls/https',
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
      }

      // rejectUnauthorized: false  -- disables cert verification
      if (node.key.name === 'rejectUnauthorized') {
        if (
          node.value.type === 'Literal' &&
          node.value.value === false
        ) {
          findings.push({
            algorithm: 'TLS-CERT-VALIDATION',
            library: 'tls/https',
            location: filePath,
            line, column: col,
            weak: true,
            quantumSafe: false,
            severity: 'CRITICAL',
            context: snippet,
            cwe: ['CWE-295'],
            notes: 'rejectUnauthorized: false disables TLS certificate verification'
          });
        }
      }
    },

    // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
    AssignmentExpression(node) {
      if (
        node.left.type === 'MemberExpression' &&
        node.left.object.type === 'MemberExpression' &&
        node.left.object.object.type === 'Identifier' &&
        node.left.object.object.name === 'process' &&
        node.left.object.property.type === 'Identifier' &&
        node.left.object.property.name === 'env' &&
        node.left.property.type === 'Identifier' &&
        node.left.property.name === 'NODE_TLS_REJECT_UNAUTHORIZED'
      ) {
        const val = getStringValue(node.right);
        if (val === '0') {
          const line = node.loc?.start.line || 0;
          findings.push({
            algorithm: 'TLS-CERT-VALIDATION',
            library: 'node:process',
            location: filePath,
            line,
            weak: true,
            quantumSafe: false,
            severity: 'CRITICAL',
            context: getSnippet(source, line),
            cwe: ['CWE-295'],
            notes: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables ALL TLS cert validation globally'
          });
        }
      }
    }
  });

  return findings;
}