import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import { traverseAST, getStringValue, getSnippet } from '../parser/astParser';

// Patterns that suggest a variable holds a secret
const SECRET_VAR_PATTERNS = [
  /secret/i, /private[_-]?key/i, /api[_-]?key/i, /jwt[_-]?key/i,
  /jwt[_-]?secret/i, /auth[_-]?key/i, /encryption[_-]?key/i,
  /crypto[_-]?key/i, /signing[_-]?key/i, /hmac[_-]?key/i,
  /aes[_-]?key/i, /rsa[_-]?key/i, /master[_-]?key/i
];

// Known hardcoded secret patterns (base64, hex, common test values)
const OBVIOUSLY_HARDCODED = [
  /^[A-Za-z0-9+/]{32,}={0,2}$/, // base64 encoded (32+ chars)
  /^[0-9a-fA-F]{32,}$/,          // hex string 32+ chars
  /^-----BEGIN (RSA |EC )?PRIVATE KEY-----/,
  /^-----BEGIN CERTIFICATE-----/
];

// Insecure random patterns
const INSECURE_RANDOM_PATTERNS = [
  { object: 'Math', method: 'random', note: 'Math.random() is not cryptographically secure' }
];

export function detectHardcodedSecrets(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];

  traverseAST(ast, {
    VariableDeclarator(node) {
      if (node.id.type !== 'Identifier') return;

      const varName = node.id.name;
      const isSecretVar = SECRET_VAR_PATTERNS.some(p => p.test(varName));

      if (!isSecretVar) return;

      const value = getStringValue(node.init as TSESTree.Node);
      if (!value) return;

      // Check if value looks like a hardcoded secret
      const isHardcoded =
        value.length > 8 && // not too short to be a placeholder
        !value.includes('process.env') &&
        !value.startsWith('$') &&  // not an env var reference
        !value.startsWith('<');    // not a placeholder like <your-secret>

      if (isHardcoded) {
        const line = node.loc?.start.line || 0;
        findings.push({
          algorithm: 'HARDCODED-SECRET',
          library: 'source-code',
          location: filePath,
          line,
          column: node.loc?.start.column,
          weak: true,
          quantumSafe: false,
          severity: 'CRITICAL',
          context: getSnippet(source, line),
          cwe: ['CWE-321', 'CWE-798'],
          notes: `Hardcoded value in variable '${varName}' — use environment variables instead`
        });
      }
    },

    CallExpression(node) {
      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      // Math.random() — insecure for crypto
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'Math' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'random'
      ) {
        findings.push({
          algorithm: 'MATH-RANDOM',
          library: 'javascript-builtin',
          location: filePath,
          line, column: col,
          weak: true,
          quantumSafe: false,
          severity: 'HIGH',
          context: snippet,
          cwe: ['CWE-338'],
          notes: 'Math.random() is not cryptographically secure. Use crypto.randomBytes() instead'
        });
      }

      // Date.now() used as seed / token (heuristic: assigned to key/token variable)
      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'Date' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'now'
      ) {
        // Only flag if parent is a variable with a secret-sounding name
        // (basic heuristic - will catch obvious cases)
        const snippet_lower = snippet.toLowerCase();
        if (SECRET_VAR_PATTERNS.some(p => p.test(snippet_lower))) {
          findings.push({
            algorithm: 'DATE-NOW-AS-ENTROPY',
            library: 'javascript-builtin',
            location: filePath,
            line, column: col,
            weak: true,
            quantumSafe: false,
            severity: 'HIGH',
            context: snippet,
            cwe: ['CWE-338'],
            notes: 'Date.now() is predictable and must not be used as cryptographic entropy'
          });
        }
      }
    }
  });

  return findings;
}