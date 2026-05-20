import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import {
  traverseAST,
  getStringValue,
  getSnippet,
  isMemberCall
} from '../parser/astParser';

const JWT_PACKAGES = ['jsonwebtoken', 'jose', 'jwt-simple', 'passport-jwt', '@auth0/jwt-decode'];

export function detectJWT(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const jwtAliases = new Map<string, string>(); // alias -> package

  // Collect import aliases
  traverseAST(ast, {
    ImportDeclaration(node) {
      const pkg = node.source.value as string;
      if (JWT_PACKAGES.some(p => pkg.includes(p))) {
        node.specifiers.forEach(spec => {
          if (
            spec.type === 'ImportDefaultSpecifier' ||
            spec.type === 'ImportNamespaceSpecifier'
          ) {
            jwtAliases.set(spec.local.name, pkg);
          }
          if (spec.type === 'ImportSpecifier') {
            jwtAliases.set(spec.local.name, pkg);
          }
        });
      }
    },
    VariableDeclarator(node) {
      if (
        node.init?.type === 'CallExpression' &&
        node.init.callee.type === 'Identifier' &&
        node.init.callee.name === 'require'
      ) {
        const pkg = getStringValue(node.init.arguments[0]);
        if (pkg && JWT_PACKAGES.some(p => pkg.includes(p))) {
          if (node.id.type === 'Identifier') {
            jwtAliases.set(node.id.name, pkg);
          }
        }
      }
    }
  });

  traverseAST(ast, {
    CallExpression(node) {
      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      // jwt.sign(payload, secret, { algorithm: 'HS256' })
      if (isMemberCall(node, [...jwtAliases.keys()], ['sign', 'verify', 'decode'])) {
        const options = node.arguments[2];
        if (options?.type === 'ObjectExpression') {
          const algProp = options.properties.find(
            (p): p is TSESTree.Property =>
              p.type === 'Property' &&
              p.key.type === 'Identifier' &&
              p.key.name === 'algorithm'
          );
          if (algProp) {
            const algo = getStringValue(algProp.value as TSESTree.Node);
            if (algo) {
              const callee = node.callee as TSESTree.MemberExpression;
              const objName = (callee.object as TSESTree.Identifier).name;
              const pkg = jwtAliases.get(objName) || 'jsonwebtoken';
              findings.push(makeJWTFinding(algo, pkg, filePath, line, col, snippet));
            }
          }
        }

        // jwt.sign(payload, secret) -- no algorithm specified = default HS256
        if (!node.arguments[2] || node.arguments.length < 3) {
          const callee = node.callee as TSESTree.MemberExpression;
          const objName = (callee.object as TSESTree.Identifier).name;
          const pkg = jwtAliases.get(objName) || 'jsonwebtoken';
          findings.push(makeJWTFinding('HS256', pkg, filePath, line, col, snippet, {
            notes: 'Default algorithm - not explicitly set'
          }));
        }
      }

      // new SignJWT(payload).setProtectedHeader({ alg: 'RS256' })
      // Detect alg property in objects
    },

    // Detect { alg: 'algorithm' } in objects for jose-style usage
    Property(node) {
      if (
        node.key.type === 'Identifier' &&
        node.key.name === 'alg'
      ) {
        const algo = getStringValue(node.value as TSESTree.Node);
        if (algo) {
          const line = node.loc?.start.line || 0;
          const col = node.loc?.start.column || 0;
          const snippet = getSnippet(source, line);
          findings.push(makeJWTFinding(algo, 'jose', filePath, line, col, snippet));
        }
      }

      // { algorithm: 'HS256' }
      if (
        node.key.type === 'Identifier' &&
        node.key.name === 'algorithm'
      ) {
        const algo = getStringValue(node.value as TSESTree.Node);
        if (algo && isJWTAlgorithm(algo)) {
          const line = node.loc?.start.line || 0;
          const col = node.loc?.start.column || 0;
          const snippet = getSnippet(source, line);
          findings.push(makeJWTFinding(algo, 'jwt-config', filePath, line, col, snippet));
        }
      }
    }
  });

  // Deduplicate by location
  return deduplicateByLocation(findings);
}

function isJWTAlgorithm(algo: string): boolean {
  const jwtAlgos = [
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512',
    'none'
  ];
  return jwtAlgos.includes(algo.toUpperCase());
}

function makeJWTFinding(
  algorithm: string,
  library: string,
  filePath: string,
  line: number,
  column: number,
  context: string,
  extras?: { notes?: string }
): CryptoFinding {
  const algo = algorithm.toUpperCase();
  const weak = algo === 'NONE' || algo === 'HS256'; // HS256 is weak for asymmetric use cases
  const quantumSafe = !['RS', 'ES', 'PS'].some(p => algo.startsWith(p));

  return {
    algorithm: algo,
    library,
    location: filePath,
    line,
    column,
    weak: algo === 'NONE',
    quantumSafe,
    severity: algo === 'NONE' ? 'CRITICAL' : (!quantumSafe ? 'MEDIUM' : 'INFO'),
    context,
    cwe: algo === 'NONE' ? ['CWE-327', 'CWE-347'] : [],
    notes: extras?.notes || (algo === 'NONE' ? 'JWT with algorithm=none is critically insecure' : undefined)
  };
}

function deduplicateByLocation(findings: CryptoFinding[]): CryptoFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.location}:${f.line}:${f.algorithm}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}