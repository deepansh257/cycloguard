/**
 * src/detectors/java/javaDetector.ts
 *
 * Detects cryptographic asset usage in Java source files.
 * Export signature matches all existing JS detectors exactly:
 *   detectJava(ast, filePath, source): CryptoFinding[]
 */

import { CryptoFinding } from '../../types';
import { getAlgorithmMeta } from '../../registry/registryLoader';
import {
  JavaNode,
  traverseJavaAST,
  getStringValue,
  getNumberValue,
  getSnippet,
  getLine,
  isMemberCall,
  collectImports,
} from '../../parser/javaParser';

// ─── Detection tables ─────────────────────────────────────────────────────────

const CIPHER_WEAK: Record<string, string> = {
  'DES':       'DES',
  'DESede':    '3DES',
  'DES/ECB':   'DES-ECB',
  'DES/CBC':   'DES-CBC',
  'AES/ECB':   'AES-ECB',
  'RC2':       'RC2',
  'RC4':       'RC4',
  'Blowfish':  'BLOWFISH',
  'ARCFOUR':   'RC4',
};

const DIGEST_ALGORITHMS: Record<string, { algorithm: string; weak: boolean }> = {
  'MD2':     { algorithm: 'MD2',    weak: true  },
  'MD5':     { algorithm: 'MD5',    weak: true  },
  'SHA-1':   { algorithm: 'SHA-1',  weak: true  },
  'SHA1':    { algorithm: 'SHA-1',  weak: true  },
  'SHA-224': { algorithm: 'SHA-224',weak: false },
  'SHA-256': { algorithm: 'SHA-256',weak: false },
  'SHA-384': { algorithm: 'SHA-384',weak: false },
  'SHA-512': { algorithm: 'SHA-512',weak: false },
  'SHA3-256':{ algorithm: 'SHA3-256',weak: false },
  'SHA3-512':{ algorithm: 'SHA3-512',weak: false },
};

const SIGNATURE_ALGORITHMS: Record<string, { algorithm: string; weak: boolean }> = {
  'MD5withRSA':     { algorithm: 'MD5withRSA',     weak: true  },
  'SHA1withRSA':    { algorithm: 'SHA1withRSA',     weak: true  },
  'SHA1withDSA':    { algorithm: 'SHA1withDSA',     weak: true  },
  'SHA1withECDSA':  { algorithm: 'SHA1withECDSA',   weak: true  },
  'SHA256withRSA':  { algorithm: 'SHA256withRSA',   weak: false },
  'SHA256withECDSA':{ algorithm: 'SHA256withECDSA', weak: false },
  'SHA384withRSA':  { algorithm: 'SHA384withRSA',   weak: false },
  'SHA512withRSA':  { algorithm: 'SHA512withRSA',   weak: false },
  'Ed25519':        { algorithm: 'Ed25519',         weak: false },
};

const SSL_PROTOCOLS: Record<string, { algorithm: string; weak: boolean }> = {
  'SSL':     { algorithm: 'SSL-2.0', weak: true  },
  'SSLv2':   { algorithm: 'SSL-2.0', weak: true  },
  'SSLv3':   { algorithm: 'SSL-3.0', weak: true  },
  'TLS':     { algorithm: 'TLS',     weak: false },
  'TLSv1':   { algorithm: 'TLS-1.0', weak: true  },
  'TLSv1.1': { algorithm: 'TLS-1.1', weak: true  },
  'TLSv1.2': { algorithm: 'TLS-1.2', weak: false },
  'TLSv1.3': { algorithm: 'TLS-1.3', weak: false },
};

const WEAK_KEY_SIZES: Record<string, number> = {
  'RSA':    2048,
  'DSA':    2048,
  'EC':     256,
  'DH':     2048,
  'AES':    128,
  'DES':    0,
  'DESEDE': 0,
};

const BOUNCY_CASTLE_ENGINES: Record<string, string> = {
  'AESEngine':        'AES',
  'DESEngine':        'DES',
  'DESedeEngine':     '3DES',
  'RC4Engine':        'RC4',
  'RC2Engine':        'RC2',
  'BlowfishEngine':   'BLOWFISH',
  'TwofishEngine':    'TWOFISH',
  'ChaCha7539Engine': 'CHACHA20',
  'MD5Digest':        'MD5',
  'SHA1Digest':       'SHA-1',
  'SHA256Digest':     'SHA-256',
  'SHA512Digest':     'SHA-512',
  'RSAEngine':        'RSA',
};

const HARDCODED_SECRET_VAR_PATTERNS = [
  /secret/i, /password/i, /passwd/i, /apikey/i, /api_key/i,
  /privatekey/i, /private_key/i, /secretkey/i, /secret_key/i,
  /encryptionkey/i, /aeskey/i, /hmackey/i, /signingkey/i,
];

const MIN_SECRET_LENGTH = 8;

// ─── Helper: build a CryptoFinding using only fields that exist on the type ───
// We pull meta from the registry and merge with what we know from the AST.
// Fields like description/recommendation come from the registry via getAlgorithmMeta.
// If your CryptoFinding type has fewer fields, TypeScript will flag the extras —
// just remove those lines and the rest will work.

function makeFinding(
  algorithm: string,
  filePath:  string,
  line:      number,
  snippet:   string,
  overrides: {
    weak?:           boolean;
    severity?:       string;
    // We supply these ourselves in each push() call.
    // They are NEVER read from AlgorithmMeta (which only has `notes`).
    notes?:          string;
  } = {}
): CryptoFinding {
  const meta = getAlgorithmMeta(algorithm);

  // Only reference fields that actually exist on AlgorithmMeta:
  //   weak, quantumSafe, severity, cwe, oid, notes,
  //   primitive, cryptoFunctions, classicalSecurityLevel
  const finding = {
    algorithm,
    filePath,
    line,
    snippet,
    severity:    overrides.severity ?? meta.severity    ?? 'INFO',
    weak:        overrides.weak     ?? meta.weak        ?? false,
    quantumSafe: meta.quantumSafe   ?? null,
    cwe:         meta.cwe           ?? [],
    // Use meta.notes as the fallback; the caller can override with their own notes.
    notes:       overrides.notes    ?? meta.notes       ?? '',
  };

  return finding as unknown as CryptoFinding;
}

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectJava(
  ast:      JavaNode,
  filePath: string,
  source:   string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const imports = collectImports(ast);

  function push(
    algorithm: string,
    node:      JavaNode,
    overrides: {
      weak?:     boolean;
      severity?: string;
      notes?:    string;
    } = {}
  ): void {
    findings.push(makeFinding(
      algorithm,
      filePath,
      getLine(node),
      getSnippet(source, node),
      overrides
    ));
  }

  // ── 1. MessageDigest.getInstance("...") ────────────────────────────────────
  traverseJavaAST(ast, {
    method_invocation(node) {
      if (!isMemberCall(node, 'MessageDigest', 'getInstance')) return;
      const algoStr = getStringValue(getArgumentNodes(node)[0] ?? null);
      if (!algoStr) return;

      const known     = DIGEST_ALGORITHMS[algoStr] ?? DIGEST_ALGORITHMS[algoStr.toUpperCase()];
      const algorithm = known?.algorithm ?? algoStr.toUpperCase();
      const weak      = known?.weak ?? false;

      push(algorithm, node, { weak, severity: weak ? 'HIGH' : 'INFO' });
    },
  });

  // ── 2. Cipher.getInstance("...") ───────────────────────────────────────────
  traverseJavaAST(ast, {
    method_invocation(node) {
      if (!isMemberCall(node, 'Cipher', 'getInstance')) return;
      const algoStr = getStringValue(getArgumentNodes(node)[0] ?? null);
      if (!algoStr) return;

      const base      = algoStr.split('/')[0].toUpperCase();
      const weakAlgo  = CIPHER_WEAK[algoStr] ?? CIPHER_WEAK[base];
      const algorithm = weakAlgo ?? algoStr.toUpperCase();
      const isEcb     = algoStr.toUpperCase().includes('/ECB');
      const weak      = !!weakAlgo || isEcb;

      push(algorithm, node, {
        weak,
        severity: weak ? 'HIGH' : 'INFO',
        notes: isEcb
          ? 'ECB mode does not provide semantic security and leaks data patterns.'
          : undefined,
      });
    },
  });

  // ── 3. Signature.getInstance("...") ───────────────────────────────────────
  traverseJavaAST(ast, {
    method_invocation(node) {
      if (!isMemberCall(node, 'Signature', 'getInstance')) return;
      const algoStr = getStringValue(getArgumentNodes(node)[0] ?? null);
      if (!algoStr) return;

      const known     = SIGNATURE_ALGORITHMS[algoStr];
      const algorithm = known?.algorithm ?? algoStr;
      const weak      = known?.weak ?? false;

      push(algorithm, node, { weak, severity: weak ? 'HIGH' : 'INFO' });
    },
  });

  // ── 4. SSLContext.getInstance("TLSv1") ────────────────────────────────────
  traverseJavaAST(ast, {
    method_invocation(node) {
      if (!isMemberCall(node, 'SSLContext', 'getInstance')) return;
      const proto = getStringValue(getArgumentNodes(node)[0] ?? null);
      if (!proto) return;

      const known     = SSL_PROTOCOLS[proto];
      const algorithm = known?.algorithm ?? proto;
      const weak      = known?.weak ?? false;

      push(algorithm, node, { weak, severity: weak ? 'HIGH' : 'INFO' });
    },
  });

  // ── 5. KeyPairGenerator / KeyGenerator — weak key sizes ───────────────────
  traverseJavaAST(ast, {
    method_invocation(node) {
      const isKPG = isMemberCall(node, 'KeyPairGenerator', 'getInstance');
      const isKG  = isMemberCall(node, 'KeyGenerator',     'getInstance');
      if (!isKPG && !isKG) return;

      const algoStr = getStringValue(getArgumentNodes(node)[0] ?? null);
      if (!algoStr) return;

      const algoUpper = algoStr.toUpperCase();
      const minSafe   = WEAK_KEY_SIZES[algoUpper];
      const sizeNode  = findKeySize(node);
      const keySize   = sizeNode !== null ? getNumberValue(sizeNode) : null;

      const alwaysWeak = minSafe === 0;
      const weakSize   = keySize !== null && minSafe !== undefined && keySize < minSafe;
      const weak       = alwaysWeak || weakSize;

      push(algoUpper, node, {
        weak,
        severity: weak ? 'HIGH' : 'INFO',
        notes: weakSize
          ? `Key size ${keySize} bits is below the recommended minimum of ${minSafe} bits for ${algoUpper}.`
          : alwaysWeak
          ? `${algoUpper} is cryptographically weak regardless of key size.`
          : undefined,
      });
    },
  });

  // ── 6. java.util.Random (insecure RNG) ────────────────────────────────────
  traverseJavaAST(ast, {
    object_creation_expression(node) {
      const typeNode = node.childForFieldName('type');
      if (!typeNode) return;
      if (typeNode.text !== 'Random') return;
      if ([...imports].some(i => i === 'java.security.SecureRandom')) return;

      push('INSECURE-RANDOM', node, {
        weak:     true,
        severity: 'MEDIUM',
        notes:    'java.util.Random is not cryptographically secure. Use java.security.SecureRandom instead.',
      });
    },
  });

  // ── 7. X509TrustManager with empty body (disabled cert validation) ─────────
  traverseJavaAST(ast, {
    class_declaration(node) {
      const interfaces = getSuperInterfaces(node);
      if (!interfaces.includes('X509TrustManager')) return;

      let hasEmptyCheck = false;
      traverseJavaAST(node, {
        method_declaration(methodNode) {
          const nameNode = methodNode.childForFieldName('name');
          if (!nameNode) return;
          if (
            nameNode.text !== 'checkServerTrusted' &&
            nameNode.text !== 'checkClientTrusted'
          ) return;
          const body = methodNode.childForFieldName('body');
          if (body && isEmptyOrNoop(body)) hasEmptyCheck = true;
        },
      });

      if (hasEmptyCheck) {
        push('TLS-CERT-VALIDATION', node, {
          weak:     true,
          severity: 'CRITICAL',
          notes:    'X509TrustManager with empty checkServerTrusted/checkClientTrusted disables certificate validation. Remove the custom TrustManager override and use the default trust manager.',
        });
      }
    },
  });

  // ── 8. Bouncy Castle engine instantiation ─────────────────────────────────
  traverseJavaAST(ast, {
    object_creation_expression(node) {
      const typeNode = node.childForFieldName('type');
      if (!typeNode) return;

      const simpleName = typeNode.text.split('.').pop() ?? '';
      const algorithm  = BOUNCY_CASTLE_ENGINES[simpleName];
      if (!algorithm) return;

      const hasBC = [...imports].some(i => i.startsWith('org.bouncycastle'));
      if (!hasBC) return;

      const meta = getAlgorithmMeta(algorithm);
      push(algorithm, node, {
        weak:     meta.weak ?? false,
        severity: meta.weak ? 'HIGH' : 'INFO',
        notes:    `Bouncy Castle: ${simpleName} instantiated.`,
      });
    },
  });

  // ── 9. Hardcoded secrets in String variables ──────────────────────────────
  traverseJavaAST(ast, {
    local_variable_declaration(node) {
      const typeNode = node.childForFieldName('type');
      if (!typeNode) return;
      if (!['String', 'byte[]', 'char[]'].includes(typeNode.text)) return;

      const declarator = node.namedChildren.find(c => c.type === 'variable_declarator');
      if (!declarator) return;

      const nameNode  = declarator.childForFieldName('name');
      const valueNode = declarator.childForFieldName('value');
      if (!nameNode || !valueNode) return;

      const isSecretVar = HARDCODED_SECRET_VAR_PATTERNS.some(re => re.test(nameNode.text));
      if (!isSecretVar) return;

      const literal = getStringValue(valueNode);
      if (!literal || literal.length < MIN_SECRET_LENGTH) return;

      push('HARDCODED-SECRET', node, {
        weak:     true,
        severity: 'CRITICAL',
        notes:    `Potential hardcoded secret in variable "${nameNode.text}". Store secrets in environment variables or a secrets manager.`,
      });
    },
  });

  // ── 10. Mac.getInstance — HMAC algorithm ──────────────────────────────────
  traverseJavaAST(ast, {
    method_invocation(node) {
      if (!isMemberCall(node, 'Mac', 'getInstance')) return;
      const algoStr = getStringValue(getArgumentNodes(node)[0] ?? null);
      if (!algoStr) return;

      const upper  = algoStr.toUpperCase();
      const isWeak = upper.includes('MD5') || upper.includes('SHA1') || upper.includes('SHA-1');

      push(upper, node, {
        weak:     isWeak,
        severity: isWeak ? 'MEDIUM' : 'INFO',
        notes:    isWeak
          ? `HMAC with weak digest ${algoStr}. Prefer HMAC-SHA256 or HMAC-SHA512.`
          : undefined,
      });
    },
  });

  return findings;
}

// ─── Private helpers ──────────────────────────────────────────────────────────

function getArgumentNodes(node: JavaNode): JavaNode[] {
  const argList = node.namedChildren.find(c => c.type === 'argument_list');
  if (!argList) return [];
  return argList.namedChildren;
}

function findKeySize(getInstanceNode: JavaNode): JavaNode | null {
  let current: JavaNode | null = getInstanceNode.parent;
  while (
    current &&
    current.type !== 'local_variable_declaration' &&
    current.type !== 'expression_statement'
  ) {
    current = current.parent;
  }
  if (!current?.parent) return null;

  const block = current.parent;
  let foundCurrent = false;

  for (const sibling of block.namedChildren) {
    if (sibling === current) { foundCurrent = true; continue; }
    if (!foundCurrent) continue;

    let sizeNode: JavaNode | null = null;
    traverseJavaAST(sibling, {
      method_invocation(n) {
        const nameNode = n.childForFieldName('name');
        if (nameNode?.text !== 'initialize') return;
        const args = getArgumentNodes(n);
        if (args[0]) sizeNode = args[0];
      },
    });
    if (sizeNode) return sizeNode;
    break;
  }
  return null;
}

function getSuperInterfaces(node: JavaNode): string[] {
  const result: string[] = [];
  for (const child of node.namedChildren) {
    if (child.type === 'super_interfaces') {
      traverseJavaAST(child, {
        type_identifier(n) { result.push(n.text); },
      });
    }
  }
  return result;
}

function isEmptyOrNoop(bodyNode: JavaNode): boolean {
  const meaningful = bodyNode.namedChildren.filter(c =>
    c.type !== 'line_comment' &&
    c.type !== 'block_comment' &&
    c.type !== 'comment'
  );
  return meaningful.length === 0;
}