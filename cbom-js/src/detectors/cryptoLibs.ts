import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import {
  traverseAST,
  getStringValue,
  getSnippet,
  isMemberCall
} from '../parser/astParser';

// Map of package name -> canonical name
const CRYPTO_LIBS: Record<string, string> = {
  'crypto-js': 'crypto-js',
  'cryptojs': 'crypto-js',
  'node-forge': 'node-forge',
  'forge': 'node-forge',
  'bcrypt': 'bcrypt',
  'bcryptjs': 'bcryptjs',
  'argon2': 'argon2',
  'argon2-browser': 'argon2',
  'tweetnacl': 'tweetnacl',
  'nacl': 'tweetnacl',
  'libsodium-wrappers': 'libsodium',
  'sodium': 'libsodium',
  'elliptic': 'elliptic',
  'noble-curves': '@noble/curves',
  '@noble/curves': '@noble/curves',
  '@noble/hashes': '@noble/hashes',
  'sjcl': 'sjcl',
  'jsencrypt': 'jsencrypt',
  'aes-js': 'aes-js',
  'md5': 'md5',
  'sha.js': 'sha.js',
  'sha256': 'sha256',
  'sha1': 'sha1'
};

// crypto-js methods -> algorithms
const CRYPTO_JS_METHODS: Record<string, string> = {
  'MD5': 'MD5',
  'SHA1': 'SHA-1',
  'SHA256': 'SHA-256',
  'SHA512': 'SHA-512',
  'SHA3': 'SHA-3',
  'RIPEMD160': 'RIPEMD-160',
  'AES': 'AES',
  'DES': 'DES',
  'TripleDES': '3DES',
  'Rabbit': 'RABBIT',
  'RC4': 'RC4',
  'RC4Drop': 'RC4',
  'HmacMD5': 'HMAC-MD5',
  'HmacSHA1': 'HMAC-SHA1',
  'HmacSHA256': 'HMAC-SHA256',
  'HmacSHA512': 'HMAC-SHA512',
  'PBKDF2': 'PBKDF2',
  'EvpKDF': 'EVP-KDF'
};

export function detectCryptoLibs(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const importedAliases = new Map<string, string>(); // alias -> library

  // Collect imports
  traverseAST(ast, {
    ImportDeclaration(node) {
      const pkg = node.source.value as string;
      const canonicalLib = resolveLibrary(pkg);
      if (canonicalLib) {
        node.specifiers.forEach(spec => {
          if (
            spec.type === 'ImportDefaultSpecifier' ||
            spec.type === 'ImportNamespaceSpecifier'
          ) {
            importedAliases.set(spec.local.name, canonicalLib);
          }
          if (spec.type === 'ImportSpecifier') {
            importedAliases.set(spec.local.name, canonicalLib);
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
        if (pkg) {
          const canonicalLib = resolveLibrary(pkg);
          if (canonicalLib && node.id.type === 'Identifier') {
            importedAliases.set(node.id.name, canonicalLib);
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

      // CryptoJS.MD5(message), CryptoJS.AES.encrypt(...)
      if (node.callee.type === 'MemberExpression') {
        const callee = node.callee;

        // Direct method call: CryptoJS.MD5(...)
        if (
          callee.object.type === 'Identifier' &&
          importedAliases.has(callee.object.name) &&
          importedAliases.get(callee.object.name) === 'crypto-js'
        ) {
          const method = callee.property.type === 'Identifier' ? callee.property.name : null;
          if (method && CRYPTO_JS_METHODS[method]) {
            findings.push(makeFinding(CRYPTO_JS_METHODS[method], 'crypto-js', filePath, line, col, snippet));
          }
        }

        // Nested: CryptoJS.AES.encrypt(...)
        if (
          callee.object.type === 'MemberExpression' &&
          callee.object.object.type === 'Identifier' &&
          importedAliases.has(callee.object.object.name) &&
          importedAliases.get(callee.object.object.name) === 'crypto-js'
        ) {
          const algo = callee.object.property.type === 'Identifier'
            ? callee.object.property.name
            : null;
          if (algo && CRYPTO_JS_METHODS[algo]) {
            findings.push(makeFinding(CRYPTO_JS_METHODS[algo], 'crypto-js', filePath, line, col, snippet));
          }
        }
      }

      // bcrypt.hash(), bcrypt.compare(), bcrypt.genSalt()
      for (const [alias, lib] of importedAliases.entries()) {
        if (lib === 'bcrypt' || lib === 'bcryptjs') {
          if (isMemberCall(node, alias, ['hash', 'hashSync', 'compare', 'compareSync', 'genSalt'])) {
            findings.push(makeFinding('BCRYPT', lib, filePath, line, col, snippet, {
              notes: 'bcrypt - secure password hashing KDF'
            }));
          }
        }

        if (lib === 'argon2') {
          if (isMemberCall(node, alias, ['hash', 'verify', 'hashRaw'])) {
            findings.push(makeFinding('ARGON2', lib, filePath, line, col, snippet, {
              notes: 'argon2 - memory-hard KDF, recommended'
            }));
          }
        }

        // node-forge
        if (lib === 'node-forge') {
          // forge.pki.rsa.generateKeyPair
          if (isMemberCall(node, [alias], ['generateKeyPair', 'generateKeyPairSync'])) {
            findings.push(makeFinding('RSA', lib, filePath, line, col, snippet));
          }
          // forge.cipher.createCipher('AES-CBC', key)
          if (isMemberCall(node, [alias], ['createCipher', 'createDecipher'])) {
            const algo = getStringValue(node.arguments[0]);
            if (algo) {
              findings.push(makeFinding(algo.toUpperCase(), lib, filePath, line, col, snippet));
            }
          }
          // forge.md.sha256.create()
          if (
            node.callee.type === 'MemberExpression' &&
            node.callee.property.type === 'Identifier' &&
            node.callee.property.name === 'create'
          ) {
            const mdChain = extractForgeHashName(node.callee);
            if (mdChain) {
              findings.push(makeFinding(mdChain, lib, filePath, line, col, snippet));
            }
          }
        }

        // elliptic
        if (lib === 'elliptic') {
          // new ec('secp256k1') or new eddsa('ed25519')
        }

        // md5 package: const md5 = require('md5'); md5(data)
        if (lib === 'md5') {
          if (
            node.callee.type === 'Identifier' &&
            node.callee.name === alias
          ) {
            findings.push(makeFinding('MD5', 'md5', filePath, line, col, snippet));
          }
        }
      }
    },

    // new ec('secp256k1') from elliptic
    NewExpression(node) {
      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      for (const [alias, lib] of importedAliases.entries()) {
        if (lib === 'elliptic') {
          if (
            node.callee.type === 'Identifier' &&
            (node.callee.name === alias || node.callee.name === 'ec' || node.callee.name === 'EC')
          ) {
            const curve = getStringValue(node.arguments[0]);
            if (curve) {
              findings.push(makeFinding(`ECDSA-${curve.toUpperCase()}`, lib, filePath, line, col, snippet, {
                notes: `Elliptic curve: ${curve}`
              }));
            }
          }
        }
      }
    }
  });

  return deduplicateByLocation(findings);
}

function extractForgeHashName(node: TSESTree.MemberExpression): string | null {
  // forge.md.sha256.create() -> SHA-256
  const forgeHashMap: Record<string, string> = {
    'sha256': 'SHA-256',
    'sha512': 'SHA-512',
    'sha1': 'SHA-1',
    'md5': 'MD5',
    'sha384': 'SHA-384'
  };

  if (
    node.object.type === 'MemberExpression' &&
    node.object.property.type === 'Identifier'
  ) {
    const hashName = node.object.property.name.toLowerCase();
    return forgeHashMap[hashName] || null;
  }
  return null;
}

function resolveLibrary(pkg: string): string | null {
  for (const [key, value] of Object.entries(CRYPTO_LIBS)) {
    if (pkg === key || pkg.endsWith(`/${key}`) || pkg.includes(key)) {
      return value;
    }
  }
  return null;
}

function makeFinding(
  algorithm: string,
  library: string,
  filePath: string,
  line: number,
  column: number,
  context: string,
  extras?: { notes?: string }
): CryptoFinding {
  const algo = algorithm.toLowerCase();
  const weak = isWeak(algo);
  const quantumSafe = isQuantumSafe(algo);
  const severity = getSeverity(algo, weak, quantumSafe);

  return {
    algorithm: algorithm.toUpperCase(),
    library,
    location: filePath,
    line,
    column,
    weak,
    quantumSafe,
    severity,
    context,
    cwe: weak ? ['CWE-327'] : [],
    notes: extras?.notes
  };
}

function isWeak(algo: string): boolean {
  const weak = ['md5', 'sha1', 'sha-1', 'des', '3des', 'rc4', 'rc2', 'rabbit', 'md4', 'md2', 'ripemd160'];
  return weak.some(w => algo.includes(w));
}

function isQuantumSafe(algo: string): boolean {
  const qv = ['rsa', 'ecdsa', 'ecdh', 'ecc', 'dh', 'dsa', 'elliptic'];
  return !qv.some(q => algo.includes(q));
}

function getSeverity(algo: string, weak: boolean, quantumSafe: boolean): CryptoFinding['severity'] {
  if (['md5', 'rc4', 'des', 'md4'].some(w => algo.includes(w))) return 'CRITICAL';
  if (['sha1', '3des', 'rc2'].some(w => algo.includes(w))) return 'HIGH';
  if (!quantumSafe) return 'MEDIUM';
  if (weak) return 'HIGH';
  return 'INFO';
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