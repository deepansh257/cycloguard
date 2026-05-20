import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import {
  traverseAST,
  getStringValue,
  getNumberValue,
  getSnippet,
  isMemberCall
} from '../parser/astParser';

const LIBRARY = 'node:crypto';

export function detectNodeCrypto(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const cryptoAliases = new Set<string>(['crypto']);

  // First pass: collect import aliases
  // e.g. import crypto from 'crypto'
  // e.g. const { createHash } = require('crypto')
  traverseAST(ast, {
    ImportDeclaration(node) {
      if (
        node.source.value === 'crypto' ||
        node.source.value === 'node:crypto'
      ) {
        node.specifiers.forEach(spec => {
          if (
            spec.type === 'ImportDefaultSpecifier' ||
            spec.type === 'ImportNamespaceSpecifier'
          ) {
            cryptoAliases.add(spec.local.name);
          }
        });
      }
    },
    VariableDeclarator(node) {
      // const crypto = require('crypto')
      if (
        node.init?.type === 'CallExpression' &&
        node.init.callee.type === 'Identifier' &&
        node.init.callee.name === 'require'
      ) {
        const reqArg = getStringValue(node.init.arguments[0]);
        if (reqArg === 'crypto' || reqArg === 'node:crypto') {
          if (node.id.type === 'Identifier') {
            cryptoAliases.add(node.id.name);
          }
        }
      }
    }
  });

  // Second pass: detect crypto API calls
  traverseAST(ast, {
    CallExpression(node) {
      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      // crypto.createHash('algorithm')
      if (isMemberCall(node, [...cryptoAliases], 'createHash')) {
        const algo = getStringValue(node.arguments[0]);
        if (algo) {
          findings.push(makeFinding(algo, 'hash', filePath, line, col, snippet, LIBRARY));
        }
      }

      // crypto.createHmac('algorithm', key)
      if (isMemberCall(node, [...cryptoAliases], 'createHmac')) {
        const algo = getStringValue(node.arguments[0]);
        if (algo) {
          findings.push(makeFinding(`HMAC-${algo.toUpperCase()}`, 'mac', filePath, line, col, snippet, LIBRARY));
        }
      }

      // crypto.createCipheriv('algorithm', key, iv)
      // crypto.createCipher('algorithm', key)  -- deprecated
      if (isMemberCall(node, [...cryptoAliases], ['createCipheriv', 'createCipher', 'createDecipheriv', 'createDecipher'])) {
        const algo = getStringValue(node.arguments[0]);
        if (algo) {
          const parts = algo.toLowerCase().split('-');
          const baseAlgo = parts[0].toUpperCase();
          const mode = parts[1]?.toUpperCase();
          const keySize = parts[2] ? parseInt(parts[2]) : undefined;
          findings.push(makeFinding(
            algo.toUpperCase(),
            'blockCipher',
            filePath, line, col, snippet, LIBRARY,
            { mode, keySize }
          ));
        }
      }

      // crypto.createSign('algorithm')
      // crypto.createVerify('algorithm')
      if (isMemberCall(node, [...cryptoAliases], ['createSign', 'createVerify'])) {
        const algo = getStringValue(node.arguments[0]);
        if (algo) {
          findings.push(makeFinding(algo.toUpperCase(), 'signature', filePath, line, col, snippet, LIBRARY));
        }
      }

      // crypto.generateKeyPair('type', options)
      if (isMemberCall(node, [...cryptoAliases], ['generateKeyPair', 'generateKeyPairSync'])) {
        const keyType = getStringValue(node.arguments[0]);
        const options = node.arguments[1];
        let keySize: number | undefined;

        if (options?.type === 'ObjectExpression') {
          const modulusProp = options.properties.find(
            (p): p is TSESTree.Property =>
              p.type === 'Property' &&
              p.key.type === 'Identifier' &&
              (p.key.name === 'modulusLength' || p.key.name === 'namedCurve')
          );
          if (modulusProp) {
            keySize = getNumberValue(modulusProp.value as TSESTree.Node) || undefined;
          }
        }

        if (keyType) {
          findings.push(makeFinding(
            keyType.toUpperCase(),
            'pke',
            filePath, line, col, snippet, LIBRARY,
            { keySize }
          ));
        }
      }

      // crypto.createDiffieHellman(keySize)
      if (isMemberCall(node, [...cryptoAliases], ['createDiffieHellman', 'createDiffieHellmanGroup', 'createECDH'])) {
        const methNode = node.callee as TSESTree.MemberExpression;
        const methodName = methNode.property.type === 'Identifier'
          ? methNode.property.name
          : 'DH';
        const algo = methodName === 'createECDH' ? 'ECDH' : 'DH';
        findings.push(makeFinding(algo, 'keyAgreement', filePath, line, col, snippet, LIBRARY));
      }

      // crypto.randomBytes() - check for insecure random usage
      // We only flag if used in a security context but for CBOM we note it
      if (isMemberCall(node, [...cryptoAliases], 'randomBytes')) {
        findings.push(makeFinding('CSPRNG', 'prf', filePath, line, col, snippet, LIBRARY, {
          notes: 'crypto.randomBytes - secure PRNG'
        }));
      }

      // crypto.pbkdf2, scrypt, bcrypt
      if (isMemberCall(node, [...cryptoAliases], ['pbkdf2', 'pbkdf2Sync'])) {
        findings.push(makeFinding('PBKDF2', 'kdf', filePath, line, col, snippet, LIBRARY));
      }
      if (isMemberCall(node, [...cryptoAliases], ['scrypt', 'scryptSync'])) {
        findings.push(makeFinding('SCRYPT', 'kdf', filePath, line, col, snippet, LIBRARY));
      }
    }
  });

  return findings;
}

function makeFinding(
  algorithm: string,
  primitive: string,
  filePath: string,
  line: number,
  column: number,
  context: string,
  library: string,
  extras?: {
    mode?: string;
    keySize?: number;
    notes?: string;
  }
): CryptoFinding {
  const algo = algorithm.toLowerCase();

  const weak = isWeak(algo, extras?.mode, extras?.keySize);
  const quantumSafe = isQuantumSafe(algo);
  const severity = getSeverity(algo, weak, quantumSafe, extras?.keySize);
  const cwe = getCWE(algo, extras?.mode);

  return {
    algorithm: algorithm.toUpperCase(),
    library,
    location: filePath,
    line,
    column,
    mode: extras?.mode,
    keySize: extras?.keySize,
    weak,
    quantumSafe,
    severity,
    context,
    cwe,
    notes: extras?.notes
  };
}

function isWeak(algo: string, mode?: string, keySize?: number): boolean {
  const weakAlgos = ['md5', 'sha1', 'sha-1', 'des', '3des', 'rc2', 'rc4', 'md4', 'md2', 'blowfish'];
  const weakModes = ['ecb'];

  if (weakAlgos.some(w => algo.includes(w))) return true;
  if (mode && weakModes.includes(mode.toLowerCase())) return true;
  if (algo.includes('rsa') && keySize && keySize < 2048) return true;
  if (algo.includes('rsa') && keySize && keySize < 4096) return false; // warn but not weak
  return false;
}

function isQuantumSafe(algo: string): boolean {
  const quantumVulnerable = ['rsa', 'ecdsa', 'ecdh', 'ecc', 'dh', 'dsa', 'elgamal'];
  return !quantumVulnerable.some(q => algo.includes(q));
}

function getSeverity(
  algo: string,
  weak: boolean,
  quantumSafe: boolean,
  keySize?: number
): CryptoFinding['severity'] {
  if (['md5', 'md4', 'md2', 'rc4', 'des'].some(w => algo.includes(w))) return 'CRITICAL';
  if (['sha1', 'sha-1', '3des', 'rc2'].some(w => algo.includes(w))) return 'HIGH';
  if (algo.includes('rsa') && keySize && keySize < 2048) return 'CRITICAL';
  if (algo.includes('rsa') && keySize && keySize < 4096) return 'MEDIUM';
  if (algo.includes('ecb')) return 'HIGH';
  if (!quantumSafe) return 'MEDIUM'; // quantum vulnerable but otherwise ok
  if (weak) return 'HIGH';
  return 'INFO';
}

function getCWE(algo: string, mode?: string): string[] {
  const cwes: string[] = [];
  const a = algo.toLowerCase();

  if (['md5', 'sha1', 'sha-1', 'md4', 'rc4', 'des'].some(w => a.includes(w))) {
    cwes.push('CWE-327'); // Use of Broken/Risky Algorithm
  }
  if (mode?.toLowerCase() === 'ecb') {
    cwes.push('CWE-327');
  }
  if (['rsa', 'ecdsa', 'dh', 'dsa'].some(q => a.includes(q))) {
    cwes.push('CWE-326'); // Inadequate Encryption Strength (quantum context)
  }

  return cwes;
}