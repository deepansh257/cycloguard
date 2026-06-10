/**
 * src/detectors/python/pythonDetector.ts
 *
 * Registry-driven crypto detector for Python source files.
 * Architecture mirrors javaDetector.ts:
 *   Pass 1 — build an importMap from import/from-import statements
 *   Pass 2 — walk call_expression / call nodes, match against registry rules
 *
 * All detection rules live in libraries.json ("language": "python" entries).
 * Nothing is hardcoded here except the two structural Python-specific patterns
 * that cannot be expressed as a simple registry rule:
 *   1. os.urandom() — already in registry as a fixedAlgorithm memberCall
 *   2. Insecure random (random.random, random.randint) — in insecureRandomPatterns
 */

import {
  PythonNode,
  PythonImport,
  parsePythonSource,
  traversePythonAST,
  collectImports,
  getStringValue,
  getNumberValue,
  getLine,
  getSnippet,
} from '../../parser/pythonParser';
import {
  getRegistry,
  getAlgorithmMeta,
  MethodRule,
} from '../../registry/registryLoader';
import { CryptoFinding } from '../../types';

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Resolved import entry: what local alias maps to which registry package key.
 *
 * For `import hashlib` → alias='hashlib', registryKey='hashlib'
 * For `from Crypto.Cipher import AES` → alias='AES', registryKey='pycryptodome', methodName='AES'
 * For `from cryptography.hazmat.primitives import hashes` → alias='hashes', registryKey='cryptography'
 */
interface ResolvedImport {
  alias:       string;   // local name in source
  registryKey: string;   // key in libraries.json packages
  methodHint?: string;   // if a specific method was imported (from X import Y)
}

// ─── Pass 1: Import resolution ────────────────────────────────────────────────

function resolveImports(rawImports: PythonImport[]): ResolvedImport[] {
  const registry = getRegistry();
  const resolved: ResolvedImport[] = [];

  for (const imp of rawImports) {
    // Try to match the full module path against registry package aliases
    for (const [pkgKey, pkgRule] of registry.packageRules.entries()) {
      if ((pkgRule as any).language !== 'python') continue;

      const aliases: string[] = (pkgRule as any).aliases ?? [];
      const fullModule = imp.module + (imp.name ? `.${imp.name}` : '');

      const matched =
        aliases.includes(imp.module) ||
        aliases.includes(fullModule)  ||
        aliases.some(a => imp.module.startsWith(a)) ||
        aliases.some(a => fullModule.startsWith(a));

      if (matched) {
        resolved.push({
          alias:       imp.alias,
          registryKey: pkgKey,
          methodHint:  imp.name,
        });
        break; // first match wins
      }
    }
  }

  return resolved;
}

// ─── Pass 2: Call detection ───────────────────────────────────────────────────

/**
 * Main entry point — mirrors detectJava(javaAst, filePath, source).
 */
export function detectPython(
  ast: PythonNode,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const registry = getRegistry();

  // Pass 1
  const rawImports   = collectImports(ast);
  const resolvedImps = resolveImports(rawImports);

  if (resolvedImps.length === 0) return findings;

  // Build a quick lookup: alias → ResolvedImport[]  (multiple packages may share alias)
  const aliasMap = new Map<string, ResolvedImport[]>();
  for (const ri of resolvedImps) {
    if (!aliasMap.has(ri.alias)) aliasMap.set(ri.alias, []);
    aliasMap.get(ri.alias)!.push(ri);
  }

  // Pass 2 — walk call nodes
  traversePythonAST(ast, {
    call(node) {
      const line    = getLine(node);
      const snippet = getSnippet(source, node);
      const col     = node.startPosition.column;

      // Resolve the callee shape
      const callee  = node.childForFieldName('function');
      if (!callee) return;

      // Shape A: simple identifier call → `AES.new(...)` after `from X import AES`
      //          or `hashlib.new(algo, ...)` where hashlib was imported as module
      // Shape B: attribute access → `alias.method(...)`
      // Shape C: chained access  → `alias.submodule.method(...)`

      const calleeText = callee.text; // full text of callee, e.g. "hashlib.new"

      for (const [alias, riList] of aliasMap.entries()) {
        for (const ri of riList) {
          const pkgRule = registry.packageRules.get(ri.registryKey);
          if (!pkgRule) continue;

          const methods = (pkgRule as any).methods as Array<{
            name: string;
            detection: string;
            algoArgIndex?: number;
            fixedAlgorithm?: string;
            primitive: string;
            notes?: string;
            keySizeOption?: string;
            algoPrefix?: string;
          }>;

          for (const methodDef of methods) {
            const finding = tryMatchPythonCall(
              node, callee, calleeText,
              alias, ri, methodDef,
              ri.registryKey, filePath, line, col, snippet, source
            );
            if (finding) {
              findings.push(finding);
              return; // one finding per call node
            }
          }
        }
      }
    },
  });

  return deduplicateByLocation(findings);
}

// ─── Call matching ────────────────────────────────────────────────────────────

type PythonMethodDef = {
  name:           string;
  detection:      string;
  algoArgIndex?:  number;
  fixedAlgorithm?: string;
  primitive:      string;
  notes?:         string;
  keySizeOption?: string;
  algoPrefix?:    string;
};

function tryMatchPythonCall(
  node:      PythonNode,
  callee:    PythonNode,
  calleeText: string,
  alias:     string,
  ri:        ResolvedImport,
  methodDef: PythonMethodDef,
  pkgKey:    string,
  filePath:  string,
  line:      number,
  col:       number,
  snippet:   string,
  source:    string
): CryptoFinding | null {

  const args = getCallArgs(node);

  switch (methodDef.detection) {

    // alias.method(args)  — e.g. hashlib.new('md5')
    case 'memberCall': {
      const expected = `${alias}.${methodDef.name}`;
      if (calleeText !== expected && !calleeText.endsWith(`.${methodDef.name}`)) return null;
      // Make sure the object part starts with our alias
      const dotIdx = calleeText.lastIndexOf('.');
      const objPart = calleeText.slice(0, dotIdx);
      if (objPart !== alias && !objPart.startsWith(alias + '.')) return null;

      const algo = resolvePythonAlgo(args, methodDef);
      if (!algo) return null;
      return buildPythonFinding(algo, pkgKey, methodDef, filePath, line, col, snippet);
    }

    // method(args) where method was imported directly — `from X import Y; Y(args)`
    // or class constructor — `AES.new(key, mode)` where AES was imported
    case 'directCall':
    case 'importedFunction': {
      if (calleeText !== alias && calleeText !== `${alias}.new`) return null;
      const algo = resolvePythonAlgo(args, methodDef);
      if (!algo) return null;
      return buildPythonFinding(algo, pkgKey, methodDef, filePath, line, col, snippet);
    }

    // alias.sub.method(args) — e.g. hazmat.primitives.hashes.SHA256()
    case 'deepMemberCall': {
      const parts    = methodDef.name.split('.');
      const expected = [alias, ...parts].join('.');
      if (calleeText !== expected && !calleeText.endsWith(methodDef.name.split('.').pop()!)) return null;
      if (!calleeText.startsWith(alias + '.') && calleeText !== alias) return null;

      const algo = resolvePythonAlgo(args, methodDef);
      if (!algo) return null;
      return buildPythonFinding(algo, pkgKey, methodDef, filePath, line, col, snippet);
    }

    // Cipher.new() / hashlib.new(algo, ...) pattern
    // methodHint is the class name imported: `from Crypto.Cipher import AES`
    case 'newExpression': {
      // `AES.new(key, mode)` where alias='AES' and methodDef.name='AES'
      // or just `AES(key)` in some libs
      const baseName = methodDef.name.split('.').pop()!;
      if (
        calleeText === alias ||
        calleeText === `${alias}.new` ||
        calleeText === baseName ||
        calleeText === `${baseName}.new`
      ) {
        if (ri.methodHint && ri.methodHint !== baseName) return null;
        const algo = resolvePythonAlgo(args, methodDef);
        if (!algo) return null;
        return buildPythonFinding(algo, pkgKey, methodDef, filePath, line, col, snippet);
      }
      return null;
    }

    default:
      return null;
  }
}

// ─── Argument helpers ─────────────────────────────────────────────────────────

function getCallArgs(node: PythonNode): PythonNode[] {
  const argsNode = node.childForFieldName('arguments');
  if (!argsNode) return [];
  return argsNode.namedChildren.filter(
    c => c.type !== ',' && c.type !== '(' && c.type !== ')'
  );
}

function resolvePythonAlgo(args: PythonNode[], methodDef: PythonMethodDef): string | null {
  if (methodDef.fixedAlgorithm) {
    const prefix = methodDef.algoPrefix ?? '';
    return prefix + methodDef.fixedAlgorithm;
  }

  if (methodDef.algoArgIndex !== undefined) {
    const argNode = args[methodDef.algoArgIndex];
    if (!argNode) return 'DYNAMIC-ALGO';

    const raw = getStringValue(argNode);
    if (raw) {
      return ((methodDef.algoPrefix ?? '') + raw).toUpperCase();
    }
    // attribute access used as algo: hashlib.sha256 → extract name
    if (argNode.type === 'attribute' || argNode.type === 'identifier') {
      const attrText = argNode.text.split('.').pop()!.toUpperCase();
      return (methodDef.algoPrefix ?? '') + attrText;
    }
    return 'DYNAMIC-ALGO';
  }

  return null;
}

// ─── Finding builder ──────────────────────────────────────────────────────────

function buildPythonFinding(
  algorithm: string,
  library:   string,
  methodDef: PythonMethodDef,
  filePath:  string,
  line:      number,
  column:    number,
  context:   string
): CryptoFinding {
  const meta     = getAlgorithmMeta(algorithm);
  const notes    = [meta.notes, methodDef.notes].filter(Boolean).join(' | ') || undefined;
  const severity = meta.severity;

  return {
    algorithm: algorithm.toUpperCase(),
    library,
    location:  filePath,
    line,
    column,
    weak:        meta.weak,
    quantumSafe: meta.quantumSafe,
    severity,
    context,
    cwe:         meta.cwe ?? [],
    notes,
    detectionSource: 'ast',
  };
}

// ─── Deduplication ────────────────────────────────────────────────────────────

function deduplicateByLocation(findings: CryptoFinding[]): CryptoFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.location}:${f.line}:${f.algorithm}:${f.library}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}