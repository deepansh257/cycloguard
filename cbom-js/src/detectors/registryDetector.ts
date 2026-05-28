import { TSESTree } from '@typescript-eslint/typescript-estree';
import { CryptoFinding } from '../types';
import {
  traverseAST,
  getStringValue,
  getNumberValue,
  getSnippet,
  isMemberCall
} from '../parser/astParser';
import {
  getRegistry,
  getAlgorithmMeta,
  resolvePackage,
  getPackageRule,
  MethodRule
} from '../registry/registryLoader';

// Tracks which aliases are in scope for a file: alias → packageName
type AliasMap = Map<string, string>;

export function detectFromRegistry(
  ast: TSESTree.Program,
  filePath: string,
  source: string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const aliasMap: AliasMap = new Map();

  // ── Pass 1: collect all imports / requires ────────────────────────────────
  traverseAST(ast, {
    ImportDeclaration(node) {
      const pkgName = node.source.value as string;
      const resolvedPkg = resolvePackage(pkgName);
      if (!resolvedPkg) return;

      node.specifiers.forEach(spec => {
        if (
          spec.type === 'ImportDefaultSpecifier' ||
          spec.type === 'ImportNamespaceSpecifier'
        ) {
          aliasMap.set(spec.local.name, resolvedPkg);
        }
        if (spec.type === 'ImportSpecifier') {
          aliasMap.set(spec.local.name, resolvedPkg);
        }
      });
    },

    VariableDeclarator(node) {
      if (
        node.init?.type !== 'CallExpression' ||
        node.init.callee.type !== 'Identifier' ||
        node.init.callee.name !== 'require'
      ) return;

      const pkgName = getStringValue(node.init.arguments[0]);
      if (!pkgName) return;

      const resolvedPkg = resolvePackage(pkgName);
      if (!resolvedPkg) return;

      if (node.id.type === 'Identifier') {
        aliasMap.set(node.id.name, resolvedPkg);
      }

      if (node.id.type === 'ObjectPattern') {
        node.id.properties.forEach(prop => {
          if (prop.type === 'Property' && prop.value.type === 'Identifier') {
            aliasMap.set(prop.value.name, resolvedPkg);
          }
        });
      }
    }
  });

  // ── Pass 2: match method calls against registry rules ────────────────────
  traverseAST(ast, {
    CallExpression(node) {
      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      for (const [alias, pkgName] of aliasMap.entries()) {
        const pkgRule = getPackageRule(pkgName);
        if (!pkgRule) continue;

        for (const [methodName, methodRule] of Object.entries(pkgRule.methods)) {
          const finding = tryMatchMethod(
            node, alias, pkgName, methodName, methodRule,
            filePath, line, col, snippet, source
          );
          if (finding) {
            findings.push(finding);
          }
        }
      }
    },

    NewExpression(node) {
      const line = node.loc?.start.line || 0;
      const col = node.loc?.start.column || 0;
      const snippet = getSnippet(source, line);

      for (const [alias, pkgName] of aliasMap.entries()) {
        const pkgRule = getPackageRule(pkgName);
        if (!pkgRule) continue;

        for (const [methodName, methodRule] of Object.entries(pkgRule.methods)) {
          if (methodRule.detection !== 'newExpression') continue;

          const calleeName =
            node.callee.type === 'Identifier' ? node.callee.name : null;

          if (calleeName === methodName || calleeName === alias) {
            const algo = resolveAlgorithm(node.arguments, methodRule, node);
            if (algo) {
              findings.push(buildFinding(algo, pkgName, methodRule, filePath, line, col, snippet));
            }
          }
        }
      }
    }
  });

  return deduplicateByLocation(findings);
}

// ── Method matching ───────────────────────────────────────────────────────────

function tryMatchMethod(
  node: TSESTree.CallExpression,
  alias: string,
  pkgName: string,
  methodName: string,
  methodRule: MethodRule,
  filePath: string,
  line: number,
  col: number,
  snippet: string,
  source: string
): CryptoFinding | null {

  switch (methodRule.detection) {
    case 'memberCall':
      return matchMemberCall(node, alias, pkgName, methodName, methodRule, filePath, line, col, snippet);

    case 'nestedMemberCall':
      return matchNestedMemberCall(node, alias, pkgName, methodName, methodRule, filePath, line, col, snippet);

    case 'deepMemberCall':
      return matchDeepMemberCall(node, alias, pkgName, methodName, methodRule, filePath, line, col, snippet);

    case 'directCall':
      return matchDirectCall(node, alias, pkgName, methodName, methodRule, filePath, line, col, snippet);

    case 'importedFunction':
      return matchImportedFunction(node, alias, pkgName, methodName, methodRule, filePath, line, col, snippet);

    default:
      return null;
  }
}

// alias.method(args) — e.g. crypto.createHash('md5')
function matchMemberCall(
  node: TSESTree.CallExpression,
  alias: string,
  pkgName: string,
  methodName: string,
  rule: MethodRule,
  filePath: string, line: number, col: number, snippet: string
): CryptoFinding | null {
  if (!isMemberCall(node, alias, methodName)) return null;

  const algo = resolveAlgorithm(node.arguments, rule, node);
  if (!algo) return null;

  return buildFinding(algo, pkgName, rule, filePath, line, col, snippet, node);
}
function matchNestedMemberCall(
  node: TSESTree.CallExpression,
  alias: string,
  pkgName: string,
  methodName: string,
  rule: MethodRule,
  filePath: string, line: number, col: number, snippet: string
): CryptoFinding | null {
  if (node.callee.type !== 'MemberExpression') return null;
  const callee = node.callee;

  if (
    callee.object.type === 'MemberExpression' &&
    callee.object.object.type === 'Identifier' &&
    callee.object.object.name === alias &&
    callee.object.property.type === 'Identifier' &&
    callee.object.property.name === methodName
  ) {
    const algo = rule.fixedAlgorithm || methodName.toUpperCase();
    return buildFinding(algo, pkgName, rule, filePath, line, col, snippet, node);
  }

  return null;
}
function matchDeepMemberCall(
  node: TSESTree.CallExpression,
  alias: string,
  pkgName: string,
  methodName: string,
  rule: MethodRule,
  filePath: string, line: number, col: number, snippet: string
): CryptoFinding | null {
  const parts = methodName.split('.');
  const lastMethod = parts[parts.length - 1];
  const chain = parts.slice(0, -1);

  if (node.callee.type !== 'MemberExpression') return null;
  const callee = node.callee;

  if (
    callee.property.type !== 'Identifier' ||
    callee.property.name !== lastMethod
  ) return null;

  const callChain = extractMemberChain(callee.object);
  const expected = [alias, ...chain].join('.');

  if (!callChain.startsWith(expected)) return null;

  const algo = resolveAlgorithm(node.arguments, rule, node);
  if (!algo) return null;

  return buildFinding(algo, pkgName, rule, filePath, line, col, snippet, node);
}

function matchDirectCall(
  node: TSESTree.CallExpression,
  alias: string,
  pkgName: string,
  methodName: string,
  rule: MethodRule,
  filePath: string, line: number, col: number, snippet: string
): CryptoFinding | null {
  if (
    node.callee.type === 'Identifier' &&
    node.callee.name === alias
  ) {
    const algo = rule.fixedAlgorithm || methodName.toUpperCase();
    return buildFinding(algo, pkgName, rule, filePath, line, col, snippet, node);
  }
  return null;
}

function matchImportedFunction(
  node: TSESTree.CallExpression,
  alias: string,
  pkgName: string,
  methodName: string,
  rule: MethodRule,
  filePath: string, line: number, col: number, snippet: string
): CryptoFinding | null {
  if (
    node.callee.type === 'Identifier' &&
    (node.callee.name === alias || node.callee.name === methodName)
  ) {
    const algo = rule.fixedAlgorithm || methodName.toUpperCase();
    return buildFinding(algo, pkgName, rule, filePath, line, col, snippet, node);
  }
  return null;
}

// ── Algorithm resolution ──────────────────────────────────────────────────────

function resolveAlgorithm(
  args: TSESTree.CallExpression['arguments'] | TSESTree.NewExpression['arguments'],
  rule: MethodRule,
  node: TSESTree.CallExpression | TSESTree.NewExpression
): string | null {
  if (rule.fixedAlgorithm) {
    const prefix = rule.algoPrefix || '';
    return prefix + rule.fixedAlgorithm;
  }

  if (rule.algoArgIndex !== undefined && args[rule.algoArgIndex]) {
    const raw = getStringValue(args[rule.algoArgIndex] as TSESTree.Node);
    if (raw) {
      const prefix = rule.algoPrefix || '';
      const algo = (prefix + raw).toUpperCase();

      if (rule.parseAlgoMode) {
        return algo; 
      }
      return algo;
    }

    return `DYNAMIC-ALGO`;
  }

  // Algorithm comes from an options object property
  if (rule.algoFromOption && rule.optionArgIndex !== undefined) {
    const optArg = args[rule.optionArgIndex];
    if (optArg?.type === 'ObjectExpression') {
      const prop = optArg.properties.find(
        (p): p is TSESTree.Property =>
          p.type === 'Property' &&
          p.key.type === 'Identifier' &&
          p.key.name === rule.algoFromOption
      );
      if (prop) {
        const val = getStringValue(prop.value as TSESTree.Node);
        if (val) return val.toUpperCase();
      }
    }

    return rule.defaultAlgorithm?.toUpperCase() || null;
  }
  if (rule.defaultAlgorithm) return rule.defaultAlgorithm.toUpperCase();
  return null;
}

// ── Finding builder ───────────────────────────────────────────────────────────

function buildFinding(
  algorithm: string,
  library: string,
  rule: MethodRule,
  filePath: string,
  line: number,
  column: number,
  context: string,
  node?: TSESTree.CallExpression | TSESTree.NewExpression
): CryptoFinding {
  const meta = getAlgorithmMeta(algorithm);

  // Extract keySize from options if available
  let keySize: number | undefined;
  if (rule.keySizeOption && node) {
    const args = node.arguments;
    for (const arg of args) {
      if (arg.type === 'ObjectExpression') {
        const prop = arg.properties.find(
          (p): p is TSESTree.Property =>
            p.type === 'Property' &&
            p.key.type === 'Identifier' &&
            p.key.name === rule.keySizeOption
        );
        if (prop) {
          keySize = getNumberValue(prop.value as TSESTree.Node) || undefined;
        }
      }
    }
  }

  // Parse mode from algo string (e.g. AES-128-ECB → mode=ECB, keySize=128)
  let mode: string | undefined;
  if (rule.parseAlgoMode) {
    const parts = algorithm.split('-');
    if (parts.length >= 3) {
      mode = parts[parts.length - 1];
      if (!keySize && !isNaN(Number(parts[1]))) {
        keySize = Number(parts[1]);
      }
    }
  }

  // Override severity for RSA with small key
  let severity = meta.severity;
  if (algorithm.toUpperCase().includes('RSA') && keySize) {
    if (keySize < 2048) severity = 'CRITICAL';
    else if (keySize < 4096) severity = 'MEDIUM';
  }

  // Merge notes from registry algo meta and method rule
  const notes = [meta.notes, rule.notes].filter(Boolean).join(' | ') || undefined;

  return {
    algorithm: algorithm.toUpperCase(),
    library,
    location: filePath,
    line,
    column,
    mode,
    keySize,
    weak: meta.weak,
    quantumSafe: meta.quantumSafe,
    severity,
    context,
    cwe: meta.cwe || [],
    notes
  };
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function extractMemberChain(node: TSESTree.Node): string {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = extractMemberChain(node.object);
    const prop =
      node.property.type === 'Identifier' ? node.property.name : '?';
    return `${obj}.${prop}`;
  }
  return '';
}

function deduplicateByLocation(findings: CryptoFinding[]): CryptoFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.location}:${f.line}:${f.algorithm}:${f.library}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}