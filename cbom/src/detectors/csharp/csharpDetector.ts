/**
 * src/detectors/csharp/csharpDetector.ts
 *
 * Registry-driven crypto detector for C# source files.
 * Architecture mirrors javaDetector.ts:
 *   Pass 1 — build a usingMap from using directives
 *   Pass 2 — walk invocation_expression / object_creation_expression nodes,
 *             match against registry rules
 *
 * All detection rules live in libraries.json ("language": "csharp" entries).
 * Two patterns are structural-only and cannot be expressed as registry rules:
 *   1. new RijndaelManaged() — class name is the API (handled via newExpression detection)
 *   2. CryptoConfig.CreateFromName(algo) — dynamic algo (handled as dynamic-algo)
 */

import {
  CSharpNode,
  CSharpUsing,
  parseCSharpSource,
  traverseCSharpAST,
  collectUsings,
  getStringValue,
  getNumberValue,
  getLine,
  getSnippet,
} from '../../parser/csharpParser';
import {
  getRegistry,
  getAlgorithmMeta,
} from '../../registry/registryLoader';
import { CryptoFinding } from '../../types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface CSharpMethodDef {
  name:             string;
  detection:        string;
  algoArgIndex?:    number;
  fixedAlgorithm?:  string;
  primitive:        string;
  notes?:           string;
  keySizeOption?:   string;
  algoPrefix?:      string;
}

/**
 * Resolved using entry: namespace maps to registry package key.
 * C# doesn't have per-symbol imports (unlike Python "from X import Y"),
 * so we track the namespace and match on class name at the call site.
 */
interface ResolvedUsing {
  namespace:   string;
  registryKey: string;
}

// ─── Pass 1: Using resolution ─────────────────────────────────────────────────

function resolveUsings(rawUsings: CSharpUsing[]): ResolvedUsing[] {
  const registry = getRegistry();
  const resolved: ResolvedUsing[] = [];

  for (const u of rawUsings) {
    for (const [pkgKey, pkgRule] of registry.packageRules.entries()) {
      if ((pkgRule as any).language !== 'csharp') continue;

      const aliases: string[] = (pkgRule as any).aliases ?? [];
      const matched =
        aliases.includes(u.namespace) ||
        aliases.some(a => u.namespace.startsWith(a)) ||
        aliases.some(a => a.startsWith(u.namespace));

      if (matched) {
        resolved.push({ namespace: u.namespace, registryKey: pkgKey });
        break;
      }
    }
  }

  return resolved;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/**
 * Mirrors detectJava(javaAst, filePath, source).
 */
export function detectCSharp(
  ast:      CSharpNode,
  filePath: string,
  source:   string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const registry = getRegistry();

  // Pass 1
  const rawUsings     = collectUsings(ast);
  const resolvedUsings = resolveUsings(rawUsings);

  if (resolvedUsings.length === 0) return findings;

  // Build quick lookup: registryKey → pkg methods
  const activePackages = new Set(resolvedUsings.map(r => r.registryKey));

  // Pass 2 — walk invocation and object-creation nodes
  traverseCSharpAST(ast, {

    // ClassName.Method(args) or variable.Method(args)
    invocation_expression(node) {
      const line    = getLine(node);
      const snippet = getSnippet(source, node);
      const col     = node.startPosition.column;

      const calleeNode = node.childForFieldName('expression') ??
                         node.namedChildren[0];
      if (!calleeNode) return;

      const calleeText = calleeNode.text;

      for (const ri of resolvedUsings) {
        const pkgRule = registry.packageRules.get(ri.registryKey);
        if (!pkgRule) continue;

        const methods = (pkgRule as any).methods as CSharpMethodDef[];

        for (const methodDef of methods) {
          if (
            methodDef.detection !== 'staticCall' &&
            methodDef.detection !== 'memberCall'
          ) continue;

          const finding = tryMatchCSharpInvocation(
            node, calleeText, methodDef, ri.registryKey,
            filePath, line, col, snippet
          );
          if (finding) {
            findings.push(finding);
            return;
          }
        }
      }
    },

    // new ClassName(args)
    object_creation_expression(node) {
      const line    = getLine(node);
      const snippet = getSnippet(source, node);
      const col     = node.startPosition.column;

      const typeNode = node.childForFieldName('type');
      if (!typeNode) return;

      // Short class name (without namespace prefix)
      const typeName = typeNode.text.split('.').pop() ?? typeNode.text;

      for (const ri of resolvedUsings) {
        const pkgRule = registry.packageRules.get(ri.registryKey);
        if (!pkgRule) continue;

        const methods = (pkgRule as any).methods as CSharpMethodDef[];

        for (const methodDef of methods) {
          if (methodDef.detection !== 'newExpression') continue;

          // Match on the short class name, e.g. "AesCryptoServiceProvider"
          const defShortName = methodDef.name.split('.').pop()!;
          if (typeName !== defShortName && typeNode.text !== methodDef.name) continue;

          const args  = getCSharpCallArgs(node);
          const algo  = resolveCSharpAlgo(args, methodDef);
          if (!algo) continue;

          findings.push(buildCSharpFinding(
            algo, ri.registryKey, methodDef, filePath, line, col, snippet
          ));
          return;
        }
      }
    },
  });

  return deduplicateByLocation(findings);
}

// ─── Invocation matching ──────────────────────────────────────────────────────

function tryMatchCSharpInvocation(
  node:      CSharpNode,
  calleeText: string,
  methodDef: CSharpMethodDef,
  pkgKey:    string,
  filePath:  string,
  line:      number,
  col:       number,
  snippet:   string
): CryptoFinding | null {

  // calleeText for C# invocations looks like:
  //   "HashAlgorithm.Create"
  //   "Aes.Create"
  //   "someVar.CreateEncryptor"
  //   "SHA256.Create"

  const defParts   = methodDef.name.split('.');
  const className  = defParts.length > 1 ? defParts[defParts.length - 2] : null;
  const methodName = defParts[defParts.length - 1];

  // The callee must end with the method name
  if (!calleeText.endsWith(`.${methodName}`) && calleeText !== methodName) return null;

  // If we have a class name constraint, the part before the dot must match
  if (className) {
    const dotIdx  = calleeText.lastIndexOf('.');
    const objPart = dotIdx >= 0 ? calleeText.slice(0, dotIdx).split('.').pop() : calleeText;
    if (objPart !== className) return null;
  }

  const args   = getCSharpCallArgs(node);
  const algo   = resolveCSharpAlgo(args, methodDef);
  if (!algo) return null;

  return buildCSharpFinding(algo, pkgKey, methodDef, filePath, line, col, snippet);
}

// ─── Argument helpers ─────────────────────────────────────────────────────────

function getCSharpCallArgs(node: CSharpNode): CSharpNode[] {
  // For invocation_expression, args are under argument_list
  // For object_creation_expression, args are under argument_list too
  const argList = node.namedChildren.find(
    c => c.type === 'argument_list'
  );
  if (!argList) return [];

  return argList.namedChildren.filter(
    c => c.type === 'argument' || c.type === 'string_literal' ||
         c.type === 'integer_literal' || c.type === 'identifier'
  );
}

function resolveCSharpAlgo(args: CSharpNode[], methodDef: CSharpMethodDef): string | null {
  if (methodDef.fixedAlgorithm) {
    return (methodDef.algoPrefix ?? '') + methodDef.fixedAlgorithm;
  }

  if (methodDef.algoArgIndex !== undefined) {
    const argNode = args[methodDef.algoArgIndex];
    if (!argNode) return 'DYNAMIC-ALGO';

    // Unwrap "argument" wrapper node
    const valueNode =
      argNode.type === 'argument'
        ? argNode.namedChildren[0] ?? argNode
        : argNode;

    const raw = getStringValue(valueNode);
    if (raw) {
      return ((methodDef.algoPrefix ?? '') + raw).toUpperCase();
    }

    // Member access used as algo constant: HashAlgorithmName.SHA256 → "SHA256"
    if (valueNode.type === 'member_access_expression' || valueNode.type === 'identifier') {
      const name = valueNode.text.split('.').pop()!.toUpperCase();
      return (methodDef.algoPrefix ?? '') + name;
    }

    return 'DYNAMIC-ALGO';
  }

  return null;
}

// ─── Finding builder ──────────────────────────────────────────────────────────

function buildCSharpFinding(
  algorithm: string,
  library:   string,
  methodDef: CSharpMethodDef,
  filePath:  string,
  line:      number,
  column:    number,
  context:   string
): CryptoFinding {
  const meta  = getAlgorithmMeta(algorithm);
  const notes = [meta.notes, methodDef.notes].filter(Boolean).join(' | ') || undefined;

  return {
    algorithm: algorithm.toUpperCase(),
    library,
    location:  filePath,
    line,
    column,
    weak:        meta.weak,
    quantumSafe: meta.quantumSafe,
    severity:    meta.severity,
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