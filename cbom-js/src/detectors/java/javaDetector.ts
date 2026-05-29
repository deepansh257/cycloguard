import { CryptoFinding } from '../../types';
import {
  getRegistry,
  getAlgorithmMeta,
  PackageRule,
  MethodRule,
} from '../../registry/registryLoader';
import {
  JavaNode,
  traverseJavaAST,
  getStringValue,
  getNumberValue,
  getSnippet,
  getLine,
  collectImports,
} from '../../parser/javaParser';

type ClassMap = Map<string, string>;

function getJavaPackages(): Map<string, PackageRule> {
  const { registry } = getRegistry();
  const result = new Map<string, PackageRule>();
  for (const [pkgName, rule] of Object.entries(registry.packages)) {
    if ((rule as any).language === 'java') {
      result.set(pkgName, rule as PackageRule);
    }
  }
  return result;
}

// ─── Main detector ────────────────────────────────────────────────────────────

export function detectJava(
  ast:      JavaNode,
  filePath: string,
  source:   string
): CryptoFinding[] {
  const findings: CryptoFinding[] = [];
  const javaPackages = getJavaPackages();
  const imports      = collectImports(ast);

  const classMap: ClassMap = new Map();

  for (const importedName of imports) {
    for (const [pkgName] of javaPackages) {
      // Exact match: import javax.crypto.Cipher
      if (importedName.startsWith(pkgName)) {
        const simpleName = importedName.slice(pkgName.length + 1); // strip "javax.crypto."
        if (simpleName && !simpleName.includes('.')) {
          classMap.set(simpleName, pkgName);
        }
        if (simpleName === '*') {
          registerAllClassesForPackage(pkgName, javaPackages, classMap);
        }
      }
    }
  }

  for (const [pkgName] of javaPackages) {
    registerAllClassesForPackage(pkgName, javaPackages, classMap);
  }

  // ── Pass 2: match method calls against registry rules ─────────────────────
  traverseJavaAST(ast, {
    method_invocation(node) {
      const nameNode = node.childForFieldName('name');
      if (!nameNode) return;
      const methodName = nameNode.text;

      const objectNode = node.childForFieldName('object');
      if (!objectNode) return;

      const objectText = objectNode.text;
      const simpleName = objectText.split('.').pop() ?? objectText;

      const pkgName = classMap.get(simpleName);
      if (!pkgName) return;

      const pkgRule = javaPackages.get(pkgName);
      if (!pkgRule) return;

      const matchingRule = findMethodRule(pkgRule, simpleName, methodName);
      if (!matchingRule) return;

      const args      = getArgumentNodes(node);
      const algorithm = resolveAlgorithm(args, matchingRule);
      if (!algorithm) return;

      findings.push(buildFinding(
        algorithm,
        pkgName,
        matchingRule,
        filePath,
        getLine(node),
        getSnippet(source, node),
        node,
        source,
      ));
    },

    object_creation_expression(node) {
      const typeNode = node.childForFieldName('type');
      if (!typeNode) return;

      const simpleName = typeNode.text.split('.').pop() ?? typeNode.text;
      const pkgName    = classMap.get(simpleName);
      if (!pkgName) return;

      const pkgRule = javaPackages.get(pkgName);
      if (!pkgRule) return;

      const matchingRule = findMethodRule(pkgRule, simpleName, simpleName);
      if (!matchingRule) return;

      const args      = getArgumentNodes(node);
      const algorithm = resolveAlgorithm(args, matchingRule);
      if (!algorithm) return;

      findings.push(buildFinding(
        algorithm,
        pkgName,
        matchingRule,
        filePath,
        getLine(node),
        getSnippet(source, node),
        node,
        source,
      ));
    },
  });

  // ── Pass 3: structural / pattern detections ───────────────────────────────
  traverseJavaAST(ast, {
    object_creation_expression(node) {
      const typeNode = node.childForFieldName('type');
      if (!typeNode || typeNode.text !== 'Random') return;

      // Exclude if SecureRandom is also imported (caller may be using the right one)
      const hasSecureRandom = [...imports].some(i =>
        i === 'java.security.SecureRandom'
      );
      if (hasSecureRandom) return;

      findings.push(buildFinding(
        'INSECURE-RANDOM',
        'java.util',
        { primitive: 'prf', detection: 'newExpression' } as unknown as MethodRule,
        filePath,
        getLine(node),
        getSnippet(source, node),
        node,
        source,
      ));
    },
  });

  // 3b. X509TrustManager with empty body — disabled cert validation
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

      if (!hasEmptyCheck) return;

      findings.push(buildFinding(
        'TLS-CERT-VALIDATION',
        'javax.net.ssl',
        { primitive: 'protocol', detection: 'staticCall' } as unknown as MethodRule,
        filePath,
        getLine(node),
        getSnippet(source, node),
        node,
        source,
      ));
    },
  });

  // 3c. Hardcoded secrets in String / byte[] / char[] variables
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

      const { hardcodedPatterns } = getRegistry().registry;
      const varName  = nameNode.text.toLowerCase();
      const isSecret = hardcodedPatterns.variableNames.some(
        (n: string) => varName.includes(n.toLowerCase())
      );
      if (!isSecret) return;

      const literal = getStringValue(valueNode);
      if (!literal || literal.length < hardcodedPatterns.minLength) return;

      const isExcluded =
        hardcodedPatterns.excludePrefixes.some((p: string) => literal.startsWith(p)) ||
        hardcodedPatterns.excludePatterns.some((p: string) =>
          literal.toLowerCase().includes(p.toLowerCase())
        );
      if (isExcluded) return;

      findings.push(buildFinding(
        'HARDCODED-SECRET',
        'java',
        { primitive: 'other', detection: 'staticCall' } as unknown as MethodRule,
        filePath,
        getLine(node),
        getSnippet(source, node),
        node,
        source,
        `Potential hardcoded secret in variable "${nameNode.text}". Store secrets in environment variables or a secrets manager.`,
      ));
    },
  });

  // 3d. Weak key size — KeyPairGenerator.initialize(keySize) / KeyGenerator.init(keySize)
  traverseJavaAST(ast, {
    method_invocation(node) {
      const nameNode = node.childForFieldName('name');
      if (!nameNode) return;
      if (nameNode.text !== 'initialize' && nameNode.text !== 'init') return;
      const args    = getArgumentNodes(node);
      const keySize = args[0] ? getNumberValue(args[0]) : null;
      if (!keySize) return;

      const thresholds: Record<string, number> = {
        RSA: 2048, DSA: 2048, EC: 256, DH: 2048, AES: 128,
      };

      for (const [algo, minBits] of Object.entries(thresholds)) {
        if (keySize < minBits) {
          findings.push(buildFinding(
            algo,
            'java.security',
            { primitive: 'pke', detection: 'staticCall' } as unknown as MethodRule,
            filePath,
            getLine(node),
            getSnippet(source, node),
            node,
            source,
            `Key size ${keySize} bits may be below the recommended minimum of ${minBits} bits for ${algo}.`,
          ));
          break;
        }
      }
    },
  });

  return deduplicateByLocation(findings);
}

// ─── Registry helpers ─────────────────────────────────────────────────────────
function registerAllClassesForPackage(
  pkgName: string,
  javaPackages: Map<string, PackageRule>,
  classMap: ClassMap
): void {
  const rule = javaPackages.get(pkgName);
  if (!rule) return;
  const methods = (rule as any).methods;
  if (!Array.isArray(methods)) return;

  for (const method of methods) {
    const className = (method.name as string).split('.')[0];
    if (className && !classMap.has(className)) {
      classMap.set(className, pkgName);
    }
  }
}

function findMethodRule(
  pkgRule: PackageRule,
  className: string,
  methodName: string
): MethodRule | null {
  const methods = (pkgRule as any).methods;
  if (!Array.isArray(methods)) {
    return (methods as Record<string, MethodRule>)[methodName] ?? null;
  }
  for (const m of methods) {
    const [mClass, mMethod] = (m.name as string).split('.');
    const isClassMatch  = mClass === className;
    const isMethodMatch = mMethod === methodName || mMethod === undefined;
    if (isClassMatch && isMethodMatch) return m as MethodRule;
  }

  return null;
}

function resolveAlgorithm(
  args: JavaNode[],
  rule: MethodRule,
): string | null {
  if (rule.fixedAlgorithm) return rule.fixedAlgorithm;

  const argIndex = (rule as any).algoArgIndex ?? 0;
  const argNode  = args[argIndex] ?? null;
  if (!argNode) return null;

  const raw = getStringValue(argNode);
  if (raw) return raw.toUpperCase();
  return 'DYNAMIC-ALGO';
}

// ─── Finding builder ──────────────────────────────────────────────────────────

function buildFinding(
  algorithm:   string,
  library:     string,
  rule:        MethodRule,
  filePath:    string,
  line:        number,
  context:     string,
  _node:       JavaNode,
  _source:     string,
  notesOverride?: string,
): CryptoFinding {
  const meta  = getAlgorithmMeta(algorithm);
  const notes = notesOverride ?? meta.notes ?? '';

  return {
    algorithm:   algorithm.toUpperCase(),
    library,
    location:    filePath,
    line,
    context,
    weak:        meta.weak        ?? false,
    quantumSafe: meta.quantumSafe ?? null,
    severity:    meta.severity    ?? 'INFO',
    cwe:         meta.cwe         ?? [],
    notes,
  } as unknown as CryptoFinding;
}

// ─── AST helpers ──────────────────────────────────────────────────────────────

function getArgumentNodes(node: JavaNode): JavaNode[] {
  const argList = node.namedChildren.find(c => c.type === 'argument_list');
  if (!argList) return [];
  return argList.namedChildren;
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
  return bodyNode.namedChildren.filter(c =>
    c.type !== 'line_comment' &&
    c.type !== 'block_comment' &&
    c.type !== 'comment'
  ).length === 0;
}

function deduplicateByLocation(findings: CryptoFinding[]): CryptoFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${(f as any).location}:${f.line}:${f.algorithm}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}