/**
 * src/parser/javaParser.ts
 *
 * Parses Java source files into a tree-sitter AST and exposes the same
 * helper surface that astParser.ts provides for JS/TS — so Java detectors
 * can be written in an identical style to the existing JS detectors.
 *
 * Dependencies (add to package.json):
 *   "tree-sitter":      "^0.25.0"
 *   "tree-sitter-java": "^0.23.5"
 *
 * Install: npm install tree-sitter tree-sitter-java
 */

import Parser from 'tree-sitter';
// tree-sitter-java ships a pre-built native binding — no extra build step.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const Java = require('tree-sitter-java');

// ─── Types ────────────────────────────────────────────────────────────────────

/** A tree-sitter SyntaxNode (subset of fields we actually use). */
export interface JavaNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  children: JavaNode[];
  namedChildren: JavaNode[];
  parent: JavaNode | null;
  /** tree-sitter helper — returns the first named child with the given field name. */
  childForFieldName(name: string): JavaNode | null;
}

/** Visitor map passed to traverseJavaAST. */
export type JavaVisitors = Partial<Record<string, (node: JavaNode) => void>>;

// ─── Singleton parser ─────────────────────────────────────────────────────────

let _parser: Parser | null = null;

function getParser(): Parser {
  if (!_parser) {
    _parser = new Parser();
    _parser.setLanguage(Java);
  }
  return _parser;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Parse a Java source string and return the root tree-sitter node.
 * Mirrors: astParser.parseSource(filePath, source)
 */
export function parseJavaSource(filePath: string, source: string): JavaNode {
  const parser = getParser();
  const tree = parser.parse(source);
  if (tree.rootNode.hasError) {
    // Non-fatal — tree-sitter recovers gracefully from syntax errors.
    // We log at debug level only; detectors will still find most patterns.
    process.stderr.write(
      `[javaParser] Parse warning: syntax errors in ${filePath}\n`
    );
  }
  return tree.rootNode as unknown as JavaNode;
}

/**
 * Walk every node in the tree, calling the matching visitor by node type.
 * Mirrors: astParser.traverseAST(ast, visitors)
 */
export function traverseJavaAST(
  node: JavaNode,
  visitors: JavaVisitors
): void {
  const visit = visitors[node.type];
  if (visit) visit(node);
  for (const child of node.children) {
    traverseJavaAST(child, visitors);
  }
}

// ─── Helper utilities (mirrors astParser helpers) ─────────────────────────────

/**
 * Returns the trimmed text of a node — equivalent to getStringValue for
 * string literals; strips surrounding quotes.
 */
export function getStringValue(node: JavaNode | null): string | null {
  if (!node) return null;
  if (node.type === 'string_literal') {
    // tree-sitter includes the surrounding quotes in .text
    return node.text.replace(/^["']|["']$/g, '');
  }
  return null;
}

/**
 * Returns the numeric value of an integer/decimal literal node.
 */
export function getNumberValue(node: JavaNode | null): number | null {
  if (!node) return null;
  if (
    node.type === 'decimal_integer_literal' ||
    node.type === 'hex_integer_literal' ||
    node.type === 'decimal_floating_point_literal'
  ) {
    const n = Number(node.text.replace(/_/g, '').replace(/[lLfFdD]$/, ''));
    return isNaN(n) ? null : n;
  }
  return null;
}

/**
 * Extract the source snippet for a node (up to 200 chars).
 * Mirrors: astParser.getSnippet
 */
export function getSnippet(source: string, node: JavaNode): string {
  const start = node.startPosition;
  const lines = source.split('\n');
  const line = lines[start.row] ?? '';
  return line.trim().slice(0, 200);
}

/**
 * 1-based line number for a node.
 */
export function getLine(node: JavaNode): number {
  return node.startPosition.row + 1;
}

/**
 * True when a method_invocation node matches object.method(...)
 * e.g. isMemberCall(node, 'MessageDigest', 'getInstance')
 *
 * Mirrors: astParser.isMemberCall
 */
export function isMemberCall(
  node: JavaNode,
  objectName: string,
  methodName: string
): boolean {
  if (node.type !== 'method_invocation') return false;

  const method = node.childForFieldName('name');
  if (!method || method.text !== methodName) return false;

  const obj = node.childForFieldName('object');
  if (!obj) return false;

  // Handle both direct names (MessageDigest.getInstance) and variable refs
  return obj.text === objectName || obj.text.endsWith(`.${objectName}`);
}

/**
 * Collect all import declarations in a file as a Set of fully-qualified names.
 * e.g.  "javax.crypto.Cipher", "org.bouncycastle.crypto.engines.AESEngine"
 */
export function collectImports(root: JavaNode): Set<string> {
  const imports = new Set<string>();
  traverseJavaAST(root, {
    import_declaration(node) {
      // text is like: "import javax.crypto.Cipher;"
      const raw = node.text.replace(/^import\s+/, '').replace(/;$/, '').trim();
      // strip static keyword
      imports.add(raw.replace(/^static\s+/, ''));
    },
  });
  return imports;
}

/**
 * Collect all local variable declarations of a given type into a Map of
 * variableName → initialiser node.  Used to resolve chained calls like:
 *   MessageDigest md = MessageDigest.getInstance("MD5");
 *   md.update(data);   // ← need to know md is a MessageDigest
 */
export function collectVariableTypes(
  root: JavaNode
): Map<string, string> {
  const vars = new Map<string, string>(); // varName → declared type
  traverseJavaAST(root, {
    local_variable_declaration(node) {
      const typeNode = node.childForFieldName('type');
      const declarator = node.namedChildren.find(
        (c) => c.type === 'variable_declarator'
      );
      if (typeNode && declarator) {
        const nameNode = declarator.childForFieldName('name');
        if (nameNode) {
          vars.set(nameNode.text, typeNode.text);
        }
      }
    },
  });
  return vars;
}