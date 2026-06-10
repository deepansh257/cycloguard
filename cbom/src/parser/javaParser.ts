import Parser from 'tree-sitter';
const Java = require('tree-sitter-java');

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

export function parseJavaSource(filePath: string, source: string): JavaNode {
  const parser = getParser();
  const tree = parser.parse(source);
  if (tree.rootNode.hasError) {
    process.stderr.write(
      `[javaParser] Parse warning: syntax errors in ${filePath}\n`
    );
  }
  return tree.rootNode as unknown as JavaNode;
}

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

export function getStringValue(node: JavaNode | null): string | null {
  if (!node) return null;
  if (node.type === 'string_literal') {
    // tree-sitter includes the surrounding quotes in .text
    return node.text.replace(/^["']|["']$/g, '');
  }
  return null;
}

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

export function getSnippet(source: string, node: JavaNode): string {
  const start = node.startPosition;
  const lines = source.split('\n');
  const line = lines[start.row] ?? '';
  return line.trim().slice(0, 200);
}

export function getLine(node: JavaNode): number {
  return node.startPosition.row + 1;
}

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

  return obj.text === objectName || obj.text.endsWith(`.${objectName}`);
}

export function collectImports(root: JavaNode): Set<string> {
  const imports = new Set<string>();
  traverseJavaAST(root, {
    import_declaration(node) {
      const raw = node.text.replace(/^import\s+/, '').replace(/;$/, '').trim();
      imports.add(raw.replace(/^static\s+/, ''));
    },
  });
  return imports;
}

export function collectVariableTypes(
  root: JavaNode
): Map<string, string> {
  const vars = new Map<string, string>(); 
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