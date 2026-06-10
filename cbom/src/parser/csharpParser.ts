import Parser from 'tree-sitter';
const CSharp = require('tree-sitter-c-sharp');

// ─── Types ────────────────────────────────────────────────────────────────────
export interface CSharpNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition:   { row: number; column: number };
  children:       CSharpNode[];
  namedChildren:  CSharpNode[];
  parent:         CSharpNode | null;
  childForFieldName(name: string): CSharpNode | null;
}

export type CSharpVisitors = Partial<Record<string, (node: CSharpNode) => void>>;

// ─── Singleton parser ─────────────────────────────────────────────────────────

let _parser: Parser | null = null;

function getParser(): Parser {
  if (!_parser) {
    _parser = new Parser();
    _parser.setLanguage(CSharp);
  }
  return _parser;
}

// ─── Public API ───────────────────────────────────────────────────────────────
export function parseCSharpSource(filePath: string, source: string): CSharpNode {
  const parser = getParser();
  const tree   = parser.parse(source);
  if (tree.rootNode.hasError) {
    process.stderr.write(`[csharpParser] Parse warning: syntax errors in ${filePath}\n`);
  }
  return tree.rootNode as unknown as CSharpNode;
}

export function traverseCSharpAST(node: CSharpNode, visitors: CSharpVisitors): void {
  const visit = visitors[node.type];
  if (visit) visit(node);
  for (const child of node.children) {
    traverseCSharpAST(child, visitors);
  }
}

// ─── Helper utilities ─────────────────────────────────────────────────────────
export function getStringValue(node: CSharpNode | null): string | null {
  if (!node) return null;
  if (
    node.type === 'string_literal' ||
    node.type === 'verbatim_string_literal' ||
    node.type === 'interpolated_string_expression'
  ) {
    let t = node.text;
    if (t.startsWith('@"') || t.startsWith('@\'')) t = t.slice(2, -1);
    else if (t.startsWith('$"')) t = t.slice(2, -1);
    else if (t.startsWith('"') && t.endsWith('"')) t = t.slice(1, -1);
    else if (t.startsWith("'") && t.endsWith("'")) t = t.slice(1, -1);
    return t;
  }
  return null;
}

export function getNumberValue(node: CSharpNode | null): number | null {
  if (!node) return null;
  if (
    node.type === 'integer_literal' ||
    node.type === 'real_literal' ||
    node.type === 'hex_integer_literal'
  ) {
    const n = Number(node.text.replace(/_/g, '').replace(/[uUlLfFdDmM]+$/, ''));
    return isNaN(n) ? null : n;
  }
  return null;
}

export function getSnippet(source: string, node: CSharpNode): string {
  const lines = source.split('\n');
  const line  = lines[node.startPosition.row] ?? '';
  return line.trim().slice(0, 200);
}

export function getLine(node: CSharpNode): number {
  return node.startPosition.row + 1;
}

// ─── Using-directive collection ───────────────────────────────────────────────
export interface CSharpUsing {
  namespace: string;
  alias:     string;
}

export function collectUsings(root: CSharpNode): CSharpUsing[] {
  const usings: CSharpUsing[] = [];

  traverseCSharpAST(root, {
    using_directive(node) {
      const children = node.namedChildren.filter(
        c => c.type !== ';' && c.type !== 'using'
      );
      if (children.length === 1) {
        // plain using
        const ns = children[0].text;
        usings.push({ namespace: ns, alias: ns });
      } else if (children.length === 2) {
        // aliased using: alias = namespace
        usings.push({ namespace: children[1].text, alias: children[0].text });
      }
    },
  });

  return usings;
}

export function collectObjectCreations(root: CSharpNode): Map<string, CSharpNode[]> {
  const map = new Map<string, CSharpNode[]>();
  traverseCSharpAST(root, {
    object_creation_expression(node) {
      const typeNode = node.childForFieldName('type');
      if (!typeNode) return;
      const typeName = typeNode.text.split('.').pop() ?? typeNode.text;
      if (!map.has(typeName)) map.set(typeName, []);
      map.get(typeName)!.push(node);
    },
  });

  return map;
}