import Parser from 'tree-sitter';
const Python = require('tree-sitter-python');

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PythonNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition:   { row: number; column: number };
  children:       PythonNode[];
  namedChildren:  PythonNode[];
  parent:         PythonNode | null;
  childForFieldName(name: string): PythonNode | null;
}

export type PythonVisitors = Partial<Record<string, (node: PythonNode) => void>>;

let _parser: Parser | null = null;

function getParser(): Parser {
  if (!_parser) {
    _parser = new Parser();
    _parser.setLanguage(Python);
  }
  return _parser;
}

export function parsePythonSource(filePath: string, source: string): PythonNode {
  const parser = getParser();
  const tree   = parser.parse(source);
  if (tree.rootNode.hasError) {
    process.stderr.write(`[pythonParser] Parse warning: syntax errors in ${filePath}\n`);
  }
  return tree.rootNode as unknown as PythonNode;
}

export function traversePythonAST(node: PythonNode, visitors: PythonVisitors): void {
  const visit = visitors[node.type];
  if (visit) visit(node);
  for (const child of node.children) {
    traversePythonAST(child, visitors);
  }
}

export function getStringValue(node: PythonNode | null): string | null {
  if (!node) return null;
  if (node.type === 'string') {
    let t = node.text;
    if (t.startsWith('"""') || t.startsWith("'''")) {
      t = t.slice(3, -3);
    } else if (
      (t.startsWith('"') && t.endsWith('"')) ||
      (t.startsWith("'") && t.endsWith("'"))
    ) {
      t = t.slice(1, -1);
    }
    return t;
  }
  if (node.type === 'concatenated_string') {
    return getStringValue(node.namedChildren[0]);
  }
  return null;
}

export function getNumberValue(node: PythonNode | null): number | null {
  if (!node) return null;
  if (node.type === 'integer' || node.type === 'float') {
    const n = Number(node.text.replace(/_/g, ''));
    return isNaN(n) ? null : n;
  }
  return null;
}

export function getSnippet(source: string, node: PythonNode): string {
  const lines = source.split('\n');
  const line  = lines[node.startPosition.row] ?? '';
  return line.trim().slice(0, 200);
}

export function getLine(node: PythonNode): number {
  return node.startPosition.row + 1;
}

export interface PythonImport {
  module:  string;          // the dotted module path
  name?:   string;          // the imported name (for "from X import Y")
  alias:   string;          // the local identifier in scope
}

export function collectImports(root: PythonNode): PythonImport[] {
  const imports: PythonImport[] = [];
  traversePythonAST(root, {
    import_statement(node) {
      for (const child of node.namedChildren) {
        if (child.type === 'dotted_name') {
          imports.push({ module: child.text, alias: child.text });
        }
        if (child.type === 'aliased_import') {
          const modNode   = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          if (modNode && aliasNode) {
            imports.push({ module: modNode.text, alias: aliasNode.text });
          }
        }
      }
    },
    import_from_statement(node) {
      const moduleNode = node.childForFieldName('module_name');
      if (!moduleNode) return;
      const modName = moduleNode.text;

      for (const child of node.namedChildren) {
        if (child === moduleNode) continue;
        if (child.type === 'dotted_name' || child.type === 'identifier') {
          imports.push({ module: modName, name: child.text, alias: child.text });
        }
        if (child.type === 'aliased_import') {
          const nameNode  = child.childForFieldName('name');
          const aliasNode = child.childForFieldName('alias');
          if (nameNode && aliasNode) {
            imports.push({ module: modName, name: nameNode.text, alias: aliasNode.text });
          }
        }
      }
    },
  });

  return imports;
}