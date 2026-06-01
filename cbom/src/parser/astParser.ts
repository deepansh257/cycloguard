import { parse, TSESTree, simpleTraverse } from '@typescript-eslint/typescript-estree';
import * as path from 'path';

export type ASTNode = TSESTree.Node;
export type CallExpressionNode = TSESTree.CallExpression;
export type NewExpressionNode = TSESTree.NewExpression;
export type ImportDeclarationNode = TSESTree.ImportDeclaration;
export type VariableDeclaratorNode = TSESTree.VariableDeclarator;

export interface ParsedFile {
  filePath: string;
  ast: TSESTree.Program | null;
  error?: string;
}

export function parseSource(filePath: string, source: string): ParsedFile {
  const ext = path.extname(filePath).toLowerCase();
  const isTS = ['.ts', '.tsx'].includes(ext);
  const isJSX = ['.jsx', '.tsx'].includes(ext);

  try {
    const ast = parse(source, {
      loc: true,
      range: true,
      tolerant: true,
      jsx: isJSX || isTS,
      // Tell the parser what to expect
      ...(isTS ? {} : {})
    });

    return { filePath, ast };
  } catch (err: any) {
    // Try again without strict mode on parse error
    try {
      const ast = parse(source, {
        loc: true,
        range: true,
        tolerant: true,
        jsx: true
      });
      return { filePath, ast };
    } catch {
      return {
        filePath,
        ast: null,
        error: err?.message || 'Parse error'
      };
    }
  }
}

export function traverseAST(
  ast: TSESTree.Program,
  visitors: Partial<{
    CallExpression: (node: TSESTree.CallExpression) => void;
    NewExpression: (node: TSESTree.NewExpression) => void;
    ImportDeclaration: (node: TSESTree.ImportDeclaration) => void;
    VariableDeclarator: (node: TSESTree.VariableDeclarator) => void;
    Property: (node: TSESTree.Property) => void;
    AssignmentExpression: (node: TSESTree.AssignmentExpression) => void;
  }>
): void {
  simpleTraverse(ast, {
    enter(node) {
      switch (node.type) {
        case 'CallExpression':
          visitors.CallExpression?.(node as TSESTree.CallExpression);
          break;
        case 'NewExpression':
          visitors.NewExpression?.(node as TSESTree.NewExpression);
          break;
        case 'ImportDeclaration':
          visitors.ImportDeclaration?.(node as TSESTree.ImportDeclaration);
          break;
        case 'VariableDeclarator':
          visitors.VariableDeclarator?.(node as TSESTree.VariableDeclarator);
          break;
        case 'Property':
          visitors.Property?.(node as TSESTree.Property);
          break;
        case 'AssignmentExpression':
          visitors.AssignmentExpression?.(node as TSESTree.AssignmentExpression);
          break;
      }
    }
  });
}

// Helper: extract string literal value from a node
export function getStringValue(node: TSESTree.Node | null | undefined): string | null {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  if (node.type === 'TemplateLiteral' && node.quasis.length === 1) {
    return node.quasis[0].value.raw;
  }
  return null;
}

// Helper: extract number literal value from a node
export function getNumberValue(node: TSESTree.Node | null | undefined): number | null {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'number') {
    return node.value;
  }
  return null;
}

// Helper: get source snippet around a line
export function getSnippet(source: string, line: number, context: number = 1): string {
  const lines = source.split('\n');
  const start = Math.max(0, line - 1 - context);
  const end = Math.min(lines.length, line + context);
  return lines.slice(start, end).join('\n').trim();
}

// Helper: check if a member expression matches object.method pattern
export function isMemberCall(
  node: TSESTree.CallExpression,
  objectName: string | string[],
  methodName: string | string[]
): boolean {
  if (node.callee.type !== 'MemberExpression') return false;

  const obj = node.callee.object;
  const prop = node.callee.property;

  const objNames = Array.isArray(objectName) ? objectName : [objectName];
  const methNames = Array.isArray(methodName) ? methodName : [methodName];

  const objMatch =
    (obj.type === 'Identifier' && objNames.includes(obj.name)) ||
    (obj.type === 'MemberExpression' &&
      obj.property.type === 'Identifier' &&
      objNames.includes(obj.property.name));

  const propMatch =
    prop.type === 'Identifier' && methNames.includes(prop.name);

  return objMatch && propMatch;
}