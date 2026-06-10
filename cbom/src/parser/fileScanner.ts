/**
 * src/parser/fileScanner.ts
 *
 * Discovers source files under a root directory using glob patterns.
 * Supports JS/TS, Java, Python, and C# out of the box.
 */

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

// ─── Default patterns ─────────────────────────────────────────────────────────

export const DEFAULT_INCLUDE: string[] = [
  // JavaScript / TypeScript
  '**/*.js',
  '**/*.ts',
  '**/*.jsx',
  '**/*.tsx',
  '**/*.mjs',
  '**/*.cjs',
  // Java
  '**/*.java',
  // Python
  '**/*.py',
  // C#
  '**/*.cs',
];

export const DEFAULT_EXCLUDE: string[] = [
  // JS/TS build artefacts
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.bundle.js',
  '**/*.test.js',
  '**/*.spec.js',
  '**/*.test.ts',
  '**/*.spec.ts',
  // Java build artefacts
  '**/target/**',
  '**/out/**',
  // Python build artefacts
  '**/__pycache__/**',
  '**/*.pyc',
  '**/.venv/**',
  '**/venv/**',
  '**/site-packages/**',
  // C# build artefacts
  '**/bin/**',
  '**/obj/**',
  '**/*.Designer.cs',       // auto-generated WinForms/WPF code
  '**/*.g.cs',              // Roslyn source generators
  '**/*.AssemblyInfo.cs',   // auto-generated assembly info
];

// ─── Public API ───────────────────────────────────────────────────────────────

export async function findFiles(
  rootDir:  string,
  include:  string[] = DEFAULT_INCLUDE,
  exclude?: string[]
): Promise<string[]> {
  const effectiveExclude = exclude?.length ? exclude : DEFAULT_EXCLUDE;
  const files: string[] = [];

  for (const pattern of include) {
    const matches = await glob(pattern, {
      cwd:      rootDir,
      ignore:   effectiveExclude,
      absolute: true,
      nodir:    true,
    });
    files.push(...matches);
  }

  // Deduplicate and sort for deterministic output
  return [...new Set(files)].sort();
}

export function readFile(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

export function getRelativePath(filePath: string, rootDir: string): string {
  return path.relative(rootDir, filePath);
}