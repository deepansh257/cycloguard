import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

const DEFAULT_INCLUDE = [
  '**/*.js',
  '**/*.ts',
  '**/*.jsx',
  '**/*.tsx',
  '**/*.mjs',
  '**/*.cjs'
];

const DEFAULT_EXCLUDE = [
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
  '**/*.spec.ts'
];

export async function findFiles(
  rootDir: string,
  include: string[] = DEFAULT_INCLUDE,
  exclude: string[] = DEFAULT_EXCLUDE
): Promise<string[]> {
  const files: string[] = [];

  for (const pattern of include) {
    const matches = await glob(pattern, {
      cwd: rootDir,
      ignore: exclude,
      absolute: true,
      nodir: true
    });
    files.push(...matches);
  }

  // Deduplicate
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