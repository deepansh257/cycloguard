import * as fs from 'fs';
import * as path from 'path';

export type TechStack = 'java' | 'javascript' | 'typescript' | 'python' | 'csharp';

/**
 * Detects languages/frameworks present in a local repo by looking at
 * marker files and extensions. Returns an array of detected stacks.
 */
export function detectTechStack(localPath: string): TechStack[] {
  const detected = new Set<TechStack>();

  const markers: Array<[string, TechStack]> = [
    // Java
    ['pom.xml',        'java'],
    ['build.gradle',   'java'],
    ['build.gradle.kts', 'java'],
    // JavaScript / TypeScript
    ['package.json',   'javascript'],
    // Python
    ['requirements.txt', 'python'],
    ['setup.py',         'python'],
    ['pyproject.toml',   'python'],
    ['Pipfile',          'python'],
    // C#
    ['.csproj',        'csharp'],   // checked by extension below
    ['*.sln',          'csharp'],   // checked by extension below
  ];

  for (const [marker, stack] of markers) {
    if (marker.startsWith('*')) continue; // handled below
    if (fs.existsSync(path.join(localPath, marker))) {
      detected.add(stack);
    }
  }

  // Scan top-level for .csproj / .sln / .ts files
  try {
    const entries = fs.readdirSync(localPath);
    for (const entry of entries) {
      if (entry.endsWith('.csproj') || entry.endsWith('.sln')) detected.add('csharp');
      if (entry.endsWith('.ts'))                                detected.add('typescript');
    }
  } catch { /* ignore */ }

  // If package.json exists AND .ts files found, mark typescript too
  if (detected.has('javascript')) {
    if (hasExtensionRecursive(localPath, '.ts', 3)) {
      detected.add('typescript');
    }
  }

  return Array.from(detected);
}

/** Recursively checks up to `maxDepth` levels for any file with the given extension. */
function hasExtensionRecursive(dir: string, ext: string, maxDepth: number): boolean {
  if (maxDepth === 0) return false;
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith(ext)) return true;
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
        if (hasExtensionRecursive(path.join(dir, entry.name), ext, maxDepth - 1)) return true;
      }
    }
  } catch { /* ignore permission errors */ }
  return false;
}
