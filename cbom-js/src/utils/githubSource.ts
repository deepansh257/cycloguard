import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import simpleGit from 'simple-git';

export interface GitSourceResult {
  localPath: string;
  projectName: string;
  cleanup: () => void;
  isTemp: boolean;
}

// Cache lives at ~/.cbom-js/cache/<org>__<repo>/
const CACHE_ROOT = path.join(os.homedir(), '.cbom-js', 'cache');

function getCacheDir(url: string, branch?: string): string {
  // Normalise URL to a safe directory name
  // https://github.com/org/repo.git  →  github.com__org__repo[__branch]
  const safe = url
    .replace(/https?:\/\//, '')
    .replace(/git@/, '')
    .replace(/:/g, '__')
    .replace(/\//g, '__')
    .replace(/\.git$/, '');
  const suffix = branch ? `__${branch}` : '';
  return path.join(CACHE_ROOT, `${safe}${suffix}`);
}

function isCachedRepoValid(cacheDir: string): boolean {
  // A valid cache must have a .git folder inside
  return fs.existsSync(path.join(cacheDir, '.git'));
}

export function isGitHubUrl(input: string): boolean {
  return (
    input.startsWith('https://github.com') ||
    input.startsWith('http://github.com')  ||
    input.startsWith('git@github.com')     ||
    input.startsWith('https://gitlab.com') ||
    input.startsWith('https://bitbucket.org')
  );
}

export function extractProjectName(url: string): string {
  const match = url.match(/\/([^/]+?)(\.git)?$/);
  return match ? match[1] : 'unknown-project';
}

export async function cloneRepository(
  url: string,
  branch?: string,
  verbose: boolean = false
): Promise<GitSourceResult> {
  const projectName = extractProjectName(url);
  const cacheDir    = getCacheDir(url, branch);

  // ── Already cached ────────────────────────────────────────────────────────
  if (isCachedRepoValid(cacheDir)) {
    if (verbose) {
      console.log(`  Using cached clone at ${cacheDir} (skipping network clone)`);
    }
    return {
      localPath:   cacheDir,
      projectName,
      isTemp:      false,   // don't delete the cache on cleanup
      cleanup:     () => {},
    };
  }

  // ── First time — clone into cache ─────────────────────────────────────────
  fs.mkdirSync(cacheDir, { recursive: true });

  if (verbose) {
    console.log(`  Cloning ${url} into cache at ${cacheDir}...`);
  }

  const git = simpleGit();
  const cloneOptions: string[] = ['--depth', '1'];
  if (branch) cloneOptions.push('--branch', branch);

  try {
    await git.clone(url, cacheDir, cloneOptions);
  } catch (err: any) {
    // Branch not found — retry without branch specifier
    if (branch && err?.message?.includes('not found')) {
      if (verbose) {
        console.log(`  Branch '${branch}' not found, cloning default branch...`);
      }
      await git.clone(url, cacheDir, ['--depth', '1']);
    } else {
      // Clean up the empty cache dir so next run retries fresh
      fs.rmSync(cacheDir, { recursive: true, force: true });
      throw err;
    }
  }

  return {
    localPath:   cacheDir,
    projectName,
    isTemp:      false,   // cache is persistent — never auto-delete
    cleanup:     () => {},
  };
}

export function resolveLocalSource(inputPath: string): GitSourceResult {
  const resolved = path.resolve(inputPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Path does not exist: ${resolved}`);
  }
  return {
    localPath:   resolved,
    projectName: path.basename(resolved),
    isTemp:      false,
    cleanup:     () => {},
  };
}

// ── Cache management helpers (optional, exposed for a future --clear-cache flag)
export function clearRepoCache(url: string, branch?: string): void {
  const cacheDir = getCacheDir(url, branch);
  if (fs.existsSync(cacheDir)) {
    fs.rmSync(cacheDir, { recursive: true, force: true });
  }
}

export function clearAllCache(): void {
  if (fs.existsSync(CACHE_ROOT)) {
    fs.rmSync(CACHE_ROOT, { recursive: true, force: true });
  }
}