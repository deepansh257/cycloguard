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

export function isGitHubUrl(input: string): boolean {
  return (
    input.startsWith('https://github.com') ||
    input.startsWith('http://github.com') ||
    input.startsWith('git@github.com') ||
    input.startsWith('https://gitlab.com') ||
    input.startsWith('https://bitbucket.org')
  );
}

export function extractProjectName(url: string): string {
  // https://github.com/org/repo.git -> repo
  const match = url.match(/\/([^/]+?)(\.git)?$/);
  return match ? match[1] : 'unknown-project';
}

export async function cloneRepository(
  url: string,
  branch?: string,
  verbose: boolean = false
): Promise<GitSourceResult> {
  const projectName = extractProjectName(url);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `cbom-${projectName}-`));

  if (verbose) {
    console.log(`  Cloning ${url} into ${tempDir}...`);
  }

  const git = simpleGit();

  const cloneOptions: string[] = ['--depth', '1'];
  if (branch) {
    cloneOptions.push('--branch', branch);
  }

  try {
    await git.clone(url, tempDir, cloneOptions);
  } catch (err: any) {
    // If branch not found, try without branch
    if (branch && err?.message?.includes('not found')) {
      if (verbose) {
        console.log(`  Branch '${branch}' not found, cloning default branch...`);
      }
      await git.clone(url, tempDir, ['--depth', '1']);
    } else {
      throw err;
    }
  }

  return {
    localPath: tempDir,
    projectName,
    isTemp: true,
    cleanup: () => {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
  };
}

export function resolveLocalSource(inputPath: string): GitSourceResult {
  const resolved = path.resolve(inputPath);

  if (!fs.existsSync(resolved)) {
    throw new Error(`Path does not exist: ${resolved}`);
  }

  return {
    localPath: resolved,
    projectName: path.basename(resolved),
    isTemp: false,
    cleanup: () => {} // nothing to clean up for local paths
  };
}