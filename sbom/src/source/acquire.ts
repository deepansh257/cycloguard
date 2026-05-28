/**
 * Source acquisition module.
 * Resolves local or GitHub sources and manages clone/pull cache behavior.
 */
import { execSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ensureDir } from "../core/fs";
import { run } from "../core/shell";
import { Args } from "../types";

export function isGithubUrl(source: string): boolean {
  return source.startsWith("https://github.com/") || source.startsWith("git@github.com:");
}

function cacheSlug(source: string): string {
  return source
    .replace(/^https?:\/\//, "")
    .replace(/^git@/, "")
    .replace(/[:/]+/g, "_")
    .replace(/\.git$/, "")
    .toLowerCase();
}

export function outputSlugFromSource(source: string, branch?: string): string {
  let base = source;
  if (isGithubUrl(source)) {
    base = source
      .replace(/^https?:\/\/github\.com\//, "")
      .replace(/^git@github\.com:/, "")
      .replace(/\.git$/, "")
      .split("/")
      .slice(-1)[0] || "repo";
  } else {
    base = path.basename(path.resolve(source)) || "local-repo";
  }

  const safeBase = base.replace(/[^a-zA-Z0-9._-]/g, "_");
  const safeBranch = (branch || "default").replace(/[^a-zA-Z0-9._-]/g, "_");
  const d = new Date();
  const pad = (n: number) => n.toString().padStart(2, "0");
  const timestamp =
    `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-` +
    `${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  return `${safeBase}__${safeBranch}__${timestamp}`;
}

function branchExistsLocally(repoDir: string, branch: string): boolean {
  try {
    execSync(`git show-ref --verify --quiet "refs/heads/${branch}"`, { cwd: repoDir, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export function acquireSource(args: Args): { repoRoot: string; cleanup?: () => void } {
  if (!isGithubUrl(args.source)) {
    const local = path.resolve(args.source);
    if (!fs.existsSync(local)) {
      throw new Error(`Local source path not found: ${local}`);
    }
    return { repoRoot: local };
  }

  const defaultCacheBase = process.platform === "win32"
    ? "C:\\cg-sbom-cache"
    : path.join(os.tmpdir(), "cycloguard-sbom-cache");
  const cacheBase = args.workdir ? path.resolve(args.workdir) : defaultCacheBase;
  ensureDir(cacheBase);
  const repoDir = path.join(cacheBase, cacheSlug(args.source));
  const requestedBranch = args.branch;

  if (!fs.existsSync(path.join(repoDir, ".git"))) {
    const branchArg = requestedBranch ? `--branch ${requestedBranch}` : "";
    run(`git clone -c core.longpaths=true --depth 1 ${branchArg} ${args.source} "${repoDir}"`);
    return { repoRoot: repoDir };
  }

  run("git config core.longpaths true", repoDir);
  run("git fetch --all --prune", repoDir);
  if (requestedBranch) {
    if (branchExistsLocally(repoDir, requestedBranch)) {
      run(`git checkout ${requestedBranch}`, repoDir);
    } else {
      run(`git checkout -b ${requestedBranch} --track origin/${requestedBranch}`, repoDir);
    }
    run(`git pull origin ${requestedBranch}`, repoDir);
  } else {
    run("git pull", repoDir);
  }

  return { repoRoot: repoDir };
}
