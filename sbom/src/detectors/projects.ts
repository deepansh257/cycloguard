/**
 * Project detection module.
 * Scans repository files to infer language stacks and project targets.
 */
import * as fs from "fs";
import * as path from "path";
import { Language, ProjectTarget } from "../types";

function relSafe(root: string, p: string): string {
  const rel = path.relative(root, p);
  return rel || "root";
}

function walk(root: string): string[] {
  const files: string[] = [];
  const skipDirs = new Set([".git", "node_modules", "target", "build", ".venv", "venv", "dist", "bin", ".gradle"]);

  function dfs(curr: string): void {
    const entries = fs.readdirSync(curr, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(curr, entry.name);
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        dfs(full);
      } else {
        files.push(full);
      }
    }
  }

  dfs(root);
  return files;
}

export function detectProjects(repoRoot: string): ProjectTarget[] {
  const files = walk(repoRoot);
  const byDir = new Map<string, Set<Language>>();
  const frameworkByDir = new Map<string, "react" | "angular" | undefined>();

  for (const f of files) {
    const name = path.basename(f).toLowerCase();
    const dir = path.dirname(f);
    const add = (lang: Language) => {
      if (!byDir.has(dir)) byDir.set(dir, new Set());
      byDir.get(dir)!.add(lang);
    };

    if (name === "package.json") {
      add("node");
      try {
        const pkg = JSON.parse(fs.readFileSync(f, "utf-8"));
        const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
        if (deps.react || deps["react-dom"]) frameworkByDir.set(dir, "react");
        if (deps["@angular/core"] || deps["@angular/cli"]) frameworkByDir.set(dir, "angular");
      } catch {
        // best-effort framework detection
      }
    }
    if (name === "requirements.txt" || name === "pyproject.toml") add("python");
    if (name === "pom.xml" || name === "build.gradle" || name === "build.gradle.kts") add("java");
    if (name.endsWith(".csproj") || name.endsWith(".sln")) add("csharp");
  }

  const targets: ProjectTarget[] = [];
  for (const [projectPath, langs] of byDir.entries()) {
    for (const language of langs) {
      targets.push({
        language,
        projectPath,
        id: relSafe(repoRoot, projectPath).replace(/[\\/]/g, "_"),
        framework: language === "node" ? frameworkByDir.get(projectPath) : undefined
      });
    }
  }

  return targets;
}

export function groupByLanguage(targets: ProjectTarget[]): Record<Language, ProjectTarget[]> {
  return {
    node: targets.filter((t) => t.language === "node"),
    python: targets.filter((t) => t.language === "python"),
    java: targets.filter((t) => t.language === "java"),
    csharp: targets.filter((t) => t.language === "csharp")
  };
}
