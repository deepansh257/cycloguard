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

function hasPinnedPythonRequirements(filePath: string): boolean {
  if (!fs.existsSync(filePath)) return false;
  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));

  if (lines.length === 0) return false;

  return lines.every((line) => {
    if (line.startsWith("-r ") || line.startsWith("--requirement ")) return false;
    if (line.startsWith("-e ") || line.startsWith("--editable ")) return false;
    return line.includes("==");
  });
}

function existingFiles(projectPath: string, candidates: string[]): string[] {
  return candidates.filter((file) => fs.existsSync(path.join(projectPath, file)));
}

function hasDynamicJavaVersions(projectPath: string): boolean {
  const buildFiles = existingFiles(projectPath, ["pom.xml", "build.gradle", "build.gradle.kts"]);
  const dynamicVersionPatterns = [
    /\bSNAPSHOT\b/u,
    /\bLATEST\b/u,
    /\bRELEASE\b/u,
    /\[[^,\]]+,[^\]]+\]/u,
    /\([^)]+,[^)]+\)/u,
    /version\s*[:=]\s*['"][^'"]*[+*][^'"]*['"]/u
  ];

  return buildFiles.some((file) => {
    const content = fs.readFileSync(path.join(projectPath, file), "utf-8");
    return dynamicVersionPatterns.some((pattern) => pattern.test(content));
  });
}

function resolveLockfileStatus(language: Language, projectPath: string): {
  sourceOfTruthType: "lockfile" | "pinned-manifest" | "manifest" | "build-file";
  sourceOfTruthFiles: string[];
  supportingFiles: string[];
  lockfilePresent: boolean;
  lockfileFiles: string[];
  reproducibility: "deterministic" | "non-deterministic";
  lockfileWarning?: string;
} {
  const fileCandidates: Record<Language, string[]> = {
    node: ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
    python: ["poetry.lock", "Pipfile.lock", "uv.lock", "requirements.lock"],
    java: ["gradle.lockfile", "versions.lock"],
    csharp: ["packages.lock.json", "paket.lock"]
  };

  const foundFiles = existingFiles(projectPath, fileCandidates[language]);
  const supportingFiles = new Set<string>();

  const sourceOfTruth = (() => {
    if (language === "node") {
      if (foundFiles.length > 0) {
        if (fs.existsSync(path.join(projectPath, "package.json"))) supportingFiles.add("package.json");
        return { type: "lockfile" as const, files: foundFiles };
      }
      return { type: "manifest" as const, files: ["package.json"] };
    }

    if (language === "python") {
      const requirementsPath = path.join(projectPath, "requirements.txt");
      if (foundFiles.length > 0) {
        if (fs.existsSync(requirementsPath)) supportingFiles.add("requirements.txt");
        if (fs.existsSync(path.join(projectPath, "pyproject.toml"))) supportingFiles.add("pyproject.toml");
        return { type: "lockfile" as const, files: foundFiles };
      }
      if (hasPinnedPythonRequirements(requirementsPath)) {
        if (fs.existsSync(path.join(projectPath, "pyproject.toml"))) supportingFiles.add("pyproject.toml");
        return { type: "pinned-manifest" as const, files: ["requirements.txt"] };
      }
      if (fs.existsSync(requirementsPath)) {
        if (fs.existsSync(path.join(projectPath, "pyproject.toml"))) supportingFiles.add("pyproject.toml");
        return { type: "manifest" as const, files: ["requirements.txt"] };
      }
      if (fs.existsSync(path.join(projectPath, "pyproject.toml"))) {
        return { type: "manifest" as const, files: ["pyproject.toml"] };
      }
    }

    if (language === "java") {
      if (foundFiles.length > 0) {
        existingFiles(projectPath, ["pom.xml", "build.gradle", "build.gradle.kts"]).forEach((file) => supportingFiles.add(file));
        return { type: "lockfile" as const, files: foundFiles };
      }
      const buildFiles = existingFiles(projectPath, ["pom.xml", "build.gradle", "build.gradle.kts"]);
      return { type: "build-file" as const, files: buildFiles };
    }

    if (language === "csharp") {
      if (foundFiles.length > 0) {
        fs.readdirSync(projectPath)
          .filter((file) => file.toLowerCase().endsWith(".csproj") || file.toLowerCase().endsWith(".sln") || file === "Directory.Packages.props")
          .forEach((file) => supportingFiles.add(file));
        return { type: "lockfile" as const, files: foundFiles };
      }
      const projectFiles = fs.readdirSync(projectPath)
        .filter((file) => file.toLowerCase().endsWith(".csproj") || file.toLowerCase().endsWith(".sln") || file === "Directory.Packages.props");
      return { type: "build-file" as const, files: projectFiles };
    }

    return { type: "manifest" as const, files: [] };
  })();

  if (language === "python" && foundFiles.length === 0) {
    const requirementsPath = path.join(projectPath, "requirements.txt");
    if (hasPinnedPythonRequirements(requirementsPath)) {
      foundFiles.push("requirements.txt");
    }
  }

  const lockfilePresent = foundFiles.length > 0;
  const hasJavaDynamicVersions = language === "java" && !lockfilePresent && hasDynamicJavaVersions(projectPath);
  const reproducibility = lockfilePresent ? "deterministic" : "non-deterministic";

  const warningByLanguage: Record<Language, string> = {
    node: "Generating a Node.js SBOM without a lockfile is non-deterministic. Commit package-lock.json, yarn.lock, pnpm-lock.yaml, or an equivalent lockfile.",
    python: "Generating a Python SBOM without a lockfile or fully pinned requirements is non-deterministic. Prefer poetry.lock, Pipfile.lock, uv.lock, requirements.lock, or fully pinned requirements.txt entries.",
    java: hasJavaDynamicVersions
      ? "Java dependency locking was not detected and dynamic versions were found in the build files. Reproducibility may vary significantly between scans."
      : "Java dependency locking was not detected for this project. Reproducibility may vary if dependency versions are dynamic or resolved differently over time.",
    csharp: "C# dependency locking was not detected for this project. Reproducibility may vary without packages.lock.json or an equivalent lock artifact."
  };

  return {
    sourceOfTruthType: sourceOfTruth.type,
    sourceOfTruthFiles: sourceOfTruth.files,
    supportingFiles: [...supportingFiles].filter((file) => !sourceOfTruth.files.includes(file)),
    lockfilePresent,
    lockfileFiles: foundFiles,
    reproducibility,
    lockfileWarning: lockfilePresent ? undefined : warningByLanguage[language]
  };
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
      const lockfileStatus = resolveLockfileStatus(language, projectPath);
      targets.push({
        language,
        projectPath,
        id: relSafe(repoRoot, projectPath).replace(/[\\/]/g, "_"),
        framework: language === "node" ? frameworkByDir.get(projectPath) : undefined,
        ...lockfileStatus
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
