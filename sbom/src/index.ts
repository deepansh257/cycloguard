import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

type Language = "node" | "python" | "java" | "csharp";

type Args = {
  source: string;
  output: string;
  threshold: "critical" | "high";
  branch?: string;
  workdir?: string;
  fsScan: boolean;
  secretScan: boolean;
  misconfigScan: boolean;
};

type ProjectTarget = {
  language: Language;
  projectPath: string;
  id: string;
  framework?: "react" | "angular";
};

function parseArgs(argv: string[]): Args {
  const map = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      map.set(key, "true");
    } else {
      map.set(key, next);
      i += 1;
    }
  }

  const source = map.get("source") || "";
  if (!source) {
    throw new Error("Missing required argument: --source <github-url-or-local-path>");
  }

  return {
    source,
    output: map.get("output") || path.resolve("sbom-output"),
    threshold: (map.get("threshold") as "critical" | "high") || "high",
    branch: map.get("branch"),
    workdir: map.get("workdir"),
    fsScan: map.get("fs-scan") !== "false",
    secretScan: map.get("secret-scan") === "true",
    misconfigScan: map.get("misconfig-scan") === "true"
  };
}

function run(command: string, cwd?: string): void {
  console.log(`\n$ ${command}`);
  execSync(command, {
    cwd,
    stdio: "inherit",
    env: process.env
  });
}

function commandExists(command: string): boolean {
  try {
    const checkCmd = process.platform === "win32" ? `where ${command}` : `command -v ${command}`;
    execSync(checkCmd, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function findWindowsTrivyBinary(): string | null {
  const localAppData = process.env.LOCALAPPDATA || "";
  const userProfile = process.env.USERPROFILE || "";
  const candidates = [
    path.join(localAppData, "Microsoft", "WinGet", "Links", "trivy.exe"),
    path.join(userProfile, "scoop", "shims", "trivy.exe")
  ];

  for (const c of candidates) {
    if (c && fs.existsSync(c)) return c;
  }

  const wingetPackagesRoot = path.join(localAppData, "Microsoft", "WinGet", "Packages");
  if (fs.existsSync(wingetPackagesRoot)) {
    const stack = [wingetPackagesRoot];
    while (stack.length > 0) {
      const curr = stack.pop()!;
      let entries: fs.Dirent[] = [];
      try {
        entries = fs.readdirSync(curr, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const entry of entries) {
        const full = path.join(curr, entry.name);
        if (entry.isDirectory()) {
          stack.push(full);
        } else if (entry.isFile() && entry.name.toLowerCase() === "trivy.exe") {
          return full;
        }
      }
    }
  }

  return null;
}

function ensureWindowsTrivyInPathIfPresent(): boolean {
  const trivyPath = findWindowsTrivyBinary();
  if (!trivyPath) return false;
  const trivyDir = path.dirname(trivyPath);
  const currPath = process.env.PATH || "";
  if (!currPath.toLowerCase().includes(trivyDir.toLowerCase())) {
    process.env.PATH = `${trivyDir};${currPath}`;
  }
  return true;
}

function ensureDir(p: string): void {
  fs.mkdirSync(p, { recursive: true });
}

function isGithubUrl(source: string): boolean {
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

function outputSlugFromSource(source: string, branch?: string): string {
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

function acquireSource(args: Args): { repoRoot: string; cleanup?: () => void } {
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
  const cacheBase = args.workdir
    ? path.resolve(args.workdir)
    : defaultCacheBase;
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

function detectProjects(repoRoot: string): ProjectTarget[] {
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

function groupByLanguage(targets: ProjectTarget[]): Record<Language, ProjectTarget[]> {
  return {
    node: targets.filter((t) => t.language === "node"),
    python: targets.filter((t) => t.language === "python"),
    java: targets.filter((t) => t.language === "java"),
    csharp: targets.filter((t) => t.language === "csharp")
  };
}

function writeJson(filePath: string, data: unknown): void {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function generateSbomForTarget(target: ProjectTarget, outDir: string): string {
  const langDir = path.join(outDir, "sbom", target.language);
  ensureDir(langDir);

  const outFile = path.join(langDir, `${target.id}-cyclonedx.json`);

  if (target.language === "python") {
    const req = path.join(target.projectPath, "requirements.txt");
    if (!fs.existsSync(req)) {
      throw new Error(`Python project missing requirements.txt: ${target.projectPath}`);
    }
    run(`cyclonedx-py requirements "${req}" -o "${outFile}" --of JSON --sv 1.5`);
  } else {
    const cdxTypeMap: Record<Exclude<Language, "python">, string> = {
      node: "nodejs",
      java: "java",
      csharp: "dotnet"
    };
    const cdxType = cdxTypeMap[target.language as Exclude<Language, "python">];
    try {
      run(`npx @cyclonedx/cdxgen -t ${cdxType} --spec-version 1.5 -o "${outFile}" "${target.projectPath}"`);
    } catch {
      // Fallback to generic mode for repos that don't fit strict cdxgen type assumptions.
      run(`npx @cyclonedx/cdxgen --spec-version 1.5 -o "${outFile}" "${target.projectPath}"`);
    }
  }

  return outFile;
}

function scanSbom(sbomFile: string, outFile: string, severity: string): void {
  try {
    run(`trivy sbom "${sbomFile}" --format json --output "${outFile}" --severity "${severity}" --ignore-unfixed`);
  } catch {
    writeJson(outFile, {});
  }
}

function mergeReports(scanFiles: string[], outFile: string): void {
  const merged = { Results: [] as any[] };
  for (const f of scanFiles) {
    if (!fs.existsSync(f)) continue;
    const report = readJson(f);
    const results = report?.Results || [];
    merged.Results.push(...results);
  }
  writeJson(outFile, merged);
}

function maybeFsScan(repoRoot: string, outDir: string, args: Args): { fsJson: string; sarif: string } {
  const fsJson = path.join(outDir, "trivy-fs.json");
  const sarif = path.join(outDir, "trivy-results.sarif");
  if (!args.fsScan) {
    writeJson(fsJson, {});
    writeJson(sarif, { version: "2.1.0", runs: [] });
    return { fsJson, sarif };
  }

  try {
    run(`trivy fs "${repoRoot}" --format json --output "${fsJson}"`);
  } catch {
    writeJson(fsJson, {});
  }

  const scanners = ["vuln"];
  if (args.secretScan) scanners.push("secret");
  if (args.misconfigScan) scanners.push("misconfig");

  try {
    run(`trivy fs "${repoRoot}" --scanners "${scanners.join(",")}" --format sarif --output "${sarif}"`);
  } catch {
    writeJson(sarif, { version: "2.1.0", runs: [] });
  }

  return { fsJson, sarif };
}

function ensureTools(): void {
  // cdxgen
  if (!commandExists("cdxgen")) {
    run("npm install -g @cyclonedx/cdxgen");
  }

  // cyclonedx-py
  if (!commandExists("cyclonedx-py")) {
    run("pip install cyclonedx-bom");
  }

  // trivy
  if (!commandExists("trivy")) {
    console.log("\nTrivy not found. Attempting automatic installation...");
    if (process.platform === "win32") {
      if (commandExists("winget")) {
        run("winget install AquaSecurity.Trivy --accept-package-agreements --accept-source-agreements");
        // winget often updates PATH for future shells only; inject discovered binary for current process.
        ensureWindowsTrivyInPathIfPresent();
      } else if (commandExists("choco")) {
        run("choco install trivy -y");
        ensureWindowsTrivyInPathIfPresent();
      } else {
        throw new Error(
          "Trivy not found and no supported installer detected on Windows.\n" +
          "Install Trivy manually: https://github.com/aquasecurity/trivy/releases"
        );
      }
    } else if (process.platform === "darwin") {
      if (commandExists("brew")) {
        run("brew install trivy");
      } else {
        throw new Error(
          "Trivy not found and Homebrew is not available.\n" +
          "Install Trivy manually: https://github.com/aquasecurity/trivy/releases"
        );
      }
    } else {
      // Linux
      run("sudo apt-get update");
      run("sudo apt-get install -y wget gnupg lsb-release");
      run("wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -");
      run("echo \"deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main\" | sudo tee /etc/apt/sources.list.d/trivy.list");
      run("sudo apt-get update");
      run("sudo apt-get install -y trivy");
    }
  }

  if (process.platform === "win32" && !commandExists("trivy")) {
    ensureWindowsTrivyInPathIfPresent();
  }

  run("trivy --version");
}

function runGateParser(outDir: string, threshold: "critical" | "high"): void {
  const mergedFile = path.join(outDir, "trivy-merged.json");
  const gateFile = path.join(outDir, "gate-result.json");
  const parserScript = path.resolve(__dirname, "..", "scripts", "parse_trivy_report.js");
  run(`node "${parserScript}" --report-dir "${outDir}" --threshold "${threshold}" --output "${gateFile}"`);
  const gate = readJson(gateFile);
  console.log("\nGate summary:");
  console.log(JSON.stringify(gate, null, 2));
  if (!fs.existsSync(mergedFile)) {
    throw new Error(`Expected merged report not found: ${mergedFile}`);
  }
}

function createTrivyMerged(outDir: string, byLangMerged: Record<Language, string>, fsJson: string): void {
  const payload = {
    scan_prefix: "trivy",
    reports: {
      node: readJson(byLangMerged.node),
      java: readJson(byLangMerged.java),
      python: readJson(byLangMerged.python),
      csharp: readJson(byLangMerged.csharp),
      filesystem: readJson(fsJson)
    }
  };
  writeJson(path.join(outDir, "trivy-merged.json"), payload);
}

function buildLanguageReports(
  repoRoot: string,
  outDir: string,
  targetsByLang: Record<Language, ProjectTarget[]>,
  threshold: "critical" | "high",
  args: Args
): void {
  const severity = threshold === "critical" ? "CRITICAL" : "HIGH,CRITICAL";

  const mergedByLang: Record<Language, string> = {
    node: path.join(outDir, "trivy-node.json"),
    java: path.join(outDir, "trivy-java.json"),
    python: path.join(outDir, "trivy-python.json"),
    csharp: path.join(outDir, "trivy-csharp.json")
  };

  for (const lang of ["node", "java", "python", "csharp"] as Language[]) {
    const scanFiles: string[] = [];

    for (const target of targetsByLang[lang]) {
      const sbomFile = generateSbomForTarget(target, outDir);
      const scanFile = path.join(outDir, `${lang}-${target.id}-trivy.json`);
      scanSbom(sbomFile, scanFile, severity);
      scanFiles.push(scanFile);
    }

    if (scanFiles.length === 0) {
      writeJson(mergedByLang[lang], {});
      continue;
    }

    mergeReports(scanFiles, mergedByLang[lang]);
  }

  const fsResult = maybeFsScan(repoRoot, outDir, args);
  createTrivyMerged(outDir, mergedByLang, fsResult.fsJson);
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  // Keep each scan isolated by source repo/branch to avoid report mixing.
  const outputDir = path.join(path.resolve(args.output), outputSlugFromSource(args.source, args.branch));
  ensureDir(outputDir);

  const { repoRoot, cleanup } = acquireSource(args);
  try {
    console.log(`Using source at: ${repoRoot}`);
    ensureTools();

    const targets = detectProjects(repoRoot);
    if (targets.length === 0) {
      throw new Error("No supported projects detected. Expected package.json, requirements.txt/pyproject.toml, pom.xml or build.gradle.");
    }

    const detectedFile = path.join(outputDir, "detected-projects.json");
    writeJson(detectedFile, {
      source: args.source,
      repoRoot,
      detected: targets
    });

    const targetsByLang = groupByLanguage(targets);
    buildLanguageReports(repoRoot, outputDir, targetsByLang, args.threshold, args);
    runGateParser(outputDir, args.threshold);

    console.log(`\nDone. Reports available at: ${outputDir}`);
  } finally {
    if (cleanup) cleanup();
  }
}

main();
