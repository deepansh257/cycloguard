/**
 * Tool bootstrap module.
 * Ensures required scanner dependencies exist and auto-installs when possible.
 */
import * as fs from "fs";
import * as path from "path";
import pino from "pino";
import { commandExists, run, runCapture } from "../core/shell-command-utils";

const { createAppLogger } = require(path.resolve(__dirname, "..", "..", "..", "common", "logger.js")) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    warn: (message: string, meta?: Record<string, unknown>) => void;
  };
};
const logger = createAppLogger({ pino });
const sbomRoot = path.resolve(__dirname, "..", "..");
const trivyInstallScriptUrl = "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh";
const toolVenvDir = path.join(sbomRoot, ".tool-venv");

function isWindows(): boolean {
  return process.platform === "win32";
}

function isMacOS(): boolean {
  return process.platform === "darwin";
}

function isLinux(): boolean {
  return !isWindows() && !isMacOS();
}

function ensureDirectoryInPath(directory: string): void {
  const currPath = process.env.PATH || "";
  const delimiter = isWindows() ? ";" : ":";
  if (!currPath.toLowerCase().includes(directory.toLowerCase())) {
    process.env.PATH = `${directory}${delimiter}${currPath}`;
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

function addDirectoryToWindowsPath(directory: string): void {
  ensureDirectoryInPath(directory);
}

function canRunShellCommand(command: string): boolean {
  try {
    runCapture(command, { quiet: true });
    return true;
  } catch {
    return false;
  }
}

function hasCycloneDxCommand(directory: string): boolean {
  const files = isWindows()
    ? ["cyclonedx-py.exe", "cyclonedx-py-script.py", "cyclonedx-py"]
    : ["cyclonedx-py"];
  return files.some((file) => fs.existsSync(path.join(directory, file)));
}

function getAvailablePythonCommands(): string[] {
  const candidates = isWindows()
    ? ["py -3", "python", "py"]
    : ["python3", "python"];

  return [...new Set(candidates)].filter((command) => canRunShellCommand(`${command} --version`));
}

function getToolVenvScriptsDirectory(): string {
  return isWindows()
    ? path.join(toolVenvDir, "Scripts")
    : path.join(toolVenvDir, "bin");
}

function getToolVenvPythonCommand(): string {
  const scriptsDir = getToolVenvScriptsDirectory();
  return isWindows()
    ? `"${path.join(scriptsDir, "python.exe")}"`
    : `"${path.join(scriptsDir, "python")}"`;
}

function ensureToolVenvInPathIfPresent(): boolean {
  const scriptsDir = getToolVenvScriptsDirectory();
  if (!fs.existsSync(scriptsDir)) {
    return false;
  }
  ensureDirectoryInPath(scriptsDir);
  return true;
}

function getPythonScriptsDirectory(pythonCommand: string): string | null {
  const script = [
    "import os,site,sysconfig",
    "scripts=sysconfig.get_path('scripts') or ''",
    "user_base=getattr(site,'USER_BASE','') or ''",
    "user_scripts=os.path.join(user_base, 'Scripts' if os.name=='nt' else 'bin') if user_base else ''",
    "print('\\n'.join([scripts, user_scripts]))"
  ].join("; ");

  try {
    const output = runCapture(
      `${pythonCommand} -c "${script.replace(/"/g, '\\"')}"`,
      { quiet: true, displayCommand: `${pythonCommand} -c <resolve-python-scripts-dir>` }
    );

    for (const line of output.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)) {
      if (fs.existsSync(line)) {
        return line;
      }
    }
  } catch {
    return null;
  }

  return null;
}

function findCycloneDxPyDirectory(pythonCommands: string[]): string | null {
  const toolVenvScriptsDir = getToolVenvScriptsDirectory();
  if (fs.existsSync(toolVenvScriptsDir) && hasCycloneDxCommand(toolVenvScriptsDir)) {
    return toolVenvScriptsDir;
  }

  for (const pythonCommand of pythonCommands) {
    const scriptsDir = getPythonScriptsDirectory(pythonCommand);
    if (scriptsDir && hasCycloneDxCommand(scriptsDir)) {
      return scriptsDir;
    }
  }

  return null;
}

function ensureCycloneDxPyInPathIfPresent(pythonCommands: string[]): boolean {
  const scriptsDir = findCycloneDxPyDirectory(pythonCommands);
  if (!scriptsDir) return false;
  if (isWindows()) {
    addDirectoryToWindowsPath(scriptsDir);
  } else {
    ensureDirectoryInPath(scriptsDir);
  }
  return true;
}

function removeToolVenvDirectory(): void {
  if (fs.existsSync(toolVenvDir)) {
    fs.rmSync(toolVenvDir, { recursive: true, force: true });
  }
}

function getPythonMajorMinorVersion(pythonCommand: string): string | null {
  try {
    const output = runCapture(
      `${pythonCommand} -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"` ,
      { quiet: true, displayCommand: `${pythonCommand} -c <python-version>` }
    );
    const version = output.trim();
    return version || null;
  } catch {
    return null;
  }
}

function installLinuxPythonVenvSupport(pythonCommand: string): boolean {
  if (!isLinux() || !commandExists("apt-get") || !commandExists("sudo")) {
    return false;
  }

  run("sudo apt-get update");

  let installed = false;
  try {
    run("sudo apt-get install -y python3-venv");
    installed = true;
  } catch {
    const version = getPythonMajorMinorVersion(pythonCommand);
    if (!version) {
      return false;
    }

    try {
      run(`sudo apt-get install -y python${version}-venv`);
      installed = true;
    } catch {
      return false;
    }
  }

  return installed;
}

function buildPythonVenvSupportError(): string {
  if (isLinux()) {
    return (
      "Unable to create the local Python tool virtual environment because Python venv support is missing.\n" +
      "On Debian/Ubuntu install it with: sudo apt-get install python3-venv\n" +
      "If your distribution uses a versioned package, install python3.x-venv for the active Python version."
    );
  }

  if (isMacOS()) {
    return (
      "Unable to create the local Python tool virtual environment.\n" +
      "Ensure Python 3 is installed with venv support, then rerun CycloGuard."
    );
  }

  return (
    "Unable to create the local Python tool virtual environment.\n" +
    "Ensure Python 3 is installed with venv support, then rerun CycloGuard."
  );
}

function ensurePythonToolVenv(pythonCommands: string[]): void {
  if (ensureToolVenvInPathIfPresent() && hasCycloneDxCommand(getToolVenvScriptsDirectory())) {
    return;
  }

  if (pythonCommands.length === 0) {
    throw new Error(
      "Python 3 was not found. Install Python 3 with venv support to bootstrap cyclonedx-bom."
    );
  }

  if (fs.existsSync(getToolVenvScriptsDirectory())) {
    ensureToolVenvInPathIfPresent();
    return;
  }

  let created = false;
  let attemptedLinuxVenvInstall = false;

  for (const pythonCommand of pythonCommands) {
    removeToolVenvDirectory();

    try {
      run(`${pythonCommand} -m venv "${toolVenvDir}"`, {
        displayCommand: `${pythonCommand} -m venv <sbom>/.tool-venv`
      });
      created = true;
      break;
    } catch {
      removeToolVenvDirectory();

      if (!attemptedLinuxVenvInstall && installLinuxPythonVenvSupport(pythonCommand)) {
        attemptedLinuxVenvInstall = true;
        try {
          run(`${pythonCommand} -m venv "${toolVenvDir}"`, {
            displayCommand: `${pythonCommand} -m venv <sbom>/.tool-venv`
          });
          created = true;
          break;
        } catch {
          removeToolVenvDirectory();
        }
      }
    }
  }

  if (!created) {
    throw new Error(buildPythonVenvSupportError());
  }

  ensureToolVenvInPathIfPresent();
}

function ensurePipAvailableInToolVenv(): void {
  const pythonCommand = getToolVenvPythonCommand();
  try {
    run(`${pythonCommand} -m ensurepip --upgrade`, {
      displayCommand: "<sbom>/.tool-venv python -m ensurepip --upgrade"
    });
  } catch {
    // Some Python distributions already bundle pip in venvs or do not expose ensurepip.
  }
}

function installCycloneDxPyInsideToolVenv(): void {
  const pythonCommand = getToolVenvPythonCommand();
  ensurePipAvailableInToolVenv();

  try {
    run(`${pythonCommand} -m pip install --upgrade pip`, {
      displayCommand: "<sbom>/.tool-venv python -m pip install --upgrade pip"
    });
  } catch {
    // A pip self-upgrade failure should not block the actual tool installation.
  }

  run(`${pythonCommand} -m pip install cyclonedx-bom`, {
    displayCommand: "<sbom>/.tool-venv python -m pip install cyclonedx-bom"
  });
}

function ensureLocalCdxgenInPath(): boolean {
  const localBin = path.join(sbomRoot, "node_modules", ".bin");
  const commandName = process.platform === "win32" ? "cdxgen.cmd" : "cdxgen";
  if (!fs.existsSync(path.join(localBin, commandName))) {
    return false;
  }
  ensureDirectoryInPath(localBin);
  return true;
}

type CdxgenVerificationResult = {
  ok: boolean;
  state: "missing" | "broken" | "healthy";
  detail: string;
};

function verifyCdxgenAvailable(): CdxgenVerificationResult {
  if (!commandExists("cdxgen")) {
    return {
      ok: false,
      state: "missing",
      detail: "cdxgen command was not found on PATH"
    };
  }

  try {
    const version = runCapture("cdxgen --version", { quiet: true }).trim();
    return {
      ok: true,
      state: "healthy",
      detail: version || "cdxgen executed successfully"
    };
  } catch (err: any) {
    return {
      ok: false,
      state: "broken",
      detail: err?.message || "cdxgen command exists but failed to execute"
    };
  }
}

function getNpmGlobalBinDirectory(): string | null {
  try {
    const prefix = runCapture("npm prefix -g", { quiet: true }).trim();
    if (!prefix) {
      return null;
    }
    return isWindows() ? prefix : path.join(prefix, "bin");
  } catch {
    return null;
  }
}

function ensureNpmGlobalBinInPath(): boolean {
  const globalBin = getNpmGlobalBinDirectory();
  if (!globalBin || !fs.existsSync(globalBin)) {
    return false;
  }
  ensureDirectoryInPath(globalBin);
  return true;
}

function ensureCdxgenAvailable(): void {
  const initialCheck = verifyCdxgenAvailable();
  if (initialCheck.ok) {
    return;
  }
  logger.warn(`cdxgen bootstrap: initial check=${initialCheck.state} (${initialCheck.detail})`);

  const localPathAdded = ensureLocalCdxgenInPath();
  if (localPathAdded) {
    const localCheck = verifyCdxgenAvailable();
    if (localCheck.ok) {
      return;
    }
    logger.warn(`cdxgen bootstrap: local binary check=${localCheck.state} (${localCheck.detail})`);
  }

  const localCacheDir = path.join(sbomRoot, ".npm-cache");
  fs.mkdirSync(localCacheDir, { recursive: true });
  const attempts: string[] = [];

  try {
    run(
      `npm install --no-save --prefix "${sbomRoot}" @cyclonedx/cdxgen --cache "${localCacheDir}"`,
      { displayCommand: "npm install --no-save --prefix <sbom> @cyclonedx/cdxgen" }
    );
    attempts.push("local install: succeeded");
  } catch (err: any) {
    attempts.push(`local install: failed (${err?.message || "unknown error"})`);
  }

  ensureLocalCdxgenInPath();
  let postLocalCheck = verifyCdxgenAvailable();
  if (postLocalCheck.ok) {
    return;
  }
  attempts.push(`post-local verification: ${postLocalCheck.state} (${postLocalCheck.detail})`);

  try {
    run("npm install -g @cyclonedx/cdxgen", {
      displayCommand: "npm install -g @cyclonedx/cdxgen"
    });
    attempts.push("global install: succeeded");
  } catch (err: any) {
    attempts.push(`global install: failed (${err?.message || "unknown error"})`);
  }

  const globalPathAdded = ensureNpmGlobalBinInPath();
  attempts.push(`global PATH refresh: ${globalPathAdded ? "applied" : "not applied"}`);

  const finalCheck = verifyCdxgenAvailable();
  if (finalCheck.ok) {
    return;
  }

  attempts.push(`final verification: ${finalCheck.state} (${finalCheck.detail})`);
  throw new Error(
    "cdxgen bootstrap failed. " +
    attempts.join("; ") +
    '. Validate the local toolchain with "npx @cyclonedx/cdxgen --version". ' +
    "If that fails, clean the npm cache and reinstall dependencies before retrying."
  );
}

function installCycloneDxPy(pythonCommands: string[]): void {
  ensurePythonToolVenv(pythonCommands);
  installCycloneDxPyInsideToolVenv();
  ensureToolVenvInPathIfPresent();
}

function installTrivyOnLinux(): void {
  if (commandExists("apt-get")) {
    run("sudo apt-get update");
    run("sudo apt-get install -y wget gnupg lsb-release");
    run("wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -");
    run("echo \"deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main\" | sudo tee /etc/apt/sources.list.d/trivy.list");
    run("sudo apt-get update");
    run("sudo apt-get install -y trivy");
    return;
  }

  if (commandExists("dnf")) {
    run("sudo dnf install -y trivy");
    return;
  }

  if (commandExists("yum")) {
    run("sudo yum install -y trivy");
    return;
  }

  if (commandExists("zypper")) {
    run("sudo zypper --non-interactive install trivy");
    return;
  }

  if (commandExists("pacman")) {
    run("sudo pacman -Sy --noconfirm trivy");
    return;
  }

  if (commandExists("apk")) {
    run("sudo apk add --no-cache trivy");
    return;
  }

  if (commandExists("brew")) {
    run("brew install trivy");
    return;
  }

  if (commandExists("curl")) {
    run(`curl -sfL ${trivyInstallScriptUrl} | sudo sh -s -- -b /usr/local/bin`);
    return;
  }

  if (commandExists("wget")) {
    run(`wget -qO - ${trivyInstallScriptUrl} | sudo sh -s -- -b /usr/local/bin`);
    return;
  }

  throw new Error(
    "Trivy not found and no supported installer was detected for this Linux environment.\n" +
    "Install Trivy manually: https://github.com/aquasecurity/trivy/releases"
  );
}

export function ensureTools(): void {
  ensureCdxgenAvailable();
  const pythonCommands = getAvailablePythonCommands();

  ensureToolVenvInPathIfPresent();

  if (!commandExists("cyclonedx-py")) {
    installCycloneDxPy(pythonCommands);
  }

  if (!commandExists("cyclonedx-py")) {
    ensureCycloneDxPyInPathIfPresent(pythonCommands);
  }

  if (!commandExists("cyclonedx-py")) {
    throw new Error(
      "cyclonedx-py was not found after installation. Ensure your Python Scripts directory is available in PATH."
    );
  }

  if (!commandExists("trivy")) {
    logger.warn("Trivy not found. Attempting automatic installation...");
    if (isWindows()) {
      if (commandExists("winget")) {
        run("winget install AquaSecurity.Trivy --accept-package-agreements --accept-source-agreements");
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
    } else if (isMacOS()) {
      if (commandExists("brew")) {
        run("brew install trivy");
      } else {
        throw new Error(
          "Trivy not found and Homebrew is not available.\n" +
          "Install Trivy manually: https://github.com/aquasecurity/trivy/releases"
        );
      }
    } else if (isLinux()) {
      installTrivyOnLinux();
    }
  }

  if (isWindows() && !commandExists("trivy")) {
    ensureWindowsTrivyInPathIfPresent();
  }

  run("trivy --version");
}
