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

function ensureDirectoryInPath(directory: string): void {
  const currPath = process.env.PATH || "";
  const delimiter = process.platform === "win32" ? ";" : ":";
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
  const files = process.platform === "win32"
    ? ["cyclonedx-py.exe", "cyclonedx-py-script.py", "cyclonedx-py"]
    : ["cyclonedx-py"];
  return files.some((file) => fs.existsSync(path.join(directory, file)));
}

function getAvailablePythonCommands(): string[] {
  const candidates = process.platform === "win32"
    ? ["py -3", "python", "py"]
    : ["python3", "python"];

  return [...new Set(candidates)].filter((command) => canRunShellCommand(`${command} --version`));
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
  if (process.platform === "win32") {
    addDirectoryToWindowsPath(scriptsDir);
  } else {
    ensureDirectoryInPath(scriptsDir);
  }
  return true;
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

function ensureCdxgenAvailable(): void {
  if (commandExists("cdxgen")) {
    return;
  }

  if (ensureLocalCdxgenInPath() && commandExists("cdxgen")) {
    return;
  }

  const localCacheDir = path.join(sbomRoot, ".npm-cache");
  fs.mkdirSync(localCacheDir, { recursive: true });

  try {
    run(
      `npm install --no-save --prefix "${sbomRoot}" @cyclonedx/cdxgen --cache "${localCacheDir}"`,
      { displayCommand: "npm install --no-save --prefix <sbom> @cyclonedx/cdxgen" }
    );
  } catch {
    // Fallback to the previous global install path if local install is not possible.
    run("npm install -g @cyclonedx/cdxgen");
  }

  ensureLocalCdxgenInPath();

  if (!commandExists("cdxgen")) {
    throw new Error("cdxgen was not found after installation. Ensure Node.js/npm can install @cyclonedx/cdxgen.");
  }
}

function installCycloneDxPy(pythonCommands: string[]): void {
  for (const pythonCommand of pythonCommands) {
    try {
      run(`${pythonCommand} -m pip install cyclonedx-bom`, {
        displayCommand: `${pythonCommand} -m pip install cyclonedx-bom`
      });
      return;
    } catch {
      continue;
    }
  }

  if (commandExists("pip3")) {
    run("pip3 install cyclonedx-bom");
    return;
  }

  if (commandExists("pip")) {
    run("pip install cyclonedx-bom");
    return;
  }

  throw new Error(
    "Python/pip was not found for cyclonedx-bom installation. Install Python 3 with pip and retry."
  );
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
    if (process.platform === "win32") {
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
      installTrivyOnLinux();
    }
  }

  if (process.platform === "win32" && !commandExists("trivy")) {
    ensureWindowsTrivyInPathIfPresent();
  }

  run("trivy --version");
}
