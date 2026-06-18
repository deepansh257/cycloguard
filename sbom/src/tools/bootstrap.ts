/**
 * Tool bootstrap module.
 * Ensures required scanner dependencies exist and auto-installs when possible.
 */
import * as fs from "fs";
import * as path from "path";
import pino from "pino";
import { commandExists, run, runCapture } from "../core/shell";

const { createAppLogger } = require(path.resolve(__dirname, "..", "..", "..", "common", "logger.js")) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    warn: (message: string, meta?: Record<string, unknown>) => void;
  };
};
const logger = createAppLogger({ pino });

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
  const currPath = process.env.PATH || "";
  if (!currPath.toLowerCase().includes(directory.toLowerCase())) {
    process.env.PATH = `${directory};${currPath}`;
  }
}

function findWindowsCycloneDxPyDirectory(): string | null {
  const localAppData = process.env.LOCALAPPDATA || "";
  const appData = process.env.APPDATA || "";
  const userProfile = process.env.USERPROFILE || "";

  const directCandidates = [
    path.join(localAppData, "Programs", "Python", "Python314", "Scripts"),
    path.join(localAppData, "Programs", "Python", "Python313", "Scripts"),
    path.join(localAppData, "Programs", "Python", "Python312", "Scripts"),
    path.join(localAppData, "Programs", "Python", "Python311", "Scripts"),
    path.join(localAppData, "Python", "pythoncore-3.14-64", "Scripts"),
    path.join(localAppData, "Python", "pythoncore-3.13-64", "Scripts"),
    path.join(localAppData, "Python", "pythoncore-3.12-64", "Scripts"),
    path.join(localAppData, "Python", "pythoncore-3.11-64", "Scripts"),
    path.join(appData, "Python", "Python314", "Scripts"),
    path.join(appData, "Python", "Python313", "Scripts"),
    path.join(appData, "Python", "Python312", "Scripts"),
    path.join(appData, "Python", "Python311", "Scripts"),
    path.join(userProfile, "AppData", "Roaming", "Python", "Python314", "Scripts"),
    path.join(userProfile, "AppData", "Roaming", "Python", "Python313", "Scripts"),
    path.join(userProfile, "AppData", "Roaming", "Python", "Python312", "Scripts"),
    path.join(userProfile, "AppData", "Roaming", "Python", "Python311", "Scripts")
  ];

  const hasCycloneDxCommand = (directory: string): boolean => {
    const files = ["cyclonedx-py.exe", "cyclonedx-py-script.py", "cyclonedx-py"];
    return files.some((file) => fs.existsSync(path.join(directory, file)));
  };

  for (const candidate of directCandidates) {
    if (candidate && fs.existsSync(candidate) && hasCycloneDxCommand(candidate)) {
      return candidate;
    }
  }

  const pythonCommands = ["python", "py"];
  for (const pythonCommand of pythonCommands) {
    if (!commandExists(pythonCommand)) {
      continue;
    }

    try {
      const scriptsDir = runCapture(
        `${pythonCommand} -c "import sysconfig; print(sysconfig.get_path('scripts') or '')"`,
        { quiet: true }
      ).trim();
      if (scriptsDir && fs.existsSync(scriptsDir) && hasCycloneDxCommand(scriptsDir)) {
        return scriptsDir;
      }
    } catch {
      continue;
    }
  }

  return null;
}

function ensureWindowsCycloneDxPyInPathIfPresent(): boolean {
  const scriptsDir = findWindowsCycloneDxPyDirectory();
  if (!scriptsDir) return false;
  addDirectoryToWindowsPath(scriptsDir);
  return true;
}

export function ensureTools(): void {
  if (!commandExists("cdxgen")) {
    run("npm install -g @cyclonedx/cdxgen");
  }

  if (!commandExists("cyclonedx-py")) {
    run("pip install cyclonedx-bom");
    if (process.platform === "win32") {
      ensureWindowsCycloneDxPyInPathIfPresent();
    }
  }

  if (process.platform === "win32" && !commandExists("cyclonedx-py")) {
    ensureWindowsCycloneDxPyInPathIfPresent();
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
