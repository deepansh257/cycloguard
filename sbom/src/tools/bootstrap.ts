/**
 * Tool bootstrap module.
 * Ensures required scanner dependencies exist and auto-installs when possible.
 */
import * as fs from "fs";
import * as path from "path";
import { commandExists, run } from "../core/shell";

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

export function ensureTools(): void {
  if (!commandExists("cdxgen")) {
    run("npm install -g @cyclonedx/cdxgen");
  }

  if (!commandExists("cyclonedx-py")) {
    run("pip install cyclonedx-bom");
  }

  if (!commandExists("trivy")) {
    console.log("\nTrivy not found. Attempting automatic installation...");
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
