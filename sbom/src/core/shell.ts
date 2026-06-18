/**
 * Shell execution helpers.
 * Provides a single place for command execution and command-existence checks.
 */
import { execSync } from "child_process";
import * as path from "path";

type RunOptions = {
  cwd?: string;
  quiet?: boolean;
  displayCommand?: string;
};

export function run(command: string, cwdOrOptions?: string | RunOptions): void {
  const options = typeof cwdOrOptions === "string"
    ? { cwd: cwdOrOptions }
    : (cwdOrOptions || {});
  if (!options.quiet) {
    console.log(`\n$ ${options.displayCommand || command}`);
  }
  execSync(command, {
    cwd: options.cwd,
    stdio: "inherit",
    env: process.env
  });
}

export function runCapture(command: string, options: RunOptions = {}): string {
  if (!options.quiet) {
    console.log(`\n$ ${options.displayCommand || command}`);
  }
  return execSync(command, {
    cwd: options.cwd,
    stdio: ["ignore", "pipe", "ignore"],
    env: process.env
  }).toString("utf-8");
}

export function commandExists(command: string): boolean {
  try {
    const checkCmd = process.platform === "win32" ? `where ${command}` : `command -v ${command}`;
    execSync(checkCmd, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export function runNodeScript(scriptPath: string, args: string[]): void {
  const escapedArgs = args.map((arg) => `"${arg.replace(/"/g, '\\"')}"`).join(" ");
  run(`node "${path.resolve(scriptPath)}" ${escapedArgs}`);
}
