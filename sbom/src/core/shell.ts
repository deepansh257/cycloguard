/**
 * Shell execution helpers.
 * Provides a single place for command execution and command-existence checks.
 */
import { execSync } from "child_process";
import * as path from "path";

type RunOptions = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  quiet?: boolean;
  displayCommand?: string;
  stdio?: "inherit" | "pipe" | "ignore";
};

export function run(command: string, cwdOrOptions?: string | RunOptions): void {
  const options: RunOptions = typeof cwdOrOptions === "string"
    ? { cwd: cwdOrOptions }
    : (cwdOrOptions || {});

  if (!options.quiet) {
    console.log(`\n$ ${options.displayCommand || command}`);
  }

  execSync(command, {
    cwd: options.cwd,
    stdio: options.stdio || "inherit",
    env: { ...process.env, ...(options.env || {}) }
  });
}

export function runCapture(command: string, cwdOrOptions?: string | RunOptions): string {
  const options: RunOptions = typeof cwdOrOptions === "string"
    ? { cwd: cwdOrOptions }
    : (cwdOrOptions || {});

  if (!options.quiet) {
    console.log(`\n$ ${options.displayCommand || command}`);
  }

  return execSync(command, {
    cwd: options.cwd,
    stdio: options.stdio || "pipe",
    env: { ...process.env, ...(options.env || {}) }
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
