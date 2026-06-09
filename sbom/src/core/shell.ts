/**
 * Shell execution helpers.
 * Provides a single place for command execution and command-existence checks.
 */
import { execSync } from "child_process";
import * as path from "path";

export function run(command: string, cwd?: string): void {
  console.log(`\n$ ${command}`);
  execSync(command, {
    cwd,
    stdio: "inherit",
    env: process.env
  });
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
