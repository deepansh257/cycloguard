/**
 * Shell execution helpers.
 * Provides a single place for command execution and command-existence checks.
 */
import { execSync } from "child_process";

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
