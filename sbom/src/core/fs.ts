/**
 * File-system helpers shared by scanner modules.
 * Encapsulates common JSON read/write and directory creation operations.
 */
import * as fs from "fs";

export function ensureDir(p: string): void {
  fs.mkdirSync(p, { recursive: true });
}

export function writeJson(filePath: string, data: unknown): void {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

export function readJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}
