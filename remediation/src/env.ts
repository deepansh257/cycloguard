/**
 * Loads local .env values for remediation runs so the planner can access
 * OpenAI credentials and shared scan configuration without manual exports.
 */
import * as fs from "fs";
import * as path from "path";

export function loadLocalEnv(): void {
  const candidates = [
    path.resolve(process.cwd(), ".env"),
    path.resolve(__dirname, "..", "..", ".env")
  ];

  for (const envPath of candidates) {
    if (!fs.existsSync(envPath)) {
      continue;
    }

    const lines = fs.readFileSync(envPath, "utf-8").split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) {
        continue;
      }

      const separatorIndex = line.indexOf("=");
      if (separatorIndex === -1) {
        continue;
      }

      const key = line.slice(0, separatorIndex).trim();
      let value = line.slice(separatorIndex + 1).trim();

      if (
        (value.startsWith("\"") && value.endsWith("\"")) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (!(key in process.env)) {
        process.env[key] = value;
      }
    }

    break;
  }
}
