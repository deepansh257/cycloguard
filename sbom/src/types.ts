/**
 * Shared domain types used across the SBOM scanner modules.
 * Keeping these centralized ensures all layers use consistent contracts.
 */
export type Language = "node" | "python" | "java" | "csharp";

export type Args = {
  source: string;
  output: string;
  threshold: "critical" | "high";
  branch?: string;
  workdir?: string;
  fsScan: boolean;
  secretScan: boolean;
  misconfigScan: boolean;
};

export type ProjectTarget = {
  language: Language;
  projectPath: string;
  id: string;
  framework?: "react" | "angular";
};
