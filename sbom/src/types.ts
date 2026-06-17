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
  enableIssueCreation: boolean;
  enableSlack: boolean;
  enableRemediation: boolean;
  enablePrCreation: boolean;
  remediationBaseBranch?: string;
  gitUserName: string;
  gitUserEmail: string;
  githubRepo?: string;
  githubToken?: string;
  slackWebhookUrl?: string;
};

export type ProjectTarget = {
  language: Language;
  projectPath: string;
  id: string;
  framework?: "react" | "angular";
};

export type VulnerabilityRecord = {
  app: string;
  severity: "UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  cve_id: string;
  package: string;
  installed?: string;
  fixed?: string;
  title?: string;
};

export type RemediationPlanItem = {
  id: string;
  sourceType?: "sbom" | "cbom";
  language: Language;
  fixKind?: "dependency" | "code" | "config" | "manual";
  packageName: string;
  vulnerabilityId: string;
  installedVersion?: string;
  targetVersion: string;
  severity: "HIGH" | "CRITICAL";
  confidence: "high" | "medium" | "low";
  rationale: string;
  targetFile?: string;
  autoApply?: boolean;
  operations?: Array<{
    type: "replace_text";
    file: string;
    searchText: string;
    replaceText: string;
  }>;
  status: "planned" | "unsupported" | "no_fixed_version";
  notes?: string;
};

export type RemediationPlan = {
  createdAt: string;
  sourceRepo: string;
  sourceBranch: string;
  threshold: "critical" | "high";
  items: RemediationPlanItem[];
};

export type RemediationApplyResult = {
  itemId: string;
  language: Language;
  packageName: string;
  targetVersion: string;
  status: "applied" | "skipped" | "failed";
  filesChanged: string[];
  notes?: string;
};

export type ValidationResult = {
  language: Language;
  targetId: string;
  command: string;
  status: "passed" | "failed" | "skipped";
  notes?: string;
};
