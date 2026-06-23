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
  githubRepo?: string;
  githubToken?: string;
  slackWebhookUrl?: string;
  remediationBaseBranch?: string;
  gitUserName: string;
  gitUserEmail: string;
};

export type ProjectTarget = {
  language: Language;
  projectPath: string;
  id: string;
  framework?: "react" | "angular";
  sourceOfTruthType: "lockfile" | "pinned-manifest" | "manifest" | "build-file";
  sourceOfTruthFiles: string[];
  supportingFiles: string[];
  lockfilePresent: boolean;
  lockfileFiles: string[];
  reproducibility: "deterministic" | "non-deterministic";
  lockfileWarning?: string;
};

export type RemediationOperation = {
  type?: string;
  file?: string;
  searchText?: string;
  replaceText?: string;
};

export type RemediationPlanItem = {
  id: string;
  sourceType?: "sbom" | "cbom";
  language: Language;
  fixKind: "dependency" | "code" | "config" | "manual";
  packageName: string;
  vulnerabilityId: string;
  installedVersion?: string;
  targetVersion: string;
  severity: string;
  confidence?: string;
  rationale?: string;
  status: string;
  autoApply?: boolean;
  targetFile?: string;
  operations?: RemediationOperation[];
  notes?: string;
};

export type RemediationPlan = {
  plannerMode?: string;
  createdAt?: string;
  sourceType?: "sbom" | "cbom";
  sourceRepo?: string;
  sourceBranch?: string;
  threshold?: string;
  items: RemediationPlanItem[];
};

export type RemediationApplyResult = {
  itemId: string;
  language: Language;
  packageName: string;
  targetVersion: string;
  status: "applied" | "skipped";
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
