/**
 * Shared types for the remediation module.
 * These keep artifact loading, planning, and reporting aligned on one contract.
 */
export type AiProvider = "openai" | "anthropic" | "gemini";

export type RemediationArgs = {
  runDir: string;
  sourcePath: string;
  sourceRepo?: string;
  sourceBranch?: string;
  threshold?: string;
};

export type RemediationFinding = {
  id: string;
  sourceType: "sbom" | "cbom";
  category: "dependency" | "crypto" | "secret" | "config";
  severity: string;
  title: string;
  packageName?: string;
  vulnerabilityId?: string;
  installedVersion?: string;
  fixedVersion?: string;
  filePath?: string;
  line?: number;
  snippet?: string;
  notes?: string;
};

export type RemediationContext = {
  sourceRepo?: string;
  sourceBranch?: string;
  sourcePath: string;
  threshold?: string;
  reproducibilityWarnings: string[];
  findings: RemediationFinding[];
};

export type RemediationOperation = {
  type: "replace" | "upgrade" | "manual";
  file?: string;
  searchText?: string;
  replaceText?: string;
  notes?: string;
};

export type RemediationApprovalStatus = "proposed" | "approved" | "rejected" | "applied" | "failed" | "skipped";

export type RemediationPlanItem = {
  id: string;
  sourceType: "sbom" | "cbom";
  category: "dependency" | "crypto" | "secret" | "config";
  severity: string;
  title: string;
  vulnerabilityId?: string;
  packageName?: string;
  installedVersion?: string;
  targetVersion?: string;
  targetFile?: string;
  confidence: "high" | "medium" | "low";
  rationale: string;
  recommendedChanges: string[];
  operations: RemediationOperation[];
  reviewNotes?: string[];
  approvalStatus?: RemediationApprovalStatus;
  autoApplicable?: boolean;
};

export type RemediationPlan = {
  plannerMode: "ai" | "fallback";
  plannerProvider: AiProvider | "fallback";
  createdAt: string;
  sourceRepo?: string;
  sourceBranch?: string;
  sourcePath: string;
  threshold?: string;
  reproducibilityWarnings: string[];
  items: RemediationPlanItem[];
};

export type RemediationApprovalItem = {
  id: string;
  status: Exclude<RemediationApprovalStatus, "applied" | "failed" | "skipped">;
  notes?: string;
};

export type RemediationApprovalDocument = {
  createdAt: string;
  sourceRepo?: string;
  sourceBranch?: string;
  items: RemediationApprovalItem[];
};

export type RemediationApplyArgs = {
  runDir: string;
  sourcePath?: string;
};

export type RemediationApplyItemResult = {
  id: string;
  status: "applied" | "failed" | "skipped";
  reason: string;
  filesChanged: string[];
};

export type RemediationApplyResult = {
  createdAt: string;
  runDir: string;
  sourcePath: string;
  items: RemediationApplyItemResult[];
};
