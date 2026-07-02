/**
 * Shared types for the remediation module.
 * These keep artifact loading, planning, and reporting aligned on one contract.
 */
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
};

export type RemediationPlan = {
  plannerMode: "ai" | "fallback";
  createdAt: string;
  sourceRepo?: string;
  sourceBranch?: string;
  sourcePath: string;
  threshold?: string;
  reproducibilityWarnings: string[];
  items: RemediationPlanItem[];
};
