/**
 * Shared helpers for provider adapters.
 * This file builds the common remediation prompt, parses model output, and
 * merges provider-specific JSON back into the normalized remediation plan.
 */
import { RemediationContext, RemediationPlan, RemediationPlanItem } from "../types";

type PromptMessage = {
  role: "system" | "user";
  content: string;
};

export function createPrompt(context: RemediationContext): PromptMessage[] {
  return [
    {
      role: "system",
      content: [
        "You are generating remediation guidance for a security scanning pipeline.",
        "Return valid JSON only.",
        "Do not include markdown fences.",
        "Use this exact shape:",
        "{\"items\":[{\"id\":\"...\",\"confidence\":\"high|medium|low\",\"rationale\":\"...\",\"recommendedChanges\":[\"...\"],\"targetFile\":\"optional\",\"targetVersion\":\"optional\",\"operations\":[{\"type\":\"replace|upgrade|manual\",\"file\":\"optional\",\"searchText\":\"optional\",\"replaceText\":\"optional\",\"notes\":\"optional\"}],\"reviewNotes\":[\"...\"]}]}"
      ].join(" ")
    },
    {
      role: "user",
      content: JSON.stringify({
        sourceRepo: context.sourceRepo,
        sourceBranch: context.sourceBranch,
        sourcePath: context.sourcePath,
        threshold: context.threshold,
        reproducibilityWarnings: context.reproducibilityWarnings,
        findings: context.findings
      })
    }
  ];
}

export function parseJsonObject(content: string): any | null {
  const trimmed = content.trim();
  if (!trimmed) {
    return null;
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    const firstBrace = trimmed.indexOf("{");
    const lastBrace = trimmed.lastIndexOf("}");
    if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
      return null;
    }

    try {
      return JSON.parse(trimmed.slice(firstBrace, lastBrace + 1));
    } catch {
      return null;
    }
  }
}

export async function buildErrorMessage(response: Response, providerName: string): Promise<string> {
  const bodyText = await response.text();
  const compactBody = bodyText.replace(/\s+/g, " ").trim();
  return compactBody
    ? `${providerName} request failed with status ${response.status}: ${compactBody}`
    : `${providerName} request failed with status ${response.status}`;
}

export function mergeAiPlan(
  parsed: any,
  fallbackPlan: RemediationPlan,
  providerName: RemediationPlan["plannerProvider"]
): RemediationPlan | null {
  if (!parsed || !Array.isArray(parsed.items)) {
    return null;
  }

  const fallbackById = new Map(fallbackPlan.items.map((item) => [item.id, item]));
  const items = parsed.items
    .map((item: any) => {
      const base = fallbackById.get(String(item.id));
      if (!base) {
        return null;
      }

      return {
        ...base,
        confidence: item.confidence === "high" || item.confidence === "low" ? item.confidence : "medium",
        rationale: typeof item.rationale === "string" && item.rationale.trim() ? item.rationale.trim() : base.rationale,
        recommendedChanges: Array.isArray(item.recommendedChanges) && item.recommendedChanges.length > 0
          ? item.recommendedChanges.map((entry: unknown) => String(entry))
          : base.recommendedChanges,
        targetFile: typeof item.targetFile === "string" ? item.targetFile : base.targetFile,
        targetVersion: typeof item.targetVersion === "string" ? item.targetVersion : base.targetVersion,
        operations: Array.isArray(item.operations) && item.operations.length > 0
          ? item.operations.map((operation: any) => ({
              type: operation?.type === "replace" || operation?.type === "upgrade" ? operation.type : "manual",
              file: typeof operation?.file === "string" ? operation.file : undefined,
              searchText: typeof operation?.searchText === "string" ? operation.searchText : undefined,
              replaceText: typeof operation?.replaceText === "string" ? operation.replaceText : undefined,
              notes: typeof operation?.notes === "string" ? operation.notes : undefined
            }))
          : base.operations,
        reviewNotes: Array.isArray(item.reviewNotes)
          ? item.reviewNotes.map((entry: unknown) => String(entry))
          : base.reviewNotes
      } satisfies RemediationPlanItem;
    })
    .filter((item: RemediationPlanItem | null): item is RemediationPlanItem => Boolean(item));

  return {
    ...fallbackPlan,
    plannerMode: "ai",
    plannerProvider: providerName,
    createdAt: new Date().toISOString(),
    items
  };
}
