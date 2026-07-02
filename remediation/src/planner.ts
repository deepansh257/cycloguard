/**
 * Builds remediation guidance for scan findings.
 * It prefers AI-generated suggestions when configured, then falls back to
 * deterministic local heuristics so the pipeline still produces useful output.
 */
import { RemediationContext, RemediationPlan, RemediationPlanItem } from "./types";
import { enrichFinding } from "./context-builder";

type OpenAiMessage = {
  role: "system" | "user";
  content: string;
};

type OpenAiResponse = {
  choices?: Array<{
    message?: {
      content?: string;
    };
  }>;
};

function createFallbackPlan(context: RemediationContext): RemediationPlan {
  const items: RemediationPlanItem[] = context.findings.map((finding) => {
    const enriched = enrichFinding(finding, context);

    if (finding.sourceType === "sbom") {
      const targetVersion = enriched.normalizedTargetVersion;
      const targetFile = enriched.targetManifest;
      return {
        id: finding.id,
        sourceType: finding.sourceType,
        category: finding.category,
        severity: finding.severity,
        title: finding.title,
        vulnerabilityId: finding.vulnerabilityId,
        packageName: finding.packageName,
        installedVersion: finding.installedVersion,
        targetVersion,
        targetFile,
        confidence: targetFile && targetVersion ? "high" : "medium",
        rationale: targetVersion
          ? `Upgrade ${finding.packageName} from ${finding.installedVersion || "the current version"} to at least ${targetVersion} to address ${finding.vulnerabilityId || "the reported advisory"}.`
          : `Review the dependency chain for ${finding.packageName} and align it with a fixed release listed by the scanner.`,
        recommendedChanges: [
          targetFile
            ? `Update ${finding.packageName} in ${targetFile}.`
            : `Locate the manifest that brings in ${finding.packageName} and update it to a fixed version.`,
          "Regenerate the lockfile and rerun the scan to confirm the vulnerability is removed."
        ],
        operations: [
          {
            type: "upgrade",
            file: targetFile,
            notes: targetVersion
              ? `Set ${finding.packageName} to ${targetVersion} or a later safe version, then refresh the lockfile.`
              : "Adjust the resolved dependency to a fixed version and refresh the lockfile."
          }
        ],
        reviewNotes: enriched.reviewNotes
      };
    }

    const normalizedTitle = finding.title.toUpperCase();
    const replacement = normalizedTitle === "MD5"
      ? "sha256"
      : normalizedTitle === "MATH-RANDOM"
        ? "crypto.randomBytes(...)"
        : undefined;

    return {
      id: finding.id,
      sourceType: finding.sourceType,
      category: finding.category,
      severity: finding.severity,
      title: finding.title,
      vulnerabilityId: finding.vulnerabilityId,
      targetFile: finding.filePath,
      confidence: finding.snippet ? "high" : "medium",
      rationale: replacement
        ? `${finding.title} is flagged as weak in the CBOM output. Replace it with a stronger primitive in the identified source location.`
        : `Review the flagged cryptographic usage and replace it with an approved primitive for this use case.`,
      recommendedChanges: [
        replacement
          ? `Replace ${finding.title} with ${replacement} in the flagged code path.`
          : "Replace the weak cryptographic primitive with a stronger approved alternative.",
        "Rerun the CBOM scan to confirm the finding no longer appears."
      ],
      operations: [
        {
          type: replacement && finding.snippet ? "replace" : "manual",
          file: finding.filePath,
          searchText: finding.snippet,
          replaceText: replacement,
          notes: finding.line ? `Review the code near line ${finding.line}.` : "Review the flagged code path."
        }
      ],
      reviewNotes: enriched.reviewNotes
    };
  });

  return {
    plannerMode: "fallback",
    createdAt: new Date().toISOString(),
    sourceRepo: context.sourceRepo,
    sourceBranch: context.sourceBranch,
    sourcePath: context.sourcePath,
    threshold: context.threshold,
    reproducibilityWarnings: context.reproducibilityWarnings,
    items
  };
}

function createPrompt(context: RemediationContext): OpenAiMessage[] {
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

function parseJsonObject(content: string): any | null {
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

async function requestAiPlan(context: RemediationContext): Promise<RemediationPlan | null> {
  const apiKey = process.env.OPENAI_API_KEY;
  const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

  if (!apiKey || !context.findings.length) {
    return null;
  }

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      messages: createPrompt(context)
    })
  });

  if (!response.ok) {
    throw new Error(`OpenAI request failed with status ${response.status}`);
  }

  const payload = await response.json() as OpenAiResponse;
  const content = payload.choices?.[0]?.message?.content;
  if (!content) {
    return null;
  }

  const parsed = parseJsonObject(content);
  if (!parsed || !Array.isArray(parsed.items)) {
    return null;
  }

  const fallbackById = new Map(createFallbackPlan(context).items.map((item) => [item.id, item]));
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
    plannerMode: "ai",
    createdAt: new Date().toISOString(),
    sourceRepo: context.sourceRepo,
    sourceBranch: context.sourceBranch,
    sourcePath: context.sourcePath,
    threshold: context.threshold,
    reproducibilityWarnings: context.reproducibilityWarnings,
    items
  };
}

export async function buildRemediationPlan(context: RemediationContext): Promise<RemediationPlan> {
  if (!context.findings.length) {
    console.log("Remediation planner: no findings available. Using fallback planning with an empty result set.");
    return createFallbackPlan(context);
  }

  if (!process.env.OPENAI_API_KEY) {
    console.log("Remediation planner: OPENAI_API_KEY not set. Using local rule-based planning.");
    return createFallbackPlan(context);
  }

  try {
    const aiPlan = await requestAiPlan(context);
    if (aiPlan) {
      console.log("Remediation planner: using AI-generated planning.");
      return aiPlan;
    }
    console.warn("Remediation planner: OpenAI response was empty or invalid. Using local rule-based planning.");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown OpenAI planning error";
    console.warn(`Remediation planner: AI planning failed (${message}). Using local rule-based planning.`);
  }

  return createFallbackPlan(context);
}
