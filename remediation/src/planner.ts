/**
 * Builds remediation guidance for scan findings.
 * It prefers AI-generated suggestions when configured, then falls back to
 * deterministic local heuristics so the pipeline still produces useful output.
 */
import { RemediationContext, RemediationPlan, RemediationPlanItem } from "./types";
import { enrichFinding } from "./context-builder";
import { createAiProvider, getConfiguredProviderName } from "./providers";

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
    plannerProvider: "fallback",
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
  const fallbackPlan = createFallbackPlan(context);

  if (!context.findings.length) {
    console.log("Remediation planner: no findings available. Using fallback planning with an empty result set.");
    return fallbackPlan;
  }

  const providerName = getConfiguredProviderName();
  const provider = createAiProvider(providerName);
  const configurationStatus = provider.getConfigurationStatus();

  if (!configurationStatus.configured) {
    const reason = configurationStatus.reason || "provider is not configured";
    console.log(`Remediation planner: provider '${providerName}' is not configured (${reason}). Using local rule-based planning.`);
    return fallbackPlan;
  }

  try {
    const aiPlan = await provider.generatePlan(context, fallbackPlan);
    if (aiPlan) {
      console.log(`Remediation planner: using AI-generated planning via provider '${provider.name}'.`);
      return aiPlan;
    }
    console.warn(`Remediation planner: provider '${provider.name}' returned an empty or invalid response. Using local rule-based planning.`);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown OpenAI planning error";
    console.warn(`Remediation planner: AI planning failed for provider '${provider.name}' (${message}). Using local rule-based planning.`);
  }

  return fallbackPlan;
}
