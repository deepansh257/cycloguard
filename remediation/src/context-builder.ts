/**
 * Enriches normalized findings with source-level context such as candidate
 * manifests, fixed-version targets, and review notes for human approval.
 */
import * as fs from "fs";
import * as path from "path";
import { RemediationContext, RemediationFinding } from "./types";

function safeReadJson(filePath: string): any | null {
  if (!fs.existsSync(filePath)) {
    return null;
  }

  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return null;
  }
}

function findPackageManifests(sourcePath: string): string[] {
  const manifests: string[] = [];
  const queue = [sourcePath];
  const seen = new Set<string>();
  const skipped = new Set([".git", "node_modules", "dist", "build", "coverage", ".cycloguard"]);

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (seen.has(current)) {
      continue;
    }
    seen.add(current);

    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!skipped.has(entry.name)) {
          queue.push(fullPath);
        }
        continue;
      }

      if (entry.isFile() && entry.name === "package.json") {
        manifests.push(fullPath);
      }
    }
  }

  manifests.sort((left, right) => left.length - right.length);
  return manifests;
}

function findTargetManifest(sourcePath: string, packageName?: string): string | undefined {
  if (!packageName) {
    return undefined;
  }

  for (const manifestPath of findPackageManifests(sourcePath)) {
    const manifest = safeReadJson(manifestPath);
    if (!manifest || typeof manifest !== "object") {
      continue;
    }

    const sections = [
      manifest.dependencies,
      manifest.devDependencies,
      manifest.peerDependencies,
      manifest.optionalDependencies
    ];

    if (sections.some((section) => section && typeof section === "object" && packageName in section)) {
      return manifestPath;
    }
  }

  return undefined;
}

function normalizeVersionTarget(fixedVersion?: string): string | undefined {
  if (!fixedVersion) {
    return undefined;
  }

  const first = fixedVersion
    .split(",")
    .map((value) => value.trim())
    .find(Boolean);

  return first || fixedVersion;
}

function buildHeuristicReviewNotes(finding: RemediationFinding, reproducibilityWarnings: string[]): string[] {
  const notes: string[] = [];

  if (finding.sourceType === "sbom" && reproducibilityWarnings.length > 0) {
    notes.push("This repository produced a non-deterministic SBOM. Confirm the dependency tree with a lockfile before treating version upgrades as complete.");
  }

  if (finding.sourceType === "cbom" && finding.filePath && !fs.existsSync(finding.filePath)) {
    notes.push("The original finding location could not be re-opened from the cloned source. Verify the file path before editing.");
  }

  return notes;
}

export function enrichFinding(finding: RemediationFinding, context: RemediationContext) {
  const targetManifest = finding.sourceType === "sbom"
    ? findTargetManifest(context.sourcePath, finding.packageName)
    : undefined;

  return {
    finding,
    targetManifest,
    normalizedTargetVersion: normalizeVersionTarget(finding.fixedVersion),
    reviewNotes: buildHeuristicReviewNotes(finding, context.reproducibilityWarnings)
  };
}
