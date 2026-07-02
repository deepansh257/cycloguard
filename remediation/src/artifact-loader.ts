/**
 * Reads SBOM and CBOM scan artifacts and converts them into a normalized
 * remediation context that the planner can reason about consistently.
 */
import * as fs from "fs";
import * as path from "path";
import { RemediationArgs, RemediationContext, RemediationFinding } from "./types";

type GateResult = {
  reproducibility?: {
    warnings?: Array<{ warning?: string }>;
  };
  vulnerabilities?: Array<{
    app?: string;
    severity?: string;
    cve_id?: string;
    package?: string;
    installed?: string;
    fixed?: string;
    title?: string;
  }>;
};

type CbomComponent = {
  "bom-ref"?: string;
  name?: string;
  evidence?: {
    occurrences?: Array<{
      location?: string;
      line?: number;
    }>;
  };
  properties?: Array<{
    name?: string;
    value?: string;
  }>;
};

type CbomDocument = {
  components?: CbomComponent[];
};

function readJsonFile<T>(filePath: string): T | null {
  if (!fs.existsSync(filePath)) {
    return null;
  }

  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
  } catch {
    return null;
  }
}

function normalizeLocation(sourcePath: string, location?: string): string | undefined {
  if (!location) {
    return undefined;
  }

  const trimmed = location.replace(/^[\\/]+/, "");
  if (!trimmed) {
    return undefined;
  }

  return path.join(sourcePath, trimmed);
}

function readSnippet(filePath?: string, line?: number): string | undefined {
  if (!filePath || !line || !fs.existsSync(filePath)) {
    return undefined;
  }

  try {
    const lines = fs.readFileSync(filePath, "utf-8").split(/\r?\n/);
    const start = Math.max(line - 2, 0);
    const end = Math.min(line + 1, lines.length);
    return lines.slice(start, end).join("\n").trim() || undefined;
  } catch {
    return undefined;
  }
}

function mapSbomFindings(gateResult: GateResult | null): RemediationFinding[] {
  if (!gateResult?.vulnerabilities?.length) {
    return [];
  }

  const deduped = new Map<string, RemediationFinding>();

  for (const vulnerability of gateResult.vulnerabilities) {
    const packageName = vulnerability.package || "unknown-package";
    const vulnerabilityId = vulnerability.cve_id || vulnerability.title || "unknown-vuln";
    const installedVersion = vulnerability.installed;
    const key = [
      vulnerability.app || "sbom",
      packageName,
      vulnerabilityId,
      installedVersion || ""
    ].join("|");

    if (deduped.has(key)) {
      continue;
    }

    deduped.set(key, {
      id: key.replace(/[^a-zA-Z0-9|._-]/g, "_"),
      sourceType: "sbom",
      category: "dependency",
      severity: vulnerability.severity || "UNKNOWN",
      title: vulnerability.title || vulnerabilityId,
      packageName,
      vulnerabilityId,
      installedVersion,
      fixedVersion: vulnerability.fixed,
      notes: vulnerability.app ? `Detected by ${vulnerability.app} scan.` : undefined
    });
  }

  return Array.from(deduped.values());
}

function getPropertyMap(component: CbomComponent): Map<string, string> {
  const properties = new Map<string, string>();
  for (const property of component.properties || []) {
    if (!property.name || typeof property.value !== "string") {
      continue;
    }
    properties.set(property.name, property.value);
  }
  return properties;
}

function mapCbomFindings(cbomDocument: CbomDocument | null, sourcePath: string): RemediationFinding[] {
  if (!cbomDocument?.components?.length) {
    return [];
  }

  return cbomDocument.components.map((component, index) => {
    const properties = getPropertyMap(component);
    const occurrence = component.evidence?.occurrences?.[0];
    const filePath = normalizeLocation(sourcePath, occurrence?.location);
    const line = occurrence?.line;
    const snippet = properties.get("cbom-js:codeSnippet") || readSnippet(filePath, line);

    return {
      id: (component["bom-ref"] || `cbom-${index}`).replace(/[^a-zA-Z0-9:._-]/g, "_"),
      sourceType: "cbom",
      category: "crypto",
      severity: properties.get("cbom-js:severity") || "UNKNOWN",
      title: component.name || "Unknown crypto finding",
      vulnerabilityId: properties.get("cbom-js:cwe"),
      filePath,
      line,
      snippet,
      notes: properties.get("cbom-js:notes")
    } satisfies RemediationFinding;
  });
}

export function loadRemediationContext(args: RemediationArgs): RemediationContext {
  const gateResult = readJsonFile<GateResult>(path.join(args.runDir, "sbom", "gate-result.json"));
  const cbomDocument = readJsonFile<CbomDocument>(path.join(args.runDir, "cbom", "cbom.json"));

  const reproducibilityWarnings = (gateResult?.reproducibility?.warnings || [])
    .map((item) => item.warning)
    .filter((warning): warning is string => Boolean(warning));

  return {
    sourceRepo: args.sourceRepo,
    sourceBranch: args.sourceBranch,
    sourcePath: args.sourcePath,
    threshold: args.threshold,
    reproducibilityWarnings,
    findings: [
      ...mapSbomFindings(gateResult),
      ...mapCbomFindings(cbomDocument, args.sourcePath)
    ]
  };
}
