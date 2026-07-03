/**
 * Applies approved remediation items using deterministic file operations only.
 * This first version supports exact text replacement and structured dependency
 * version updates, while leaving ambiguous items for manual handling.
 */
import * as fs from "fs";
import * as path from "path";
import {
  RemediationApplyArgs,
  RemediationApplyItemResult,
  RemediationApplyResult,
  RemediationApprovalDocument,
  RemediationApprovalItem,
  RemediationPlan,
  RemediationPlanItem
} from "./types";

function readJsonFile<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
}

function writeJsonFile(filePath: string, data: unknown): void {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function resolveTargetFile(sourcePath: string, targetFile?: string): string | undefined {
  if (!targetFile) {
    return undefined;
  }

  if (path.isAbsolute(targetFile)) {
    return targetFile;
  }

  return path.join(sourcePath, targetFile);
}

function getApprovalMap(document: RemediationApprovalDocument): Map<string, RemediationApprovalItem> {
  return new Map(document.items.map((item) => [item.id, item]));
}

function shouldApplyItem(item: RemediationPlanItem, approval?: RemediationApprovalItem): { apply: boolean; reason: string } {
  if (!approval) {
    return { apply: false, reason: "No approval entry found." };
  }

  if (approval.status !== "approved") {
    return { apply: false, reason: `Approval status is '${approval.status}'.` };
  }

  if (!item.autoApplicable) {
    return { apply: false, reason: "Item is not marked auto-applicable." };
  }

  return { apply: true, reason: "Approved for apply." };
}

function updatePackageJsonVersion(filePath: string, packageName: string, targetVersion: string): boolean {
  const manifest = readJsonFile<Record<string, any>>(filePath);
  const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
  let updated = false;

  for (const section of sections) {
    if (manifest[section] && typeof manifest[section] === "object" && packageName in manifest[section]) {
      manifest[section][packageName] = targetVersion;
      updated = true;
    }
  }

  if (!updated) {
    return false;
  }

  fs.writeFileSync(filePath, `${JSON.stringify(manifest, null, 2)}\n`, "utf-8");
  return true;
}

function applyReplaceOperation(targetFile: string, searchText?: string, replaceText?: string): { changed: boolean; reason: string } {
  if (!searchText || typeof replaceText !== "string") {
    return { changed: false, reason: "Replace operation is missing searchText or replaceText." };
  }

  if (!fs.existsSync(targetFile)) {
    return { changed: false, reason: `Target file does not exist: ${targetFile}` };
  }

  const content = fs.readFileSync(targetFile, "utf-8");
  if (!content.includes(searchText)) {
    return { changed: false, reason: "Expected search text was not found. The remediation plan is stale." };
  }

  fs.writeFileSync(targetFile, content.replace(searchText, replaceText), "utf-8");
  return { changed: true, reason: "Applied exact text replacement." };
}

function applyUpgradeOperation(item: RemediationPlanItem, sourcePath: string): { filesChanged: string[]; reason: string; success: boolean } {
  const operation = item.operations.find((entry) => entry.type === "upgrade");
  const targetFile = resolveTargetFile(sourcePath, operation?.file || item.targetFile);

  if (!operation || !targetFile) {
    return { filesChanged: [], reason: "Upgrade operation is missing a target file.", success: false };
  }

  if (!fs.existsSync(targetFile)) {
    return { filesChanged: [], reason: `Target file does not exist: ${targetFile}`, success: false };
  }

  if (operation.searchText && typeof operation.replaceText === "string") {
    const replaced = applyReplaceOperation(targetFile, operation.searchText, operation.replaceText);
    return { filesChanged: replaced.changed ? [targetFile] : [], reason: replaced.reason, success: replaced.changed };
  }

  if (item.packageName && item.targetVersion && path.basename(targetFile) === "package.json") {
    const updated = updatePackageJsonVersion(targetFile, item.packageName, item.targetVersion);
    return {
      filesChanged: updated ? [targetFile] : [],
      reason: updated ? "Updated dependency version in package.json." : `Package ${item.packageName} was not found in ${targetFile}.`,
      success: updated
    };
  }

  return { filesChanged: [], reason: "Upgrade operation could not be applied deterministically.", success: false };
}

function applyPlanItem(item: RemediationPlanItem, sourcePath: string): RemediationApplyItemResult {
  const supportedOperation = item.operations.find((operation) => operation.type === "upgrade" || operation.type === "replace");
  if (!supportedOperation) {
    return {
      id: item.id,
      status: "skipped",
      reason: "No supported auto-apply operation found. Manual remediation required.",
      filesChanged: []
    };
  }

  if (supportedOperation.type === "upgrade") {
    const result = applyUpgradeOperation(item, sourcePath);
    return {
      id: item.id,
      status: result.success ? "applied" : "failed",
      reason: result.reason,
      filesChanged: result.filesChanged
    };
  }

  const targetFile = resolveTargetFile(sourcePath, supportedOperation.file || item.targetFile);
  if (!targetFile) {
    return {
      id: item.id,
      status: "failed",
      reason: "Replace operation is missing a target file.",
      filesChanged: []
    };
  }

  const result = applyReplaceOperation(targetFile, supportedOperation.searchText, supportedOperation.replaceText);
  return {
    id: item.id,
    status: result.changed ? "applied" : "failed",
    reason: result.reason,
    filesChanged: result.changed ? [targetFile] : []
  };
}

function mergeStatusesIntoPlan(plan: RemediationPlan, itemResults: RemediationApplyItemResult[]): RemediationPlan {
  const resultMap = new Map(itemResults.map((item) => [item.id, item]));
  return {
    ...plan,
    items: plan.items.map((item) => {
      const result = resultMap.get(item.id);
      if (!result) {
        return item;
      }

      return {
        ...item,
        approvalStatus: result.status
      };
    })
  };
}

export function applyApprovedRemediations(args: RemediationApplyArgs): {
  applyResult: RemediationApplyResult;
  updatedPlan: RemediationPlan;
  applyResultPath: string;
  updatedPlanPath: string;
} {
  const remediationDir = path.join(args.runDir, "remediation");
  const planPath = path.join(remediationDir, "remediation-plan.json");
  const approvalPath = path.join(remediationDir, "remediation-approval.json");

  if (!fs.existsSync(planPath)) {
    throw new Error(`Remediation plan not found at ${planPath}`);
  }

  if (!fs.existsSync(approvalPath)) {
    throw new Error(`Remediation approval file not found at ${approvalPath}`);
  }

  const plan = readJsonFile<RemediationPlan>(planPath);
  const approvals = readJsonFile<RemediationApprovalDocument>(approvalPath);
  const approvalMap = getApprovalMap(approvals);
  const sourcePath = args.sourcePath || plan.sourcePath;

  if (!sourcePath) {
    throw new Error("No source path available for remediation apply.");
  }

  const itemResults = plan.items.map((item) => {
    const approval = approvalMap.get(item.id);
    const eligibility = shouldApplyItem(item, approval);
    if (!eligibility.apply) {
      return {
        id: item.id,
        status: "skipped",
        reason: eligibility.reason,
        filesChanged: []
      } satisfies RemediationApplyItemResult;
    }

    return applyPlanItem(item, sourcePath);
  });

  const updatedPlan = mergeStatusesIntoPlan(plan, itemResults);
  const applyResult: RemediationApplyResult = {
    createdAt: new Date().toISOString(),
    runDir: args.runDir,
    sourcePath,
    items: itemResults
  };

  const applyResultPath = path.join(remediationDir, "remediation-apply-result.json");
  writeJsonFile(planPath, updatedPlan);
  writeJsonFile(applyResultPath, applyResult);

  return {
    applyResult,
    updatedPlan,
    applyResultPath,
    updatedPlanPath: planPath
  };
}
