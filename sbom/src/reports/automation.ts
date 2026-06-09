/**
 * Post-scan automation module.
 * Bridges local/CI scanner output with GitHub issue creation, Slack alerts,
 * and report history tracking.
 */
import * as fs from "fs";
import * as https from "https";
import * as path from "path";
import { runNodeScript } from "../core/shell";
import { Args } from "../types";

type AutomationOptions = {
  outputDir: string;
  sourceRepoLabel: string;
  sourceBranch: string;
  historyFile: string;
};

function postJson(url: string, payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(payload));
    const req = https.request(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": body.length
      }
    }, (res) => {
      let response = "";
      res.on("data", (chunk) => { response += chunk; });
      res.on("end", () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
          return;
        }
        reject(new Error(`Slack webhook failed ${res.statusCode}: ${response}`));
      });
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function buildRunUrl(outputDir: string): string {
  return `local-run:${outputDir.replace(/\\/g, "/")}`;
}

export async function runPostScanAutomation(args: Args, opts: AutomationOptions): Promise<void> {
  const scriptsDir = path.resolve(__dirname, "..", "..", "scripts");
  const gateReport = path.join(opts.outputDir, "gate-result.json");
  const issueResult = path.join(opts.outputDir, "issue-result.json");
  const slackPayload = path.join(opts.outputDir, "slack-payload.json");
  const runUrl = buildRunUrl(opts.outputDir);

  if (args.enableIssueCreation && args.githubToken && args.githubRepo) {
    runNodeScript(path.join(scriptsDir, "create_github_issue.js"), [
      "--repo", args.githubRepo,
      "--report", gateReport,
      "--run-url", runUrl,
      "--token", args.githubToken,
      "--source-repo", opts.sourceRepoLabel,
      "--source-branch", opts.sourceBranch,
      "--output", issueResult
    ]);
  } else if (!fs.existsSync(issueResult)) {
    fs.writeFileSync(issueResult, JSON.stringify({
      mode: "skipped",
      reason: "github_issue_automation_disabled_or_unconfigured"
    }, null, 2), "utf-8");
  }

  if (args.enableSlack) {
    runNodeScript(path.join(scriptsDir, "build_slack_payload.js"), [
      "--report-dir", opts.outputDir,
      "--run-url", runUrl,
      "--source-repo", opts.sourceRepoLabel,
      "--source-branch", opts.sourceBranch,
      "--output", slackPayload
    ]);

    if (args.slackWebhookUrl) {
      const payload = JSON.parse(fs.readFileSync(slackPayload, "utf-8"));
      await postJson(args.slackWebhookUrl, payload);
    }
  }

  runNodeScript(path.join(scriptsDir, "manage_reports.js"), [
    "--report-dir", opts.outputDir,
    "--run-id", new Date().getTime().toString(),
    "--run-attempt", "1",
    "--sha", "local-run",
    "--ref", opts.sourceBranch,
    "--actor", process.env.USERNAME || process.env.USER || "local-user",
    "--source-repo", opts.sourceRepoLabel,
    "--source-branch", opts.sourceBranch,
    "--history-file", opts.historyFile
  ]);
}
