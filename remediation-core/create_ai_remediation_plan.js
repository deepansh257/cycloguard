#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const https = require("https");

function getArg(name, fallback = null) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function safeReadContext(repoRoot, location, lineNumber) {
  if (!repoRoot || !location) return "";
  const absolute = path.isAbsolute(location) ? location : path.join(repoRoot, location);
  if (!fs.existsSync(absolute)) return "";
  const lines = fs.readFileSync(absolute, "utf8").split(/\r?\n/);
  const line = Math.max(1, Number(lineNumber || 1));
  const start = Math.max(0, line - 3);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).map((value, index) => `${start + index + 1}: ${value}`).join("\n");
}

function normalizeSbom(reportPath) {
  const gate = readJson(reportPath);
  const vulnerabilities = Array.isArray(gate.vulnerabilities) ? gate.vulnerabilities : [];
  return vulnerabilities
    .filter((item) => ["HIGH", "CRITICAL"].includes(item.severity))
    .map((item, index) => ({
      id: `sbom-${index + 1}`,
      sourceType: "sbom",
      language: item.app === "filesystem" ? "node" : item.app,
      fixKind: "dependency",
      packageName: item.package,
      vulnerabilityId: item.cve_id,
      installedVersion: item.installed || "",
      fixedVersion: item.fixed || "",
      severity: item.severity,
      title: item.title || item.cve_id,
      evidence: item
    }));
}

function getProperty(component, name) {
  const props = Array.isArray(component.properties) ? component.properties : [];
  const match = props.find((prop) => prop && prop.name === name);
  return match ? match.value : undefined;
}

function normalizeCbom(reportPath, repoRoot) {
  const cbom = readJson(reportPath);
  const components = Array.isArray(cbom.components) ? cbom.components : [];
  return components
    .map((component, index) => {
      const occurrence = component?.evidence?.occurrences?.[0] || {};
      const severity = (getProperty(component, "cbom-js:severity") || "LOW").toUpperCase();
      const location = occurrence.location || "";
      const line = occurrence.line || 1;
      const context = getProperty(component, "cbom-js:codeSnippet") || safeReadContext(repoRoot, location, line);
      return {
        id: `cbom-${index + 1}`,
        sourceType: "cbom",
        language: inferCbomLanguage(location),
        fixKind: "code",
        packageName: getProperty(component, "cbom-js:library") || "source-code",
        vulnerabilityId: component["bom-ref"] || `cbom-${index + 1}`,
        severity,
        title: component.name || "Cryptographic issue",
        file: location,
        line,
        context,
        notes: getProperty(component, "cbom-js:notes") || "",
        cwe: collectCwe(component)
      };
    })
    .filter((item) => ["HIGH", "CRITICAL"].includes(item.severity));
}

function inferCbomLanguage(location) {
  const ext = path.extname(location || "").toLowerCase();
  if ([".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"].includes(ext)) return "node";
  if (ext === ".py") return "python";
  if (ext === ".java") return "java";
  if (ext === ".cs") return "csharp";
  return "node";
}

function collectCwe(component) {
  const props = Array.isArray(component.properties) ? component.properties : [];
  return props.filter((prop) => prop.name === "cbom-js:cwe").map((prop) => prop.value);
}

function cbomRulesByLanguage() {
  return {
    node: [
      "Keep JavaScript/TypeScript fixes minimal and localized.",
      "Prefer replacing hardcoded secrets with process.env access.",
      "Prefer crypto.randomBytes or Web Crypto APIs over Math.random for security-sensitive randomness.",
      "Do not change function signatures or module exports unless strictly required.",
      "Do not invent new dependencies unless the finding explicitly requires one and the confidence is high."
    ],
    python: [
      "Keep Python fixes minimal and localized.",
      "Prefer os.environ or secure secret stores over hardcoded secrets.",
      "Prefer secrets or hashlib-compatible secure APIs over weak/random sources for security-sensitive operations.",
      "Avoid changing public function signatures or package structure.",
      "Do not introduce new dependencies unless clearly necessary and high confidence."
    ],
    java: [
      "Keep Java fixes minimal and localized.",
      "Prefer SecureRandom and standard JCA secure APIs over weak randomness or outdated crypto choices.",
      "Prefer environment or configuration-backed secrets over hardcoded values.",
      "Avoid changing method signatures, class names, or package structure.",
      "Do not add external libraries unless the recommendation is high confidence and clearly justified."
    ],
    csharp: [
      "Keep C# fixes minimal and localized.",
      "Prefer RandomNumberGenerator or other secure .NET cryptography APIs over weak randomness.",
      "Prefer IConfiguration or environment-based secrets over hardcoded values.",
      "Do not change public APIs, namespaces, or project structure unless strictly required.",
      "Do not add packages unless the recommendation is high confidence and clearly necessary."
    ]
  };
}

function buildFallbackPlan(sourceType, findings, meta) {
  const items = findings.map((finding) => {
    if (sourceType === "sbom") {
      if (!finding.fixedVersion) {
        return {
          id: finding.id,
          sourceType,
          language: finding.language,
          fixKind: "dependency",
          packageName: finding.packageName,
          vulnerabilityId: finding.vulnerabilityId,
          installedVersion: finding.installedVersion,
          targetVersion: "",
          severity: finding.severity,
          confidence: "low",
          rationale: "No fixed version was available in the SBOM report.",
          status: "no_fixed_version",
          autoApply: false
        };
      }
      return {
        id: finding.id,
        sourceType,
        language: finding.language,
        fixKind: "dependency",
        packageName: finding.packageName,
        vulnerabilityId: finding.vulnerabilityId,
        installedVersion: finding.installedVersion,
        targetVersion: finding.fixedVersion,
        severity: finding.severity,
        confidence: "high",
        rationale: `Using Trivy fixed version ${finding.fixedVersion} for ${finding.packageName}.`,
        status: "planned",
        autoApply: true
      };
    }

    return {
      id: finding.id,
      sourceType,
      language: finding.language,
      fixKind: "manual",
      packageName: finding.packageName,
      vulnerabilityId: finding.vulnerabilityId,
      targetVersion: "",
      severity: finding.severity,
      confidence: "low",
      rationale: "AI key not configured, so only a manual recommendation can be produced for CBOM findings.",
      status: "unsupported",
      autoApply: false,
      notes: `${finding.title} at ${finding.file}:${finding.line}`
    };
  });

  return {
    plannerMode: "fallback",
    createdAt: new Date().toISOString(),
    sourceType,
    sourceRepo: meta.sourceRepo,
    sourceBranch: meta.sourceBranch,
    threshold: meta.threshold,
    items
  };
}

function callOpenAI(model, apiKey, input) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({
      model,
      response_format: { type: "json_object" },
      messages: input
    }));

    const req = https.request("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "Content-Length": payload.length
      }
    }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const parsed = JSON.parse(body);
            const content = parsed?.choices?.[0]?.message?.content;
            if (!content) {
              reject(new Error("OpenAI response did not contain message content."));
              return;
            }
            resolve(JSON.parse(content));
          } catch (err) {
            reject(err);
          }
          return;
        }
        reject(new Error(`OpenAI API failed ${res.statusCode}: ${body}`));
      });
    });

    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function buildPrompt(sourceType, findings, meta) {
  const cbomRules = cbomRulesByLanguage();
  const system = [
    "You are a security remediation planner.",
    "Return JSON only.",
    "Plan minimal, reviewable fixes.",
    "Prefer direct dependency upgrades for SBOM findings.",
    "For CBOM findings, only propose exact text replacements when confidence is high and the replacement is clearly safer.",
    "For CBOM findings, follow the provided language-specific coding rules strictly.",
    "For CBOM findings, only emit operations when the exact search text exists in the provided context or can be derived safely from it.",
    "For CBOM findings, if you are not highly confident, mark the item unsupported instead of guessing.",
    "If a safe auto-fix is not possible, mark the item as unsupported and explain why.",
    "Output schema:",
    "{ plannerMode, createdAt, sourceType, sourceRepo, sourceBranch, threshold, items: [{ id, sourceType, language, fixKind, packageName, vulnerabilityId, installedVersion?, targetVersion, severity, confidence, rationale, status, autoApply, targetFile?, operations?, notes? }] }"
  ].join(" ");

  const user = {
    sourceType,
    sourceRepo: meta.sourceRepo,
    sourceBranch: meta.sourceBranch,
    threshold: meta.threshold,
    findings,
    cbomLanguageRules: sourceType === "cbom" ? cbomRules : undefined
  };

  return [
    { role: "system", content: system },
    { role: "user", content: JSON.stringify(user) }
  ];
}

async function main() {
  const sourceType = getArg("source-type");
  const reportPath = getArg("report");
  const repoRoot = getArg("repo-root");
  const outputPath = getArg("output");
  const sourceRepo = getArg("source-repo", "unknown-repo");
  const sourceBranch = getArg("source-branch", "unknown-branch");
  const threshold = getArg("threshold", "high");
  const apiKey = process.env.OPENAI_API_KEY || process.env.API_OPENAI_KEY || process.env.OPENAI_KEY;
  const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

  if (!sourceType || !reportPath || !outputPath) {
    console.error("Missing required args: --source-type --report --output");
    process.exit(1);
  }

  const findings = sourceType === "sbom"
    ? normalizeSbom(reportPath)
    : normalizeCbom(reportPath, repoRoot);

  const meta = { sourceRepo, sourceBranch, threshold };

  if (findings.length === 0) {
    writeJson(outputPath, {
      plannerMode: apiKey ? "ai" : "fallback",
      createdAt: new Date().toISOString(),
      sourceType,
      sourceRepo,
      sourceBranch,
      threshold,
      items: []
    });
    return;
  }

  if (!apiKey) {
    writeJson(outputPath, buildFallbackPlan(sourceType, findings, meta));
    return;
  }

  try {
    const aiPlan = await callOpenAI(model, apiKey, buildPrompt(sourceType, findings, meta));
    writeJson(outputPath, {
      plannerMode: "ai",
      createdAt: new Date().toISOString(),
      sourceType,
      sourceRepo,
      sourceBranch,
      threshold,
      items: Array.isArray(aiPlan.items) ? aiPlan.items : []
    });
  } catch (err) {
    writeJson(outputPath, {
      ...buildFallbackPlan(sourceType, findings, meta),
      plannerMode: "fallback",
      fallbackReason: err instanceof Error ? err.message : String(err)
    });
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
