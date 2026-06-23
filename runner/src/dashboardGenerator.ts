import * as fs from 'fs';
import * as path from 'path';

// ── Types matching the actual JSON shapes ─────────────────────────────────────

interface CbomProperty { name: string; value: string; }
interface CbomOccurrence { location: string; line: number; offset?: number; symbol?: string; }
interface CbomComponent {
  type: string;
  name: string;
  'bom-ref': string;
  properties?: CbomProperty[];
  evidence?: { occurrences?: CbomOccurrence[] };
  cryptoProperties?: {
    assetType?: string;
    oid?: string;
    algorithmProperties?: Record<string, unknown>;
  };
}
interface CbomJson {
  metadata?: {
    timestamp?: string;
    component?: { name?: string };
    properties?: CbomProperty[];
  };
  components?: CbomComponent[];
  vulnerabilities?: unknown[];
}

interface SbomVuln {
  app?: string;
  severity?: string;
  cve_id?: string;
  package?: string;
  installed?: string;
  fixed?: string;
  title?: string;
}
interface SbomSecret {
  app?: string;
  severity?: string;
  rule_id?: string;
  category?: string;
  title?: string;
  target?: string;
  start_line?: number | null;
  end_line?: number | null;
}
interface ReproducibilityWarning {
  language?: string;
  project_id?: string;
  project_path?: string;
  source_of_truth_type?: string;
  source_of_truth_files?: string[];
  warning?: string;
}
interface SourceSelectionEntry {
  language?: string;
  project_id?: string;
  project_path?: string;
  source_of_truth_type?: string;
  source_of_truth_files?: string[];
  supporting_files?: string[];
  reproducibility?: string;
}
interface ReproducibilitySummary {
  deterministic_projects?: number;
  non_deterministic_projects?: number;
  source_selection?: SourceSelectionEntry[];
  warnings?: ReproducibilityWarning[];
}
interface SbomJson {
  gate_failed?: boolean;
  threshold?: string;
  total_vulnerabilities?: number;
  total_secrets?: number;
  total_findings?: number;
  counts?: Record<string, number>;
  secret_counts?: Record<string, number>;
  finding_counts?: Record<string, number>;
  reproducibility?: ReproducibilitySummary;
  vulnerabilities?: SbomVuln[];
  secrets?: SbomSecret[];
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface DashboardOptions {
  runDir:      string;   // the timestamped output dir, e.g. .../juice-shop-2026-06-16T05-40-56
  projectName: string;
  scanMode:    string;   // 'cbom' | 'sbom' | 'all'
}

export function generateDashboard(opts: DashboardOptions): string {
  const cbomFile = path.join(opts.runDir, 'cbom', 'cbom.json');
  const sbomFile = path.join(opts.runDir, 'sbom', 'gate-result.json');

  // locate the short vulnerability summary JSON inside sbom output dir

  const cbomData: CbomJson | null = readJson(cbomFile);
  const sbomData: SbomJson | null = readJson(sbomFile);

  const html = buildHtml(opts.projectName, cbomData, sbomData);

  const outFile = path.join(opts.runDir, 'dashboard.html');
  fs.writeFileSync(outFile, html, 'utf-8');
  return outFile;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function readJson(filePath: string | null): any | null {
  if (!filePath || !fs.existsSync(filePath)) return null;
  try { return JSON.parse(fs.readFileSync(filePath, 'utf-8')); }
  catch { return null; }
}

// ── Derive stats from data ─────────────────────────────────────────────────

interface CbomStats {
  totalFindings:  number;
  bySeverity:     Record<string, number>;
  byAlgo:         Record<string, number>;
  filesScanned:   string;
  scanDuration:   string;
  weakCount:      number;
  qvCount:        number;
  timestamp:      string;
}

function getCbomStats(data: CbomJson): CbomStats {
  const comps = data.components ?? [];
  const getProp  = (c: CbomComponent, name: string) =>
    (c.properties ?? []).filter(p => p.name === name).map(p => p.value);
  const getMeta  = (name: string) =>
    (data.metadata?.properties ?? []).find(p => p.name === `cbom-js:${name}`)?.value ?? '';

  const bySeverity: Record<string, number> = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0 };
  const byAlgo:     Record<string, number> = {};

  for (const c of comps) {
    const sev = getProp(c, 'cbom-js:severity')[0] ?? 'UNKNOWN';
    if (bySeverity[sev] !== undefined) bySeverity[sev]++;
    byAlgo[c.name] = (byAlgo[c.name] ?? 0) + 1;
  }

  return {
    totalFindings: comps.length,
    bySeverity,
    byAlgo,
    filesScanned:  getMeta('filesScanned'),
    scanDuration:  getMeta('scanDuration'),
    weakCount:     comps.filter(c => getProp(c,'cbom-js:weak')[0] === 'true').length,
    qvCount:       comps.filter(c => getProp(c,'cbom-js:quantumSafe')[0] === 'false').length,
    timestamp:     data.metadata?.timestamp ?? '',
  };
}

interface SbomStats {
  total:      number;
  totalSecrets: number;
  totalFindings: number;
  bySeverity: Record<string, number>;
  secretBySeverity: Record<string, number>;
  findingBySeverity: Record<string, number>;
  byPackage:  Record<string, number>;
  gateFailed: boolean;
  threshold:  string;
  reproducibility: ReproducibilitySummary;
}

function getSbomStats(data: SbomJson): SbomStats {
  const unique = dedupeVulns(data.vulnerabilities ?? []);
  const secrets = data.secrets ?? [];
  const bySeverity: Record<string, number> = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  const secretBySeverity: Record<string, number> = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  const findingBySeverity: Record<string, number> = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  const byPackage:  Record<string, number> = {};

  for (const v of unique) {
    const sev = (v.severity ?? 'UNKNOWN').toUpperCase();
    if (bySeverity[sev] !== undefined) bySeverity[sev]++;
    if (findingBySeverity[sev] !== undefined) findingBySeverity[sev]++;
    if (v.package) byPackage[v.package] = (byPackage[v.package] ?? 0) + 1;
  }

  for (const secret of secrets) {
    const sev = (secret.severity ?? 'UNKNOWN').toUpperCase();
    if (secretBySeverity[sev] !== undefined) secretBySeverity[sev]++;
    if (findingBySeverity[sev] !== undefined) findingBySeverity[sev]++;
  }

  return {
    total:      unique.length,
    totalSecrets: secrets.length,
    totalFindings: unique.length + secrets.length,
    bySeverity,
    secretBySeverity,
    findingBySeverity,
    byPackage,
    gateFailed: data.gate_failed ?? false,
    threshold:  data.threshold ?? '',
    reproducibility: data.reproducibility ?? {},
  };
}

function dedupeVulns(vulns: SbomVuln[]): SbomVuln[] {
  const seen = new Set<string>();
  return vulns.filter(v => {
    const key = [v.cve_id, v.package, v.installed].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ── Serialise data into the page so the browser JS can use it ──────────────

function buildDataScript(cbomData: CbomJson | null, sbomData: SbomJson | null): string {
  const cbomComponents = cbomData?.components ?? [];
  const sbomVulns      = sbomData ? dedupeVulns(sbomData.vulnerabilities ?? []) : [];
  const sbomSecrets    = sbomData?.secrets ?? [];

  // Slim the component list — strip the large codeSnippet for the embedded
  // dataset; we still emit it but gzip / browser cache handle it fine.
  const safeComponents = cbomComponents.map(c => {
    const props = (c.properties ?? []);
    return {
      name:  c.name,
      props: props.reduce<Record<string, string[]>>((acc, p) => {
        const k = p.name.replace('cbom-js:', '');
        (acc[k] = acc[k] ?? []).push(p.value);
        return acc;
      }, {}),
      occurrences: (c.evidence?.occurrences ?? []).map(o => ({
        location: o.location,
        line:     o.line,
      })),
    };
  });

  return `<script>
const CBOM_COMPONENTS = ${JSON.stringify(safeComponents)};
const SBOM_VULNS      = ${JSON.stringify(sbomVulns)};
const SBOM_SECRETS    = ${JSON.stringify(sbomSecrets)};
const CBOM_STATS      = ${cbomData  ? JSON.stringify(getCbomStats(cbomData))  : 'null'};
const SBOM_STATS      = ${sbomData  ? JSON.stringify(getSbomStats(sbomData))  : 'null'};
const GATE_FAILED     = ${sbomData?.gate_failed ?? false};
const SCAN_THRESHOLD  = ${JSON.stringify(sbomData?.threshold ?? '')};
</script>`;
}

// ── HTML builder ─────────────────────────────────────────────────────────────

function buildHtml(
  projectName: string,
  cbomData:    CbomJson | null,
  sbomData:    SbomJson | null,
): string {
  const timestamp = cbomData?.metadata?.timestamp
    ? new Date(cbomData.metadata.timestamp).toLocaleString('en-GB', { dateStyle:'medium', timeStyle:'short' })
    : new Date().toLocaleString('en-GB', { dateStyle:'medium', timeStyle:'short' });

  const hasCbom = !!cbomData;
  const hasSbom = !!sbomData;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Cycloguard — ${esc(projectName)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400&display=swap" />
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f5f4f0;--surface:#ffffff;--surface2:#f0eee8;
  --border:rgba(0,0,0,.10);--border2:rgba(0,0,0,.18);
  --text:#1a1918;--muted:#6b6a66;--hint:#9c9b97;
  --radius:10px;--radius-lg:14px;
  --font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono','Fira Code',monospace;
  --purple:#534AB7;--purple-bg:#EEEDFE;--purple-tx:#26215C;
  --red:#A32D2D;--red-bg:#FCEBEB;--red-tx:#501313;
  --amber:#854F0B;--amber-bg:#FAEEDA;--amber-tx:#412402;
  --blue:#185FA5;--blue-bg:#E6F1FB;--blue-tx:#042C53;
  --green:#3B6D11;--green-bg:#EAF3DE;--green-tx:#173404;
  --gray-bg:#F1EFE8;--gray-tx:#2C2C2A;
}
@media(prefers-color-scheme:dark){
  :root{
    --bg:#18181a;--surface:#222226;--surface2:#2c2c31;
    --border:rgba(255,255,255,.10);--border2:rgba(255,255,255,.18);
    --text:#f0efe9;--muted:#9c9b97;--hint:#6b6a66;
    --purple-bg:#26215C;--purple-tx:#CECBF6;
    --red-bg:#501313;--red-tx:#F7C1C1;
    --amber-bg:#412402;--amber-tx:#FAC775;
    --blue-bg:#042C53;--blue-tx:#B5D4F4;
    --green-bg:#173404;--green-tx:#C0DD97;
    --gray-bg:#2C2C2A;--gray-tx:#D3D1C7;
  }
}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:15px;line-height:1.6}
a{color:var(--blue)}
.shell{max-width:1080px;margin:0 auto;padding:2rem 1.5rem}

/* header */
.hdr{display:flex;align-items:center;gap:14px;margin-bottom:2rem;flex-wrap:wrap}
.logo{width:42px;height:42px;border-radius:10px;background:var(--purple);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.logo svg{width:22px;height:22px;fill:none;stroke:#fff;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.hdr-text h1{font-size:20px;font-weight:600;letter-spacing:-.02em}
.hdr-text p{font-size:13px;color:var(--muted)}
.gate-badge{display:inline-flex;align-items:center;gap:5px;padding:5px 14px;border-radius:20px;font-size:12px;font-weight:600;margin-left:auto}
.gate-pass{background:var(--green-bg);color:var(--green-tx)}
.gate-fail{background:var(--red-bg);color:var(--red-tx)}

/* scan meta */
.scan-meta{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-bottom:1.5rem}

/* tabs */
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:1.5rem}
.tab{padding:9px 20px;font-size:14px;cursor:pointer;border-bottom:2px solid transparent;color:var(--muted);transition:color .15s;user-select:none}
.tab:hover{color:var(--text)}
.tab.active{color:var(--purple);border-bottom-color:var(--purple);font-weight:500}
.tab-panel{display:none}
.tab-panel.active{display:block}

/* metric cards */
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:10px;margin-bottom:1.25rem}
.mc{background:var(--surface2);border-radius:var(--radius);padding:14px 16px}
.mc-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.mc-val{font-size:24px;font-weight:600;letter-spacing:-.03em}
.c-crit{color:var(--red)}.c-high{color:var(--amber)}.c-med{color:var(--blue)}.c-safe{color:var(--green)}.c-muted{color:var(--muted)}

/* cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:1.25rem;margin-bottom:1.25rem}
.card-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:1rem}
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:1.25rem}
@media(max-width:640px){.charts-row{grid-template-columns:1fr}}
.chart-wrap{position:relative;height:240px}
.warn-card{background:var(--amber-bg);color:var(--amber-tx);border:1px solid rgba(133,79,11,.18);border-radius:var(--radius-lg);padding:1rem 1.25rem;margin-bottom:1.25rem}
.warn-card h3{font-size:13px;font-weight:600;margin-bottom:.4rem}
.warn-card p,.warn-card li{font-size:13px}
.warn-card ul{margin:.5rem 0 0 1rem}
.source-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin-bottom:1.25rem}
.source-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}
.source-card h4{font-size:13px;font-weight:600;margin-bottom:6px}
.source-card p{font-size:12px;color:var(--muted);margin-bottom:4px}

/* section label */
.section-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:1.5rem 0 .75rem}

/* filter bar */
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:1rem;align-items:center}
.filter-bar select,.filter-bar input{padding:6px 10px;border:1px solid var(--border2);border-radius:var(--radius);background:var(--surface);color:var(--text);font-size:13px;font-family:var(--font)}
.filter-bar input{flex:1;min-width:160px}

/* tables */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:480px}
thead tr{border-bottom:1px solid var(--border2)}
th{text-align:left;font-weight:600;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;padding:8px 12px}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--surface2)}

/* badges */
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600;white-space:nowrap}
.b-crit{background:var(--red-bg);color:var(--red-tx)}
.b-high{background:var(--amber-bg);color:var(--amber-tx)}
.b-med{background:var(--blue-bg);color:var(--blue-tx)}
.b-low{background:var(--green-bg);color:var(--green-tx)}
.b-info{background:var(--gray-bg);color:var(--gray-tx)}

/* mono */
.mono{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.loc{font-family:var(--mono);font-size:11px;color:var(--hint)}

/* snippet */
.snip-btn{font-size:11px;color:var(--blue);cursor:pointer;background:none;border:none;font-family:var(--font);padding:2px 0;display:block;margin-top:3px}
.snip-box{display:none;margin-top:6px;background:var(--surface2);border-radius:6px;padding:8px 10px;font-family:var(--mono);font-size:11px;white-space:pre-wrap;word-break:break-all;color:var(--text);max-height:140px;overflow:auto;border:1px solid var(--border)}

/* empty */
.empty{text-align:center;padding:4rem 2rem;color:var(--muted);font-size:14px}
</style>
</head>
<body>
<div class="shell">

  <div class="hdr">
    <div class="logo">
      <svg viewBox="0 0 24 24"><path d="M12 3L4 7v5c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V7L12 3z"/></svg>
    </div>
    <div class="hdr-text">
      <h1>Cycloguard — ${esc(projectName)}</h1>
      <p>Scan completed ${esc(timestamp)}</p>
    </div>
    <span id="gate-badge" class="gate-badge"></span>
  </div>

  <div class="scan-meta" id="scan-meta"></div>
  <div id="repro-warning"></div>

  <div class="tabs" id="tab-bar">
    <div class="tab active" data-tab="overview">Overview</div>
    ${hasCbom ? '<div class="tab" data-tab="cbom-tab">CBOM findings</div>' : ''}
    ${hasSbom ? '<div class="tab" data-tab="sbom-tab">SBOM findings</div>' : ''}
  </div>

  <!-- ── Overview ──────────────────────────────────────────────────────── -->
  <div class="tab-panel active" id="overview">
    <div id="cbom-overview" style="display:${hasCbom ? '' : 'none'}">
      <div class="section-label">Cryptographic findings (CBOM)</div>
      <div class="metrics" id="cbom-metrics"></div>
      <div class="charts-row">
        <div class="card">
          <div class="card-title">Findings by algorithm</div>
          <div class="chart-wrap"><canvas id="chart-algo" role="img" aria-label="CBOM findings by algorithm"></canvas></div>
        </div>
        <div class="card">
          <div class="card-title">Findings by severity</div>
          <div class="chart-wrap"><canvas id="chart-cbom-sev" role="img" aria-label="CBOM severity distribution"></canvas></div>
        </div>
      </div>
    </div>

    <div id="sbom-overview" style="display:${hasSbom ? '' : 'none'}">
      <div class="section-label">Dependency and secret findings (SBOM)</div>
      <div id="sbom-source-selection"></div>
      <div class="metrics" id="sbom-metrics"></div>
      <div class="charts-row">
        <div class="card">
          <div class="card-title">Top vulnerable packages</div>
          <div class="chart-wrap"><canvas id="chart-pkg" role="img" aria-label="SBOM vulnerabilities by package"></canvas></div>
        </div>
        <div class="card">
          <div class="card-title">All findings by severity</div>
          <div class="chart-wrap"><canvas id="chart-sbom-sev" role="img" aria-label="SBOM findings by severity"></canvas></div>
        </div>
      </div>
    </div>

    ${!hasCbom && !hasSbom ? '<div class="empty">No scan data available.</div>' : ''}
  </div>

  <!-- ── CBOM findings tab ──────────────────────────────────────────────── -->
  ${hasCbom ? `
  <div class="tab-panel" id="cbom-tab">
    <div class="filter-bar">
      <select id="cbom-sev-filter" onchange="renderCbomTable()">
        <option value="">All severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
        <option value="INFO">Info</option>
      </select>
      <input type="text" id="cbom-search" placeholder="Search algorithm, file, CWE…" oninput="renderCbomTable()" />
    </div>
    <div class="card" style="padding:0">
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th style="width:90px">Severity</th>
            <th>Algorithm</th>
            <th>CWE</th>
            <th>Location</th>
            <th>Library</th>
          </tr></thead>
          <tbody id="cbom-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>` : ''}

  <!-- ── SBOM vulnerabilities tab ───────────────────────────────────────── -->
  ${hasSbom ? `
  <div class="tab-panel" id="sbom-tab">
    <div class="section-label">Dependency vulnerabilities</div>
    <div class="filter-bar">
      <select id="sbom-sev-filter" onchange="renderSbomTable()">
        <option value="">All severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      <input type="text" id="sbom-search" placeholder="Search CVE, package, title…" oninput="renderSbomTable()" />
    </div>
    <div class="card" style="padding:0">
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th style="width:90px">Severity</th>
            <th>Package</th>
            <th>Installed</th>
            <th>Fixed in</th>
            <th>CVE / Advisory</th>
            <th>Description</th>
          </tr></thead>
          <tbody id="sbom-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="section-label">Secret findings</div>
    <div class="filter-bar">
      <select id="sbom-secret-sev-filter" onchange="renderSbomSecretTable()">
        <option value="">All severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      <input type="text" id="sbom-secret-search" placeholder="Search rule, category, file..." oninput="renderSbomSecretTable()" />
    </div>
    <div class="card" style="padding:0">
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th style="width:90px">Severity</th>
            <th>Rule</th>
            <th>Category</th>
            <th>Location</th>
            <th>Description</th>
          </tr></thead>
          <tbody id="sbom-secret-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>` : ''}

</div>

${buildDataScript(cbomData, sbomData)}

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
// ── constants ────────────────────────────────────────────────────────────────
const SEV_ORDER  = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'];
const SEV_COLOR  = { CRITICAL:'#A32D2D', HIGH:'#854F0B', MEDIUM:'#185FA5', LOW:'#3B6D11', INFO:'#888780', UNKNOWN:'#888780' };
const isDark     = matchMedia('(prefers-color-scheme:dark)').matches;
const chartTx    = isDark ? 'rgba(255,255,255,.55)' : 'rgba(0,0,0,.45)';
const chartGrid  = isDark ? 'rgba(255,255,255,.07)' : 'rgba(0,0,0,.07)';
const charts     = {};

// ── tabs ──────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById(t.dataset.tab).classList.add('active');
  });
});

// ── helpers ───────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function sevBadge(s) {
  const cls = { CRITICAL:'b-crit', HIGH:'b-high', MEDIUM:'b-med', LOW:'b-low', INFO:'b-info', UNKNOWN:'b-info' };
  return '<span class="badge ' + (cls[s]||'b-info') + '">' + s + '</span>';
}
function shortText(t, n) { return t && t.length > n ? t.slice(0,n)+'…' : (t||''); }

function mkBarChart(id, labels, data, color) {
  if (charts[id]) charts[id].destroy();
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ data, backgroundColor: color, borderWidth: 0, borderRadius: 4 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: chartTx, font: { size: 11 }, maxRotation: 35, autoSkip: false }, grid: { color: chartGrid } },
        y: { ticks: { color: chartTx, font: { size: 11 }, precision: 0 }, grid: { color: chartGrid } }
      }
    }
  });
}

function mkDoughnut(id, labels, data, colors) {
  if (charts[id]) charts[id].destroy();
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: true, position: 'right', labels: { color: chartTx, font: { size: 11 }, boxWidth: 12, padding: 12 } } }
    }
  });
}

// ── gate badge + scan meta ────────────────────────────────────────────────────
function renderHeader() {
  const badge = document.getElementById('gate-badge');
  if (SBOM_STATS) {
    badge.className = 'gate-badge ' + (GATE_FAILED ? 'gate-fail' : 'gate-pass');
    badge.textContent = GATE_FAILED
      ? '⚠ Quality gate failed (threshold: ' + SCAN_THRESHOLD + ')'
      : '✓ Quality gate passed';
  } else if (CBOM_STATS) {
    const hasCrit = CBOM_STATS.bySeverity.CRITICAL > 0;
    badge.className = 'gate-badge ' + (hasCrit ? 'gate-fail' : 'gate-pass');
    badge.textContent = hasCrit ? '⚠ Critical crypto findings' : '✓ No critical findings';
  } else {
    badge.style.display = 'none';
  }

  const parts = [];
  if (CBOM_STATS) {
    if (CBOM_STATS.filesScanned) parts.push('📂 ' + CBOM_STATS.filesScanned + ' files scanned');
    if (CBOM_STATS.scanDuration) parts.push('⏱ ' + CBOM_STATS.scanDuration);
    parts.push('🔐 ' + CBOM_STATS.totalFindings + ' crypto findings');
  }
  if (SBOM_STATS) {
    parts.push('📦 ' + SBOM_STATS.total + ' dependency vulnerabilities');
    parts.push('🔐 ' + SBOM_STATS.totalSecrets + ' secret findings');
    parts.push('🛡 ' + SBOM_STATS.totalFindings + ' total SBOM findings');
    if (SCAN_THRESHOLD) parts.push('🎯 Threshold: ' + SCAN_THRESHOLD);
  }
  document.getElementById('scan-meta').innerHTML =
    parts.map(p => '<span>' + p + '</span>').join('');

  const repro = SBOM_STATS?.reproducibility;
  const warnings = repro?.warnings || [];
  const warningMount = document.getElementById('repro-warning');
  if (!warningMount) return;
  if (!warnings.length) {
    warningMount.innerHTML = '';
    return;
  }

  warningMount.innerHTML = '<div class="warn-card">'
    + '<h3>Reproducibility warning</h3>'
    + '<p>Some detected projects do not have a dependency lockfile or an equivalent pinned dependency definition. SBOM generation can still run, but the resolved dependency graph may change between scans.</p>'
    + '<ul>'
    + warnings.map((entry) => {
      const selectedSource = (entry.source_of_truth_files || []).join(', ') || 'fallback manifest';
      const supportingFiles = (entry.supporting_files || []).join(', ') || 'none';
      return '<li><strong>' + esc(entry.language || 'unknown') + '</strong> at <span class="mono">' + esc(entry.project_path || entry.project_id || 'unknown') + '</span>: '
        + esc(entry.warning || '')
        + '<div class="loc" style="margin-top:4px">Selected source: ' + esc(selectedSource) + ' (' + esc(entry.source_of_truth_type || 'unknown') + ')</div>'
        + '<div class="loc">Supporting files: ' + esc(supportingFiles) + '</div>'
        + '</li>';
    }).join('')
    + '</ul>'
    + '</div>';
}

// ── CBOM overview ─────────────────────────────────────────────────────────────
function renderCbomOverview() {
  if (!CBOM_STATS) return;
  const s = CBOM_STATS;
  document.getElementById('cbom-metrics').innerHTML = [
    ['Files scanned',     s.filesScanned || '—', ''],
    ['Total findings',    s.totalFindings, ''],
    ['Critical',          s.bySeverity.CRITICAL, 'c-crit'],
    ['High',              s.bySeverity.HIGH,     'c-high'],
    ['Medium',            s.bySeverity.MEDIUM,   'c-med'],
    ['Weak algorithms',   s.weakCount,           'c-high'],
    ['Quantum-vulnerable',s.qvCount,             'c-crit'],
  ].map(([l,v,c]) =>
    '<div class="mc"><div class="mc-label">' + l + '</div><div class="mc-val ' + c + '">' + v + '</div></div>'
  ).join('');

  const sortedAlgo = Object.entries(s.byAlgo).sort((a,b) => b[1]-a[1]);
  mkBarChart('chart-algo',
    sortedAlgo.map(x => x[0]),
    sortedAlgo.map(x => x[1]),
    isDark ? '#7F77DD' : '#534AB7'
  );

  const sevLabels = SEV_ORDER.filter(k => s.bySeverity[k] > 0);
  mkDoughnut('chart-cbom-sev', sevLabels, sevLabels.map(k => s.bySeverity[k]), sevLabels.map(k => SEV_COLOR[k]));
}

// ── SBOM overview ─────────────────────────────────────────────────────────────
function renderSbomOverview() {
  if (!SBOM_STATS) return;
  const s = SBOM_STATS;
  const sourceSelectionMount = document.getElementById('sbom-source-selection');
  if (sourceSelectionMount) {
    const sourceEntries = s.reproducibility.source_selection || [];
    sourceSelectionMount.innerHTML = sourceEntries.length
      ? '<div class="source-grid">' + sourceEntries.map((entry) => {
        const primary = (entry.source_of_truth_files || []).join(', ') || 'unknown';
        const supporting = (entry.supporting_files || []).join(', ') || 'none';
        return '<div class="source-card">'
          + '<h4>' + esc(entry.language || 'unknown') + ' · ' + esc(entry.project_id || 'root') + '</h4>'
          + '<p><strong>Primary source:</strong> <span class="mono">' + esc(primary) + '</span></p>'
          + '<p><strong>Primary type:</strong> ' + esc(entry.source_of_truth_type || 'unknown') + '</p>'
          + '<p><strong>Supporting files:</strong> <span class="mono">' + esc(supporting) + '</span></p>'
          + '<p><strong>Reproducibility:</strong> ' + esc(entry.reproducibility || 'unknown') + '</p>'
          + '</div>';
      }).join('') + '</div>'
      : '';
  }
  document.getElementById('sbom-metrics').innerHTML = [
    ['Dependency CVEs', s.total,                       ''],
    ['Secret findings', s.totalSecrets,               'c-high'],
    ['Total findings',  s.totalFindings,              ''],
    ['Critical',        s.findingBySeverity.CRITICAL, 'c-crit'],
    ['High',            s.findingBySeverity.HIGH,     'c-high'],
    ['Medium',          s.findingBySeverity.MEDIUM,   'c-med'],
    ['Low',             s.findingBySeverity.LOW,      'c-safe'],
  ].map(([l,v,c]) =>
    '<div class="mc"><div class="mc-label">' + l + '</div><div class="mc-val ' + c + '">' + v + '</div></div>'
  ).join('');

  const sortedPkg = Object.entries(s.byPackage).sort((a,b) => b[1]-a[1]).slice(0,8);
  mkBarChart('chart-pkg',
    sortedPkg.map(x => x[0]),
    sortedPkg.map(x => x[1]),
    isDark ? '#EF9F27' : '#854F0B'
  );

  const sevLabels = ['CRITICAL','HIGH','MEDIUM','LOW'].filter(k => s.findingBySeverity[k] > 0);
  mkDoughnut('chart-sbom-sev', sevLabels, sevLabels.map(k => s.findingBySeverity[k]), sevLabels.map(k => SEV_COLOR[k]));
}

// ── CBOM table ────────────────────────────────────────────────────────────────
function renderCbomTable() {
  const tbody = document.getElementById('cbom-tbody');
  if (!tbody) return;

  const sevFilter = (document.getElementById('cbom-sev-filter')?.value || '').toUpperCase();
  const q         = (document.getElementById('cbom-search')?.value || '').toLowerCase();

  let rows = CBOM_COMPONENTS.filter(c => {
    const sev = (c.props.severity?.[0] || 'UNKNOWN').toUpperCase();
    if (sevFilter && sev !== sevFilter) return false;
    if (q) {
      const haystack = [
        c.name,
        (c.props.cwe || []).join(' '),
        (c.props.library || []).join(' '),
        (c.occurrences || []).map(o => o.location).join(' '),
      ].join(' ').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });

  rows.sort((a,b) => {
    const as = (a.props.severity?.[0] || 'UNKNOWN').toUpperCase();
    const bs = (b.props.severity?.[0] || 'UNKNOWN').toUpperCase();
    return SEV_ORDER.indexOf(as) - SEV_ORDER.indexOf(bs);
  });

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem">No findings match the filter.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map((c, i) => {
    const sev     = (c.props.severity?.[0] || 'UNKNOWN').toUpperCase();
    const cwes    = (c.props.cwe || []).join(', ') || '—';
    const lib     = c.props.library?.[0] || '—';
    const notes   = c.props.notes?.[0] || '';
    const snippet = c.props.codeSnippet?.[0] || '';
    const locHtml = (c.occurrences || [])
      .map(o => '<span class="loc">' + esc(o.location) + ':' + o.line + '</span>')
      .join('<br>') || '—';
    const uid = 'snip_' + i;
    return '<tr>'
      + '<td>' + sevBadge(sev) + '</td>'
      + '<td><strong>' + esc(c.name) + '</strong>'
      + (notes   ? '<div class="loc" style="margin-top:3px">' + esc(notes) + '</div>' : '')
      + (snippet ? '<button class="snip-btn" onclick="toggleSnip(\\'' + uid + '\\')">▸ view snippet</button>'
                 + '<pre class="snip-box" id="' + uid + '">' + esc(snippet) + '</pre>' : '')
      + '</td>'
      + '<td class="mono">' + esc(cwes) + '</td>'
      + '<td>' + locHtml + '</td>'
      + '<td class="mono">' + esc(lib) + '</td>'
      + '</tr>';
  }).join('');
}

// ── SBOM table ────────────────────────────────────────────────────────────────
function renderSbomTable() {
  const tbody = document.getElementById('sbom-tbody');
  if (!tbody) return;

  const sevFilter = (document.getElementById('sbom-sev-filter')?.value || '').toUpperCase();
  const q         = (document.getElementById('sbom-search')?.value || '').toLowerCase();

  let rows = SBOM_VULNS.filter(v => {
    const sev = (v.severity || '').toUpperCase();
    if (sevFilter && sev !== sevFilter) return false;
    if (q && ![v.package, v.cve_id, v.title, v.installed, v.fixed].join(' ').toLowerCase().includes(q)) return false;
    return true;
  });

  rows.sort((a,b) => {
    const as = (a.severity || '').toUpperCase();
    const bs = (b.severity || '').toUpperCase();
    return SEV_ORDER.indexOf(as) - SEV_ORDER.indexOf(bs);
  });

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem">No vulnerabilities match the filter.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(v => {
    const sev    = (v.severity || 'UNKNOWN').toUpperCase();
    const cveId  = v.cve_id || '—';
    const cveUrl = cveId.startsWith('CVE-')
      ? 'https://nvd.nist.gov/vuln/detail/' + cveId
      : cveId.startsWith('GHSA-')
        ? 'https://github.com/advisories/' + cveId
        : null;
    const cveLink = cveUrl
      ? '<a href="' + cveUrl + '" target="_blank" rel="noopener">' + esc(cveId) + '</a>'
      : esc(cveId);
    return '<tr>'
      + '<td>' + sevBadge(sev) + '</td>'
      + '<td><strong>' + esc(v.package || '—') + '</strong></td>'
      + '<td class="mono">' + esc(v.installed || '—') + '</td>'
      + '<td class="mono" style="color:var(--green)">' + esc(v.fixed || '—') + '</td>'
      + '<td class="mono" style="white-space:nowrap">' + cveLink + '</td>'
      + '<td style="max-width:260px;font-size:12px;color:var(--muted)">' + esc(shortText(v.title, 90)) + '</td>'
      + '</tr>';
  }).join('');
}

// ── snippet toggle ─────────────────────────────────────────────────────────────
function renderSbomSecretTable() {
  const tbody = document.getElementById('sbom-secret-tbody');
  if (!tbody) return;

  const sevFilter = (document.getElementById('sbom-secret-sev-filter')?.value || '').toUpperCase();
  const q = (document.getElementById('sbom-secret-search')?.value || '').toLowerCase();

  let rows = SBOM_SECRETS.filter((secret) => {
    const sev = (secret.severity || '').toUpperCase();
    if (sevFilter && sev !== sevFilter) return false;
    if (q && ![secret.rule_id, secret.category, secret.title, secret.target].join(' ').toLowerCase().includes(q)) return false;
    return true;
  });

  rows.sort((a, b) => {
    const as = (a.severity || '').toUpperCase();
    const bs = (b.severity || '').toUpperCase();
    return SEV_ORDER.indexOf(as) - SEV_ORDER.indexOf(bs);
  });

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem">No secret findings match the filter.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map((secret) => {
    const sev = (secret.severity || 'UNKNOWN').toUpperCase();
    const location = secret.target
      ? esc(secret.target) + (secret.start_line ? ':' + secret.start_line : '')
      : '?';
    return '<tr>'
      + '<td>' + sevBadge(sev) + '</td>'
      + '<td class="mono">' + esc(secret.rule_id || '?') + '</td>'
      + '<td>' + esc(secret.category || '?') + '</td>'
      + '<td><span class="loc">' + location + '</span></td>'
      + '<td style="max-width:320px;font-size:12px;color:var(--muted)">' + esc(shortText(secret.title, 110)) + '</td>'
      + '</tr>';
  }).join('');
}

function toggleSnip(id) {
  const el  = document.getElementById(id);
  const btn = el.previousElementSibling;
  const open = el.style.display === 'block';
  el.style.display = open ? 'none' : 'block';
  btn.textContent  = open ? '▸ view snippet' : '▾ hide snippet';
}

// ── init ───────────────────────────────────────────────────────────────────────
renderHeader();
renderCbomOverview();
renderSbomOverview();
renderCbomTable();
renderSbomTable();
renderSbomSecretTable();
</script>
</body>
</html>`;
}

// ── tiny HTML escaper used in template strings ────────────────────────────────
function esc(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
