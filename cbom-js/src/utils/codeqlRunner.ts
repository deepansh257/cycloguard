import { execSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { getRegistry } from '../registry/registryLoader';

export interface CodeQLRunnerOptions {
  codeqlPath?: string;
  sourceRoot: string;
  queriesDir: string;
}

export interface SARIFResult {
  ruleId:      string;
  message:     string;
  filePath:    string;
  startLine:   number;
  startColumn: number;
  snippet:     string;
  codeFlows:   string[][];
}

export function isCodeQLAvailable(codeqlBin: string): boolean {
  try {
    console.log("Received codeqlBin:", codeqlBin);
console.log("Absolute?", path.isAbsolute(codeqlBin));
console.log("Exists?", fs.existsSync(codeqlBin));
    // Use fs.existsSync first for an absolute path — avoids shell resolution issues on Windows
    if (path.isAbsolute(codeqlBin)) {
      if (!fs.existsSync(codeqlBin)) {
        throw new Error(`File not found at path: ${codeqlBin}`);
      }
      return true;
    }
    // For a bare command name like 'codeql', verify it runs
    execSync(`"${codeqlBin}" version`, { stdio: 'ignore' });
    return true;
  } catch (err: any) {
    throw new Error(
      `CodeQL binary not found at "${codeqlBin}": ${err.message}. ` +
      `Install from https://github.com/github/codeql-cli-binaries or pass --codeql-path.`
    );
  }
}

// ---------------------------------------------------------------------------
// Registry-driven data extraction
// ---------------------------------------------------------------------------

function buildSinkNamesFromRegistry(): string[] {
  const registry = getRegistry();
  const sinks = new Set<string>();

  // packageRules is Map<string, PackageRule>
  // PackageRule.methods is Record<string, MethodRule> — keys are the method names
  registry.packageRules.forEach((pkg) => {
    for (const methodName of Object.keys(pkg.methods)) {
      // "AES.encrypt" → "encrypt", "createHash" → "createHash"
      const leaf = methodName.split('.').pop();
      if (leaf) sinks.add(leaf);
    }
  });

  return [...sinks];
}

function buildWeakAlgosFromRegistry(): string[] {
  const registry = getRegistry();
  const weak = new Set<string>();

  // algorithmMeta is Map<string, AlgorithmMeta>
  // The KEY is the algorithm name — AlgorithmMeta has no .name field
  registry.algorithmMeta.forEach((meta, algoName) => {
    if (meta.weak) {
      weak.add(algoName.toLowerCase());
    }
  });

  return [...weak].filter(Boolean);
}

function buildSecretVarPatternFromRegistry(): string {
  const registry = getRegistry();
  // hardcodedVarNames is Set<string> of lowercased substrings
  const escaped = [...registry.hardcodedVarNames]
    .filter(Boolean)
    .map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\\\$&'));
  return `(?i).*(${escaped.join('|')}).*`;
}

function qlStringList(values: string[]): string {
  return values.map(v => `"${v}"`).join(', ');
}

// ---------------------------------------------------------------------------
// Query generators — produce complete .ql source from registry data
// ---------------------------------------------------------------------------

function generateRegistryDrivenQuery(): string {
  const sinkNames   = buildSinkNamesFromRegistry();
  const secretRegex = buildSecretVarPatternFromRegistry();
  const sinkList    = qlStringList(sinkNames);

  return `/**
 * @name Registry-driven crypto taint (auto-generated from libraries.json)
 * @description Tracks hardcoded key/secret material flowing to any crypto sink
 * @kind path-problem
 * @id crypto-taint/registry-driven
 * @severity error
 * @tags security cryptography
 */
import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

private class HardcodedKeySource extends DataFlow::Node {
  HardcodedKeySource() {
    exists(VariableDeclarator vd, StringLiteral lit |
      vd.getBindingPattern().(VarDecl).getName().regexpMatch("${secretRegex}") and
      vd.getInit() = lit and
      this = DataFlow::valueNode(lit)
    )
  }
}

private class RegistryCryptoSink extends DataFlow::Node {
  RegistryCryptoSink() {
    exists(CallExpr call |
      call.getCalleeName() = [${sinkList}] and
      this = DataFlow::valueNode(call.getAnArgument())
    )
  }
}

class RegistryTaintConfig extends TaintTracking::Configuration {
  RegistryTaintConfig() { this = "RegistryTaintConfig" }
  override predicate isSource(DataFlow::Node n) { n instanceof HardcodedKeySource }
  override predicate isSink(DataFlow::Node n)   { n instanceof RegistryCryptoSink }
}

from RegistryTaintConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select sink.getNode(), src, sink,
  "Hardcoded key/secret flows to crypto sink from $@.", src.getNode(), "this source"
`;
}

function generateWeakAlgoQuery(): string {
  const weakAlgos = buildWeakAlgosFromRegistry();
  const sinkNames = buildSinkNamesFromRegistry();
  const algoList  = qlStringList(weakAlgos);
  const sinkList  = qlStringList(sinkNames);

  return `/**
 * @name Weak algorithm flows to crypto function (auto-generated from libraries.json)
 * @description Detects weak algorithm name flowing into a registered crypto function
 * @kind path-problem
 * @id crypto-taint/weak-algo-flow
 * @severity warning
 * @tags security cryptography
 */
import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph

private class WeakAlgoSource extends DataFlow::Node {
  WeakAlgoSource() {
    exists(StringLiteral lit |
      lit.getStringValue().toLowerCase() = [${algoList}] and
      this = DataFlow::valueNode(lit)
    )
  }
}

private class AlgoParamSink extends DataFlow::Node {
  AlgoParamSink() {
    exists(CallExpr call |
      call.getCalleeName() = [${sinkList}] and
      this = DataFlow::valueNode(call.getArgument(0))
    )
  }
}

class WeakAlgoTaintConfig extends TaintTracking::Configuration {
  WeakAlgoTaintConfig() { this = "WeakAlgoTaintConfig" }
  override predicate isSource(DataFlow::Node n) { n instanceof WeakAlgoSource }
  override predicate isSink(DataFlow::Node n)   { n instanceof AlgoParamSink }
}

from WeakAlgoTaintConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select sink.getNode(), src, sink,
  "Weak algorithm flows into crypto function ($@).", src.getNode(), src.getNode().toString()
`;
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

export function runCodeQL(opts: CodeQLRunnerOptions): SARIFResult[] {
  const codeqlPackageCache = path.join(os.homedir(), '.codeql', 'packages');
  let codeqlBin = opts.codeqlPath ?? 'codeql';
  if (process.platform === 'win32' && !codeqlBin.endsWith('.exe')) {
    codeqlBin = codeqlBin + '.exe';
  }
  const codeqlHome = path.dirname(codeqlBin);

  isCodeQLAvailable(codeqlBin);

  const dbDir = path.join(os.tmpdir(), `cbomjs-codeql-db-${Date.now()}`);
  const tempQueryFiles: string[] = [];

  const generatedDir = path.join(opts.queriesDir, '_generated');
  fs.mkdirSync(generatedDir, { recursive: true });

  const sourceRoot = opts.sourceRoot.replace(/\\/g, '/');

  try {
    console.log(`Creating CodeQL database at ${dbDir}...`);
    const dbResult = spawnSync(
      codeqlBin,
      [
        'database', 'create', dbDir,
        '--language=javascript',
        '--source-root', sourceRoot,
        '--overwrite',
        `--search-path=${codeqlHome}`,
      ],
      { stdio: 'pipe', encoding: 'utf8' }
    );

    if (dbResult.stdout) console.log('[CodeQL DB stdout]\n', dbResult.stdout);
    if (dbResult.stderr) console.log('[CodeQL DB stderr]\n', dbResult.stderr);
    if (dbResult.error)  console.error('[CodeQL DB spawn error]', dbResult.error);

    if (dbResult.status !== 0 || dbResult.error) {
      console.error(`❌ CodeQL database creation failed (exit code: ${dbResult.status})`);
      return [];
    }
    console.log('CodeQL database created successfully.');

    console.log('Installing CodeQL query pack dependencies...');
    const packInstallResult = spawnSync(
      codeqlBin,
      ['pack', 'install', opts.queriesDir],
      { stdio: 'pipe', encoding: 'utf8' }
    );
    if (packInstallResult.stderr) console.log('[pack install stderr]', packInstallResult.stderr);
    if (packInstallResult.status !== 0) {
      console.error('❌ codeql pack install failed — queries may not resolve stdlib imports');
    }

    const ts       = Date.now();
    const regPath  = path.join(generatedDir, `registry-${ts}.ql`);
    const weakPath = path.join(generatedDir, `weakalgo-${ts}.ql`);
    fs.writeFileSync(regPath,  generateRegistryDrivenQuery(), 'utf8');
    fs.writeFileSync(weakPath, generateWeakAlgoQuery(),       'utf8');
    tempQueryFiles.push(regPath, weakPath);

    const staticQueries = fs.existsSync(opts.queriesDir)
      ? fs.readdirSync(opts.queriesDir)
          .filter(f => f.endsWith('.ql'))
          .map(f => path.join(opts.queriesDir, f))
      : [];

    const allQueries = [...tempQueryFiles, ...staticQueries];
    const sarifOut   = path.join(generatedDir, `results-${ts}.sarif`);

    console.log(`Running CodeQL analysis with ${allQueries.length} query file(s)...`);

    const analyzeResult = spawnSync(
      codeqlBin,
      [
        'database', 'analyze', dbDir,
        ...allQueries,
        '--format=sarifv2.1.0',
        `--output=${sarifOut}`,
        ...(codeqlHome ? [`--search-path=${codeqlHome}`] : []),
    `--search-path=${codeqlPackageCache}`,
      ],
      { stdio: 'pipe', encoding: 'utf8' }
    );

    if (analyzeResult.stdout) console.log('[CodeQL Analyze stdout]\n', analyzeResult.stdout);
    if (analyzeResult.stderr) console.log('[CodeQL Analyze stderr]\n', analyzeResult.stderr);
    if (analyzeResult.error)  console.error('[CodeQL Analyze spawn error]', analyzeResult.error);

    if (analyzeResult.status !== 0 || analyzeResult.error) {
      console.error(`CodeQL analyze failed (exit code: ${analyzeResult.status})`);
      return [];
    }

    if (!fs.existsSync(sarifOut)) {
      console.error('SARIF output file was not created.');
      return [];
    }

    console.log(`SARIF written to ${sarifOut}`);
    const sarif = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    return parseSARIF(sarif, opts.sourceRoot);

  } finally {
    fs.rmSync(dbDir, { recursive: true, force: true });
    // Clean up generated query files but keep the dir
    for (const f of tempQueryFiles) {
      try { fs.rmSync(f, { force: true }); } catch {}
    }
  }
}

function parseSARIF(sarif: any, sourceRoot: string): SARIFResult[] {
  const results: SARIFResult[] = [];

  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const loc = result.locations?.[0]?.physicalLocation;
      if (!loc) continue;

      const relativeUri = loc.artifactLocation?.uri ?? '';
      const absPath = path.resolve(sourceRoot, relativeUri.replace(/^file:\/\/\//, ''));
      const startLine = loc.region?.startLine ?? 0;

      let snippet = '';
      try {
        if (fs.existsSync(absPath)) {
          const lines = fs.readFileSync(absPath, 'utf8').split('\n');
          const start = Math.max(0, startLine - 2);
          const end   = Math.min(lines.length, startLine + 1);
          snippet = lines.slice(start, end).join('\n').trim();
        }
      } catch {}

      results.push({
        ruleId:      result.ruleId ?? 'unknown',
        message:     result.message?.text ?? '',
        filePath:    absPath,
        startLine,
        startColumn: loc.region?.startColumn ?? 0,
        snippet,     // ← add this field to SARIFResult interface too
        codeFlows: (result.codeFlows ?? []).map((cf: any) =>
          (cf.threadFlows ?? []).flatMap((tf: any) =>
            (tf.locations ?? []).map((tfl: any) => {
              const pl = tfl.location?.physicalLocation;
              return pl
                ? `${pl.artifactLocation?.uri}:${pl.region?.startLine}`
                : '(unknown)';
            })
          )
        ),
      });
    }
  }

  return results;
}
