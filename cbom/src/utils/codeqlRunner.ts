import { execSync } from 'child_process';
import { spawn, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { getRegistry } from '../registry/registryLoader';

export interface CodeQLRunnerOptions {
  codeqlPath?: string;
  sourceRoot: string;
  jsQueriesDir: string;
  javaQueriesDir?: string;
  includeJava?: boolean;
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

// ─── CodeQL availability ──────────────────────────────────────────────────────
export function isCodeQLAvailable(codeqlBin: string): boolean {
  try {
    if (path.isAbsolute(codeqlBin)) {
      if (!fs.existsSync(codeqlBin)) {
        throw new Error(`File not found at path: ${codeqlBin}`);
      }
      return true;
    }
    execSync(`"${codeqlBin}" version`, { stdio: 'ignore' });
    return true;
  } catch (err: any) {
    throw new Error(
      `CodeQL binary not found at "${codeqlBin}": ${err.message}. ` +
      `Install from https://github.com/github/codeql-cli-binaries or pass --codeql-path.`
    );
  }
}

// ─── Registry helpers ─────────────────────────────────────────────────────────
function buildSinkNamesFromRegistry(): string[] {
  const registry = getRegistry();
  const sinks = new Set<string>();
  registry.packageRules.forEach((pkg) => {
    for (const methodName of Object.keys(pkg.methods)) {
      const leaf = methodName.split('.').pop();
      if (leaf) sinks.add(leaf);
    }
  });
  return [...sinks];
}

function buildWeakAlgosFromRegistry(): string[] {
  const registry = getRegistry();
  const weak = new Set<string>();
  registry.algorithmMeta.forEach((meta, algoName) => {
    if (meta.weak) weak.add(algoName.toLowerCase());
  });
  return [...weak].filter(Boolean);
}

function buildSecretVarPatternFromRegistry(): string {
  const registry = getRegistry();
  const escaped = [...registry.hardcodedVarNames]
    .filter(Boolean)
    .map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\\\$&'));
  return `(?i).*(${escaped.join('|')}).*`;
}

function qlStringList(values: string[]): string {
  return values.map(v => `"${v}"`).join(', ');
}

// ─── JS query generators ──────────────────────────────────────────────────────
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

// ─── Java query generators ────────────────────────────────────────────────────
function buildWeakJavaAlgos(): string[] {
  const registry = getRegistry();
  const fromRegistry: string[] = [];
  registry.algorithmMeta.forEach((meta, algoName) => {
    if (meta.weak) fromRegistry.push(algoName.toLowerCase());
  });

  const javaSpellings = [
    'md5', 'md2', 'sha-1', 'sha1',
    'des', 'desede', '3des',
    'rc2', 'rc4', 'arcfour',
    'blowfish',
    'ssl', 'sslv2', 'sslv3',
    'tlsv1', 'tlsv1.1',
    'md5withrsa', 'sha1withrsa', 'sha1withdsa', 'sha1withecdsa',
  ];

  return [...new Set([...fromRegistry, ...javaSpellings])].filter(Boolean);
}

function generateJavaWeakAlgoFlowQuery(): string {
  const weakAlgos = buildWeakJavaAlgos();
  const algoList  = qlStringList(weakAlgos);

  return `/**
 * @name Java weak algorithm via constant propagation or inter-procedural flow
 * @kind path-problem
 * @id crypto-java/weak-algo-flow
 * @severity warning
 * @tags security cryptography java
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

private class WeakAlgoLiteral extends StringLiteral {
  WeakAlgoLiteral() {
    this.getValue().toLowerCase() = [${algoList}]
  }
}

private class WeakAlgoSource extends DataFlow::Node {
  WeakAlgoSource() {
    this.asExpr() instanceof WeakAlgoLiteral
    or
    exists(Field f |
      f.isFinal() and
      f.getInitializer() instanceof WeakAlgoLiteral and
      this.asExpr() = f.getAnAccess()
    )
    or
    exists(LocalVariableDeclExpr lvde |
      lvde.getInit() instanceof WeakAlgoLiteral and
      this.asExpr() = lvde.getAnAccess()
    )
  }
}

private class CryptoGetInstanceSink extends DataFlow::Node {
  CryptoGetInstanceSink() {
    exists(MethodCall mc |
      mc.getMethod().hasName("getInstance") and
      mc.getMethod().getDeclaringType().getQualifiedName() in [
        "java.security.MessageDigest",
        "java.security.Signature",
        "java.security.KeyPairGenerator",
        "java.security.KeyFactory",
        "javax.crypto.Cipher",
        "javax.crypto.Mac",
        "javax.crypto.KeyGenerator",
        "javax.crypto.SecretKeyFactory",
        "javax.net.ssl.SSLContext"
      ] and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module WeakAlgoFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof WeakAlgoSource }
  predicate isSink(DataFlow::Node n)   { n instanceof CryptoGetInstanceSink }
}

module WeakAlgoFlow = TaintTracking::Global<WeakAlgoFlowConfig>;
import WeakAlgoFlow::PathGraph

from WeakAlgoFlow::PathNode src, WeakAlgoFlow::PathNode sink
where WeakAlgoFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Weak algorithm '$@' flows into getInstance().", src.getNode(), src.getNode().toString()
`;
}

function generateJavaHardcodedFieldSecretQuery(): string {
  const secretRegex = buildSecretVarPatternFromRegistry();

  return `/**
 * @name Java hardcoded secret in class field
 * @kind problem
 * @id crypto-java/hardcoded-field-secret
 * @severity error
 * @tags security cryptography java
 */
import java

from Field f, StringLiteral lit
where
  f.getName().regexpMatch("${secretRegex}") and
  f.getInitializer() = lit and
  lit.getValue().length() >= 8 and
  not lit.getValue().matches("%$%") and
  not lit.getValue().matches("%{%") and
  not lit.getValue().matches("%<%") and
  not lit.getValue().matches("%placeholder%") and
  not lit.getValue().matches("%TODO%") and
  not lit.getValue().matches("%FIXME%")
select f, "Hardcoded secret in field '" + f.getName() + "': value is a string literal."
`;
}

function generateJavaWeakSecretKeySpecQuery(): string {
  const weakAlgos = buildWeakJavaAlgos();
  const algoList  = qlStringList(weakAlgos);

  return `/**
 * @name Java SecretKeySpec with weak algorithm via constant
 * @kind path-problem
 * @id crypto-java/weak-secretkeyspec-constant
 * @severity warning
 * @tags security cryptography java
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

private class WeakAlgoLiteral extends StringLiteral {
  WeakAlgoLiteral() { this.getValue().toLowerCase() = [${algoList}] }
}

private class WeakAlgoConstantSource extends DataFlow::Node {
  WeakAlgoConstantSource() {
    this.asExpr() instanceof WeakAlgoLiteral
    or
    exists(Field f |
      f.isFinal() and f.getInitializer() instanceof WeakAlgoLiteral and
      this.asExpr() = f.getAnAccess()
    )
  }
}

private class SecretKeySpecAlgoSink extends DataFlow::Node {
  SecretKeySpecAlgoSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec", "SecretKeySpec") and
      this.asExpr() = cie.getArgument(1)
    )
  }
}

module WeakSecretKeySpecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof WeakAlgoConstantSource }
  predicate isSink(DataFlow::Node n)   { n instanceof SecretKeySpecAlgoSink }
}

module WeakSecretKeySpecFlow = TaintTracking::Global<WeakSecretKeySpecConfig>;
import WeakSecretKeySpecFlow::PathGraph

from WeakSecretKeySpecFlow::PathNode src, WeakSecretKeySpecFlow::PathNode sink
where WeakSecretKeySpecFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Weak algorithm '$@' used in SecretKeySpec constructor.", src.getNode(), src.getNode().toString()
`;
}

function generateJavaHardcodedSecretFlowQuery(): string {
  const secretRegex = buildSecretVarPatternFromRegistry();

  return `/**
 * @name Java hardcoded secret flows to crypto operation
 * @kind path-problem
 * @id crypto-java/hardcoded-secret-flow
 * @severity error
 * @tags security cryptography java
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

private class HardcodedSecretSource extends DataFlow::Node {
  HardcodedSecretSource() {
    exists(Variable v, StringLiteral lit |
      v.getName().regexpMatch("${secretRegex}") and
      v.getInitializer() = lit and
      lit.getValue().length() >= 8 and
      not lit.getValue().matches("%$%") and
      not lit.getValue().matches("%{%") and
      not lit.getValue().matches("%placeholder%") and
      not lit.getValue().matches("%TODO%") and
      this.asExpr() = lit
    )
  }
}

private class CryptoUseSink extends DataFlow::Node {
  CryptoUseSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("javax.crypto.spec", "SecretKeySpec") and
      this.asExpr() = cie.getArgument(0)
    )
    or
    exists(MethodCall mc |
      mc.getMethod().hasName(["init", "doFinal", "update"]) and
      this.asExpr() = mc.getAnArgument()
    )
  }
}

module HardcodedSecretFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof HardcodedSecretSource }
  predicate isSink(DataFlow::Node n)   { n instanceof CryptoUseSink }
}

module HardcodedSecretFlow = TaintTracking::Global<HardcodedSecretFlowConfig>;
import HardcodedSecretFlow::PathGraph

from HardcodedSecretFlow::PathNode src, HardcodedSecretFlow::PathNode sink
where HardcodedSecretFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Hardcoded secret '$@' flows into cryptographic operation.", src.getNode(), src.getNode().toString()
`;
}

function generateJavaWeakKeySizeQuery(): string {
  return `/**
 * @name Java weak key size passed to KeyPairGenerator.initialize()
 * @kind problem
 * @id crypto-java/weak-key-size
 * @severity warning
 * @tags security cryptography java
 */
import java
import semmle.code.java.dataflow.DataFlow

private int minSafeBits(string algo) {
  algo = "rsa"  and result = 2048 or
  algo = "dsa"  and result = 2048 or
  algo = "ec"   and result = 256  or
  algo = "dh"   and result = 2048
}

from
  MethodCall getInstanceCall,
  MethodCall initCall,
  StringLiteral algoLit,
  IntegerLiteral keySizeLit,
  string algoLower,
  int keySize,
  int minBits
where
  getInstanceCall.getMethod().hasName("getInstance") and
  getInstanceCall.getMethod().getDeclaringType().getQualifiedName() in [
    "java.security.KeyPairGenerator",
    "javax.crypto.KeyGenerator"
  ] and
  algoLit    = getInstanceCall.getArgument(0) and
  algoLower  = algoLit.getValue().toLowerCase() and
  initCall.getMethod().hasName(["initialize", "init"]) and
  initCall.getQualifier() = getInstanceCall.getParent*() and
  keySizeLit = initCall.getArgument(0) and
  keySize    = keySizeLit.getIntValue() and
  minBits    = minSafeBits(algoLower) and
  keySize    < minBits
select initCall,
  "Key size " + keySize + " bits is below the recommended minimum of " + minBits +
  " bits for " + algoLit.getValue() + "."
`;
}

// ─── Language detection ───────────────────────────────────────────────────────
function detectJSInSource(sourceRoot: string): boolean {
  const jsConfigIndicators = ['package.json', 'tsconfig.json', '.eslintrc', '.eslintrc.js', '.eslintrc.json'];
  for (const indicator of jsConfigIndicators) {
    if (fs.existsSync(path.join(sourceRoot, indicator))) return true;
  }
  try {
    const check = (dir: string, depth: number): boolean => {
      if (depth > 3) return false;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isFile() && /\.(js|ts|jsx|tsx)$/.test(entry.name)) return true;
        if (entry.isDirectory() && entry.name !== 'node_modules' && check(path.join(dir, entry.name), depth + 1)) return true;
      }
      return false;
    };
    return check(sourceRoot, 0);
  } catch {
    return false;
  }
}

function detectJavaInSource(sourceRoot: string): boolean {
  const indicators = ['pom.xml', 'build.gradle', 'build.gradle.kts'];
  for (const indicator of indicators) {
    if (fs.existsSync(path.join(sourceRoot, indicator))) return true;
  }
  try {
    const check = (dir: string, depth: number): boolean => {
      if (depth > 3) return false;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isFile() && entry.name.endsWith('.java')) return true;
        if (entry.isDirectory() && check(path.join(dir, entry.name), depth + 1)) return true;
      }
      return false;
    };
    return check(sourceRoot, 0);
  } catch {
    return false;
  }
}

// ─── DB reuse helpers ─────────────────────────────────────────────────────────
function getSourceFingerprint(sourceRoot: string): string {
  try {
    const result = spawnSync('git', ['rev-parse', 'HEAD'], {
      cwd: sourceRoot, encoding: 'utf8', stdio: 'pipe'
    });
    if (result.status === 0 && result.stdout.trim()) {
      return result.stdout.trim();
    }
  } catch {}
  try {
    return String(fs.statSync(sourceRoot).mtimeMs);
  } catch {}
  return '';
}

function getDbFingerprintPath(dbDir: string): string {
  return path.join(dbDir, '.cbomjs-fingerprint');
}

function isDbReusable(dbDir: string, currentFingerprint: string): boolean {
  if (!fs.existsSync(dbDir)) return false;
  const hasValidDb = fs.readdirSync(dbDir).some(f => f.startsWith('db-'));
  if (!hasValidDb) return false;
  if (!currentFingerprint) return false;
  try {
    const stored = fs.readFileSync(getDbFingerprintPath(dbDir), 'utf8').trim();
    return stored === currentFingerprint;
  } catch {
    return false;
  }
}

function saveDbFingerprint(dbDir: string, fingerprint: string): void {
  try {
    fs.writeFileSync(getDbFingerprintPath(dbDir), fingerprint, 'utf8');
  } catch {}
}

function getStableDbDir(sourceRoot: string, language: 'javascript' | 'java'): string {
  const hash = crypto.createHash('md5').update(sourceRoot).digest('hex').slice(0, 8);
  const baseDir = path.join(os.homedir(), '.cbom-js', 'codeql-dbs');
  fs.mkdirSync(baseDir, { recursive: true });
  return path.join(baseDir, `${hash}-${language}`);
}

// ─── qlpack + workspace helpers ───────────────────────────────────────────────
function getBundledQlpacksDir(codeqlHome: string): string {
  // Standard layout: codeql-win64/codeql/qlpacks/
  const bundled = path.join(codeqlHome, 'qlpacks');
  if (fs.existsSync(bundled)) return bundled;
  // Some distributions put them one level up
  const parent = path.join(path.dirname(codeqlHome), 'qlpacks');
  if (fs.existsSync(parent)) return parent;
  return bundled; // best guess — let CodeQL error naturally
}

function ensureQlPack(dir: string, language: 'javascript' | 'java', codeqlHome: string): void {
  const dep = language === 'java' ? 'codeql/java-all' : 'codeql/javascript-all';
  const packName = language === 'java'
    ? 'cbom-js/crypto-queries-java'
    : 'cbom-js/crypto-queries-js';
  fs.writeFileSync(
    path.join(dir, 'qlpack.yml'),
    `name: ${packName}\nversion: 0.0.1\ndependencies:\n  ${dep}: "*"\n`,
    'utf8'
  );

  const bundledQlpacks = getBundledQlpacksDir(codeqlHome);
  fs.writeFileSync(
    path.join(dir, 'codeql-workspace.yml'),
    `provide:\n  - "${bundledQlpacks.replace(/\\/g, '/')}/**/*.qlpack.yml"\n  - "${bundledQlpacks.replace(/\\/g, '/')}/**/qlpack.yml"\n`,
    'utf8'
  );
}

// ─── Async spawn helper ───────────────────────────────────────────────────────

function spawnAsync(
  bin: string,
  args: string[],
  options: { timeout?: number; label?: string } = {}
): Promise<{ stdout: string; stderr: string; status: number | null }> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';

    const child = spawn(bin, args, { stdio: 'pipe' });

    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString();
      process.stdout.write(d); // stream progress live
    });

    let timedOut = false;
    const timer = options.timeout
      ? setTimeout(() => {
          timedOut = true;
          child.kill('SIGKILL');
        }, options.timeout)
      : null;

    child.on('close', (status: number | null) => {
      if (timer) clearTimeout(timer);
      resolve({
        stdout,
        stderr: timedOut ? stderr + '\n[TIMED OUT]' : stderr,
        status: timedOut ? -1 : status,
      });
    });

    child.on('error', (err: Error) => {
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr: stderr + '\n' + err.message, status: -1 });
    });
  });
}

// ─── Main runner ──────────────────────────────────────────────────────────────

export async function runCodeQL(opts: CodeQLRunnerOptions): Promise<SARIFResult[]> {
  const codeqlPackageCache = path.join(os.homedir(), '.codeql', 'packages');
  let codeqlBin = opts.codeqlPath ?? 'codeql';
  if (process.platform === 'win32' && !codeqlBin.endsWith('.exe')) {
    codeqlBin += '.exe';
  }
  const codeqlHome = path.dirname(codeqlBin);

  isCodeQLAvailable(codeqlBin);
  const jsQueriesDir   = opts.jsQueriesDir;
  const javaQueriesDir = opts.javaQueriesDir
    ?? path.join(path.dirname(opts.jsQueriesDir), 'java');
  const generatedBase  = path.join(path.dirname(opts.jsQueriesDir), '_generated');

  const sourceRoot = opts.sourceRoot.replace(/\\/g, '/');
  const allResults: SARIFResult[] = [];

  const hasJS   = detectJSInSource(opts.sourceRoot);
  const hasJava = opts.includeJava ?? detectJavaInSource(opts.sourceRoot);

  if (!hasJS && !hasJava) {
    console.log('No JS/TS or Java source files detected — skipping CodeQL analysis.');
    return [];
  }

  const fingerprint = getSourceFingerprint(opts.sourceRoot);
  const ts = Date.now();

  // ── JS/TS block ──────────────────────────────────────────────────────────────
  if (hasJS) {
    console.log('\nCodeQL: JS/TS source detected.');

    const jsGeneratedDir = path.join(generatedBase, 'js');
    fs.mkdirSync(jsGeneratedDir, { recursive: true });
    ensureQlPack(jsGeneratedDir, 'javascript', codeqlHome);
    const regPath  = path.join(jsGeneratedDir, `js-registry-${ts}.ql`);
    const weakPath = path.join(jsGeneratedDir, `js-weakalgo-${ts}.ql`);
    fs.writeFileSync(regPath,  generateRegistryDrivenQuery(), 'utf8');
    fs.writeFileSync(weakPath, generateWeakAlgoQuery(),       'utf8');

    const staticJsQueries = fs.existsSync(jsQueriesDir)
      ? fs.readdirSync(jsQueriesDir)
          .filter(f => f.endsWith('.ql'))
          .map(f => path.join(jsQueriesDir, f))
      : [];

    const jsQueries = [regPath, weakPath, ...staticJsQueries];
    const jsDbDir   = getStableDbDir(opts.sourceRoot, 'javascript');
    const jsSarif   = path.join(jsGeneratedDir, `js-results-${ts}.sarif`);

    try {
      if (isDbReusable(jsDbDir, fingerprint)) {
        console.log(`  Reusing existing JS/TS CodeQL DB (no code changes detected).`);
      } else {
        console.log('  Creating CodeQL JS/TS database...');
        const dbResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'create', jsDbDir,
            '--language=javascript',
            '--source-root', sourceRoot,
            '--overwrite',
            `--search-path=${codeqlHome}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 15 * 60 * 1000, label: 'JS DB' }
        );

        if (dbResult.status !== 0) {
          console.warn('  WARNING: JS/TS CodeQL DB creation failed:\n', dbResult.stderr.slice(-1000));
          // Clean up partial DB so next run retries from scratch
          safeRm(jsDbDir);
        } else {
          saveDbFingerprint(jsDbDir, fingerprint);
        }
      }

      if (fs.existsSync(jsDbDir)) {
        console.log(`  Running JS/TS CodeQL analysis (${jsQueries.length} queries)...`);
        const analyzeResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'analyze', jsDbDir,
            ...jsQueries,
            '--format=sarifv2.1.0',
            `--output=${jsSarif}`,
            `--search-path=${codeqlHome}`,
            `--search-path=${getBundledQlpacksDir(codeqlHome)}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 20 * 60 * 1000, label: 'JS Analyze' }
        );

        if (analyzeResult.status === 0 && fs.existsSync(jsSarif)) {
          const sarif = JSON.parse(fs.readFileSync(jsSarif, 'utf8'));
          const jsFindings = parseSARIF(sarif, opts.sourceRoot);
          allResults.push(...jsFindings);
          console.log(`  JS/TS CodeQL: ${jsFindings.length} finding(s)`);
        } else if (analyzeResult.status !== 0) {
          console.warn('  WARNING: JS/TS analysis failed:\n', analyzeResult.stderr.slice(-1000));
        }
      }
    } finally {
      safeRm(regPath);
      safeRm(weakPath);
    }
  }

  // ── Java block ───────────────────────────────────────────────────────────────
  if (hasJava) {
    console.log('\nCodeQL: Java source detected — running Java crypto queries...');

    const javaGeneratedDir = path.join(generatedBase, 'java');
    fs.mkdirSync(javaGeneratedDir, { recursive: true });
    ensureQlPack(javaGeneratedDir, 'java', codeqlHome);

    const javaQueryDefs: Array<{ name: string; content: string }> = [
      { name: `java-weak-algo-flow-${ts}.ql`,        content: generateJavaWeakAlgoFlowQuery()        },
      { name: `java-hardcoded-field-${ts}.ql`,       content: generateJavaHardcodedFieldSecretQuery() },
      { name: `java-weak-secretkeyspec-${ts}.ql`,    content: generateJavaWeakSecretKeySpecQuery()    },
      { name: `java-hardcoded-secret-flow-${ts}.ql`, content: generateJavaHardcodedSecretFlowQuery()  },
      { name: `java-weak-key-size-${ts}.ql`,         content: generateJavaWeakKeySizeQuery()          },
    ];

    const javaQueryPaths: string[] = [];
    for (const q of javaQueryDefs) {
      const qPath = path.join(javaGeneratedDir, q.name);
      fs.writeFileSync(qPath, q.content, 'utf8');
      javaQueryPaths.push(qPath);
    }
    const staticJavaQueries = fs.existsSync(javaQueriesDir)
      ? fs.readdirSync(javaQueriesDir)
          .filter(f => f.endsWith('.ql'))
          .map(f => path.join(javaQueriesDir, f))
      : [];
    javaQueryPaths.push(...staticJavaQueries);

    const javaDbDir  = getStableDbDir(opts.sourceRoot, 'java');
    const javaSarif  = path.join(javaGeneratedDir, `java-results-${ts}.sarif`);

    try {
      if (isDbReusable(javaDbDir, fingerprint)) {
        console.log(`  Reusing existing Java CodeQL DB (no code changes detected).`);
      } else {
        console.log('  Creating CodeQL Java database (this may take several minutes for large repos)...');
        const javaDbResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'create', javaDbDir,
            '--language=java',
            '--source-root', sourceRoot,
            '--overwrite',
            '--build-mode=none',
            `--search-path=${codeqlHome}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 45 * 60 * 1000, label: 'Java DB' }
        );

        if (javaDbResult.status !== 0) {
          console.warn(
            '  WARNING: Java CodeQL DB creation failed. ' +
            'If the repo requires compilation, ensure the build system is available ' +
            'or remove --build-mode=none to allow autobuilding.\n',
            javaDbResult.stderr.slice(-2000)
          );
          safeRm(javaDbDir);
        } else {
          saveDbFingerprint(javaDbDir, fingerprint);
        }
      }

      if (fs.existsSync(javaDbDir)) {
        console.log(`  Running Java CodeQL analysis (${javaQueryPaths.length} queries)...`);
        const javaAnalyzeResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'analyze', javaDbDir,
            ...javaQueryPaths,
            '--format=sarifv2.1.0',
            `--output=${javaSarif}`,
            `--search-path=${codeqlHome}`,
            `--search-path=${getBundledQlpacksDir(codeqlHome)}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 20 * 60 * 1000, label: 'Java Analyze' }
        );

        if (javaAnalyzeResult.status === 0 && fs.existsSync(javaSarif)) {
          const sarif = JSON.parse(fs.readFileSync(javaSarif, 'utf8'));
          const javaFindings = parseSARIF(sarif, opts.sourceRoot);
          allResults.push(...javaFindings);
          console.log(`  Java CodeQL: ${javaFindings.length} finding(s)`);
        } else if (javaAnalyzeResult.status !== 0) {
          console.warn('  WARNING: Java analysis failed:\n', javaAnalyzeResult.stderr.slice(-1000));
        }
      }
    } finally {
      for (const qPath of javaQueryPaths) {
        if (qPath.startsWith(javaGeneratedDir)) safeRm(qPath);
      }
    }
  }

  return allResults;
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function safeRm(target: string): void {
  try { fs.rmSync(target, { recursive: true, force: true }); } catch {}
}

function parseSARIF(sarif: any, sourceRoot: string): SARIFResult[] {
  const results: SARIFResult[] = [];

  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const loc = result.locations?.[0]?.physicalLocation;
      if (!loc) continue;

      const relativeUri = loc.artifactLocation?.uri ?? '';
      const absPath     = path.resolve(sourceRoot, relativeUri.replace(/^file:\/\/\//, ''));
      const startLine   = loc.region?.startLine ?? 0;

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
        snippet,
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