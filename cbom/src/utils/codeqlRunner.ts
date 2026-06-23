import { execSync } from 'child_process';
import { spawn, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { getRegistry } from '../registry/registryLoader';
import pino from 'pino';

const { createAppLogger } = require(path.resolve(__dirname, '..', '..', '..', 'common', 'logger.js')) as {
  createAppLogger: (deps: { pino: typeof pino }) => {
    info: (message: string, meta?: Record<string, unknown>) => void;
    warn: (message: string, meta?: Record<string, unknown>) => void;
  };
};
const logger = createAppLogger({ pino });

export interface CodeQLRunnerOptions {
  codeqlPath?:       string;
  sourceRoot:        string;
  jsQueriesDir:      string;
  javaQueriesDir?:   string;
  pythonQueriesDir?: string;
  csharpQueriesDir?: string;
  includeJava?:      boolean;
  includePython?:    boolean;
  includeCSharp?:    boolean;
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

// ─── Python query generators ──────────────────────────────────────────────────
function buildWeakPythonAlgos(): string[] {
  const registry = getRegistry();
  const fromRegistry: string[] = [];
  registry.algorithmMeta.forEach((meta, algoName) => {
    if (meta.weak) fromRegistry.push(algoName.toLowerCase());
  });

  const pythonSpellings = [
    'md5', 'md4', 'sha1', 'sha-1',
    'des', '3des', 'des3', 'tripledes',
    'rc2', 'rc4', 'arcfour',
    'blowfish',
    'ssl', 'sslv2', 'sslv3',
    'tlsv1', 'tlsv1.1',
    'cast5', 'idea',
  ];

  return [...new Set([...fromRegistry, ...pythonSpellings])].filter(Boolean);
}

function generatePythonWeakAlgoFlowQuery(): string {
  const weakAlgos   = buildWeakPythonAlgos();
  const algoList    = qlStringList(weakAlgos);

  return `/**
 * @name Python weak cryptographic algorithm via constant propagation
 * @kind path-problem
 * @id crypto-python/weak-algo-flow
 * @severity warning
 * @tags security cryptography python
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private predicate isWeakAlgo(string s) {
  s = [${algoList}]
}

private class WeakAlgoSource extends DataFlow::Node {
  WeakAlgoSource() {
    exists(StringLiteral sc |
      isWeakAlgo(sc.getText().toLowerCase()) and
      this.asExpr() = sc
    )
    or
    exists(AssignStmt a, StringLiteral sc |
      isWeakAlgo(sc.getText().toLowerCase()) and
      a.getValue() = sc and
      this.asExpr() = sc
    )
  }
}

private class PythonCryptoSink extends DataFlow::Node {
  PythonCryptoSink() {
    exists(CallNode c |
      c.getFunction().(AttrNode).getName() = "new" and
      this.asCfgNode() = c.getArg(0)
    )
    or
    exists(CallNode c |
      c.getFunction().(NameNode).getId() = "HMAC" and
      this.asCfgNode() = c.getArg(0)
    )
    or
    exists(CallNode c |
      c.getFunction().(NameNode).getId() = "Cipher" and
      this.asCfgNode() = c.getArg(0)
    )
  }
}

module WeakAlgoFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof WeakAlgoSource }
  predicate isSink(DataFlow::Node n)   { n instanceof PythonCryptoSink }
}

module WeakAlgoFlow = TaintTracking::Global<WeakAlgoFlowConfig>;
import WeakAlgoFlow::PathGraph

from WeakAlgoFlow::PathNode src, WeakAlgoFlow::PathNode sink
where WeakAlgoFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Weak Python algorithm '$@' flows to crypto operation.", src.getNode(), src.getNode().toString()
`;
}

function generatePythonHardcodedSecretFlowQuery(): string {
  const secretRegex = buildSecretVarPatternFromRegistry();

  return `/**
 * @name Python hardcoded secret flows to cryptographic operation
 * @kind path-problem
 * @id crypto-python/hardcoded-secret-flow
 * @severity error
 * @tags security cryptography python
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

private class HardcodedSecretSource extends DataFlow::Node {
  HardcodedSecretSource() {
    exists(AssignStmt a, StringLiteral s, Name target |
      a.getValue() = s and
      a.getTarget(0) = target and
      target.getId().regexpMatch("${secretRegex}") and
      s.getText().length() >= 8 and
      not s.getText().matches("%placeholder%") and
      not s.getText().matches("%TODO%") and
      not s.getText().matches("%FIXME%") and
      not s.getText().matches("%$%") and
      not s.getText().matches("%{%") and
      this.asExpr() = s
    )
  }
}

private class CryptoKeySink extends DataFlow::Node {
  CryptoKeySink() {
    exists(CallNode c |
      c.getFunction().(AttrNode).getName() = ["new", "sign", "verify", "encrypt", "decrypt"] and
      this.asCfgNode() = c.getArg(0)
    )
    or
    exists(CallNode c |
      c.getFunction().(NameNode).getId() = ["HMAC", "Fernet", "Cipher"] and
      this.asCfgNode() = c.getArg(0)
    )
    or
    exists(CallNode c |
      c.getFunction().(AttrNode).getName() = "encode" and
      this.asCfgNode() = c.getArg(1)
    )
  }
}

module HardcodedSecretFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof HardcodedSecretSource }
  predicate isSink(DataFlow::Node n)   { n instanceof CryptoKeySink }
}

module HardcodedSecretFlow = TaintTracking::Global<HardcodedSecretFlowConfig>;
import HardcodedSecretFlow::PathGraph

from HardcodedSecretFlow::PathNode src, HardcodedSecretFlow::PathNode sink
where HardcodedSecretFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Hardcoded Python secret '$@' flows to cryptographic operation.", src.getNode(), src.getNode().toString()
`;
}

function generatePythonInsecureRandomQuery(): string {
  return `/**
 * @name Python insecure random used in security context
 * @kind problem
 * @id crypto-python/insecure-random
 * @severity warning
 * @tags security cryptography python
 */
import python

from CallNode c, AssignStmt a, Name target
where
  c.getFunction().(AttrNode).getName() = [
    "random", "randint", "randrange", "choice", "choices",
    "sample", "shuffle", "randbytes", "getrandbits"
  ] and
  a.getValue() = c.getNode() and
  a.getTarget(0) = target and
  target.getId().regexpMatch("(?i).*(token|nonce|salt|key|secret|session|csrf|otp|password|pin|iv|challenge|seed).*")
select c, "Non-cryptographic random() used to generate security-sensitive value. Use secrets or os.urandom() instead."
`;
}

function generatePythonTlsCertValidationQuery(): string {
  return `/**
 * @name Python TLS certificate validation disabled
 * @kind problem
 * @id crypto-python/tls-cert-validation-disabled
 * @severity error
 * @tags security cryptography python tls
 */
import python

from CallNode c, Keyword kw
where
  kw = c.getNode().(Call).getAKeyword() and
  kw.getArg() = "verify" and
  kw.getValue().(BooleanLiteral).booleanValue() = false and
  c.getFunction().(AttrNode).getName() = [
    "get", "post", "put", "delete", "patch", "request", "send", "head", "options"
  ]
select c, "TLS certificate verification disabled (verify=False). Vulnerable to MITM attacks."
`;
}

// ─── C# query generators ──────────────────────────────────────────────────────
function buildWeakCSharpAlgos(): string[] {
  const registry = getRegistry();
  const fromRegistry: string[] = [];
  registry.algorithmMeta.forEach((meta, algoName) => {
    if (meta.weak) fromRegistry.push(algoName.toLowerCase());
  });

  const csharpSpellings = [
    'md5', 'sha1', 'sha-1',
    'des', '3des', 'tripledes', 'rc2', 'rc4',
    'rijndael',
    'ssl', 'ssl2', 'ssl3',
    'tls1', 'tlsv1', 'tls 1.0', 'tls 1.1',
    'md5withrsa', 'sha1withrsa',
  ];

  return [...new Set([...fromRegistry, ...csharpSpellings])].filter(Boolean);
}

function generateCSharpWeakAlgoFlowQuery(): string {
  const weakAlgos = buildWeakCSharpAlgos();
  const algoList  = qlStringList(weakAlgos);

  return `/**
 * @name C# weak cryptographic algorithm via constant propagation
 * @kind path-problem
 * @id crypto-csharp/weak-algo-flow
 * @severity warning
 * @tags security cryptography csharp dotnet
 */
import csharp
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.dataflow.TaintTracking

private predicate isWeakAlgo(string s) {
  s = [${algoList}]
}

private class WeakAlgoSource extends DataFlow::Node {
  WeakAlgoSource() {
    exists(StringLiteral lit |
      isWeakAlgo(lit.getValue().toLowerCase()) and
      this.asExpr() = lit
    )
    or
    exists(Field f |
      isWeakAlgo(f.getInitializer().(StringLiteral).getValue().toLowerCase()) and
      this.asExpr() = f.getAnAccess()
    )
    or
    exists(LocalVariableDeclExpr lvde |
      isWeakAlgo(lvde.getInitializer().(StringLiteral).getValue().toLowerCase()) and
      this.asExpr() = lvde.getVariable().getAnAccess()
    )
  }
}

private class DotNetCryptoSink extends DataFlow::Node {
  DotNetCryptoSink() {
    exists(MethodCall mc |
      mc.getTarget().hasName(["Create", "CreateFromName", "GetCipher", "GetDigest", "GetSigner"]) and
      mc.getTarget().getDeclaringType().getFullyQualifiedName() in [
        "System.Security.Cryptography.HashAlgorithm",
        "System.Security.Cryptography.SymmetricAlgorithm",
        "System.Security.Cryptography.AsymmetricAlgorithm",
        "System.Security.Cryptography.CryptoConfig"
      ] and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module WeakAlgoFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof WeakAlgoSource }
  predicate isSink(DataFlow::Node n)   { n instanceof DotNetCryptoSink }
}

module WeakAlgoFlow = TaintTracking::Global<WeakAlgoFlowConfig>;
import WeakAlgoFlow::PathGraph

from WeakAlgoFlow::PathNode src, WeakAlgoFlow::PathNode sink
where WeakAlgoFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Weak C# algorithm '$@' flows to .NET crypto API.", src.getNode(), src.getNode().toString()
`;
}

function generateCSharpHardcodedSecretFlowQuery(): string {
  const secretRegex = buildSecretVarPatternFromRegistry();

  return `/**
 * @name C# hardcoded secret flows to cryptographic operation
 * @kind path-problem
 * @id crypto-csharp/hardcoded-secret-flow
 * @severity error
 * @tags security cryptography csharp dotnet
 */
import csharp
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.dataflow.TaintTracking

private class HardcodedSecretSource extends DataFlow::Node {
  HardcodedSecretSource() {
    exists(Field f, StringLiteral lit |
      f.getName().regexpMatch("${secretRegex}") and
      f.getInitializer() = lit and
      lit.getValue().length() >= 8 and
      not lit.getValue().matches("%$%") and
      not lit.getValue().matches("%{%") and
      not lit.getValue().matches("%placeholder%") and
      not lit.getValue().matches("%TODO%") and
      not lit.getValue().matches("%FIXME%") and
      this.asExpr() = lit
    )
    or
    exists(LocalVariableDeclExpr lvde, StringLiteral lit |
      lvde.getVariable().getName().regexpMatch("${secretRegex}") and
      lvde.getInitializer() = lit and
      lit.getValue().length() >= 8 and
      not lit.getValue().matches("%$%") and
      not lit.getValue().matches("%placeholder%") and
      not lit.getValue().matches("%TODO%") and
      this.asExpr() = lit
    )
  }
}

private class CryptoKeySink extends DataFlow::Node {
  CryptoKeySink() {
    exists(AssignExpr ae |
      ae.getLValue().(PropertyAccess).getProperty().hasName("Key") and
      ae.getLValue().(PropertyAccess).getProperty().getDeclaringType().getFullyQualifiedName().matches("System.Security.Cryptography.%") and
      this.asExpr() = ae.getRValue()
    )
    or
    exists(ObjectCreation oc |
      oc.getType().getFullyQualifiedName().matches("System.Security.Cryptography.HMAC%") and
      this.asExpr() = oc.getArgument(0)
    )
    or
    exists(ObjectCreation oc |
      oc.getType().getFullyQualifiedName() in [
        "System.Security.Cryptography.AesGcm",
        "System.Security.Cryptography.AesCcm",
        "System.Security.Cryptography.ChaCha20Poly1305"
      ] and
      this.asExpr() = oc.getArgument(0)
    )
  }
}

module HardcodedSecretFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof HardcodedSecretSource }
  predicate isSink(DataFlow::Node n)   { n instanceof CryptoKeySink }
}

module HardcodedSecretFlow = TaintTracking::Global<HardcodedSecretFlowConfig>;
import HardcodedSecretFlow::PathGraph

from HardcodedSecretFlow::PathNode src, HardcodedSecretFlow::PathNode sink
where HardcodedSecretFlow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "Hardcoded C# secret '$@' flows to cryptographic operation.", src.getNode(), src.getNode().toString()
`;
}

function generateCSharpWeakKeySizeQuery(): string {
  return `/**
 * @name C# weak key size in .NET key generation
 * @kind problem
 * @id crypto-csharp/weak-key-size
 * @severity warning
 * @tags security cryptography csharp dotnet
 */
import csharp

from Expr target, string message
where
  (
    exists(ObjectCreation oc, IntLiteral keySizeLit, int keySize |
      oc.getType().getFullyQualifiedName() in [
        "System.Security.Cryptography.RSACryptoServiceProvider",
        "System.Security.Cryptography.RSAOpenSsl"
      ] and
      keySizeLit = oc.getArgument(0) and
      keySize = keySizeLit.getIntValue() and
      keySize < 2048 and
      target = oc and
      message = "RSA key size " + keySize + " bits is below the recommended minimum of 2048 bits."
    )
    or
    exists(ObjectCreation oc, IntLiteral keySizeLit, int keySize |
      oc.getType().getFullyQualifiedName() in [
        "System.Security.Cryptography.DSACryptoServiceProvider",
        "System.Security.Cryptography.DSAOpenSsl"
      ] and
      keySizeLit = oc.getArgument(0) and
      keySize = keySizeLit.getIntValue() and
      keySize < 2048 and
      target = oc and
      message = "DSA key size " + keySize + " bits is below the recommended minimum of 2048 bits."
    )
    or
    exists(AssignExpr ae, IntLiteral keySizeLit, int keySize |
      ae.getLValue().(PropertyAccess).getProperty().hasName("KeySize") and
      ae.getLValue().(PropertyAccess).getProperty().getDeclaringType().getFullyQualifiedName() in [
        "System.Security.Cryptography.ECDsa",
        "System.Security.Cryptography.ECDiffieHellman",
        "System.Security.Cryptography.ECDsaCng",
        "System.Security.Cryptography.ECDiffieHellmanCng"
      ] and
      keySizeLit = ae.getRValue() and
      keySize = keySizeLit.getIntValue() and
      keySize < 256 and
      target = ae and
      message = "EC key size " + keySize + " bits is below the recommended minimum of 256 bits."
    )
  )
select target, message
`;
}

function generateCSharpTlsCertValidationQuery(): string {
  return `/**
 * @name C# TLS certificate validation disabled
 * @kind problem
 * @id crypto-csharp/tls-cert-validation-disabled
 * @severity error
 * @tags security cryptography csharp dotnet tls
 */
import csharp

from Element target, string message
where
  (
    exists(AssignExpr a |
      a.getLValue().(PropertyAccess).getProperty().hasName("ServerCertificateValidationCallback") and
      a.getLValue().(PropertyAccess).getQualifier().(TypeAccess).getType().getFullyQualifiedName() = "System.Net.ServicePointManager" and
      a.getRValue().(AnonymousFunctionExpr).getExpressionBody().(BoolLiteral).getValue() = "true" and
      target = a and
      message = "TLS certificate validation disabled via ServerCertificateValidationCallback returning true."
    )
    or
    exists(AssignExpr a |
      a.getLValue().(PropertyAccess).getProperty().hasName("ServerCertificateCustomValidationCallback") and
      a.getRValue().(AnonymousFunctionExpr).getExpressionBody().(BoolLiteral).getValue() = "true" and
      target = a and
      message = "TLS certificate validation disabled in HttpClientHandler callback."
    )
    or
    exists(AssignExpr a |
      a.getLValue().(PropertyAccess).getProperty().hasName("ServerCertificateCustomValidationCallback") and
      a.getRValue().(PropertyAccess).getProperty().hasName("DangerousAcceptAnyServerCertificateValidator") and
      target = a and
      message = "TLS validation bypassed via DangerousAcceptAnyServerCertificateValidator."
    )
  )
select target, message
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

function detectPythonInSource(sourceRoot: string): boolean {
  const indicators = ['requirements.txt', 'pyproject.toml', 'setup.py', 'setup.cfg', 'Pipfile'];
  for (const indicator of indicators) {
    if (fs.existsSync(path.join(sourceRoot, indicator))) return true;
  }
  try {
    const check = (dir: string, depth: number): boolean => {
      if (depth > 3) return false;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isFile() && entry.name.endsWith('.py')) return true;
        if (
          entry.isDirectory() &&
          entry.name !== '__pycache__' &&
          entry.name !== '.venv' &&
          entry.name !== 'venv' &&
          check(path.join(dir, entry.name), depth + 1)
        ) return true;
      }
      return false;
    };
    return check(sourceRoot, 0);
  } catch {
    return false;
  }
}

function detectCSharpInSource(sourceRoot: string): boolean {
  const indicators = ['.sln', '.csproj', 'global.json'];
  for (const indicator of indicators) {
    if (fs.existsSync(path.join(sourceRoot, indicator))) return true;
  }
  try {
    const check = (dir: string, depth: number): boolean => {
      if (depth > 3) return false;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isFile() && (entry.name.endsWith('.cs') || entry.name.endsWith('.csproj') || entry.name.endsWith('.sln'))) return true;
        if (
          entry.isDirectory() &&
          entry.name !== 'bin' &&
          entry.name !== 'obj' &&
          check(path.join(dir, entry.name), depth + 1)
        ) return true;
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

function getStableDbDir(
  sourceRoot: string,
  language: 'javascript' | 'java' | 'python' | 'csharp'
): string {
  const hash = crypto.createHash('md5').update(sourceRoot).digest('hex').slice(0, 8);
  const baseDir = path.join(os.homedir(), '.cbom-js', 'codeql-dbs');
  fs.mkdirSync(baseDir, { recursive: true });
  return path.join(baseDir, `${hash}-${language}`);
}

// ─── qlpack + workspace helpers ───────────────────────────────────────────────
function getBundledQlpacksDir(codeqlHome: string): string {
  const bundled = path.join(codeqlHome, 'qlpacks');
  if (fs.existsSync(bundled)) return bundled;
  const parent = path.join(path.dirname(codeqlHome), 'qlpacks');
  if (fs.existsSync(parent)) return parent;
  return bundled;
}

function ensureQlPack(
  dir: string,
  language: 'javascript' | 'java' | 'python' | 'csharp',
  codeqlHome: string
): void {
  const depMap: Record<string, string> = {
    javascript: 'codeql/javascript-all',
    java:       'codeql/java-all',
    python:     'codeql/python-all',
    csharp:     'codeql/csharp-all',
  };
  const nameMap: Record<string, string> = {
    javascript: 'cbom-js/crypto-queries-js',
    java:       'cbom-js/crypto-queries-java',
    python:     'cbom-js/crypto-queries-python',
    csharp:     'cbom-js/crypto-queries-csharp',
  };

  const dep      = depMap[language];
  const packName = nameMap[language];
  const bundledQlpacks = getBundledQlpacksDir(codeqlHome);

  fs.writeFileSync(
    path.join(dir, 'qlpack.yml'),
    `name: ${packName}\nversion: 0.0.1\ndependencies:\n  ${dep}: "*"\n`,
    'utf8'
  );
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
      process.stdout.write(d);
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

  const jsQueriesDir     = opts.jsQueriesDir;
  const javaQueriesDir   = opts.javaQueriesDir   ?? path.join(path.dirname(opts.jsQueriesDir), 'java');
  const pythonQueriesDir = opts.pythonQueriesDir  ?? path.join(path.dirname(opts.jsQueriesDir), 'python');
  const csharpQueriesDir = opts.csharpQueriesDir  ?? path.join(path.dirname(opts.jsQueriesDir), 'csharp');
  const generatedBase    = path.join(path.dirname(opts.jsQueriesDir), '_generated');

  const sourceRoot = opts.sourceRoot.replace(/\\/g, '/');
  const allResults: SARIFResult[] = [];

  const hasJS     = detectJSInSource(opts.sourceRoot);
  const hasJava   = opts.includeJava    ?? detectJavaInSource(opts.sourceRoot);
  const hasPython = opts.includePython  ?? detectPythonInSource(opts.sourceRoot);
  const hasCSharp = opts.includeCSharp  ?? detectCSharpInSource(opts.sourceRoot);

  if (!hasJS && !hasJava && !hasPython && !hasCSharp) {
    logger.info('No supported source files detected — skipping CodeQL analysis.');
    return [];
  }

  const fingerprint = getSourceFingerprint(opts.sourceRoot);
  const ts = Date.now();

  // ── JS/TS block ──────────────────────────────────────────────────────────────
  if (hasJS) {
    logger.info('\nCodeQL: JS/TS source detected.');

    const jsGeneratedDir = path.join(generatedBase, 'js');
    fs.mkdirSync(jsGeneratedDir, { recursive: true });
    ensureQlPack(jsGeneratedDir, 'javascript', codeqlHome);

    const regPath  = path.join(jsGeneratedDir, `js-registry-${ts}.ql`);
    const weakPath = path.join(jsGeneratedDir, `js-weakalgo-${ts}.ql`);
    fs.writeFileSync(regPath,  generateRegistryDrivenQuery(), 'utf8');
    fs.writeFileSync(weakPath, generateWeakAlgoQuery(),       'utf8');

    const staticJsQueries = fs.existsSync(jsQueriesDir)
      ? fs.readdirSync(jsQueriesDir).filter(f => f.endsWith('.ql')).map(f => path.join(jsQueriesDir, f))
      : [];
    const jsQueries = [regPath, weakPath, ...staticJsQueries];

    const jsDbDir  = getStableDbDir(opts.sourceRoot, 'javascript');
    const jsSarif  = path.join(jsGeneratedDir, `js-results-${ts}.sarif`);

    try {
      if (isDbReusable(jsDbDir, fingerprint)) {
        logger.info('  Reusing existing JS/TS CodeQL DB (no code changes detected).');
      } else {
        logger.info('  Creating CodeQL JS/TS database...');
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
          logger.warn(`  WARNING: JS/TS CodeQL DB creation failed:\n${dbResult.stderr.slice(-1000)}`);
          safeRm(jsDbDir);
        } else {
          saveDbFingerprint(jsDbDir, fingerprint);
        }
      }

      if (fs.existsSync(jsDbDir)) {
        logger.info(`  Running JS/TS CodeQL analysis (${jsQueries.length} queries)...`);
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
          logger.info(`  JS/TS CodeQL: ${jsFindings.length} finding(s)`);
        } else if (analyzeResult.status !== 0) {
          logger.warn(`  WARNING: JS/TS analysis failed:\n${analyzeResult.stderr.slice(-1000)}`);
        }
      }
    } finally {
      safeRm(regPath);
      safeRm(weakPath);
    }
  }

  // ── Java block ───────────────────────────────────────────────────────────────
  if (hasJava) {
    logger.info('\nCodeQL: Java source detected — running Java crypto queries...');

    const javaGeneratedDir = path.join(generatedBase, 'java');
    fs.mkdirSync(javaGeneratedDir, { recursive: true });
    ensureQlPack(javaGeneratedDir, 'java', codeqlHome);

    const javaQueryDefs: Array<{ name: string; content: string }> = [
      { name: `java-weak-algo-flow-${ts}.ql`,        content: generateJavaWeakAlgoFlowQuery()         },
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
      ? fs.readdirSync(javaQueriesDir).filter(f => f.endsWith('.ql')).map(f => path.join(javaQueriesDir, f))
      : [];
    javaQueryPaths.push(...staticJavaQueries);

    const javaDbDir = getStableDbDir(opts.sourceRoot, 'java');
    const javaSarif = path.join(javaGeneratedDir, `java-results-${ts}.sarif`);

    try {
      if (isDbReusable(javaDbDir, fingerprint)) {
        logger.info('  Reusing existing Java CodeQL DB (no code changes detected).');
      } else {
        logger.info('  Creating CodeQL Java database (this may take several minutes for large repos)...');
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
          logger.warn(
            '  WARNING: Java CodeQL DB creation failed. ' +
            'If the repo requires compilation, ensure the build system is available ' +
            `or remove --build-mode=none to allow autobuilding.\n${javaDbResult.stderr.slice(-2000)}`
          );
          safeRm(javaDbDir);
        } else {
          saveDbFingerprint(javaDbDir, fingerprint);
        }
      }

      if (fs.existsSync(javaDbDir)) {
        logger.info(`  Running Java CodeQL analysis (${javaQueryPaths.length} queries)...`);
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
          logger.info(`  Java CodeQL: ${javaFindings.length} finding(s)`);
        } else if (javaAnalyzeResult.status !== 0) {
          logger.warn(`  WARNING: Java analysis failed:\n${javaAnalyzeResult.stderr.slice(-1000)}`);
        }
      }
    } finally {
      for (const qPath of javaQueryPaths) {
        if (qPath.startsWith(javaGeneratedDir)) safeRm(qPath);
      }
    }
  }

  // ── Python block ─────────────────────────────────────────────────────────────
  if (hasPython) {
    logger.info('\nCodeQL: Python source detected — running Python crypto queries...');

    const pythonGeneratedDir = path.join(generatedBase, 'python');
    fs.mkdirSync(pythonGeneratedDir, { recursive: true });
    ensureQlPack(pythonGeneratedDir, 'python', codeqlHome);

    const pythonQueryDefs: Array<{ name: string; content: string }> = [
      { name: `python-weak-algo-flow-${ts}.ql`,       content: generatePythonWeakAlgoFlowQuery()       },
      { name: `python-hardcoded-secret-${ts}.ql`,     content: generatePythonHardcodedSecretFlowQuery() },
      { name: `python-insecure-random-${ts}.ql`,      content: generatePythonInsecureRandomQuery()      },
      { name: `python-tls-cert-validation-${ts}.ql`,  content: generatePythonTlsCertValidationQuery()   },
    ];

    const pythonQueryPaths: string[] = [];
    for (const q of pythonQueryDefs) {
      const qPath = path.join(pythonGeneratedDir, q.name);
      fs.writeFileSync(qPath, q.content, 'utf8');
      pythonQueryPaths.push(qPath);
    }
    const staticPythonQueries = fs.existsSync(pythonQueriesDir)
      ? fs.readdirSync(pythonQueriesDir).filter(f => f.endsWith('.ql')).map(f => path.join(pythonQueriesDir, f))
      : [];
    pythonQueryPaths.push(...staticPythonQueries);

    const pythonDbDir = getStableDbDir(opts.sourceRoot, 'python');
    const pythonSarif = path.join(pythonGeneratedDir, `python-results-${ts}.sarif`);

    try {
      if (isDbReusable(pythonDbDir, fingerprint)) {
        logger.info('  Reusing existing Python CodeQL DB (no code changes detected).');
      } else {
        logger.info('  Creating CodeQL Python database...');
        const pythonDbResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'create', pythonDbDir,
            '--language=python',
            '--source-root', sourceRoot,
            '--overwrite',
            `--search-path=${codeqlHome}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 20 * 60 * 1000, label: 'Python DB' }
        );
        if (pythonDbResult.status !== 0) {
          logger.warn(`  WARNING: Python CodeQL DB creation failed:\n${pythonDbResult.stderr.slice(-1000)}`);
          safeRm(pythonDbDir);
        } else {
          saveDbFingerprint(pythonDbDir, fingerprint);
        }
      }

      if (fs.existsSync(pythonDbDir)) {
        logger.info(`  Running Python CodeQL analysis (${pythonQueryPaths.length} queries)...`);
        const pythonAnalyzeResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'analyze', pythonDbDir,
            ...pythonQueryPaths,
            '--format=sarifv2.1.0',
            `--output=${pythonSarif}`,
            `--search-path=${codeqlHome}`,
            `--search-path=${getBundledQlpacksDir(codeqlHome)}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 20 * 60 * 1000, label: 'Python Analyze' }
        );
        if (pythonAnalyzeResult.status === 0 && fs.existsSync(pythonSarif)) {
          const sarif = JSON.parse(fs.readFileSync(pythonSarif, 'utf8'));
          const pythonFindings = parseSARIF(sarif, opts.sourceRoot);
          allResults.push(...pythonFindings);
          logger.info(`  Python CodeQL: ${pythonFindings.length} finding(s)`);
        } else if (pythonAnalyzeResult.status !== 0) {
          logger.warn(`  WARNING: Python analysis failed:\n${pythonAnalyzeResult.stderr.slice(-1000)}`);
        }
      }
    } finally {
      for (const qPath of pythonQueryPaths) {
        if (qPath.startsWith(pythonGeneratedDir)) safeRm(qPath);
      }
    }
  }

  // ── C# block ─────────────────────────────────────────────────────────────────
  if (hasCSharp) {
    logger.info('\nCodeQL: C# source detected — running C# crypto queries...');

    const csharpGeneratedDir = path.join(generatedBase, 'csharp');
    fs.mkdirSync(csharpGeneratedDir, { recursive: true });
    ensureQlPack(csharpGeneratedDir, 'csharp', codeqlHome);

    const csharpQueryDefs: Array<{ name: string; content: string }> = [
      { name: `csharp-weak-algo-flow-${ts}.ql`,       content: generateCSharpWeakAlgoFlowQuery()       },
      { name: `csharp-hardcoded-secret-${ts}.ql`,     content: generateCSharpHardcodedSecretFlowQuery() },
      { name: `csharp-weak-key-size-${ts}.ql`,        content: generateCSharpWeakKeySizeQuery()         },
      { name: `csharp-tls-cert-validation-${ts}.ql`,  content: generateCSharpTlsCertValidationQuery()   },
    ];

    const csharpQueryPaths: string[] = [];
    for (const q of csharpQueryDefs) {
      const qPath = path.join(csharpGeneratedDir, q.name);
      fs.writeFileSync(qPath, q.content, 'utf8');
      csharpQueryPaths.push(qPath);
    }
    const staticCSharpQueries = fs.existsSync(csharpQueriesDir)
      ? fs.readdirSync(csharpQueriesDir).filter(f => f.endsWith('.ql')).map(f => path.join(csharpQueriesDir, f))
      : [];
    csharpQueryPaths.push(...staticCSharpQueries);

    const csharpDbDir = getStableDbDir(opts.sourceRoot, 'csharp');
    const csharpSarif = path.join(csharpGeneratedDir, `csharp-results-${ts}.sarif`);

    try {
      if (isDbReusable(csharpDbDir, fingerprint)) {
        logger.info('  Reusing existing C# CodeQL DB (no code changes detected).');
      } else {
        logger.info('  Creating CodeQL C# database (may require dotnet build for older targets)...');
        const csharpDbResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'create', csharpDbDir,
            '--language=csharp',
            '--source-root', sourceRoot,
            '--overwrite',
            '--build-mode=none',
            `--search-path=${codeqlHome}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 45 * 60 * 1000, label: 'CSharp DB' }
        );
        if (csharpDbResult.status !== 0) {
          logger.warn(
            '  WARNING: C# CodeQL DB creation failed. ' +
            'If the repo requires compilation, ensure dotnet SDK is available ' +
            `or remove --build-mode=none to allow autobuilding.\n${csharpDbResult.stderr.slice(-2000)}`
          );
          safeRm(csharpDbDir);
        } else {
          saveDbFingerprint(csharpDbDir, fingerprint);
        }
      }

      if (fs.existsSync(csharpDbDir)) {
        logger.info(`  Running C# CodeQL analysis (${csharpQueryPaths.length} queries)...`);
        const csharpAnalyzeResult = await spawnAsync(
          codeqlBin,
          [
            'database', 'analyze', csharpDbDir,
            ...csharpQueryPaths,
            '--format=sarifv2.1.0',
            `--output=${csharpSarif}`,
            `--search-path=${codeqlHome}`,
            `--search-path=${getBundledQlpacksDir(codeqlHome)}`,
            `--search-path=${codeqlPackageCache}`,
          ],
          { timeout: 20 * 60 * 1000, label: 'CSharp Analyze' }
        );
        if (csharpAnalyzeResult.status === 0 && fs.existsSync(csharpSarif)) {
          const sarif = JSON.parse(fs.readFileSync(csharpSarif, 'utf8'));
          const csharpFindings = parseSARIF(sarif, opts.sourceRoot);
          allResults.push(...csharpFindings);
          logger.info(`  C# CodeQL: ${csharpFindings.length} finding(s)`);
        } else if (csharpAnalyzeResult.status !== 0) {
          logger.warn(`  WARNING: C# analysis failed:\n${csharpAnalyzeResult.stderr.slice(-1000)}`);
        }
      }
    } finally {
      for (const qPath of csharpQueryPaths) {
        if (qPath.startsWith(csharpGeneratedDir)) safeRm(qPath);
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


