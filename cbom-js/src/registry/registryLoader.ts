// src/registry/registryLoader.ts
// Loads libraries.json and exposes typed, pre-indexed access to all rules

import * as path from 'path';
import * as fs from 'fs';

// ── Types matching libraries.json schema ──────────────────────────────────────

export interface MethodRule {
  primitive: string;
  detection: 'memberCall' | 'nestedMemberCall' | 'deepMemberCall' | 'newExpression' | 'directCall' | 'importedFunction' | 'importedObject';
  fixedAlgorithm?: string;
  algoArgIndex?: number;
  algoPrefix?: string;
  algoFromOption?: string;
  optionArgIndex?: number;
  defaultAlgorithm?: string;
  keySizeOption?: string;
  parseAlgoMode?: boolean;
  notes?: string;
}

export interface PackageRule {
  aliases: string[];
  description: string;
  type: 'builtin' | 'npm';
  methods: Record<string, MethodRule>;
}

export interface AlgorithmMeta {
  weak: boolean;
  quantumSafe: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cwe: string[];
  oid?: string;
  notes?: string;
}

export interface HardcodedPatterns {
  variableNames: string[];
  minLength: number;
  excludePrefixes: string[];
  excludePatterns: string[];
}

export interface InsecureRandomPattern {
  object: string;
  method: string;
  algorithm: string;
  notes: string;
  contextCheck?: boolean;
}

export interface TLSPropertyRule {
  type: 'version' | 'cipherSuite' | 'boolean' | 'function';
  weakValues?: string[];
  weakSubstrings?: string[];
  weakValue?: boolean;
  algorithm?: string;
}

export interface Registry {
  packages: Record<string, PackageRule>;
  algorithms: Record<string, AlgorithmMeta>;
  hardcodedPatterns: HardcodedPatterns;
  insecureRandomPatterns: { patterns: InsecureRandomPattern[] };
  tlsPatterns: {
    weakVersions: string[];
    weakCiphers: string[];
    propertyMap: Record<string, TLSPropertyRule>;
    envVars: Record<string, { weakValue: string; algorithm: string }>;
  };
}

// ── Pre-built indexes for fast lookup ────────────────────────────────────────

export interface RegistryIndex {
  // raw registry
  registry: Registry;

  // alias → package name (e.g. 'CryptoJS' → 'crypto-js')
  aliasToPackage: Map<string, string>;

  // package name → PackageRule
  packageRules: Map<string, PackageRule>;

  // normalized algo name → AlgorithmMeta
  algorithmMeta: Map<string, AlgorithmMeta>;

  // hardcoded variable name set (lowercased for matching)
  hardcodedVarNames: Set<string>;
}

// ── Singleton ─────────────────────────────────────────────────────────────────

let _index: RegistryIndex | null = null;

export function getRegistry(): RegistryIndex {
  if (_index) return _index;

  const registryPath = path.join(__dirname, 'libraries.json');
  const raw = fs.readFileSync(registryPath, 'utf-8');
  const registry = JSON.parse(raw) as Registry;

  const aliasToPackage = new Map<string, string>();
  const packageRules = new Map<string, PackageRule>();
  const algorithmMeta = new Map<string, AlgorithmMeta>();
  const hardcodedVarNames = new Set<string>();

  // Index packages + aliases
  for (const [pkgName, pkgRule] of Object.entries(registry.packages)) {
    packageRules.set(pkgName, pkgRule);
    for (const alias of pkgRule.aliases) {
      aliasToPackage.set(alias, pkgName);
      aliasToPackage.set(alias.toLowerCase(), pkgName);
    }
  }

  // Index algorithms (normalize key to uppercase)
  for (const [algoName, meta] of Object.entries(registry.algorithms)) {
    if (algoName.startsWith('_')) continue;
    algorithmMeta.set(algoName.toUpperCase(), meta as AlgorithmMeta);
  }

  // Index hardcoded variable names (lowercase for case-insensitive matching)
  for (const name of registry.hardcodedPatterns.variableNames) {
    hardcodedVarNames.add(name.toLowerCase());
  }

  _index = { registry, aliasToPackage, packageRules, algorithmMeta, hardcodedVarNames };
  return _index;
}

// ── Helpers used by detectors ─────────────────────────────────────────────────

export function getAlgorithmMeta(algorithm: string): AlgorithmMeta {
  const { algorithmMeta } = getRegistry();
  const normalized = algorithm.toUpperCase();

  // Exact match first
  if (algorithmMeta.has(normalized)) {
    return algorithmMeta.get(normalized)!;
  }

  // Prefix match (e.g. 'AES-128-CBC' → 'AES-CBC' or 'AES')
  for (const [key, meta] of algorithmMeta.entries()) {
    if (normalized.startsWith(key) || normalized.includes(key)) {
      return meta;
    }
  }

  // Default — unknown algorithm, treat as INFO
  return {
    weak: false,
    quantumSafe: true,
    severity: 'INFO',
    cwe: []
  };
}

export function resolvePackage(importName: string): string | null {
  const { aliasToPackage } = getRegistry();
  return aliasToPackage.get(importName) || aliasToPackage.get(importName.toLowerCase()) || null;
}

export function getPackageRule(packageName: string): PackageRule | null {
  const { packageRules } = getRegistry();
  return packageRules.get(packageName) || null;
}

export function isHardcodedVarName(name: string): boolean {
  const { hardcodedVarNames } = getRegistry();
  return hardcodedVarNames.has(name.toLowerCase());
}

export function isExcludedHardcodedValue(value: string): boolean {
  const { registry } = getRegistry();
  const { excludePrefixes, excludePatterns, minLength } = registry.hardcodedPatterns;

  if (value.length < minLength) return true;
  if (excludePrefixes.some(p => value.startsWith(p))) return true;
  if (excludePatterns.some(p => value.toLowerCase().includes(p.toLowerCase()))) return true;

  return false;
}