export interface CryptoFinding {
  algorithm: string;
  library: string;
  location: string;
  line: number;
  column?: number;
  mode?: string;
  keySize?: number;
  weak: boolean;
  quantumSafe: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  context?: string; // surrounding code snippet
  cwe?: string[];
  notes?: string;
}

export interface ScanOptions {
  source: string;           // local path or github url
  output: string;           // output file path
  format: 'cyclonedx';      // only cyclonedx for now
  failOnWeak: boolean;      // exit 1 if weak crypto found
  failOnSeverity?: string;  // exit 1 if severity >= this
  verbose: boolean;
  include?: string[];       // file patterns to include
  exclude?: string[];       // file patterns to exclude
  branch?: string;          // git branch if using github url
}

export interface ScanResult {
  findings: CryptoFinding[];
  filesScanned: number;
  duration: number;
  projectName: string;
  projectPath: string;
  summary: ScanSummary;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  weak: number;
  quantumVulnerable: number;
  byAlgorithm: Record<string, number>;
  byLibrary: Record<string, number>;
}