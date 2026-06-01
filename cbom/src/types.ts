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
  context?: string;
  cwe?: string[];
  notes?: string;
  detectionSource?: 'ast' | 'codeql';
  taintPath?: string[];
}

export interface ScanOptions {
  source: string;           
  output: string;           
  format: 'cyclonedx';      
  failOnWeak: boolean;      
  failOnSeverity?: string;  
  verbose: boolean;
  include?: string[];      
  exclude?: string[];      
  branch?: string;          
  useCodeQL?: boolean;
  codeqlPath?: string;      
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