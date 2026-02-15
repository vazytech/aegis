
export enum Severity {
  CRITICAL = 'Critical',
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low',
  INFO = 'Info'
}

export interface ScanResult {
  id: string;
  timestamp: string;
  targetUrl: string;
  payload: string;
  vulnType: string;
  vulnerability_found: boolean;
  severity: Severity;
  analysis: string;
  fix_suggestion: string;
  rawResponse?: {
    statusCode: number;
    snippet: string;
  };
}

export interface VulnerabilityType {
  id: string;
  name: string;
  description: string;
  defaultPayload: string;
}

export enum ScanStatus {
  IDLE = 'IDLE',
  SCANNING = 'SCANNING',
  ANALYZING = 'ANALYZING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED'
}
