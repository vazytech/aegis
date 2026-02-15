/**
 * Scanner API Service
 * Connects frontend to the real scanning backend
 */

// Use environment variable for production, fallback to localhost for development
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:3001';

export interface ScanRequest {
  targetUrl: string;
  vulnType: string;
  payload: string;
}

export interface ScanResponse {
  vulnerability_found: boolean;
  severity: string;
  findings: Array<{
    payload: string;
    parameter: string;
    evidence: string;
    type: string;
    statusCode: number;
  }>;
  rawResponses: Array<{
    payload: string;
    param: string;
    statusCode: number;
    bodyLength: number;
    snippet: string;
  }>;
  testedPayloads: string[];
  analysis: string;
  fix_suggestion: string;
}

/**
 * Check if backend is running
 */
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/health`);
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Run a real security scan against the target
 */
export async function runRealScan(request: ScanRequest): Promise<ScanResponse> {
  const response = await fetch(`${BACKEND_URL}/api/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Scan failed');
  }

  return response.json();
}
