
import React from 'react';
import { Shield, Bug, Search, Zap, Code, Terminal } from 'lucide-react';
import { VulnerabilityType } from './types';

export const VULN_TYPES: VulnerabilityType[] = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    description: 'Detects if database queries can be manipulated.',
    defaultPayload: "' OR 1=1 --"
  },
  {
    id: 'xss',
    name: 'XSS (Cross-Site Scripting)',
    description: 'Checks if script tags are reflected back to the user.',
    defaultPayload: "<script>alert('XSS')</script>"
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    description: 'Attempts to access restricted local files.',
    defaultPayload: "../../etc/passwd"
  },
  {
    id: 'command-injection',
    name: 'Command Injection',
    description: 'Tests if system commands can be executed remotely.',
    defaultPayload: "; cat /etc/passwd"
  },
  {
    id: 'ssrf',
    name: 'SSRF (Server-Side Request Forgery)',
    description: 'Tests if server can be tricked into making internal requests.',
    defaultPayload: "http://localhost:8080/admin"
  },
  {
    id: 'xxe',
    name: 'XXE (XML External Entity)',
    description: 'Tests for XML parser vulnerabilities that leak data.',
    defaultPayload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
  },
  {
    id: 'ssti',
    name: 'SSTI (Server-Side Template Injection)',
    description: 'Tests if template engines can execute arbitrary code.',
    defaultPayload: "{{7*7}}"
  },
  {
    id: 'open-redirect',
    name: 'Open Redirect',
    description: 'Tests if URLs can redirect users to malicious sites.',
    defaultPayload: "//evil.com"
  },
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection',
    description: 'Tests MongoDB and other NoSQL databases for injection.',
    defaultPayload: '{"$gt": ""}'
  },
  {
    id: 'ldap-injection',
    name: 'LDAP Injection',
    description: 'Tests if LDAP queries can be manipulated.',
    defaultPayload: "*)(uid=*))(|(uid=*"
  },
  {
    id: 'crlf-injection',
    name: 'CRLF Injection',
    description: 'Tests for HTTP header injection via line breaks.',
    defaultPayload: "%0d%0aSet-Cookie:hacked=true"
  },
  {
    id: 'host-header',
    name: 'Host Header Injection',
    description: 'Tests for host header manipulation vulnerabilities.',
    defaultPayload: "evil.com"
  }
];

export const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: <Shield size={20} /> },
  { id: 'scanner', label: 'Scanner', icon: <Search size={20} /> },
  { id: 'reports', label: 'Reports', icon: <Terminal size={20} /> },
  { id: 'settings', label: 'Settings', icon: <Zap size={20} /> },
];
