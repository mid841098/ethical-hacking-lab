# Proof of Concept: Security Misconfiguration & Missing Security Headers (OWASP A05:2021)

**Vulnerability Type:** Security Misconfiguration  
**Affected Component:** HTTP Response Headers & Error Handler  
**Severity:** MEDIUM (CVSS 5.0 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
**Target:** `http://127.0.0.1:3000/` and `http://127.0.0.1:3000/api/admin/debug`  

## 1. Technical Vulnerability Description
The web server omits industry-standard defensive HTTP headers, includes verbose technology version headers (`Server` and `X-Powered-By`), and leaves an administrative debug diagnostic route publicly exposed without access controls.

## 2. Evidence of Missing Defensive Headers
```http
Server: NodeJS-Express-Lab/1.0.4-dev (Vulnerable Sandbox)   <-- LEAKED RUNTIME
X-Powered-By: Node.js/v24.13.0                             <-- LEAKED VERSION
Access-Control-Allow-Origin: *                             <-- INSECURE WILDCARD CORS

[MISSING] Content-Security-Policy
[MISSING] X-Frame-Options
[MISSING] X-Content-Type-Options
[MISSING] Strict-Transport-Security
```

## 3. Discovered Debug Route Evidence: GET `/api/admin/debug`
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "warning": "DEBUG INTERFACE EXPOSED - FOR INTERNAL TESTING ONLY",
  "environmentVariables": {
    "NODE_ENV": "development",
    "DATABASE_DIALECT": "in-memory-sqlite-sim",
    "HOST_BINDING": "127.0.0.1:3000"
  },
  "registeredRoutes": [
    "/api/health",
    "/api/version",
    "/api/products/search",
    "/api/profile",
    "/api/orders",
    "/api/auth/login",
    "/api/feedback",
    "/api/admin/debug"
  ]
}
```

## 4. Security Impact
Exposing runtime versions aids attackers in finding precise CVE exploits. Missing security headers allows MIME-sniffing attacks, clickjacking via frames, and Cross-Origin data exfiltration.
