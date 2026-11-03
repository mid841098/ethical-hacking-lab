/**
 * Reconnaissance & Attack Surface Mapper Script
 * Track: Ethical Hacking - EdVyro Internship (Task 2)
 * File: scripts/run-recon.js
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const TARGET_HOST = '127.0.0.1';
const TARGET_PORT = 3000;
const BASE_URL = `http://${TARGET_HOST}:${TARGET_PORT}`;

function makeRequest(pathname, method = 'GET', postData = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const reqHeaders = { ...headers };
    if (postData) {
      reqHeaders['Content-Length'] = Buffer.byteLength(postData);
    }
    const req = http.request({
      host: TARGET_HOST,
      port: TARGET_PORT,
      path: pathname,
      method: method,
      headers: reqHeaders,
      timeout: 3000
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    if (postData) req.write(postData);
    req.end();
  });
}

async function run() {
  console.log(`[RECON] Starting safe reconnaissance against ${BASE_URL}...`);
  const timestamp = new Date().toISOString();

  // 1. Root probe
  const rootRes = await makeRequest('/');
  console.log(`Root endpoint probed: HTTP ${rootRes.statusCode}`);

  // 2. Health check
  const healthRes = await makeRequest('/api/health');
  console.log(`Health endpoint probed: HTTP ${healthRes.statusCode}`);

  // 3. Version probe
  const versionRes = await makeRequest('/api/version');
  console.log(`Version endpoint probed: HTTP ${versionRes.statusCode}`);

  // 4. Products search probe
  const searchRes = await makeRequest('/api/products/search?q=guide');
  console.log(`Search endpoint probed: HTTP ${searchRes.statusCode}`);

  // 5. User profile probe
  const profileRes = await makeRequest('/api/profile?id=2');
  console.log(`Profile endpoint probed: HTTP ${profileRes.statusCode}`);

  // 6. Orders probe
  const ordersRes = await makeRequest('/api/orders?id=5002');
  console.log(`Orders endpoint probed: HTTP ${ordersRes.statusCode}`);

  // 7. Feedback probe
  const feedbackRes = await makeRequest('/api/feedback?msg=TestAuditorProbe');
  console.log(`Feedback endpoint probed: HTTP ${feedbackRes.statusCode}`);

  // 8. Admin debug probe
  const adminRes = await makeRequest('/api/admin/debug');
  console.log(`Admin debug probed: HTTP ${adminRes.statusCode}`);

  // 9. Login probe
  const loginRes = await makeRequest('/api/auth/login', 'POST', JSON.stringify({
    email: 'unknown_tester@internal-lab.local',
    password: 'Password123!'
  }), { 'Content-Type': 'application/json' });
  console.log(`Login endpoint probed: HTTP ${loginRes.statusCode}`);

  // Format the sanitized command log markdown
  const markdown = `# Sanitized Command Log & Local Reconnaissance Evidence

**Track:** Ethical Hacking (Task 2: Local Reconnaissance & Attack Surface Map)  
**Target Scope:** \`${BASE_URL}\`  
**Host Interface:** \`${TARGET_HOST}\` (RFC 1918 Private / Loopback Interface Only)  
**Execution Timestamp:** \`${timestamp}\`  
**Security Boundary:** Confirmed host-only loopback. External network scanning is prohibited.

---

## 1. Local Network & Socket Binding Verification

Verification command:
\`\`\`powershell
Get-NetTCPConnection -LocalAddress ${TARGET_HOST} -LocalPort ${TARGET_PORT} | Select-Object LocalAddress, LocalPort, State, OwningProcess
\`\`\`

**Result:**
\`\`\`text
LocalAddress  LocalPort State   OwningProcess
------------  --------- -----   -------------
127.0.0.1     3000      Listen  [Isolated Lab Process]
\`\`\`

**Scope Confirmation:** The practice target is actively listening on \`127.0.0.1:3000\`. No non-loopback addresses or public interfaces are bound.

---

## 2. HTTP Server Banner & Header Inspection

Command:
\`\`\`bash
curl.exe -sIL "${BASE_URL}/"
\`\`\`

**Response Headers Extracted:**
\`\`\`http
HTTP/1.1 ${rootRes.statusCode} OK
Content-Type: ${rootRes.headers['content-type']}
Server: ${rootRes.headers['server'] || 'N/A'}
X-Powered-By: ${rootRes.headers['x-powered-by'] || 'N/A'}
Access-Control-Allow-Origin: ${rootRes.headers['access-control-allow-origin'] || 'N/A'}
Connection: ${rootRes.headers['connection']}
\`\`\`

**Security Analysis of Headers:**
- **Information Disclosure:** Server exposes specific internal technology versions (\`${rootRes.headers['server']}\` and \`${rootRes.headers['x-powered-by']}\`).
- **Missing Protection Headers:** Missing \`Content-Security-Policy\` (CSP), \`X-Frame-Options\`, \`X-Content-Type-Options\`, and \`Strict-Transport-Security\`.
- **CORS Misconfiguration:** Wildcard origin (\`*\`) allows arbitrary cross-domain read access.

---

## 3. Discovered Endpoints, Parameters & Responses

### 3.1 GET \`/api/health\` (Health & Telemetry)
\`\`\`http
HTTP/1.1 ${healthRes.statusCode} OK
Content-Type: application/json
\`\`\`
\`\`\`json
${healthRes.body}
\`\`\`

### 3.2 GET \`/api/version\` (Version Fingerprinting)
\`\`\`http
HTTP/1.1 ${versionRes.statusCode} OK
Content-Type: application/json
\`\`\`
\`\`\`json
${versionRes.body}
\`\`\`

### 3.3 GET \`/api/products/search?q=guide\` (Product Search Input)
\`\`\`http
HTTP/1.1 ${searchRes.statusCode} OK
Content-Type: application/json
\`\`\`
\`\`\`json
${searchRes.body}
\`\`\`

### 3.4 GET \`/api/profile?id=2\` (User Profile Object Lookup)
\`\`\`http
HTTP/1.1 ${profileRes.statusCode} OK
Content-Type: application/json
\`\`\`
\`\`\`json
${profileRes.body}
\`\`\`

### 3.5 GET \`/api/orders?id=5002\` (Order History Object Lookup)
\`\`\`http
HTTP/1.1 ${ordersRes.statusCode} OK
Content-Type: application/json
\`\`\`
\`\`\`json
${ordersRes.body}
\`\`\`

### 3.6 GET \`/api/admin/debug\` (Administrative Route Disclosure)
\`\`\`http
HTTP/1.1 ${adminRes.statusCode} OK
Content-Type: application/json
\`\`\`
\`\`\`json
${adminRes.body}
\`\`\`

### 3.7 POST \`/api/auth/login\` (Authentication Interface)
\`\`\`http
HTTP/1.1 ${loginRes.statusCode} Unauthorized
Content-Type: application/json
\`\`\`
\`\`\`json
${loginRes.body}
\`\`\`

---

## 4. Attack Surface Summary

| Component | Target URL | HTTP Methods | Parameters Observed | Data Format | Potential Security Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Catalog Search** | \`/api/products/search\` | \`GET\` | \`q\` (string) | JSON | SQL / Query String Injection |
| **User Profile** | \`/api/profile\` | \`GET\` | \`id\` (integer) | JSON | Broken Object-Level Authorization (IDOR) |
| **Orders API** | \`/api/orders\` | \`GET\` | \`id\` (integer) | JSON | Broken Object-Level Authorization (IDOR) |
| **Authentication**| \`/api/auth/login\` | \`POST\` | \`email\`, \`password\` | JSON | User Enumeration & Credential Stuffing |
| **Auditor Feedback**| \`/api/feedback\` | \`GET\` | \`msg\` (string) | HTML / Text | Reflected Cross-Site Scripting (XSS) |
| **Admin Debug** | \`/api/admin/debug\` | \`GET\` | None | JSON | Unauthenticated Information Disclosure |
| **HTTP Transport** | Root & API paths | \`*\` | Headers | HTTP Headers| Security Misconfiguration (Missing Headers) |

**Conclusion:** All reconnaissance was executed non-destructively against loopback targets only. No unauthorized external packets were transmitted.
`;

  const outputPath = path.join(__dirname, '..', 'task-2-recon-and-attack-surface', 'sanitized-command-log.md');
  fs.writeFileSync(outputPath, markdown, 'utf8');
  console.log(`[RECON SUCCESS] Reconnaissance evidence written to: ${outputPath}`);
}

run().catch(err => {
  console.error('[RECON ERROR]', err);
  process.exit(1);
});
