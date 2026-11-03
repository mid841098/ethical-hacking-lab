# Remediation Recommendations & Secure Code Implementation

**Track:** Ethical Hacking (Task 3 Portfolio Upgrade)  
**Target:** `http://127.0.0.1:3000`  
**Standard:** OWASP Secure Coding Practices Quick Reference Guide  
**Purpose:** Provide actionable, production-ready code diffs and configuration blueprints to permanently resolve all identified vulnerabilities.  

---

## 1. Fix for SEC-FIND-01: Object-Level Authorization (IDOR)

### Remediation Strategy
1. Require a cryptographic Bearer token on all profile lookups.
2. Verify that the authenticated user ID strictly matches the requested record ID, or that the requester possesses verified `admin` role privileges.
3. Exclude sensitive internal attributes (`apiToken`, `passwordHash`) from API serialization.

### Code Implementation (Before vs. After Diff)

```diff
- // VULNERABLE: Direct access without authentication or ownership check
- const requestedId = parseInt(query.id, 10);
- const user = db.users.find(u => u.id === requestedId);
- return sendJson(res, 200, user);

+ // REMEDIATED: Robust object-level authorization & token verification
+ const requestedId = parseInt(query.id, 10);
+ const currentUser = getAuthUser(req);
+ 
+ if (!currentUser) {
+   return sendJson(res, 401, { error: 'Authentication required. Missing Bearer token.' });
+ }
+ 
+ if (currentUser.userId !== requestedId && currentUser.role !== 'admin') {
+   return sendJson(res, 403, { 
+     error: 'Forbidden: Access to requested object is denied. Object-level authorization enforced.' 
+   });
+ }
+ 
+ const user = db.users.find(u => u.id === requestedId);
+ if (!user) return sendJson(res, 404, { error: 'User not found' });
+ 
+ // Explicit Data Transfer Object (DTO) - Never leak apiToken or passwordHash
+ return sendJson(res, 200, {
+   id: user.id,
+   username: user.username,
+   email: user.email,
+   role: user.role,
+   fullName: user.fullName,
+   phone: user.phone,
+   balance: user.balance
+ });
```

---

## 2. Fix for SEC-FIND-02: Parameterized Queries & Input Validation

### Remediation Strategy
1. Enforce strict regular expression whitelist validation on search terms (disallowing metacharacters like `'`, `"`, `;`, `--`).
2. Enforce parameterized querying where user parameters are treated strictly as literals, preventing query logic tampering.

### Code Implementation

```javascript
// Parameterized, strictly sanitized query handling
const q = query.q || '';

// Reject metacharacters that alter query semantics
if (typeof q !== 'string' || /[^\w\s\-]/.test(q)) {
  return sendJson(res, 400, {
    error: 'Invalid search parameters. Special characters are disallowed.',
    code: 'PARAM_VALIDATION_ERROR'
  });
}

const sanitizedTerm = q.trim().toLowerCase();
// Filter guarantees only public records are queried
const results = db.products.filter(p => p.isPublic && p.name.toLowerCase().includes(sanitizedTerm));

return sendJson(res, 200, {
  query: sanitizedTerm,
  count: results.length,
  data: results.map(({ id, name, category, price, stock }) => ({ id, name, category, price, stock }))
});
```

---

## 3. Fix for SEC-FIND-03: Rate Limiting & Timing-Safe Generic Errors

### Remediation Strategy
1. Replace disparate error messages with a single, uniform error message: `"Invalid credentials. Please verify your email and password."`
2. Implement an in-memory or Redis-backed sliding window rate limiter locking the client IP after 5 failed attempts within 60 seconds.

### Code Implementation

```javascript
// Rate Limiting & User Enumeration Defense
const attemptKey = clientIp;
const now = Date.now();
const record = failedAttempts.get(attemptKey) || { count: 0, resetTime: now + 60000 };

if (now > record.resetTime) {
  record.count = 0;
  record.resetTime = now + 60000;
}

if (record.count >= 5) {
  return sendJson(res, 429, {
    error: 'Too many failed login attempts. Account temporarily locked. Please try again after 60 seconds.',
    retryAfterSeconds: Math.ceil((record.resetTime - now) / 1000)
  });
}

const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
const hashedInput = crypto.createHash('sha256').update(password).digest('hex');

// Uniform error response regardless of whether email or password was wrong
if (!user || user.passwordHash !== hashedInput) {
  record.count += 1;
  failedAttempts.set(attemptKey, record);
  return sendJson(res, 401, {
    error: 'Invalid credentials. Please verify your email and password.',
    code: 'AUTH_FAILED'
  });
}

// Reset attempts on successful authentication
failedAttempts.delete(attemptKey);
```

---

## 4. Fix for SEC-FIND-04: Defensive HTTP Headers Configuration

### Remediation Strategy
Configure the HTTP response middleware to inject mandatory security headers and strip identifying server runtime banners.

### Configuration Blueprint

```javascript
// Hardened Security Headers Middleware
const securityHeaders = {
  // Prevent MIME-type confusion attacks
  'X-Content-Type-Options': 'nosniff',
  // Deny clickjacking / frame embedding
  'X-Frame-Options': 'DENY',
  // Enforce robust script-source boundaries
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none';",
  // Enforce HTTPS in production environments
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  // Prevent referrer leakage across origins
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  // Prohibit caching of sensitive responses
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  'X-Permitted-Cross-Domain-Policies': 'none'
};

// Suppress server banners
delete headers['Server'];
delete headers['X-Powered-By'];
```

---

## 5. Fix for SEC-FIND-05: Contextual HTML Entity Encoding

### Remediation Strategy
1. Switch API endpoints from `text/html` to `application/json`.
2. Where user input must be rendered in HTML context, apply strict character escaping to convert HTML metacharacters into harmless entities (`&lt;`, `&gt;`, `&quot;`, `&#39;`).

### Code Implementation

```javascript
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Safe feedback response
const escapedMessage = escapeHtml(query.msg || '');
return sendJson(res, 200, {
  message: 'Feedback received safely',
  sanitizedMessage: escapedMessage
});
```

---

## 6. Verification & Retest Procedure

These fixes have been directly incorporated into the application's secure operating mode (`--secure`). Reviewers can test both modes dynamically using the supplied automated scripts:
- **Test Vulnerabilities:** `npm run test:owasp` (or `node scripts/test-owasp-findings.js`)
- **Verify Fixes:** `npm run retest` (or `node scripts/run-retest.js`)
