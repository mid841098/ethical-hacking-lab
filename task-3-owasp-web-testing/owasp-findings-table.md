# OWASP Web Testing Findings Table

**Track:** Ethical Hacking (Task 3: OWASP Web Testing Lab)  
**Target:** `http://127.0.0.1:3000`  
**Assessment Standard:** OWASP Top 10:2021 & OWASP Web Security Testing Guide (WSTG v4.2)  
**Assessor:** Authorized Security Intern  
**Scope:** Authorized Local Practice Sandbox  

---

## 1. Master Findings Table

The table below summarizes all confirmed security vulnerabilities identified during the authorized penetration test, including severity ratings, affected components, root causes, and recommended remediations.

| Finding ID | Vulnerability Title | OWASP Category | CWE | Severity (CVSS v3.1) | Affected Endpoint | Safe Evidence Artifact | Root Cause Summary | Remediation Summary |
| :---: | :--- | :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| **SEC-FIND-01** | Insecure Direct Object Reference (IDOR) | **A01:2021 - Broken Access Control** | CWE-639 | **HIGH** (7.5) | `GET /api/profile?id={id}` | [poc-01-broken-access-control.md](./evidence/poc-01-broken-access-control.md) | Endpoint uses direct numeric user ID without verifying session token or record ownership. | Implement object-level authorization verifying requester matches target record ID. |
| **SEC-FIND-02** | Query String Injection in Product Catalog | **A03:2021 - Injection** | CWE-89 / CWE-943 | **HIGH** (8.2) | `GET /api/products/search?q={q}` | [poc-02-sql-injection.md](./evidence/poc-02-sql-injection.md) | Query input is directly concatenated into datastore lookup filter logic. | Use parameterized queries and strict alphanumeric input validation. |
| **SEC-FIND-03** | User Enumeration & Missing Login Rate Limiting | **A07:2021 - Identification & Auth Failures** | CWE-204 / CWE-307 | **MEDIUM** (5.3) | `POST /api/auth/login` | [poc-03-auth-bruteforce-failure.md](./evidence/poc-03-auth-bruteforce-failure.md) | Login endpoint returns distinct error messages and permits unlimited authentication attempts. | Standardize generic authentication error messages and implement IP rate limiting / lockout. |
| **SEC-FIND-04** | Security Misconfiguration & Missing Security Headers | **A05:2021 - Security Misconfiguration** | CWE-16 / CWE-200 | **MEDIUM** (5.0) | Global HTTP Headers & `/api/admin/debug` | [poc-04-security-misconfiguration.md](./evidence/poc-04-security-misconfiguration.md) | Leaking software versions in headers and exposing administrative debug route without auth. | Inject hardened security headers (`CSP`, `X-Frame-Options`, `nosniff`), suppress banners, disable debug routes. |
| **SEC-FIND-05** | Reflected Cross-Site Scripting (XSS) | **A03:2021 - Injection** | CWE-79 | **MEDIUM** (6.1) | `GET /api/feedback?msg={msg}` | [poc-05-reflected-xss.md](./evidence/poc-05-reflected-xss.md) | Endpoint reflects query parameter directly into HTML body without contextual entity encoding. | Contextually HTML-encode user input or serve strictly as `application/json`. |

---

## 2. Risk Distribution Summary

- **Total Confirmed Findings:** 5
- **Critical Risk:** 0 (0%)
- **High Risk:** 2 (40%)
- **Medium Risk:** 3 (60%)
- **Low / Informational:** 0 (0%)

**Overall Security Posture:** High Risk. The presence of unauthenticated IDOR (SEC-FIND-01) and Query Injection (SEC-FIND-02) permits unauthorized extraction of administrative API tokens and confidential catalog records. Immediate remediation is required prior to any production deployment.
