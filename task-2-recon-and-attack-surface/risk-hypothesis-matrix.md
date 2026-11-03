# Observation-to-Risk Hypothesis Matrix

**Track:** Ethical Hacking (Task 2: Local Reconnaissance and Attack Surface Map)  
**Target:** `http://127.0.0.1:3000`  
**Purpose:** Translate empirical reconnaissance observations into actionable, testable security hypotheses.  

---

## 1. Risk Hypothesis Matrix

| # | Empirical Observation | Affected Endpoint / Asset | Potential Risk Hypothesis | OWASP Category | Threat Scenario | Planned Non-Destructive Test |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- |
| **H-01** | Query parameter `?id=2` returns full user record without requiring an `Authorization` header. | `GET /api/profile?id={id}` | **Insecure Direct Object Reference (IDOR)**: The application does not verify user identity or record ownership before returning profile data. | **A01:2021 - Broken Access Control** | An attacker increments `id` to `1` to harvest the administrator's profile, balance, and private API token. | Request `?id=1` and check if administrative records and tokens are returned without authentication. |
| **H-02** | Query parameter `?id=5002` returns order records without session validation. | `GET /api/orders?id={id}` | **Broken Object-Level Authorization (BOLA)**: Order history records are accessible across tenant/user boundaries. | **A01:2021 - Broken Access Control** | An authenticated or unauthenticated attacker inspects competitor or peer order details and shipping addresses. | Request order IDs `5001` and `5003` to verify cross-user data leakage. |
| **H-03** | Product catalog search takes query parameter `?q=` and performs string matching. | `GET /api/products/search?q={term}` | **Query / SQL Injection**: Query string is interpolated directly into datastore lookup logic without sanitization. | **A03:2021 - Injection** | An attacker injects boolean tautologies (`' OR '1'='1`) to bypass catalog filters and leak unreleased/restricted inventory. | Submit harmless boolean payload `' OR '1'='1` and verify if restricted items (`isPublic=false`) are exposed. |
| **H-04** | Login endpoint returns distinct error messages for non-existent emails vs. incorrect passwords. | `POST /api/auth/login` | **User Enumeration & Identification Failure**: Disparate response messages disclose whether a target email exists in the database. | **A07:2021 - Identification & Auth Failures** | Threat actor performs automated dictionary attacks to compile verified corporate email directories. | Compare HTTP response bodies between valid email (`alice@...`) and invalid email (`fake@...`). |
| **H-05** | Multiple rapid requests to `/api/auth/login` succeed without HTTP 429 or CAPTCHA triggers. | `POST /api/auth/login` | **Missing Rate Limiting / Anti-Automation**: Login endpoint lacks lockout mechanisms or request throttling. | **A07:2021 - Identification & Auth Failures** | Attackers mount automated brute-force attacks against user accounts without account lockouts. | Send 10 rapid failed login attempts; verify if throttling or locking occurs. |
| **H-06** | Query parameter `?msg=` is returned inside an HTML `<div id="feedback-display">` without escaping. | `GET /api/feedback?msg={msg}` | **Reflected Cross-Site Scripting (XSS)**: Unsanitized user input is reflected into the HTML response document. | **A03:2021 - Injection** | Attacker tricks victim into clicking a link with injected JavaScript to hijack session tokens. | Submit payload `<script>console.log('POC')</script>` and verify raw HTML tag reflection. |
| **H-07** | Server banner reveals `NodeJS-Express-Lab/1.0.4-dev`; missing CSP, X-Frame-Options, nosniff. | Global HTTP Headers | **Security Misconfiguration**: Missing defensive headers and disclosure of underlying runtime versions. | **A05:2021 - Security Misconfiguration** | Attackers use version info to find known CVEs; site can be framed in malicious iframes (clickjacking). | Verify missing headers via `curl -I` and analyze clickjacking vulnerability. |
| **H-08** | Route `/api/admin/debug` is accessible without authentication and returns server environment data. | `GET /api/admin/debug` | **Sensitive Information Disclosure**: Administrative diagnostic interface left exposed in production environment. | **A05:2021 - Security Misconfiguration** | Attacker maps internal routing architecture and server environment variables. | Send GET request to `/api/admin/debug` and evaluate exposed configuration fields. |

---

## 2. Hypothesis Verification Strategy

Each formulated hypothesis will be subjected to strict, non-destructive verification in Task 3. Testing will proceed in order of risk priority, utilizing minimal proof-of-concept commands and capturing sanitized request/response artifacts.
