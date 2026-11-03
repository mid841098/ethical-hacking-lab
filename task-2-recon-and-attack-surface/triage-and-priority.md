# Testing Prioritization & Threat Triage Roadmap

**Track:** Ethical Hacking (Task 2 Portfolio Upgrade)  
**Target:** `http://127.0.0.1:3000`  
**Purpose:** Prioritize what should be tested next and provide rigorous justification based on likelihood, exploitability, and business impact.  

---

## 1. Prioritization Methodology

To maximize testing efficiency and minimize potential disruption, testing hypotheses are evaluated using the standard **OWASP Risk Rating Methodology**:

$$\text{Risk} = \text{Likelihood} \times \text{Impact}$$

- **Likelihood Factors:** Ease of discovery, ease of exploit, attacker skill required, authentication requirements.
- **Impact Factors:** Loss of confidentiality, integrity damage, availability loss, regulatory exposure (GDPR / DPDP).

---

## 2. Threat Triage & Testing Queue Matrix

| Priority Rank | Hypothesis ID | Target Component | Hypothesized Vulnerability | Exploitability | Business Impact | Overall Risk Tier | Estimated Test Time |
| :-: | :-: | :--- | :--- | :---: | :---: | :---: | :---: |
| **P1** | **H-01** | `GET /api/profile?id=` | Insecure Direct Object Reference (IDOR) | High (Trivial) | Critical (Admin Token Leak) | **HIGH** | 15 mins |
| **P2** | **H-03** | `GET /api/products/search?q=` | Query / SQL Injection | High (Trivial) | High (Restricted Data Leak) | **HIGH** | 20 mins |
| **P3** | **H-02** | `GET /api/orders?id=` | Broken Object-Level Authorization | High (Trivial) | Medium (Customer PII Leak) | **MEDIUM** | 15 mins |
| **P4** | **H-06** | `GET /api/feedback?msg=` | Reflected Cross-Site Scripting (XSS) | Medium (Needs UI) | Medium (Session Theft) | **MEDIUM** | 15 mins |
| **P5** | **H-04 / H-05**| `POST /api/auth/login` | User Enumeration & No Rate Limiting | High (Automated) | Medium (Account Compromise) | **MEDIUM** | 20 mins |
| **P6** | **H-07 / H-08**| Headers & `/api/admin/debug` | Security Misconfiguration & Info Leak | High (Passive) | Low-Medium (Recon Facilitation) | **LOW** | 10 mins |

---

## 3. Detailed Justification for Testing Order

### 1. Why Test H-01 (Profile IDOR) First?
**Justification:** IDOR vulnerabilities in administrative endpoints represent the shortest path to total system compromise. In modern microservice and single-page applications, object references exposed directly in URL queries without authorization checks allow attackers to bypass all front-end access controls. Testing `?id=1` immediately determines whether administrative privilege elevation is possible without credentials.

### 2. Why Test H-03 (Search Query Injection) Second?
**Justification:** Query and SQL injection flaws violate the fundamental boundary between code and data. If the application dynamically concatenates user-supplied strings into backend query logic, an attacker can manipulate boolean expressions, dump entire database tables, or exfiltrate hidden proprietary records (e.g. unreleased products, flags, or system credentials).

### 3. Why Test H-04 & H-05 (Authentication & Rate Limiting) Third?
**Justification:** Authentication endpoints are the gatekeepers of user data. User enumeration allows attackers to validate employee email lists, while the absence of rate limiting permits automated password-guessing attacks. Testing authentication ensures that credential security controls withstand basic automated attack vectors.

### 4. Why Test H-06 (Reflected XSS) Fourth?
**Justification:** While high in impact, reflected XSS requires user interaction (e.g. enticing a victim to click a malicious link). It is tested after direct server-side data exfiltration flaws (IDOR and SQLi) because server-side flaws require zero user interaction and represent immediate structural vulnerabilities.

### 5. Why Test H-07 & H-08 (Security Misconfiguration) Last?
**Justification:** Missing defensive headers and exposed debug paths provide reconnaissance intelligence rather than direct data compromise. They are documented to establish baseline hygiene and defense-in-depth remediations after addressing critical operational risks.

---

## 4. Next Steps Execution Plan

All prioritized hypotheses will be systematically tested in **Task 3: OWASP Web Testing Lab** using non-destructive curl commands and automated verification scripts (`scripts/test-owasp-findings.js`), capturing sanitized proof for every confirmed finding.
