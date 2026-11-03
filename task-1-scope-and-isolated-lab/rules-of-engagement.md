# Authorised Lab Rules of Engagement (RoE) & Legal Scope

**Track:** Ethical Hacking  
**Document Type:** Formal Rules of Engagement & Code of Conduct  
**Target Environment:** Local Isolated Practice Sandbox (`127.0.0.1:3000`)  
**Authorization Status:** Legally Authorized & Owned Practice Environment  
**Effective Dates:** November 03, 2026 – Ongoing  
**Version:** 1.0 (Final Authorised)

---

## 1. Executive Statement of Authority & Scope Boundary

> [!IMPORTANT]
> **Hard Scope Boundary**: Security testing activities are strictly confined to locally owned, intentionally vulnerable systems. Testing systems you do not own, operate, or possess explicit written permission to assess is strictly illegal under the Computer Misuse Act, the CFAA (Computer Fraud and Abuse Act), the Indian Information Technology Act (Section 43 & 66), and international cyber law.

This Rules of Engagement (RoE) document establishes safe, lawful, and reproducible parameters for ethical penetration testing exercises conducted within the EdVyro Ethical Hacking track. Under no circumstances may any assessment activity target EdVyro infrastructure, other students, public IP ranges, cloud providers, or third-party web properties.

---

## 2. In-Scope Targets

The scope of this assessment is strictly limited to the following isolated asset:

| Target Identifier | Address / Binding | Interface Type | Host Environment | Authorized Role |
| :--- | :--- | :--- | :--- | :--- |
| **Practice Lab Web Application** | `http://127.0.0.1:3000` | Loopback (`lo` / `127.0.0.1`) | Local Workstation (Isolated) | System Owner & Security Auditor |
| **Lab REST API Service** | `http://127.0.0.1:3000/api/*` | Loopback (`lo` / `127.0.0.1`) | Local Workstation (Isolated) | System Owner & Security Auditor |
| **Simulated Remediated Instance**| `http://127.0.0.1:3001` | Loopback (`lo` / `127.0.0.1`) | Local Workstation (Isolated) | System Owner & Security Auditor |

### Scope Verification Rule
Before executing any tool, command, or script, the tester must verify that the target resolves strictly to `127.0.0.1` or `::1`. Any payload aimed outside this address is considered an immediate out-of-scope breach.

---

## 3. Explicit Exclusions & Prohibited Activities

The following techniques, actions, and targets are **strictly prohibited**:

1. **No External or Public Scanning:** Scanning any public IP address, domain name, or external cloud asset is prohibited.
2. **No Denial of Service (DoS / DDoS):** High-volume packet floods, CPU exhaustion, memory exhaustion, or network saturation techniques are disallowed.
3. **No Brute-Force or Credential Floods:** High-rate automated credential stuffing is prohibited. Any authentication testing must be low-rate (maximum 2 requests per second) and focused on validation logic rather than password cracking.
4. **No Destructive Exploits:** Modifying host OS binaries, corrupting filesystem records, injecting persistent OS-level malware, or altering system files outside the lab sandbox is prohibited.
5. **No Data Exfiltration:** Real personal identifiable information (PII), external credentials, or production secrets must never be accessed, stored, or exfiltrated. All test records must be synthetic seed data.
6. **No Social Engineering or Phishing:** Phishing, spear-phishing, or social engineering targeting students, staff, or external entities is prohibited.
7. **No Persistence or Lateral Movement:** Establishing backdoor user accounts in the host operating system or attempting pivot attacks into adjacent LAN segments is prohibited.

---

## 4. Authorized Testing Techniques

The tester is authorized to utilize the following testing methodologies within the designated scope:

- **Passive Information Gathering & Header Inspection:** Extracting HTTP banners, response headers, cookies, and CORS policies via `curl`, PowerShell, or browser DevTools.
- **Controlled Route Enumeration:** Manual and low-frequency endpoint discovery across `/api/*` endpoints.
- **Input Validation & Injection Analysis:** Testing query parameters and request bodies for SQL/query injection and reflected Cross-Site Scripting (XSS) using harmless, non-destructive payloads (e.g. `' OR '1'='1`, `console.log('POC')`).
- **Access Control & IDOR Inspection:** Verifying object-level authorization across `/api/profile?id=` and `/api/orders?id=` using distinct simulated user IDs.
- **Defensive Configuration Auditing:** Inspecting session storage policies, rate limiting controls, and HTTP security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
- **Automated Verification Scripting:** Executing curated, non-destructive Node.js and PowerShell test scripts (`scripts/run-recon.js`, `scripts/test-owasp-findings.js`, `scripts/run-retest.js`).

---

## 5. Emergency Stop Conditions & Incident Protocol

Testing must immediately cease if any of the following conditions occur:

1. **Out-of-Scope Transmission:** Any network packet is detected routing across an external network interface (Wi-Fi, Ethernet, or WAN adapter).
2. **System Instability:** The host workstation experiences freeze, excessive resource consumption (>80% CPU/RAM), or operating system instability.
3. **Unexpected Data Discovery:** Discovery of real external credentials, production keys, or live user data not originating from the synthetic seed database.
4. **Target Crash:** Uncontrolled lab failure preventing normal audit procedures.

### Incident Escalation Procedure
In the event of an emergency stop:
- Terminate all active testing scripts immediately via `Ctrl+C` or task termination.
- Capture terminal logs and timestamp of the event.
- Restore the target application from the clean baseline snapshot (`scripts/baseline-snapshot.ps1`).
- Notify the lab supervisor / mentor with the incident log.

---

## 6. Finding Classification & Reporting Standards

Every security finding documented must follow the standardized structure:
1. **Finding Identifier & Title** (e.g. `SEC-FIND-01: Insecure Direct Object Reference`)
2. **OWASP Top 10 Mapping** (e.g. `A01:2021 - Broken Access Control`)
3. **Common Weakness Enumeration (CWE)** (e.g. `CWE-639`)
4. **CVSS v3.1 Base Score & Vector**
5. **Technical Root Cause**
6. **Minimal Non-Destructive Proof of Concept (PoC)** with redacted secrets
7. **Business & Operational Impact Analysis**
8. **Remediation Recommendation** (Code diff or configuration patch)
9. **Retest Status** (`FIXED`, `MITIGATED`, or `UNRESOLVED`)

---

## 7. Signed Personal Declaration of Compliance

I hereby certify and warrant that:
- I have read, understood, and agreed to abide strictly by the terms, boundaries, and restrictions outlined in this Rules of Engagement document.
- I will conduct security testing exclusively within the authorized, locally owned sandbox on `127.0.0.1:3000`.
- I will not attempt unauthorized access against any external system, provider, or individual.
- I understand that adherence to these rules of engagement is an essential ethical and legal condition of professional security testing.

**Authorized Tester / Security Intern:**  
*Name:* EdVyro Ethical Hacking Intern  
*Role:* Lead Security Auditor  
*Signature:* `[Digitally Signed - SHA256: 9F84B263CA2D87B41F0A8C927EE4A812]`  
*Date:* November 03, 2026  
*Status:* **ACTIVE & LEGALLY BINDING**
