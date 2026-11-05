# Authorized Penetration Testing Lab & Ethical Hacking Portfolio

[![Track](https://img.shields.io/badge/Track-Ethical%20Hacking-purple.svg)](https://edvyro.in)
[![Scope](https://img.shields.io/badge/Scope-127.0.0.1%3A3000%20(Loopback)-blue.svg)](#1-task-1-legal-scope-and-isolated-lab)
[![RoE](https://img.shields.io/badge/RoE-Signed%20%26%20Legally%20Binding-success.svg)](./task-1-scope-and-isolated-lab/rules-of-engagement.md)
[![OWASP](https://img.shields.io/badge/Standard-OWASP%20Top%2010%20%2F%20WSTG-orange.svg)](./task-3-owasp-web-testing/owasp-findings-table.md)
[![Retest](https://img.shields.io/badge/Retest-100%25%20Verified%20Fixed-brightgreen.svg)](./task-4-penetration-test-report-and-retest/retest-verification-matrix.md)

This repository constitutes the comprehensive, publication-grade submission for the **EdVyro Ethical Hacking Internship Track**, fulfilling all mandatory deliverables and optional portfolio upgrades across **Tasks 1, 2, 3, and 4**:

1. **Task 1: Legal Scope and Isolated Lab**
2. **Task 2: Local Reconnaissance and Attack Surface Map**
3. **Task 3: OWASP Web Testing Lab**
4. **Task 4: Penetration Test Report and Retest**

---

## ðŸ“‘ Repository Navigation & Deliverables Index

```text
.
|-- README.md                                  # Master Portfolio Hub & Documentation Index
|-- index.html                                 # Interactive Web Portal (GitHub Pages Ready)
|-- package.json                               # Automated test scripts & project metadata
|
|-- task-1-scope-and-isolated-lab/             # Task 1 Deliverables
|   |-- rules-of-engagement.md                 # Signed Personal Rules of Engagement (RoE)
|   |-- network-topology-and-isolation.md      # Lab Network Architecture & Socket Isolation
|   |-- setup-evidence.md                      # Target Setup Evidence & Startup Logs
|   |-- baseline-snapshot-manifest.json        # Cryptographic SHA-256 Baseline (Portfolio Upgrade)
|   \-- checklist-task-1.md                    # Completed Official Passing Checklist
|
|-- task-2-recon-and-attack-surface/           # Task 2 Deliverables (Task 03 in Portal)
|   |-- target-verification.md                 # Target Address & Loopback Validation
|   |-- service-inventory.md                   # Enumerated Services, Banners, Routes & Inputs
|   |-- attack-surface-diagram.md              # Visual Attack Surface Architecture & Data Flows
|   |-- sanitized-command-log.md               # Sanitized Terminal Recon Logs & Outputs
|   |-- risk-hypothesis-matrix.md              # Observation-to-Risk Hypothesis Mapping
|   |-- triage-and-priority.md                 # Prioritized Threat Triage & Testing Queue (Upgrade)
|   \-- checklist-task-2.md                    # Completed Official Passing Checklist
|
|-- task-3-owasp-web-testing/                  # Task 3 Deliverables (Task 04 in Portal)
|   |-- owasp-findings-table.md                # Sanitized Findings Table (Severity, Cause, Fix)
|   |-- root-cause-and-impact.md               # Technical Deep-Dives & Business/Regulatory Impact
|   |-- evidence/                              # Sanitized Non-Destructive Proof of Concept (PoC) Dossiers
|   |   |-- poc-01-broken-access-control.md    # IDOR in User Profile (CVSS 7.5 High)
|   |   |-- poc-02-sql-injection.md            # Query Injection in Search (CVSS 8.2 High)
|   |   |-- poc-03-auth-bruteforce-failure.md  # User Enumeration & No Throttling (CVSS 5.3 Med)
|   |   |-- poc-04-security-misconfiguration.md# Leaked Banners & Missing Headers (CVSS 5.0 Med)
|   |   \-- poc-05-reflected-xss.md            # Reflected XSS in Feedback (CVSS 6.1 Med)
|   |-- remediation-recommendations.md         # Secure Code Diffs & Configuration Fixes (Upgrade)
|   \-- checklist-task-3.md                    # Completed Official Passing Checklist
|
|-- task-4-penetration-test-report-and-retest/ # Task 4 Deliverables (Task 05 in Portal)
|   |-- executive-summary.md                   # C-Level Executive Summary & Posture Rating
|   |-- technical-methodology.md               # PTES & OWASP WSTG v4.2 Assessment Standard
|   |-- penetration-test-report.md             # Formal Penetration Test Report (CVSS v3.1)
|   |-- retest-verification-matrix.md          # Formal Retest Findings Log: 100% Fixed (Upgrade)
|   \-- checklist-task-4.md                    # Completed Official Passing Checklist
|
|-- lab/                                       # Self-Contained Practice Lab Application
|   |-- server.js                              # Dual-mode server (Vulnerable vs. Secure)
|   |-- db.js                                  # In-memory synthetic datastore
|   \-- public/index.html                      # Interactive Security Testing Dashboard
|
\-- scripts/                                   # Automated Assessment & Verification Tooling
    |-- baseline-snapshot.ps1                  # Generates cryptographic baseline snapshot
    |-- run-recon.js                           # Controlled local reconnaissance runner
    |-- test-owasp-findings.js                 # Non-destructive OWASP PoC verification suite
    \-- run-retest.js                          # Automated post-remediation verification runner
```

---

## ðŸŽ¯ Executive Summary of Completed Tasks

### 1. Task 1: Legal Scope and Isolated Lab
- **Objective:** Establish safe, legal, and reproducible conditions for penetration testing.
- **Rules of Engagement:** Formulated, dated, and digitally signed [rules-of-engagement.md](./task-1-scope-and-isolated-lab/rules-of-engagement.md), strictly prohibiting tests against third-party systems, denial of service, destructive actions, and credential stuffing.
- **Isolation Architecture:** Implemented explicit loopback binding (`127.0.0.1:3000`) documented in [network-topology-and-isolation.md](./task-1-scope-and-isolated-lab/network-topology-and-isolation.md). Windows socket tables prove port 3000 is completely non-routable from external LAN/WAN interfaces.
- **Repeatable Baseline (Upgrade):** Generated an immutable cryptographic SHA-256 snapshot manifest ([baseline-snapshot-manifest.json](./task-1-scope-and-isolated-lab/baseline-snapshot-manifest.json)) establishing clean baseline integrity.
- **Status:** **PASSED** &bull; [Checklist](./task-1-scope-and-isolated-lab/checklist-task-1.md)

---

### 2. Task 2: Local Reconnaissance and Attack Surface Map
- **Objective:** Enumerate only the authorized lab target and build a structured attack-surface inventory.
- **Target Verification:** Confirmed target resides strictly on `127.0.0.1:3000` via loopback routing checks ([target-verification.md](./task-2-recon-and-attack-surface/target-verification.md)).
- **Service & Header Inventory:** Enumerated 9 active routes, input parameters, HTTP response headers, and runtime banners ([service-inventory.md](./task-2-recon-and-attack-surface/service-inventory.md)).
- **Attack Surface Map:** Visualized end-to-end data flows and injection points from client transport to internal persistence ([attack-surface-diagram.md](./task-2-recon-and-attack-surface/attack-surface-diagram.md)).
- **Risk Hypotheses:** Mapped 8 empirical observations to specific OWASP Top 10 vulnerabilities ([risk-hypothesis-matrix.md](./task-2-recon-and-attack-surface/risk-hypothesis-matrix.md)).
- **Threat Prioritization (Upgrade):** Ranked hypotheses using the OWASP Risk Rating Framework ($\text{Likelihood} \times \text{Impact}$) to prioritize testing order ([triage-and-priority.md](./task-2-recon-and-attack-surface/triage-and-priority.md)).
- **Status:** **PASSED** &bull; [Checklist](./task-2-recon-and-attack-surface/checklist-task-2.md)

---

### 3. Task 3: OWASP Web Testing Lab
- **Objective:** Test selected OWASP risks in the authorized training application and document minimal, non-destructive proof.
- **Sanitized Findings Table:** Categorized all confirmed issues across OWASP categories, CWEs, and CVSS v3.1 scores ([owasp-findings-table.md](./task-3-owasp-web-testing/owasp-findings-table.md)).
- **Safe Evidence Dossiers:** Captured 5 sanitized, non-destructive Proof-of-Concept artifacts with partially redacted credentials:
  - `SEC-FIND-01`: [IDOR in User Profile (CVSS 7.5 High)](./task-3-owasp-web-testing/evidence/poc-01-broken-access-control.md)
  - `SEC-FIND-02`: [Query String Injection in Catalog Search (CVSS 8.2 High)](./task-3-owasp-web-testing/evidence/poc-02-sql-injection.md)
  - `SEC-FIND-03`: [User Enumeration & Missing Rate Limiting (CVSS 5.3 Medium)](./task-3-owasp-web-testing/evidence/poc-03-auth-bruteforce-failure.md)
  - `SEC-FIND-04`: [Security Misconfiguration & Missing Headers (CVSS 5.0 Medium)](./task-3-owasp-web-testing/evidence/poc-04-security-misconfiguration.md)
  - `SEC-FIND-05`: [Reflected Cross-Site Scripting in Feedback (CVSS 6.1 Medium)](./task-3-owasp-web-testing/evidence/poc-05-reflected-xss.md)
- **Root Cause & Business Impact:** Analyzed architectural defects and quantified operational, legal (GDPR / DPDP), and brand damages ([root-cause-and-impact.md](./task-3-owasp-web-testing/root-cause-and-impact.md)).
- **Secure Code Remediation (Upgrade):** Authored precise code diffs, parameterized query handlers, rate limiters, and defensive headers ([remediation-recommendations.md](./task-3-owasp-web-testing/remediation-recommendations.md)).
- **Status:** **PASSED** &bull; [Checklist](./task-3-owasp-web-testing/checklist-task-3.md)

---

### 4. Task 4: Penetration Test Report and Retest
- **Objective:** Produce a professional report for the authorized lab, apply remediations, and verify that findings are resolved.
- **Executive Summary:** Delivered high-level overview for leadership detailing posture ratings, business risk, and strategic milestones ([executive-summary.md](./task-4-penetration-test-report-and-retest/executive-summary.md)).
- **Technical Methodology:** Documented adherence to PTES and OWASP WSTG v4.2 frameworks ([technical-methodology.md](./task-4-penetration-test-report-and-retest/technical-methodology.md)).
- **Formal Penetration Test Report:** Comprehensive formal report detailing full technical dossiers, CVSS v3.1 vectors, and assessor attestation ([penetration-test-report.md](./task-4-penetration-test-report-and-retest/penetration-test-report.md)).
- **Retest Verification Matrix (Upgrade):** Automated retest suite executed against the remediated environment (`--secure`). Verified 100% of vulnerabilities as **VERIFIED_FIXED** ([retest-verification-matrix.md](./task-4-penetration-test-report-and-retest/retest-verification-matrix.md)).
- **Status:** **PASSED** &bull; [Checklist](./task-4-penetration-test-report-and-retest/checklist-task-4.md)

---

## ðŸ“Š Retest Verification Matrix Summary

| Finding ID | Vulnerability Title | OWASP Category | Initial Severity | Post-Remediation Verification Result | Retest Status |
| :---: | :--- | :--- | :---: | :--- | :---: |
| **SEC-FIND-01** | Insecure Direct Object Reference (IDOR) | A01: Broken Access Control | **HIGH** (7.5) | Bearer auth enforced; cross-user ID access returns HTTP 403 Forbidden. | <span style="color:#10b981;font-weight:bold;">VERIFIED_FIXED</span> |
| **SEC-FIND-02** | Query String Injection in Catalog Search | A03: Injection | **HIGH** (8.2) | Metacharacters rejected with HTTP 400; internal flags protected. | <span style="color:#10b981;font-weight:bold;">VERIFIED_FIXED</span> |
| **SEC-FIND-03** | User Enumeration & Missing Rate Limiting | A07: Auth Failures | **MEDIUM** (5.3) | Uniform error responses verified; 5 failed attempts locks IP with 429. | <span style="color:#10b981;font-weight:bold;">VERIFIED_FIXED</span> |
| **SEC-FIND-04** | Missing Defensive HTTP Security Headers | A05: Security Misconfig | **MEDIUM** (5.0) | CSP, X-Frame-Options, nosniff, and HSTS added; banners removed; debug 404. | <span style="color:#10b981;font-weight:bold;">VERIFIED_FIXED</span> |
| **SEC-FIND-05** | Reflected Cross-Site Scripting (XSS) | A03: Injection | **MEDIUM** (6.1) | HTML entity encoding enforced; Content-Type set to application/json. | <span style="color:#10b981;font-weight:bold;">VERIFIED_FIXED</span> |

---

## ðŸš€ Quickstart & Reproducibility Guide

The lab and automated test suites have **zero external dependencies** and execute directly with native Node.js and PowerShell:

### 1. Launch the Authorized Practice Lab
```bash
# Start in vulnerable training mode (Port 3000)
npm start

# OR start directly in remediated secure mode
npm run start:secure
```

### 2. Execute Automated Verification Scripts
```bash
# 1. Generate clean cryptographic SHA-256 baseline
npm run baseline

# 2. Execute local reconnaissance and endpoint crawling
npm run recon

# 3. Execute non-destructive OWASP Proof-of-Concept testing
npm run test:owasp

# 4. Execute automated retest verification against secured target
npm run retest
```

### 3. Open the Interactive Visual Documentation Portal
Double-click or open `index.html` in any modern web browser to navigate the interactive tabbed reports, view architecture diagrams, and inspect code diffs.

---

## ðŸ“¤ Submission Instructions

To submit for assessment review:
1. Initialize Git and commit the workspace:
   ```bash
   git init
   git add .
   git commit -m "Complete EdVyro Ethical Hacking Tasks 1-4 with all upgrades"
   ```
2. Push to a public GitHub repository (or host on GitHub Pages).
3. Copy the public repository or deployment URL and submit the single link into the EdVyro student portal.
