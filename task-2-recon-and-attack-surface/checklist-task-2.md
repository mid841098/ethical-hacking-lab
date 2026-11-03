# Passing Checklist: Local Reconnaissance and Attack Surface Map

**Track:** Ethical Hacking (Task 2)  
**Deliverable:** Sanitized command log, service inventory, and attack-surface diagram.  
**Level:** Beginner-friendly  
**Status:** **PASSED / COMPLETE**

---

## Required Passing Checklist

- [x] **Record the target address and confirm it is inside the isolated lab.**  
  *Evidence:* Documented in `target-verification.md` with DNS resolution, Windows TCP socket checks, and routing table verification showing binding strictly to `127.0.0.1:3000`.

- [x] **Enumerate services, versions, routes, headers, and visible inputs.**  
  *Evidence:* Comprehensive technical inventory compiled in `service-inventory.md` and raw terminal outputs logged in `sanitized-command-log.md`.

- [x] **Map each observation to a potential risk hypothesis.**  
  *Evidence:* Formulated structured 8-point observation-to-risk hypothesis table in `risk-hypothesis-matrix.md`.

- [x] **Put the work and a short explanation in one public or view-only link.**  
  *Evidence:* Structured within repository root with interactive documentation portal in `index.html` and master portfolio overview in `README.md`.

---

## Optional Portfolio Upgrade

- [x] **Prioritize what should be tested next and why.**  
  *Evidence:* Created comprehensive threat triage roadmap and testing queue with likelihood-impact calculations in `triage-and-priority.md`.
