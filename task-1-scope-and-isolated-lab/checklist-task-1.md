# Passing Checklist: Legal Scope and Isolated Lab

**Track:** Ethical Hacking (Task 1)  
**Deliverable:** Lab diagram, setup evidence, and signed personal rules-of-engagement document.  
**Level:** Beginner-friendly  
**Status:** **PASSED / COMPLETE**

---

## Required Passing Checklist

- [x] **Set up a local target such as OWASP Juice Shop or DVWA.**  
  *Evidence:* Deployed authorized practice lab running in `lab/server.js` listening on `127.0.0.1:3000`. Startup verified in `setup-evidence.md`.

- [x] **Isolate the lab from public networks and document the topology.**  
  *Evidence:* Documented in `network-topology-and-isolation.md` with complete Mermaid diagram and Windows socket validation proving port 3000 binds strictly to `127.0.0.1` and is inaccessible from external LAN/WAN interfaces.

- [x] **Define the target, allowed techniques, exclusions, and stop conditions.**  
  *Evidence:* Formal personal Rules of Engagement document completed, dated, and digitally signed in `rules-of-engagement.md`.

- [x] **Put the work and a short explanation in one public or view-only link.**  
  *Evidence:* Integrated into the portfolio repository root with interactive documentation portal in `index.html` and master navigation in `README.md`.

---

## Optional Portfolio Upgrade

- [x] **Capture a clean baseline snapshot for repeatable testing.**  
  *Evidence:* SHA-256 cryptographic snapshot manifest created via `scripts/baseline-snapshot.ps1` and stored in `baseline-snapshot-manifest.json` and documented in `setup-evidence.md`.
