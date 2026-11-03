# Lab Setup Evidence & Repeatable Testing Baseline

**Track:** Ethical Hacking (Task 1: Legal Scope and Isolated Lab)  
**Deliverable:** Setup Evidence & Clean Baseline Snapshot  
**Target Application:** Authorized Practice Lab (`127.0.0.1:3000`)  
**Timestamp:** November 03, 2026  

---

## 1. Environment Prerequisite Verification

Before initializing the training lab, local runtime dependencies were validated on the host machine:

```powershell
# Command:
node --version; npm --version; git --version

# Output:
v24.13.0
11.6.2
git version 2.55.0.windows.3
```

---

## 2. Lab Target Initialization Evidence

The target application was deployed within the workspace (`d:\ethical hack 2\lab`) and launched with strict loopback parameters:

```powershell
# Launch Command:
node lab/server.js
```

**Startup Terminal Output:**
```text
[AUTHORIZED LAB] Server started successfully.
[SECURITY BOUNDARY] Listening exclusively on: http://127.0.0.1:3000
[MODE] Current Operation Mode: VULNERABLE (Training Sandbox)
[RULES OF ENGAGEMENT] Testing authorized strictly for 127.0.0.1:3000.
```

---

## 3. Port & Process Binding Verification

The Windows networking stack was queried to confirm the active socket and owning process identifier:

```powershell
Get-NetTCPConnection -LocalPort 3000 | Select-Object LocalAddress, LocalPort, State, OwningProcess
```

**Output:**
```text
LocalAddress LocalPort State  OwningProcess
------------ --------- -----  -------------
127.0.0.1         3000 Listen         26992
```

---

## 4. HTTP Health & Status Verification

A local loopback query was sent to the `/api/health` diagnostic endpoint:

```bash
curl.exe -i http://127.0.0.1:3000/api/health
```

**Output:**
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Server: NodeJS-Express-Lab/1.0.4-dev (Vulnerable Sandbox)
X-Powered-By: Node.js/v24.13.0
Access-Control-Allow-Origin: *
Date: Tue, 03 Nov 2026 14:26:28 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

{
  "status": "UP",
  "mode": "VULNERABLE_TRAINING",
  "targetBinding": "127.0.0.1:3000",
  "isolationState": "ISOLATED_RFC1918_LOOPBACK",
  "timestamp": "2026-11-03T14:26:28.495Z"
}
```

---

## 5. Optional Portfolio Upgrade: Cryptographic Baseline Snapshot

To ensure repeatable testing and provide an immutable audit trail, a cryptographic baseline snapshot was generated using `scripts/baseline-snapshot.ps1`. Every application file and data seed was hashed using SHA-256.

### Snapshot Summary
- **Manifest File:** `task-1-scope-and-isolated-lab/baseline-snapshot-manifest.json`
- **Integrity Status:** `VERIFIED_CLEAN`
- **Target Interface:** `127.0.0.1:3000`

```json
{
  "SnapshotVersion": "1.0.0",
  "GeneratedAt": "2026-11-03T19:56:46+05:30",
  "TargetScope": "127.0.0.1:3000",
  "IsolationType": "RFC 1918 Host-Only Loopback",
  "ProcessId": 26992,
  "BoundInterface": "127.0.0.1",
  "State": "Listen",
  "ArtifactFiles": [
    {
      "File": "lab/server.js",
      "Algorithm": "SHA-256",
      "Hash": "BA7D03687B09CE6D5B509D1CFA591B0F2FEA795009196F6B67E4FD2C632BF696",
      "SizeBytes": 17173
    },
    {
      "File": "lab/db.js",
      "Algorithm": "SHA-256",
      "Hash": "4350F224D138CCD77C740F1FFAF5AB01FCCCAEDCFB0CCFE1FC461A6AF0549016",
      "SizeBytes": 3452
    },
    {
      "File": "lab/public/index.html",
      "Algorithm": "SHA-256",
      "Hash": "BC6E13ABCB7341BDD6B2C1AEEA4CEDDD339C8B7946CFE2A42DD50073FA90B86E",
      "SizeBytes": 8723
    },
    {
      "File": "package.json",
      "Algorithm": "SHA-256",
      "Hash": "8E94BF96AD99B56C86DBDD88A95B9F4C6F0CAFE7C29D18887BFDA2C12BDADF3C",
      "SizeBytes": 1136
    }
  ],
  "IntegrityStatus": "VERIFIED_CLEAN"
}
```

This ensures that any subsequent modifications or remediation testing can be benchmarked against this exact verified clean state.
