# Sanitized Command Log & Local Reconnaissance Evidence

**Track:** Ethical Hacking (Task 2: Local Reconnaissance & Attack Surface Map)  
**Target Scope:** `http://127.0.0.1:3000`  
**Host Interface:** `127.0.0.1` (RFC 1918 Private / Loopback Interface Only)  
**Execution Timestamp:** `2026-11-05T12:39:26.561Z`  
**Security Boundary:** Confirmed host-only loopback. External network scanning is prohibited.

---

## 1. Local Network & Socket Binding Verification

Verification command:
```powershell
Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 3000 | Select-Object LocalAddress, LocalPort, State, OwningProcess
```

**Result:**
```text
LocalAddress  LocalPort State   OwningProcess
------------  --------- -----   -------------
127.0.0.1     3000      Listen  [Isolated Lab Process]
```

**Scope Confirmation:** The practice target is actively listening on `127.0.0.1:3000`. No non-loopback addresses or public interfaces are bound.

---

## 2. HTTP Server Banner & Header Inspection

Command:
```bash
curl.exe -sIL "http://127.0.0.1:3000/"
```

**Response Headers Extracted:**
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: N/A
X-Powered-By: N/A
Access-Control-Allow-Origin: N/A
Connection: keep-alive
```

**Security Analysis of Headers:**
- **Information Disclosure:** Server exposes specific internal technology versions (`undefined` and `undefined`).
- **Missing Protection Headers:** Missing `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security`.
- **CORS Misconfiguration:** Wildcard origin (`*`) allows arbitrary cross-domain read access.

---

## 3. Discovered Endpoints, Parameters & Responses

### 3.1 GET `/api/health` (Health & Telemetry)
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "status": "UP",
  "mode": "VULNERABLE_TRAINING",
  "targetBinding": "127.0.0.1:3000",
  "isolationState": "ISOLATED_RFC1918_LOOPBACK",
  "timestamp": "2026-11-05T12:39:26.628Z"
}
```

### 3.2 GET `/api/version` (Version Fingerprinting)
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "application": "Authorized Security Practice Lab (JuiceShop-Model)",
  "version": "1.2.0-alpha",
  "environment": "Local Isolated Practice Lab",
  "nodeRuntime": "v24.13.0",
  "authorizedTester": "Security Intern / Auditor"
}
```

### 3.3 GET `/api/products/search?q=guide` (Product Search Input)
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "query": "guide",
  "count": 1,
  "data": [
    {
      "id": 101,
      "name": "OWASP Security Guide v4.2",
      "category": "Books",
      "price": 29.99,
      "isPublic": true,
      "stock": 45,
      "internalNotes": "Public catalog item"
    }
  ]
}
```

### 3.4 GET `/api/profile?id=2` (User Profile Object Lookup)
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "id": 2,
  "username": "bob_student",
  "email": "bob@internal-lab.local",
  "role": "user",
  "fullName": "Bob Martinez",
  "phone": "+1-555-0102",
  "balance": 245.5,
  "apiToken": "tok_user_3857ca02981ef8471",
  "isSuperUser": false
}
```

### 3.5 GET `/api/orders?id=5002` (Order History Object Lookup)
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "order": {
    "id": 5002,
    "userId": 2,
    "total": 29.99,
    "status": "Processing",
    "items": [
      "OWASP Security Guide v4.2"
    ],
    "shippingAddress": "42 Student Way, Campus Dorms"
  }
}
```

### 3.6 GET `/api/admin/debug` (Administrative Route Disclosure)
```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "warning": "DEBUG INTERFACE EXPOSED - FOR INTERNAL TESTING ONLY",
  "environmentVariables": {
    "NODE_ENV": "development",
    "DATABASE_DIALECT": "in-memory-sqlite-sim",
    "HOST_BINDING": "127.0.0.1:3000"
  },
  "registeredRoutes": [
    "/api/health",
    "/api/version",
    "/api/products/search",
    "/api/profile",
    "/api/orders",
    "/api/auth/login",
    "/api/feedback",
    "/api/admin/debug"
  ]
}
```

### 3.7 POST `/api/auth/login` (Authentication Interface)
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
```
```json
{
  "error": "Account not found: The specified email is not registered.",
  "vulnerability": "User Enumeration"
}
```

---

## 4. Attack Surface Summary

| Component | Target URL | HTTP Methods | Parameters Observed | Data Format | Potential Security Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Catalog Search** | `/api/products/search` | `GET` | `q` (string) | JSON | SQL / Query String Injection |
| **User Profile** | `/api/profile` | `GET` | `id` (integer) | JSON | Broken Object-Level Authorization (IDOR) |
| **Orders API** | `/api/orders` | `GET` | `id` (integer) | JSON | Broken Object-Level Authorization (IDOR) |
| **Authentication**| `/api/auth/login` | `POST` | `email`, `password` | JSON | User Enumeration & Credential Stuffing |
| **Auditor Feedback**| `/api/feedback` | `GET` | `msg` (string) | HTML / Text | Reflected Cross-Site Scripting (XSS) |
| **Admin Debug** | `/api/admin/debug` | `GET` | None | JSON | Unauthenticated Information Disclosure |
| **HTTP Transport** | Root & API paths | `*` | Headers | HTTP Headers| Security Misconfiguration (Missing Headers) |

**Conclusion:** All reconnaissance was executed non-destructively against loopback targets only. No unauthorized external packets were transmitted.
