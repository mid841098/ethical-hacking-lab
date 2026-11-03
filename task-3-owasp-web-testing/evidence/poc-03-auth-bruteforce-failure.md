# Proof of Concept: User Enumeration & Missing Rate Limiting (OWASP A07:2021)

**Vulnerability Type:** Identification and Authentication Failures  
**Affected Component:** `/api/auth/login`  
**Severity:** MEDIUM (CVSS 5.3 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
**Target:** `http://127.0.0.1:3000/api/auth/login`  

## 1. Technical Vulnerability Description
The login endpoint responds with distinct error messages depending on whether an email exists in the database. Furthermore, no rate limiting, account lockout, or anti-automation delays exist, facilitating automated credential stuffing and brute-force dictionary attacks.

## 2. Reproduction Steps
1. Send POST request with a known valid email and incorrect password. Observe error message: `"Incorrect password"`.
2. Send POST request with an invalid email. Observe error message: `"Account not found"`.
3. Send 10 rapid login attempts; observe 0 rate limit responses (HTTP 429).

## 3. Comparative Response Evidence

### Case A: Valid User / Wrong Password
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8

{
  "error": "Incorrect password: Password does not match our records for this user.",
  "vulnerability": "User Enumeration"
}
```

### Case B: Invalid User
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8

{
  "error": "Account not found: The specified email is not registered.",
  "vulnerability": "User Enumeration"
}
```

## 4. Security Impact
Attackers can rapidly validate lists of corporate email addresses, compile accurate employee directories, and perform targeted offline or online password guessing attacks without triggering defensive locks.
