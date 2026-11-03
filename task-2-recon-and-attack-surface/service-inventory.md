# Structured Service Inventory & Component Catalog

**Track:** Ethical Hacking (Task 2: Local Reconnaissance and Attack Surface Map)  
**Target:** `http://127.0.0.1:3000`  
**Assessment Date:** November 03, 2026  
**Methodology:** Passive enumeration and low-rate manual inspection  

---

## 1. Network & Service Profile

| Property | Observed Value | Security Implication |
| :--- | :--- | :--- |
| **IP Address** | `127.0.0.1` | Isolated local loopback (Safe scope) |
| **Port** | `3000 / TCP` | Standard custom development port |
| **Service Protocol** | `HTTP/1.1` | Plaintext HTTP (Unencrypted transport) |
| **Application Runtime**| `Node.js v24.13.0` | Modern LTS JavaScript engine |
| **Framework Banner** | `NodeJS-Express-Lab/1.0.4-dev` | Leaked internal framework and development version |
| **Database Engine** | In-Memory SQLite/JSON simulator | Fast, ephemeral datastore seeded with synthetic records |

---

## 2. HTTP Header Profile

Extracted via `curl.exe -sIL "http://127.0.0.1:3000/"`:

| Header Name | Value Observed | Evaluation |
| :--- | :--- | :--- |
| `Content-Type` | `text/html; charset=utf-8` | Valid standard encoding |
| `Server` | `NodeJS-Express-Lab/1.0.4-dev` | **Insecure**: Leaks exact framework and build |
| `X-Powered-By` | `Node.js/v24.13.0` | **Insecure**: Leaks underlying execution runtime |
| `Access-Control-Allow-Origin` | `*` | **Insecure**: Overly permissive wildcard CORS |
| `Content-Security-Policy` | *Not Present* | **Missing**: No protection against script injection |
| `X-Frame-Options` | *Not Present* | **Missing**: Vulnerable to iframe framing & clickjacking |
| `X-Content-Type-Options` | *Not Present* | **Missing**: Vulnerable to MIME-type sniffing |
| `Strict-Transport-Security` | *Not Present* | **Missing**: No HSTS enforcement |

---

## 3. Discovered Routes & Endpoint Inventory

The application exposes 9 primary endpoints across public, user, and administrative functional domains:

| # | Route / Path | HTTP Method | Expected Inputs | Content-Type | Auth Required | Purpose / Function |
| :-: | :--- | :---: | :--- | :---: | :---: | :--- |
| **1** | `/` | `GET` | None | `text/html` | No | Main landing page & visual testing GUI |
| **2** | `/api/health` | `GET` | None | `application/json` | No | Service availability & isolation telemetry |
| **3** | `/api/version` | `GET` | None | `application/json` | No | Software build and tester identification |
| **4** | `/api/products/search` | `GET` | `q` (string query) | `application/json` | No | Catalog search across product inventory |
| **5** | `/api/profile` | `GET` | `id` (integer user ID) | `application/json` | No | Retrieval of account profile details |
| **6** | `/api/orders` | `GET` | `id` (integer order ID) | `application/json` | No | Retrieval of customer order records |
| **7** | `/api/auth/login` | `POST` | `email`, `password` (JSON) | `application/json` | No | User authentication & credential validation |
| **8** | `/api/feedback` | `GET` | `msg` (string message) | `text/html` | No | Auditor feedback viewer & reflection |
| **9** | `/api/admin/debug` | `GET` | None | `application/json` | No | Internal administration debug route |

---

## 4. Parameter & Input Surface Analysis

| Parameter Name | Target Endpoint | Input Type | Transport | Sanitization Observed | Risk Indicator |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `q` | `/api/products/search` | String | URL Query String | None (Raw interpolation) | High (Query Injection) |
| `id` | `/api/profile` | Integer | URL Query String | Numeric cast only | High (IDOR / BOLA) |
| `id` | `/api/orders` | Integer | URL Query String | Numeric cast only | High (IDOR / BOLA) |
| `email` | `/api/auth/login` | String (Email)| JSON Body | String match only | Medium (Enumeration) |
| `password` | `/api/auth/login` | String (Pass) | JSON Body | Hashed, but no lockout | Medium (Brute-Force) |
| `msg` | `/api/feedback` | String | URL Query String | None (Rendered in DOM) | Medium (Reflected XSS) |
