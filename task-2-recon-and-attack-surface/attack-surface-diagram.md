# Visual Attack Surface Map & Architecture Diagram

**Track:** Ethical Hacking (Task 2: Local Reconnaissance and Attack Surface Map)  
**Target:** `http://127.0.0.1:3000`  
**Scope:** Complete End-to-End Application Data Flow & Attack Boundaries  

---

## 1. Attack Surface Architecture Flowchart

The diagram below maps all identified entry points, exposed parameters, middleware processing steps, and sensitive backend data stores:

```mermaid
flowchart TD
    subgraph Client_Tier["Client Tier (Untrusted Input Space)"]
        Attacker["Auditor / Threat Actor (Local Client)"]
        BrowserUI["Web UI Client (index.html)"]
    end

    subgraph Transport_Tier["Transport & Edge Layer"]
        HTTP["HTTP/1.1 Socket (127.0.0.1:3000)<br/>- Server banner disclosure<br/>- Missing CSP / HSTS / XFO<br/>- Wildcard CORS (*)"]
    end

    subgraph Routing_Layer["Application Routing & Controller Layer"]
        Router{"URL Path Routing Dispatcher"}
        
        EP_Search["GET /api/products/search?q={searchTerm}<br/><b>Risk: SQL / Query Injection</b>"]
        EP_Profile["GET /api/profile?id={userId}<br/><b>Risk: IDOR / Access Control</b>"]
        EP_Orders["GET /api/orders?id={orderId}<br/><b>Risk: IDOR / Access Control</b>"]
        EP_Login["POST /api/auth/login {email, password}<br/><b>Risk: User Enumeration & No Rate Limit</b>"]
        EP_Feedback["GET /api/feedback?msg={message}<br/><b>Risk: Reflected XSS</b>"]
        EP_Debug["GET /api/admin/debug<br/><b>Risk: Info Disclosure</b>"]
        EP_Health["GET /api/health<br/>Telemetry & Mode"]
    end

    subgraph Data_Storage_Layer["Internal Data Storage (In-Memory)"]
        DB_Users[("Users Table<br/>- Admin API Tokens<br/>- Balances & Emails")]
        DB_Products[("Products Table<br/>- Public Catalog<br/>- Restricted Red-Team Flag")]
        DB_Orders[("Orders Table<br/>- PII & Shipping Addresses")]
    end

    %% Flow connections
    Attacker -->|"HTTP Requests with payloads"| HTTP
    BrowserUI --> HTTP
    HTTP --> Router

    Router -->|"Dispatch query 'q'"| EP_Search
    Router -->|"Dispatch param 'id'"| EP_Profile
    Router -->|"Dispatch param 'id'"| EP_Orders
    Router -->|"Dispatch credentials"| EP_Login
    Router -->|"Dispatch text 'msg'"| EP_Feedback
    Router -->|"Unauthenticated probe"| EP_Debug
    Router -->|"Health check"| EP_Health

    %% Backend links
    EP_Search -->|"Vulnerable Unsanitized Filter"| DB_Products
    EP_Profile -->|"Direct Index without Auth Validation"| DB_Users
    EP_Orders -->|"Direct Index without Auth Validation"| DB_Orders
    EP_Login -->|"Query Hash & Verbose Status"| DB_Users

    classDef client fill:#f5f3ff,stroke:#7c3aed,stroke-width:2px;
    classDef vuln fill:#fee2e2,stroke:#ef4444,stroke-width:2px;
    classDef safe fill:#ecfdf5,stroke:#10b981,stroke-width:2px;
    classDef storage fill:#eff6ff,stroke:#3b82f6,stroke-width:2px;
    
    class Client_Tier client;
    class EP_Search,EP_Profile,EP_Orders,EP_Login,EP_Feedback,EP_Debug vuln;
    class EP_Health safe;
    class Data_Storage_Layer storage;
```

---

## 2. Attack Surface Breakdown by Layer

### Layer 1: Network & Transport Surface
- **Exposed Surface:** Port `3000/TCP` bound to `127.0.0.1`.
- **Protocol:** HTTP/1.1 without TLS encapsulation.
- **Header Surface:**
  - Leaked server runtime headers (`Server`, `X-Powered-By`).
  - Missing browser protection policies (no CSP, no frame protection, no MIME sniff blocking).

### Layer 2: API & Controller Surface
- **Public Unauthenticated APIs:**
  - `/api/products/search`: String parameter `q` is directly evaluated in datastore query filters.
  - `/api/profile`: Numeric parameter `id` looks up user profiles without token checks.
  - `/api/orders`: Numeric parameter `id` looks up order details without ownership checks.
  - `/api/auth/login`: Accepts JSON body `{email, password}` with verbose differentiation between invalid email and invalid password.
  - `/api/feedback`: Reflects parameter `msg` as raw HTML.
  - `/api/admin/debug`: Directly dumps server environment variables and internal route maps.

### Layer 3: Persistence & Data Storage Surface
- **Database Tables:** `users`, `products`, `orders`.
- **Sensitive Assets Stored:**
  - Administrator session tokens (`apiToken`).
  - User financial balances and personal contact details (phone, full name).
  - Unreleased/restricted red-team assessment packages and internal flags.
  - Order histories with residential shipping addresses.
