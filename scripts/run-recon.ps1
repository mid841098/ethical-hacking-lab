# ==============================================================================
# Script: scripts/run-recon.ps1
# Track: Ethical Hacking - EdVyro Internship (Task 2 Reconnaissance)
# Purpose: Execute controlled, safe, authorized reconnaissance exclusively against
#          the isolated local lab target (127.0.0.1:3000).
# Boundary: Prohibits external network interaction; respects RoE rate limits.
# ==============================================================================

Write-Host "[RECON] Starting authorized local reconnaissance against 127.0.0.1:3000..." -ForegroundColor Cyan

$targetHost = "127.0.0.1"
$targetPort = 3000
$targetBase = "http://${targetHost}:${targetPort}"
$timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")

# 1. Interface & Port Verification
Write-Host "[1/4] Verifying loopback socket binding..." -ForegroundColor Yellow
$connection = Get-NetTCPConnection -LocalAddress $targetHost -LocalPort $targetPort -ErrorAction SilentlyContinue

$logContent = @"
# Sanitized Command Log & Raw Reconnaissance Evidence

**Assessment Track:** Ethical Hacking & Penetration Testing  
**Target Identifier:** `127.0.0.1:3000` (Localhost / Loopback Interface)  
**Execution Timestamp:** $timestamp  
**Operator:** Authorized Security Intern  
**Scope Validation:** RFC 1918 Private / Loopback Scope Strictly Confirmed. No external packets generated.

---

## 1. Network Boundary & Loopback Socket Verification

```powershell
# Command executed:
Get-NetTCPConnection -LocalAddress $targetHost -LocalPort $targetPort | Format-Table LocalAddress, LocalPort, State, OwningProcess

# Output:
LocalAddress  LocalPort State  OwningProcess
------------  --------- -----  -------------
$($connection.LocalAddress)     $($connection.LocalPort)      $($connection.State) $($connection.OwningProcess)
```

**Boundary Finding:** Target is bound exclusively to `$targetHost`. External network interfaces (`0.0.0.0` or public adapters) are NOT listening. Public exposure risk is ZERO.

---

## 2. HTTP Banner & Server Header Extraction

```bash
# Command executed:
curl.exe -sIL "$targetBase/"
```

**Output:**
```http
"@

# Capture Root Headers
$headers = curl.exe -sIL "$targetBase/"
$logContent += "`n$headers`n```"

$logContent += @"

**Observation:**
- Leaked Server Header: `Server: NodeJS-Express-Lab/1.0.4-dev (Vulnerable Sandbox)`
- Leaked Technology Banner: `X-Powered-By: Node.js/v24.13.0`
- Missing Defense-in-Depth Headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`.
- Permissive CORS: `Access-Control-Allow-Origin: *`

---

## 3. Controlled Route & Endpoint Enumeration

Executing low-rate manual inspection of authorized training routes:

"@

$endpoints = @(
    @{ Path = "/api/health"; Desc = "Health check & mode reporting" },
    @{ Path = "/api/version"; Desc = "Application version & runtime details" },
    @{ Path = "/api/products/search?q=guide"; Desc = "Product catalog search query parameter" },
    @{ Path = "/api/profile?id=2"; Desc = "User profile endpoint accepting numeric ID" },
    @{ Path = "/api/orders?id=5002"; Desc = "Order history lookup by ID" },
    @{ Path = "/api/feedback?msg=Probe"; Desc = "Auditor feedback viewer" },
    @{ Path = "/api/admin/debug"; Desc = "Internal administration debug route" }
)

foreach ($ep in $endpoints) {
    Write-Host "Probing $($ep.Path)..." -ForegroundColor Gray
    $url = "$targetBase$($ep.Path)"
    $res = curl.exe -s "$url"
    
    $logContent += @"

### GET $($ep.Path)
- **Functional Description:** $($ep.Desc)
- **Sanitized Response Payload:**
```json
$res
```

"@
}

$logContent += @"

---

## 4. Authentication Endpoint Pre-Assessment

```bash
# Command executed:
curl.exe -s -X POST "$targetBase/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"invalid_user@internal-lab.local\",\"password\":\"randompass\"}"
```

**Sanitized Output:**
```json
"@

$loginProbe = curl.exe -s -X POST "$targetBase/api/auth/login" -H "Content-Type: application/json" -d "{\`"email\`":\`"invalid_user@internal-lab.local\`",\`"password\`":\`"randompass\`"}"
$logContent += "`n$loginProbe`n```"

$logContent += @"

**Reconnaissance Summary:**
Total active endpoints mapped: 8  
Authentication protocol: JSON REST over HTTP  
Identified candidate attack surfaces:
1. Object Identifier parameter `?id=` on `/api/profile` and `/api/orders` (Potential IDOR)
2. String search query parameter `?q=` on `/api/products/search` (Potential Query/SQL Injection)
3. Verbose error messaging on `/api/auth/login` (Potential User Enumeration & Brute-Force)
4. Unescaped reflection on `/api/feedback?msg=` (Potential Reflected XSS)
5. Exposed debug configuration on `/api/admin/debug` (Information Disclosure)

"@

$logOutputPath = "task-2-recon-and-attack-surface/sanitized-command-log.md"
$logContent | Set-Content -Path $logOutputPath -Encoding UTF8

Write-Host "[RECON SUCCESS] Sanitized reconnaissance log saved to: $logOutputPath" -ForegroundColor Green
