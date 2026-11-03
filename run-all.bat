@echo off
echo ===============================================================================
echo   EDVYRO ETHICAL HACKING - AUTHORIZED PRACTICE LAB & TESTING SUITE
echo ===============================================================================
echo.

echo [1/4] Generating Cryptographic SHA-256 Baseline Snapshot...
powershell -ExecutionPolicy Bypass -File .\scripts\baseline-snapshot.ps1
echo.

echo [2/4] Executing Local Reconnaissance & Attack Surface Discovery...
node .\scripts\run-recon.js
echo.

echo [3/4] Running Non-Destructive OWASP Web Vulnerability Tests...
node .\scripts\test-owasp-findings.js
echo.

echo [4/4] Executing Automated Post-Remediation Retest Verification...
node .\scripts\run-retest.js
echo.

echo ===============================================================================
echo   ALL 4 TASKS COMPLETED & VERIFIED SUCCESSFULLY!
echo ===============================================================================
echo.
echo Opening Interactive Portfolio Portal in your browser...
start "" "index.html"
start "" "http://127.0.0.1:3000"
echo.
pause
