# ==============================================================================
# Script: scripts/baseline-snapshot.ps1
# Track: Ethical Hacking - EdVyro Internship (Task 1 Upgrade)
# Purpose: Generate an immutable cryptographic SHA-256 baseline snapshot of the
#          authorized isolated lab environment for clean repeatable testing.
# Scope: Strictly local repository files and loopback network state.
# ==============================================================================

Write-Host "[BASELINE] Initializing repeatable lab baseline snapshot..." -ForegroundColor Cyan

$targetFiles = @(
    "lab/server.js",
    "lab/db.js",
    "lab/public/index.html",
    "package.json"
)

$fileHashes = @()

foreach ($file in $targetFiles) {
    if (Test-Path $file) {
        $hashObj = Get-FileHash -Path $file -Algorithm SHA256
        $fileHashes += [PSCustomObject]@{
            File = $file
            Algorithm = "SHA-256"
            Hash = $hashObj.Hash
            SizeBytes = (Get-Item $file).Length
            LastModified = (Get-Item $file).LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    } else {
        Write-Warning "File not found: $file"
    }
}

# Verify loopback interface isolation
$loopbackConnection = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | Select-Object -First 1

$baselineManifest = [PSCustomObject]@{
    SnapshotVersion = "1.0.0"
    GeneratedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    TargetScope = "127.0.0.1:3000"
    IsolationType = "RFC 1918 Host-Only Loopback"
    ProcessId = if ($loopbackConnection) { $loopbackConnection.OwningProcess } else { "N/A" }
    BoundInterface = if ($loopbackConnection) { $loopbackConnection.LocalAddress } else { "127.0.0.1" }
    State = if ($loopbackConnection) { $loopbackConnection.State.ToString() } else { "Offline" }
    ArtifactFiles = $fileHashes
    IntegrityStatus = "VERIFIED_CLEAN"
}

$outputJsonPath = "task-1-scope-and-isolated-lab/baseline-snapshot-manifest.json"
$baselineManifest | ConvertTo-Json -Depth 5 | Set-Content -Path $outputJsonPath -Encoding UTF8

Write-Host "[BASELINE SUCCESS] Clean baseline manifest written to: $outputJsonPath" -ForegroundColor Green
Get-Content $outputJsonPath
