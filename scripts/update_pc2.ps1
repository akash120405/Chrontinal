# =============================================================================
# CLIF v8.1 — PC2 Update & Rebuild Script
# =============================================================================
# Run this ON PC2 (via SSH or directly) to pull latest code and rebuild triage.
#
# Usage (from PC2):
#   cd C:\CLIF
#   .\scripts\update_pc2.ps1
#
# Or from PC1 via SSH:
#   ssh reddy@10.52.166.71 "cd C:\CLIF; powershell -File scripts\update_pc2.ps1"
# =============================================================================

$ErrorActionPreference = "Stop"
Set-Location "C:\CLIF"

Write-Host "`n=== CLIF v8.1 PC2 Update ===" -ForegroundColor Cyan

# ── Step 1: Pull latest code from GitHub ──
Write-Host "`n[1/5] Pulling latest code..." -ForegroundColor Yellow
git pull origin master
if ($LASTEXITCODE -ne 0) { throw "git pull failed" }
Write-Host "  OK — code updated" -ForegroundColor Green

# ── Step 2: Rebuild triage agent image ──
Write-Host "`n[2/5] Rebuilding triage agent image..." -ForegroundColor Yellow
docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env build clif-triage-agent
if ($LASTEXITCODE -ne 0) { throw "triage build failed" }
Write-Host "  OK — triage image rebuilt" -ForegroundColor Green

# ── Step 3: Restart triage agents (all 4 use same image) ──
Write-Host "`n[3/5] Restarting triage agents..." -ForegroundColor Yellow
docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env up -d --force-recreate clif-triage-agent clif-triage-agent-2 clif-triage-agent-3 clif-triage-agent-4
if ($LASTEXITCODE -ne 0) { throw "triage restart failed" }
Write-Host "  OK — triage agents restarted" -ForegroundColor Green

# ── Step 4: Ensure all other services are up ──
Write-Host "`n[4/5] Ensuring all services are up..." -ForegroundColor Yellow
docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env up -d
if ($LASTEXITCODE -ne 0) { throw "compose up failed" }
Write-Host "  OK — all services running" -ForegroundColor Green

# ── Step 5: Health check ──
Write-Host "`n[5/5] Waiting for health checks..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

$services = @(
    @{ Name = "triage-1"; Url = "http://localhost:8300/health" },
    @{ Name = "triage-2"; Url = "http://localhost:8301/health" },
    @{ Name = "triage-3"; Url = "http://localhost:8302/health" },
    @{ Name = "triage-4"; Url = "http://localhost:8303/health" },
    @{ Name = "hunter-1"; Url = "http://localhost:8400/health" },
    @{ Name = "hunter-2"; Url = "http://localhost:8401/health" },
    @{ Name = "xai";      Url = "http://localhost:8200/health" },
    @{ Name = "prometheus"; Url = "http://localhost:9090/-/healthy" }
)

$allHealthy = $true
foreach ($svc in $services) {
    try {
        $resp = Invoke-WebRequest -Uri $svc.Url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        Write-Host "  $($svc.Name): OK ($($resp.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Host "  $($svc.Name): FAIL" -ForegroundColor Red
        $allHealthy = $false
    }
}

# ── Summary ──
Write-Host "`n=== Container Status ===" -ForegroundColor Cyan
docker compose -f docker-compose.pc2.yml ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>$null
if ($LASTEXITCODE -ne 0) {
    docker compose -f docker-compose.pc2.yml ps
}

if ($allHealthy) {
    Write-Host "`n=== ALL SERVICES HEALTHY ===" -ForegroundColor Green
} else {
    Write-Host "`n=== SOME SERVICES UNHEALTHY — check logs ===" -ForegroundColor Red
    Write-Host "  docker compose -f docker-compose.pc2.yml logs --tail 50 <service-name>"
}
