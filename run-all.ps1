#Requires -Version 5.1
<#
.SYNOPSIS
  One entry point: optional install → verify → check APScheduler onsite → optional start scheduler.

.USAGE
  cd <repo-root>
  powershell -ExecutionPolicy Bypass -File .\run-all.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
$VenvDir = Join-Path $RepoRoot ".venv"
$VenvPy = Join-Path $VenvDir "Scripts\python.exe"
$AgentDir = Join-Path $RepoRoot "Agent-SIEM-maintenance"

function Get-PythonExe {
    if (Test-Path $VenvPy) { return $VenvPy }
    $g = Get-Command python -ErrorAction SilentlyContinue
    if (-not $g) {
        Write-Error "No Python found. Install Python 3.10+ or run install.ps1 (creates .venv)."
        exit 1
    }
    return "python"
}

function Read-Yn([string]$Message, [string]$Default = "Y") {
    $r = Read-Host "$Message [Y/n]"
    if ([string]::IsNullOrWhiteSpace($r)) { $r = $Default }
    return ($r -notmatch '^[Nn]')
}

Write-Host ""
Write-Host "=== SIEM-Maintenance - setup + scheduler ===" -ForegroundColor Cyan
Write-Host "Repository: $RepoRoot"
Write-Host ""

if (Read-Yn "Run interactive install (env, pip, model presets, verify offer)?" "Y") {
    $install = Join-Path $RepoRoot "install.ps1"
    if (-not (Test-Path $install)) {
        Write-Error "Missing install.ps1"
        exit 1
    }
    & $install
}

$py = Get-PythonExe
Write-Host ""
Write-Host "--- Environment check ---" -ForegroundColor Green
$verify = Join-Path $RepoRoot "verify_setup.py"
if (-not (Test-Path $verify)) {
    Write-Error "Missing verify_setup.py"
    exit 1
}
Push-Location $RepoRoot
try {
    & $py $verify
    if ($LASTEXITCODE -ne 0) {
        Write-Host "verify_setup.py reported issues. Fix .env or network, then re-run this script." -ForegroundColor Yellow
        if (-not (Read-Yn "Continue anyway to scheduler check?" "N")) {
            exit $LASTEXITCODE
        }
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "--- Onsite scheduler (APScheduler + maintenance_service) ---" -ForegroundColor Green
Push-Location $RepoRoot
try {
    $check = @"
import sys
sys.path.insert(0, r'$AgentDir')
import maintenance_service
from apscheduler.schedulers.background import BackgroundScheduler
print('OK: maintenance_service.py loads; APScheduler (BackgroundScheduler) is installed.')
"@
    & $py -c $check
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Scheduler check failed. Run: pip install -r requirements.txt"
        exit 1
    }
}
finally {
    Pop-Location
}

Write-Host ""
if (Read-Yn "Start maintenance scheduler now (foreground: daily report + health polls)?" "Y") {
    $ms = Join-Path $AgentDir "maintenance_service.py"
    Write-Host "Starting: $ms (Ctrl+C to stop)" -ForegroundColor Cyan
    Push-Location $AgentDir
    try {
        & $py $ms
    }
    finally {
        Pop-Location
    }
}
else {
    Write-Host "Skipped. Later run:" -ForegroundColor Green
    $msLater = Join-Path $AgentDir "maintenance_service.py"
    Write-Host ('  & "' + $py + '" "' + $msLater + '"')
}
