#Requires -Version 5.1
<#
.SYNOPSIS
  Interactive install: prompts for Elasticsearch / Chat / LLM settings, writes .env, installs Python deps.

.USAGE
  cd <repo-root>
  powershell -ExecutionPolicy Bypass -File .\install.ps1

  Or double-click is not recommended (window closes); run from a terminal.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
$AgentDir = Join-Path $RepoRoot "Agent-SIEM-maintenance"
$ReqFile = Join-Path $RepoRoot "requirements.txt"
$VenvDir = Join-Path $RepoRoot ".venv"

function Read-Prompt {
    param(
        [string]$Message,
        [string]$Default = ""
    )
    if ($Default) {
        $r = Read-Host "$Message [default: $Default]"
        if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
        return $r
    }
    return Read-Host $Message
}

function Escape-EnvVal([string]$Value) {
    if ($null -eq $Value) { return '""' }
    $v = $Value.Trim()
    if ($v.Length -eq 0) { return '""' }
    if ($v -match '[\s#"''\x00-\x1f]' -or $v -match '[&]') {
        return '"' + ($v -replace '\\', '\\' -replace '"', '\"') + '"'
    }
    return $v
}

function Pick-OpenAIModel {
    Write-Host "OpenAI model preset (default = 1):"
    Write-Host "  1 = gpt-4o-mini   2 = gpt-4o   3 = gpt-4-turbo   4 = gpt-3.5-turbo   5 = custom"
    $c = (Read-Prompt "Choice" "1").Trim()
    switch ($c) {
        "2" { return "gpt-4o" }
        "3" { return "gpt-4-turbo" }
        "4" { return "gpt-3.5-turbo" }
        "5" { return Read-Prompt "Custom OpenAI model id" "gpt-4o-mini" }
        default { return "gpt-4o-mini" }
    }
}

function Pick-OllamaModel {
    Write-Host "Ollama model preset (default = 1):"
    Write-Host "  1 = llama3.2   2 = llama3.1   3 = mistral   4 = gemma2:2b   5 = phi3   6 = custom"
    $c = (Read-Prompt "Choice" "1").Trim()
    switch ($c) {
        "2" { return "llama3.1" }
        "3" { return "mistral" }
        "4" { return "gemma2:2b" }
        "5" { return "phi3" }
        "6" { return Read-Prompt "Custom Ollama model tag" "llama3.2" }
        default { return "llama3.2" }
    }
}

Write-Host ""
Write-Host "=== SIEM-Maintenance - interactive setup ===" -ForegroundColor Cyan
Write-Host "Repository: $RepoRoot"
Write-Host ""

if (-not (Test-Path $ReqFile)) {
    Write-Error "Missing requirements.txt at $ReqFile"
    exit 1
}

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Error "Python is not on PATH. Install Python 3.10+ from python.org and re-run."
    exit 1
}
$ver = & python --version 2>&1
Write-Host "Using $ver"
Write-Host ""

$useVenv = Read-Prompt "Create/use a local virtualenv at .venv? (Y/n)" "Y"
if ($useVenv -match '^[Nn]') {
    $pip = "pip"
    $PyExe = "python"
    Write-Host "Installing into current Python environment (user site packages may apply)." -ForegroundColor Yellow
    & python -m pip install --upgrade pip
}
else {
    $pyExeVenv = Join-Path $VenvDir "Scripts\python.exe"
    $pipExeCheck = Join-Path $VenvDir "Scripts\pip.exe"
    $venvOk = (Test-Path $pyExeVenv) -and (Test-Path $pipExeCheck)
    if ($venvOk) {
        Write-Host "Using existing venv at $VenvDir"
    }
    else {
        if (Test-Path $VenvDir) {
            Write-Host "Removing incomplete or broken .venv (expected Scripts\python.exe and pip)..." -ForegroundColor Yellow
            Remove-Item -Recurse -Force $VenvDir
        }
        Write-Host "Creating venv..."
        & python -m venv $VenvDir
    }
    $pipExe = Join-Path $VenvDir "Scripts\pip.exe"
    if (-not (Test-Path $pipExe)) {
        Write-Error "pip not found at $pipExe after venv creation"
        exit 1
    }
    $PyExe = Join-Path $VenvDir "Scripts\python.exe"
    & $PyExe -m pip install --upgrade pip
}

Write-Host ""
Write-Host "--- Elasticsearch (https://host:9200) ---" -ForegroundColor Green
$esHost = Read-Prompt "ES_HOST" "https://localhost:9200"
$esUser = Read-Prompt "ES_USERNAME" ""
$sec = Read-Host "ES_PASSWORD" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try {
    $esPass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

$kibanaDefault = $esHost -replace ":9200", ":5601"
if ($kibanaDefault -eq $esHost) { $kibanaDefault = ($esHost.TrimEnd("/") + ":5601") }
$kibana = Read-Prompt "KIBANA_HOST" $kibanaDefault

Write-Host ""
Write-Host "--- Google Chat (SIEM-MAINTENANCE webhook) ---" -ForegroundColor Green
$webhook = Read-Prompt "GC_ALERT_WEBHOOK (full https URL)" ""
$space = Read-Prompt "GC_ALERT_SPACE_NAME" "SIEM-MAINTENANCE"

Write-Host ""
Write-Host "--- LLM - AI recommendations (daily report + health alerts) ---" -ForegroundColor Green
Write-Host "Choose how narrative recommendations are generated:"
Write-Host '  1 = OpenAI API  (model name must start with gpt-, e.g. gpt-4o-mini; needs API key)'
Write-Host '  2 = Ollama      (local or remote; model tag e.g. llama3.2 - run: ollama pull your-model-tag)'
Write-Host '  3 = Off         (LLM_ENABLED=false - metrics and Chat cards still work, no AI text)'
Write-Host ""

$prov = ""
while ($prov -notmatch "^[123]$") {
    $prov = (Read-Prompt "Enter 1, 2, or 3" "2").Trim()
}

$llmEnabled = "true"
$openai = ""
$ollamaUrl = "http://localhost:11434"
$llmModel = "llama3.2"

switch ($prov) {
    "1" {
        $llmModel = Pick-OpenAIModel
        if (-not $llmModel.ToLower().StartsWith("gpt-")) {
            Write-Host "Warning: OpenAI chat models usually start with 'gpt-'. Continuing anyway." -ForegroundColor Yellow
        }
        $sec = Read-Host "OPENAI_API_KEY" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try {
            $openai = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        $ollamaUrl = Read-Prompt "OLLAMA_URL (fallback / optional tools)" "http://localhost:11434"
    }
    "2" {
        $ollamaUrl = Read-Prompt "OLLAMA_URL (base URL, no trailing path)" "http://localhost:11434"
        Write-Host ""
        Write-Host "--- This machine: suggested Ollama tags ---" -ForegroundColor DarkGray
        $preflightPy = Join-Path $RepoRoot "ollama_preflight.py"
        Push-Location $RepoRoot
        try {
            & $PyExe $preflightPy recommend
        }
        finally {
            Pop-Location
        }
        Write-Host ""
        $llmModel = Pick-OllamaModel
    }
    "3" {
        $llmEnabled = "false"
        $llmModel = Read-Prompt "LLM_MODEL (unused when LLM is off; placeholder)" "llama3.2"
        $ollamaUrl = Read-Prompt "OLLAMA_URL (optional)" "http://localhost:11434"
    }
}

Write-Host ""
Write-Host "--- Scheduler (maintenance_service.py) ---" -ForegroundColor Green
$tz = Read-Prompt "MAINTENANCE_IANA_TIMEZONE" "Africa/Johannesburg"
$daily = Read-Prompt "DAILY_REPORT_TIME_CAT (HH:MM)" "08:30"
$poll = Read-Prompt "ES_HEALTH_MONITOR_INTERVAL_SECONDS" "7200"
$cooldown = Read-Prompt "ES_ALERT_COOLDOWN_HOURS" "2"

$procIdx = Read-Prompt "ES_PROCESS_INDEX" ".ds-logs-endpoint.events.process-default-*"
$netIdx = Read-Prompt "ES_NETWORK_INDEX" ".ds-logs-endpoint.events.network-default-*"
$discIdx = Read-Prompt "ES_DISCOVERY_INDEX" "logs-endpoint.events.process-*"

# Build .env (no secrets logged)
$lines = @(
    "# Generated by install.ps1 - SIEM maintenance",
    "",
    "ES_HOST=$(Escape-EnvVal $esHost)",
    "KIBANA_HOST=$(Escape-EnvVal $kibana)",
    "ES_USERNAME=$(Escape-EnvVal $esUser)",
    "ES_PASSWORD=$(Escape-EnvVal $esPass)",
    "",
    "ES_PROCESS_INDEX=$(Escape-EnvVal $procIdx)",
    "ES_NETWORK_INDEX=$(Escape-EnvVal $netIdx)",
    "ES_DISCOVERY_INDEX=$(Escape-EnvVal $discIdx)",
    "",
    "ES_QUERY_SLOW_SEC=2.0",
    "ES_QUERY_CRITICAL_SEC=10.0",
    "",
    "GC_ALERT_WEBHOOK=$(Escape-EnvVal $webhook)",
    "GC_ALERT_SPACE_NAME=$(Escape-EnvVal $space)",
    "",
    "LOG_LEVEL=INFO",
    "",
    "ES_ALERT_COOLDOWN_HOURS=$cooldown",
    "ES_HEALTH_MONITOR_INTERVAL_SECONDS=$poll",
    "",
    "LLM_ENABLED=$llmEnabled",
    "LLM_MODEL=$(Escape-EnvVal $llmModel)",
    "ES_HEALTH_LLM_MODEL=$(Escape-EnvVal $llmModel)",
    "OLLAMA_URL=$(Escape-EnvVal $ollamaUrl)"
)

if (-not [string]::IsNullOrWhiteSpace($openai)) {
    $lines += "OPENAI_API_KEY=$(Escape-EnvVal $openai)"
}

$lines += @(
    "",
    "MAINTENANCE_IANA_TIMEZONE=$(Escape-EnvVal $tz)",
    "DAILY_REPORT_TIME_CAT=$(Escape-EnvVal $daily)",
    "",
    "ML_FILE_RETENTION_DAYS=7"
)

$envPath = Join-Path $RepoRoot ".env"
$lines -join "`r`n" | Set-Content -Path $envPath -Encoding utf8
Write-Host ""
Write-Host "Wrote $envPath" -ForegroundColor Green

$agentEnv = Join-Path $AgentDir ".env"
Copy-Item -Path $envPath -Destination $agentEnv -Force
Write-Host "Copied .env to $agentEnv (for scripts run from Agent-SIEM-maintenance)."

Write-Host ""
$summaryLlm = switch ($prov) {
    "1" { 'OpenAI (' + $llmModel + ')' }
    "2" { 'Ollama (' + $llmModel + ' at ' + $ollamaUrl + ')' }
    default { 'disabled (LLM_ENABLED=false)' }
}
Write-Host "LLM configuration: $summaryLlm" -ForegroundColor Green

Write-Host ""
Write-Host "Installing dependencies from requirements.txt..."
if ($useVenv -match '^[Nn]') {
    & python -m pip install -r $ReqFile
}
else {
    & $PyExe -m pip install -r $ReqFile
}

if ($prov -eq "2") {
    Write-Host ""
    $pullIfMissing = Read-Prompt "If the model is missing on the Ollama server, run 'ollama pull' now? (Y/n)" "Y"
    $preflightPy = Join-Path $RepoRoot "ollama_preflight.py"
    Push-Location $RepoRoot
    try {
        if ($pullIfMissing -match '^[Nn]') {
            & $PyExe $preflightPy ensure --url $ollamaUrl --model $llmModel --no-pull
        }
        else {
            & $PyExe $preflightPy ensure --url $ollamaUrl --model $llmModel
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ollama_preflight ensure exited $LASTEXITCODE - fix Ollama URL or run ollama pull on the server, then re-run verify_setup." -ForegroundColor Yellow
            Write-Host "The maintenance scheduler will still run; AI narrative is skipped automatically when the LLM is unreachable." -ForegroundColor DarkGray
        }
    }
    finally {
        Pop-Location
    }
}

$verifyAns = Read-Prompt "Run verify_setup.py (imports + optional Elasticsearch / Ollama checks)? (Y/n)" "Y"
if ($verifyAns -notmatch '^[Nn]') {
    $verifyScript = Join-Path $RepoRoot "verify_setup.py"
    if (Test-Path $verifyScript) {
        Write-Host ""
        Write-Host "--- Verification ---" -ForegroundColor Green
        Push-Location $RepoRoot
        try {
            & $PyExe $verifyScript
        }
        finally {
            Pop-Location
        }
    }
}

$msPath = Join-Path $AgentDir "maintenance_service.py"
$logDir = Join-Path $RepoRoot "logs"
$outLog = Join-Path $logDir "maintenance_service.log"
$errLog = Join-Path $logDir "maintenance_service.errors.log"
$pidFile = Join-Path $logDir "maintenance_service.pid"

Write-Host ""
$startSched = Read-Prompt "Start the maintenance scheduler in the background now? (daily Chat report + periodic ES health alerts per .env) (Y/n)" "Y"
if ($startSched -notmatch '^[Nn]') {
    if (-not (Test-Path $msPath)) {
        Write-Host "Skipping start: maintenance_service.py not found at $msPath" -ForegroundColor Yellow
    }
    else {
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir | Out-Null
        }
        Write-Host ""
        Write-Host "--- Starting maintenance scheduler (background) ---" -ForegroundColor Green
        if (Test-Path $pidFile) {
            $oldPid = @(Get-Content -Path $pidFile -ErrorAction SilentlyContinue)[0]
            if ($oldPid) {
                try {
                    $null = Get-Process -Id $oldPid -ErrorAction Stop
                    Write-Host "Scheduler may already be running (PID $oldPid). Start another? (y/N): " -NoNewline
                    $dup = Read-Host
                    if ($dup -notmatch '^[Yy]') {
                        Write-Host "Skipped. Stop the old process with: Stop-Process -Id $oldPid -Force" -ForegroundColor Yellow
                        $startSched = "n"
                    }
                }
                catch {
                    # stale PID file
                }
            }
        }
        if ($startSched -notmatch '^[Nn]') {
            try {
                $proc = Start-Process -FilePath $PyExe -ArgumentList @($msPath) -WorkingDirectory $AgentDir `
                    -WindowStyle Hidden -PassThru `
                    -RedirectStandardOutput $outLog -RedirectStandardError $errLog
                if ($proc) {
                    $proc.Id | Set-Content -Path $pidFile -Encoding utf8
                    Write-Host "Scheduler started (PID $($proc.Id))." -ForegroundColor Green
                    Write-Host "  Logs: $outLog  (errors also: $errLog)"
                    Write-Host "  PID file: $pidFile  (stop: Stop-Process -Id $($proc.Id) -Force)"
                }
            }
            catch {
                Write-Host "Could not start scheduler in background: $_" -ForegroundColor Yellow
                Write-Host "Start it manually in a terminal (see commands below)." -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "Run the maintenance scheduler (foreground):"
if ($useVenv -notmatch '^[Nn]') {
    $pyw = Join-Path $VenvDir "Scripts\python.exe"
    Write-Host ('  & "' + $pyw + '" "' + $msPath + '"')
    Write-Host "One-shot morning report:"
    Write-Host ('  & "' + $pyw + '" "' + $msPath + '" --once-daily')
}
else {
    Write-Host "  python `"$msPath`""
}
Write-Host ""
