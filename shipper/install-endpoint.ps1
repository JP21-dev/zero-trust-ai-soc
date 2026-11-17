<#
.SYNOPSIS
  Install (or update) the SOC shipper + enforcer on a Windows endpoint.

.DESCRIPTION
  Run from an ELEVATED PowerShell, in the folder that holds shipper.py, enforcer.py
  and requirements.txt. Works on the Hub itself and on any other tailnet laptop.

    1. Finds an all-users Python 3.10+ in C:\Program Files (installs 3.12 with winget
       if there is none). Never uses a per-user Python: the shipper runs as SYSTEM,
       and SYSTEM must not run code from a folder a normal user can modify.
    2. Copies the shipper to C:\SOCShipper (read-only for normal users) and builds
       a virtualenv with its two dependencies.
    3. Installs the shipper token and config.json (Hub URLs) in C:\ProgramData\SOCShipper
       (SYSTEM + Admins only).
    4. Pins the Hub's order-signing public key over HTTPS and checks its key_id.
    5. Does one dry run (prints a batch, sends nothing).
    6. Registers the "SOCShipper" scheduled task: at startup, as SYSTEM, restarts on
       failure, and starts it now.

  Safe to re-run: it updates the files and restarts the task.

.PARAMETER TokenFile
  Path to the shipper token. Defaults to ..\secrets\shipper_token.txt when run on the
  Hub; elsewhere you'll be asked to paste it (input is hidden).

.PARAMETER HubUrl
  The Hub's ingest URL on your tailnet, e.g. http://100.x.y.z:8080/ingest
  When run on the Hub, it's read from ..\.env. On re-runs, the saved config is kept.

.PARAMETER HubKeyUrl
  The Hub's HTTPS public-key URL, e.g. https://soc-hub.your-tailnet.ts.net/warden/public-key
  When run on the Hub, it's read from ..\.env (WEBAUTHN_ORIGIN).

.PARAMETER ExpectedKeyId
  The Hub's signing key_id (from the Hub's startup log). If given, the pinned key
  must match it or the install stops.

.PARAMETER DryRunEnforcement
  Install with enforcement in log-only mode (SOC_ENFORCE_DRY_RUN=1): approved orders
  are logged, no firewall rule is created. Re-run without it to go live.

.PARAMETER CheckOnly
  Don't change anything: report what would be used and done. Doesn't need elevation.

.EXAMPLE
  # On the Hub itself (URLs and token are read from the project folder):
  powershell -ExecutionPolicy Bypass -File .\install-endpoint.ps1 -ExpectedKeyId <key_id>

.EXAMPLE
  # On another laptop (you'll be asked to paste the token):
  powershell -ExecutionPolicy Bypass -File .\install-endpoint.ps1 `
      -HubUrl http://100.x.y.z:8080/ingest `
      -HubKeyUrl https://soc-hub.your-tailnet.ts.net/warden/public-key -ExpectedKeyId <key_id>
#>
[CmdletBinding()]
param(
    [string]$TokenFile,
    [string]$HubUrl,
    [string]$HubKeyUrl,
    [string]$ExpectedKeyId,
    [switch]$DryRunEnforcement,
    [switch]$CheckOnly,
    [string]$InstallDir = "C:\SOCShipper",
    [string]$StateDir = (Join-Path $env:ProgramData "SOCShipper"),
    [string]$TaskName = "SOCShipper"
)
# "Continue", not "Stop": Windows PowerShell 5.1 turns any stderr line from a native
# program (python's logging, pip warnings) into a terminating error under "Stop".
# Every native call below checks $LASTEXITCODE instead; cmdlets that must not fail
# use -ErrorAction Stop.
$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Step($n, $text) { Write-Host ""; Write-Host "[$n/6] $text" -ForegroundColor Magenta }
function Ok($text)   { Write-Host "  OK  $text" -ForegroundColor Green }
function Info($text) { Write-Host "      $text" }
function Fail($text) { Write-Host "  !!  $text" -ForegroundColor Red; exit 1 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $CheckOnly -and -not $isAdmin) {
    Fail "Run this from an elevated PowerShell (right-click PowerShell > Run as administrator)."
}
foreach ($f in "shipper.py", "enforcer.py", "requirements.txt") {
    if (-not (Test-Path (Join-Path $here $f))) { Fail "$f not found next to this script ($here)." }
}

# ------------------------------------------------------------------ 1. Python
Step 1 "Python (all-users install only)"
function Find-MachinePython {
    $cands = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($root) { $cands += Get-ChildItem -Path $root -Filter "Python3*" -Directory -ErrorAction SilentlyContinue |
                       ForEach-Object { Join-Path $_.FullName "python.exe" } }
    }
    $best = $null
    foreach ($p in $cands | Where-Object { Test-Path $_ }) {
        $v = & $p -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($v -and [version]$v -ge [version]"3.10" -and (-not $best -or [version]$v -gt [version]$best.Version)) {
            $best = [pscustomobject]@{ Path = $p; Version = $v }
        }
    }
    return $best
}
$py = Find-MachinePython
if (-not $py) {
    Info "No all-users Python 3.10+ in Program Files."
    if ($CheckOnly) { Info "Would install Python 3.12 for all users with winget." }
    else {
        $ans = Read-Host "  Install Python 3.12 for all users with winget now? [Y/n]"
        if ($ans -match '^[Nn]') { Fail "Python is required. Install it for all users and re-run." }
        winget install -e --id Python.Python.3.12 --scope machine
        if ($LASTEXITCODE -ne 0) { Fail "winget couldn't install Python (exit $LASTEXITCODE)." }
        $py = Find-MachinePython
        if (-not $py) { Fail "Python installed but not found in Program Files. Re-run this script." }
    }
}
if ($py) { Ok "Using Python $($py.Version): $($py.Path)" }

# ------------------------------------------------------------------ 2. Files + venv
Step 2 "Shipper files in $InstallDir"
$venvPy  = Join-Path $InstallDir ".venv\Scripts\python.exe"
$venvPyw = Join-Path $InstallDir ".venv\Scripts\pythonw.exe"
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($CheckOnly) {
    Info "Would copy shipper.py, enforcer.py, requirements.txt and build a venv."
    Info ("Existing install: " + $(if (Test-Path $venvPy) { "yes (will be updated)" } else { "no" }))
    Info ("Scheduled task '$TaskName': " + $(if ($task) { $task.State } else { "not registered" }))
} else {
    if ($task -and $task.State -eq "Running") { Stop-ScheduledTask -TaskName $TaskName; Info "Stopped the running task for the update." }
    New-Item -ItemType Directory -Force -Path $InstallDir -ErrorAction Stop | Out-Null
    # SYSTEM runs this code: normal users may read it but never change it.
    # Lock the folder FIRST so everything created below inherits the lock. Set it on
    # the folder only, then make existing contents inherit it (/reset). Applying the
    # grant to every file with /T strips files' inherited rights without adding the
    # new ones, leaving them unreadable by anyone; the /reset also repairs that.
    icacls $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /Q | Out-Null
    if ($LASTEXITCODE) { Fail "Couldn't set permissions on $InstallDir (icacls exit $LASTEXITCODE)." }
    if (Get-ChildItem -LiteralPath $InstallDir -Force) {
        icacls (Join-Path $InstallDir "*") /reset /T /C /Q | Out-Null
        if ($LASTEXITCODE) { Fail "Couldn't reset permissions inside $InstallDir (icacls exit $LASTEXITCODE)." }
    }
    Copy-Item (Join-Path $here "shipper.py"), (Join-Path $here "enforcer.py"), (Join-Path $here "requirements.txt") $InstallDir -Force -ErrorAction Stop
    if (-not (Test-Path (Join-Path $InstallDir ".venv\pyvenv.cfg"))) {
        & $py.Path -m venv --clear (Join-Path $InstallDir ".venv"); if ($LASTEXITCODE) { Fail "venv creation failed." }
    }
    & $venvPy -m pip install --disable-pip-version-check -q -r (Join-Path $InstallDir "requirements.txt")
    if ($LASTEXITCODE) { Fail "pip install failed." }
    & $venvPy -c "import psutil, cryptography" 2>$null
    if ($LASTEXITCODE) { Fail "The shipper's Python can't load its packages." }
    Ok "Installed; normal users have read-only access."
}

# ------------------------------------------------------------------ 3. Token
Step 3 "Shipper token in $StateDir"
$tokenDest = Join-Path $StateDir "token.txt"
if (-not $TokenFile) {
    $hubToken = Join-Path (Split-Path -Parent $here) "secrets\shipper_token.txt"
    if (Test-Path $hubToken) { $TokenFile = $hubToken }
}
if ($CheckOnly) {
    Info ("Token source: " + $(if ($TokenFile) { $TokenFile } elseif (Test-Path $tokenDest) { "keep existing $tokenDest" } else { "would ask you to paste it" }))
} else {
    New-Item -ItemType Directory -Force -Path $StateDir -ErrorAction Stop | Out-Null
    if ($TokenFile) {
        $token = (Get-Content -Raw -LiteralPath $TokenFile).Trim()
    } elseif (Test-Path $tokenDest) {
        $token = (Get-Content -Raw -LiteralPath $tokenDest).Trim(); Info "Keeping the existing token."
    } else {
        $sec = Read-Host "  Paste the shipper token (from the Hub's secrets\shipper_token.txt)" -AsSecureString
        $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)).Trim()
    }
    if ($token.Length -lt 32) { Fail "That token is too short; it should be 64 characters." }
    icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /Q | Out-Null
    Set-Content -NoNewline -Encoding ascii -LiteralPath $tokenDest -Value $token -ErrorAction Stop
    Remove-Variable token
    Ok "Token installed; readable by SYSTEM and Administrators only."
}

# Hub URLs: parameter > saved config.json > this project's .env (when run on the Hub) > ask.
$configPath = Join-Path $StateDir "config.json"
$saved = $null
try { if (Test-Path $configPath) { $saved = Get-Content -Raw -LiteralPath $configPath -ErrorAction Stop | ConvertFrom-Json } } catch { }
$envVals = @{}
$envFile = Join-Path (Split-Path -Parent $here) ".env"
if (Test-Path $envFile) {
    Get-Content -LiteralPath $envFile | ForEach-Object { if ($_ -match '^\s*([A-Z_]+)\s*=\s*(.*?)\s*$') { $envVals[$Matches[1]] = $Matches[2] } }
}
$urlSource = "parameter"
if (-not $HubUrl) {
    if ($saved -and $saved.hub_url) { $HubUrl = $saved.hub_url; $urlSource = "saved config" }
    elseif ($envVals["TAILSCALE_IP"] -match '^100\.\d+\.\d+\.\d+$') {
        $port = if ($envVals["ORCHESTRATOR_PORT"]) { $envVals["ORCHESTRATOR_PORT"] } else { "8080" }
        $HubUrl = "http://$($envVals['TAILSCALE_IP']):$port/ingest"; $urlSource = "this Hub's .env"
    }
}
if (-not $HubKeyUrl) {
    if ($saved -and $saved.hub_key_url) { $HubKeyUrl = $saved.hub_key_url }
    elseif ($envVals["WEBAUTHN_ORIGIN"] -match '^https://[^/]+\.ts\.net/?$' -and $envVals["WEBAUTHN_ORIGIN"] -notmatch 'your-tailnet') {
        $HubKeyUrl = $envVals["WEBAUTHN_ORIGIN"].TrimEnd("/") + "/warden/public-key"
    }
}
if ($CheckOnly) {
    Info ("Hub URL:     " + $(if ($HubUrl) { "$HubUrl ($urlSource)" } else { "would ask (e.g. http://100.x.y.z:8080/ingest)" }))
    Info ("Hub key URL: " + $(if ($HubKeyUrl) { $HubKeyUrl } else { "would ask (e.g. https://soc-hub.your-tailnet.ts.net/warden/public-key)" }))
} else {
    if (-not $HubUrl)    { $HubUrl    = (Read-Host "  Hub ingest URL (e.g. http://100.x.y.z:8080/ingest)").Trim() }
    if (-not $HubKeyUrl) { $HubKeyUrl = (Read-Host "  Hub key URL (e.g. https://soc-hub.your-tailnet.ts.net/warden/public-key)").Trim() }
    if ($HubUrl -notmatch '^https?://[^/\s]+/ingest$') { Fail "Hub URL should look like http://100.x.y.z:8080/ingest (got '$HubUrl')." }
    if ($HubKeyUrl -notmatch '^https://[^/\s]+/warden/public-key$') { Fail "Hub key URL must be https://<hub>.ts.net/warden/public-key (got '$HubKeyUrl')." }
    @{ hub_url = $HubUrl; hub_key_url = $HubKeyUrl } | ConvertTo-Json | Set-Content -Encoding ascii -LiteralPath $configPath -ErrorAction Stop
    Ok "Config saved: $HubUrl"
}

# ------------------------------------------------------------------ 4. Pin hub key
Step 4 "Pin the Hub's order-signing key"
if ($CheckOnly) { Info ("Would run: shipper.py --pin-hub-key" + $(if ($ExpectedKeyId) { " and require key_id $ExpectedKeyId" } else { "" })) }
else {
    $out = & $venvPy (Join-Path $InstallDir "shipper.py") --pin-hub-key 2>&1 | Out-String
    if ($LASTEXITCODE) { Fail "Pinning failed:`n$out" }
    $kid = [regex]::Match($out, "key_id ([0-9a-f]{16})").Groups[1].Value
    if (-not $kid) { Fail "Couldn't read the key_id from:`n$out" }
    if ($ExpectedKeyId) {
        if ($kid -ne $ExpectedKeyId) { Remove-Item (Join-Path $StateDir "hub_pubkey.json") -Force; Fail "Pinned key_id $kid does NOT match $ExpectedKeyId. Removed it; don't continue until you know why." }
        Ok "Pinned key_id $kid matches."
    } else {
        Info "Pinned key_id: $kid"
        $ans = Read-Host "  Does it match the Hub's log line 'execution orders are signed with Ed25519 key_id=...'? [y/N]"
        if ($ans -notmatch '^[Yy]') { Remove-Item (Join-Path $StateDir "hub_pubkey.json") -Force; Fail "Not confirmed. Removed the pinned key." }
        Ok "Confirmed."
    }
}

# ------------------------------------------------------------------ 5. Dry run
Step 5 "Dry run (reads connections, sends nothing)"
if ($CheckOnly) { Info "Would run: shipper.py --dry-run" }
else {
    # The batch goes to stdout and the summary line ("# N events, tailscale_up=...") to
    # stderr; merged, their order isn't guaranteed, so search all of it for the summary.
    $dryOut = (& $venvPy (Join-Path $InstallDir "shipper.py") --dry-run 2>&1 | ForEach-Object { "$_" }) -join "`n"
    if ($LASTEXITCODE) { Fail "Dry run failed:`n$($dryOut.Substring([Math]::Max(0, $dryOut.Length - 600)))" }
    $summary = [regex]::Match($dryOut, "# \d+ events?, tailscale_up=(True|False)")
    if (-not $summary.Success) { Fail "Dry run gave no summary line:`n$($dryOut.Substring([Math]::Max(0, $dryOut.Length - 600)))" }
    if ($summary.Groups[1].Value -ne "True") { Fail "Tailscale doesn't look connected ($($summary.Value)). Connect it and re-run." }
    Ok $summary.Value.TrimStart("# ")
}

# ------------------------------------------------------------------ 6. Scheduled task
Step 6 "Scheduled task '$TaskName' (at startup, as SYSTEM)"
$mode = if ($DryRunEnforcement) { "LOG-ONLY enforcement (no firewall changes)" } else { "LIVE enforcement (approved blocks apply)" }
if ($CheckOnly) { Info "Would register and start it in $mode." ; Write-Host ""; Write-Host "Check only: nothing was changed." -ForegroundColor Magenta; exit 0 }
if ($DryRunEnforcement) {
    $launcher = Join-Path $InstallDir "run-dryrun.cmd"
    Set-Content -Encoding ascii -LiteralPath $launcher -Value "@set SOC_ENFORCE_DRY_RUN=1`r`n@`"$venvPyw`" `"$InstallDir\shipper.py`""
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$launcher`"" -WorkingDirectory $InstallDir
} else {
    Remove-Item (Join-Path $InstallDir "run-dryrun.cmd") -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute $venvPyw -Argument "`"$InstallDir\shipper.py`"" -WorkingDirectory $InstallDir
}
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 5
$state = (Get-ScheduledTask -TaskName $TaskName).State
if ($state -ne "Running") { Fail "Task registered but its state is '$state'. Check Task Scheduler > $TaskName > History." }
Ok "Running in $mode."
Write-Host ""
Write-Host "Done. This machine ($($env:COMPUTERNAME.ToLower())) should appear under Devices on the dashboard within a minute." -ForegroundColor Magenta
Write-Host "Manage blocks:  & '$venvPy' '$InstallDir\shipper.py' --list-blocks   |   --unblock <IP>"
