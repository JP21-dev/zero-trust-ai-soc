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
    5. Installs or updates Microsoft Sysmon (asks first), and turns on the Windows audit
       logging the rules read: failed logins, account and group changes, new
       scheduled tasks.
    6. Does one dry run (prints a batch, sends nothing).
    7. Registers the "SOCShipper" scheduled task: at startup, as SYSTEM, and starts it
       now. The task runs agent_launcher.py, which keeps the agent running and installs
       or rolls back self-updates you approved with your passkey.

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
    [switch]$SkipSysmon,
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

function Step($n, $text) { Write-Host ""; Write-Host "[$n/7] $text" -ForegroundColor Magenta }
function Ok($text)   { Write-Host "  OK  $text" -ForegroundColor Green }
function Info($text) { Write-Host "      $text" }
function Fail($text) { Write-Host "  !!  $text" -ForegroundColor Red; exit 1 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $CheckOnly -and -not $isAdmin) {
    Fail "Run this from an elevated PowerShell (right-click PowerShell > Run as administrator)."
}
$agentFiles = "shipper.py", "enforcer.py", "sysmon.py", "winlog.py", "updater.py", "agent_launcher.py", "sysmon-config.xml", "requirements.txt"
foreach ($f in $agentFiles) {
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
    Info "Would copy $($agentFiles -join ', ') and build a venv."
    Info ("Existing install: " + $(if (Test-Path $venvPy) { "yes (will be updated)" } else { "no" }))
    Info ("Scheduled task '$TaskName': " + $(if ($task) { $task.State } else { "not registered" }))
} else {
    if ($task -and $task.State -eq "Running") { Stop-ScheduledTask -TaskName $TaskName; Info "Stopped the running task for the update." }
    # The agent runs as a child of the launcher; make sure no copy outlives the task.
    $venvDir = (Join-Path $InstallDir ".venv").ToLower()
    Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'pythonw.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and $_.ExecutablePath.ToLower().StartsWith($venvDir) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
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
    Copy-Item ($agentFiles | ForEach-Object { Join-Path $here $_ }) $InstallDir -Force -ErrorAction Stop
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
# This machine's endpoint id, exactly as the shipper computes it (lower-case hostname).
$epId = if (Test-Path $venvPy) {
    (& $venvPy -c "import os,re,socket;print(re.sub(r'[^A-Za-z0-9._-]','-',(os.environ.get('SOC_ENDPOINT_ID') or socket.gethostname()).lower())[:64])").Trim()
} else { ($env:COMPUTERNAME.ToLower() -replace '[^a-z0-9._-]', '-') }
$onHubBox = Test-Path (Join-Path (Split-Path -Parent $here) "secrets\action_signing_secret.txt")
function Test-EndpointToken($t) { return ($t -match '^(.+)\.[A-Za-z0-9_-]{43}$') -and ($Matches[1] -eq $epId) }
if ($CheckOnly) {
    Info "Endpoint id: $epId"
    Info ("Token: " + $(if ($TokenFile) { $TokenFile } elseif ($onHubBox) { "would issue a per-endpoint token from the Hub container" }
                        elseif (Test-Path $tokenDest) { "keep existing $tokenDest" } else { "would ask you to paste a per-endpoint token" }))
} else {
    New-Item -ItemType Directory -Force -Path $StateDir -ErrorAction Stop | Out-Null
    $token = $null
    if ($TokenFile) {
        $token = (Get-Content -Raw -LiteralPath $TokenFile).Trim()
    } elseif ($onHubBox) {
        # On the Hub: mint this machine's own token inside the container (needs Docker).
        $issued = (& docker exec soc-orchestrator python -m app.tokens issue $epId 2>$null | Select-Object -Last 1)
        if ($LASTEXITCODE -eq 0 -and $issued) { $token = "$issued".Trim(); Info "Issued a per-endpoint token for $epId." }
        else { Info "Couldn't issue a token from the Hub container (is it running?). Falling back." }
    }
    if (-not $token -and (Test-Path $tokenDest)) {
        $existing = (Get-Content -Raw -LiteralPath $tokenDest).Trim()
        if (Test-EndpointToken $existing) { $token = $existing; Info "Keeping the existing per-endpoint token." }
    }
    if (-not $token) {
        Info "On the Hub, run:  docker exec soc-orchestrator python -m app.tokens issue $epId"
        $sec = Read-Host "  Paste the token it prints" -AsSecureString
        $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)).Trim()
    }
    if ($token.Length -lt 32) { Fail "That token is too short." }
    if ($token.Contains(".")) {
        if (-not (Test-EndpointToken $token)) { Fail "That token was issued for a different machine; it must start with '$epId.'" }
    } else {
        Info "Note: that's the old shared token. It works until the Hub enables strict tokens; issue a per-endpoint one soon."
    }
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
    # On the Hub itself (detected by this project's .env), the shipper also reports Tailscale
    # presence so the Hub can tell "asleep" from "agent stopped" for every endpoint.
    $onHub = [bool]($envVals["TAILSCALE_IP"] -match '^100\.\d+\.\d+\.\d+$')
    $reportPresence = $onHub -or [bool]($saved -and $saved.report_presence)
    @{ hub_url = $HubUrl; hub_key_url = $HubKeyUrl; report_presence = $reportPresence } |
        ConvertTo-Json | Set-Content -Encoding ascii -LiteralPath $configPath -ErrorAction Stop
    Ok ("Config saved: $HubUrl" + $(if ($reportPresence) { " (reports Tailscale presence: this is the Hub)" } else { "" }))
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
    $pk = [regex]::Match($out, "Pinned (\d+) passkey").Groups[1].Value
    if ($pk -and [int]$pk -gt 0) { Ok "Pinned $pk passkey(s): self-updates need one of them to approve." }
    else { Info "Warning: no passkeys pinned, so self-updates stay off here. Enroll a passkey on the Hub, then re-run this." }
}

# ------------------------------------------------------------------ 5. Sysmon
Step 5 "Microsoft Sysmon and Windows audit logging"
$sysmonCfg = Join-Path $InstallDir "sysmon-config.xml"
$svc = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
$installedExe = if ($svc) { Join-Path $env:windir ($svc.Name + ".exe") } else { $null }
if ($SkipSysmon) {
    Info "Skipped (-SkipSysmon). Only network connections are watched on this machine."
} elseif ($CheckOnly) {
    Info $(if ($svc) { "Sysmon is installed ($($svc.Name)); would update its config." }
           else { "Would download Sysmon from Microsoft (download.sysinternals.com), check Microsoft's signature, and install it." })
} elseif ($svc -and (Test-Path $installedExe)) {
    & $installedExe -c $sysmonCfg | Out-Null
    if ($LASTEXITCODE) { Fail "Sysmon is installed but rejected the config (exit $LASTEXITCODE)." }
    Ok "Sysmon already installed ($($svc.Name), $($svc.Status)); config updated."
} else {
    Info "Sysmon is a free Microsoft Sysinternals tool that records program launches, new files, auto-start"
    Info "changes and more. Installing it downloads Sysmon.zip from download.sysinternals.com and accepts the"
    Info "Sysinternals license: https://learn.microsoft.com/sysinternals/license-terms"
    $ans = Read-Host "  Download and install Sysmon now? [Y/n]"
    if ($ans -match '^[Nn]') {
        Info "Skipped. Re-run later (or pass -SkipSysmon) to stop being asked."
    } else {
        $tmp = Join-Path $env:TEMP ("sysmon-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tmp -ErrorAction Stop | Out-Null
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
                -OutFile (Join-Path $tmp "Sysmon.zip") -ErrorAction Stop
            Expand-Archive -LiteralPath (Join-Path $tmp "Sysmon.zip") -DestinationPath $tmp -Force -ErrorAction Stop
            $exe = Join-Path $tmp $(if ([Environment]::Is64BitOperatingSystem) { "Sysmon64.exe" } else { "Sysmon.exe" })
            $sig = Get-AuthenticodeSignature -LiteralPath $exe
            if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
                Fail "Downloaded Sysmon is NOT validly signed by Microsoft ($($sig.Status)); not installing it."
            }
            Info "Signature verified: $($sig.SignerCertificate.Subject -replace ',.*$', '')"
            & $exe -accepteula -i $sysmonCfg | Out-Null
            if ($LASTEXITCODE) { Fail "Sysmon install failed (exit $LASTEXITCODE)." }
            Ok "Sysmon installed with the SOC config."
        } catch {
            Fail "Couldn't download or install Sysmon: $($_.Exception.Message)"
        } finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
# Windows' own audit log: what the failed-login, new-account/admin and new-task rules read.
# By GUID, because the category names are translated on non-English Windows.
$audit = @(
    @("Logon (failures)",          "{0CCE9215-69AE-11D9-BED3-505054503030}", "/failure:enable"),
    @("User account management",   "{0CCE9235-69AE-11D9-BED3-505054503030}", "/success:enable"),
    @("Security group management", "{0CCE9237-69AE-11D9-BED3-505054503030}", "/success:enable"),
    @("Scheduled tasks (other object access)", "{0CCE9227-69AE-11D9-BED3-505054503030}", "/success:enable")
)
if ($CheckOnly) {
    Info ("Would turn on Windows audit logging for: " + (($audit | ForEach-Object { $_[0] }) -join ", ") + ".")
} else {
    $failed = @()
    foreach ($a in $audit) {
        & auditpol.exe /set "/subcategory:$($a[1])" $a[2] | Out-Null
        if ($LASTEXITCODE) { $failed += $a[0] }
    }
    if ($failed) { Info "Warning: couldn't turn on audit logging for $($failed -join ', ') (a Group Policy may manage it)." }
    else { Ok ("Audit logging on: " + (($audit | ForEach-Object { $_[0] }) -join ", ") + ".") }
}

# ------------------------------------------------------------------ 6. Dry run
Step 6 "Dry run (reads connections, sends nothing)"
if ($CheckOnly) { Info "Would run: shipper.py --dry-run" }
else {
    # The batch goes to stdout and the summary line ("# N events, tailscale_up=...") to
    # stderr; merged, their order isn't guaranteed, so search all of it for the summary.
    $dryOut = (& $venvPy (Join-Path $InstallDir "shipper.py") --dry-run 2>&1 | ForEach-Object { "$_" }) -join "`n"
    if ($LASTEXITCODE) { Fail "Dry run failed:`n$($dryOut.Substring([Math]::Max(0, $dryOut.Length - 600)))" }
    $summary = [regex]::Match($dryOut, "# \d+ events?, tailscale_up=(True|False)(, sysmon=\w+)?(, winlog=[\w:,]+)?")
    if (-not $summary.Success) { Fail "Dry run gave no summary line:`n$($dryOut.Substring([Math]::Max(0, $dryOut.Length - 600)))" }
    if ($summary.Groups[1].Value -ne "True") { Fail "Tailscale doesn't look connected ($($summary.Value)). Connect it and re-run." }
    Ok $summary.Value.TrimStart("# ")
    if (-not $SkipSysmon -and $summary.Value -match "sysmon=unreadable") {
        Info "Warning: Sysmon's event log isn't readable yet; file/process events will start once it is."
    }
    if ($summary.Value -match "winlog=[\w:,]*unreadable") {
        Info "Note: some Windows logs aren't readable from this PowerShell; the scheduled task runs as SYSTEM, which can read them."
    }
}

# ------------------------------------------------------------------ 7. Scheduled task
Step 7 "Scheduled task '$TaskName' (at startup, as SYSTEM)"
$mode = if ($DryRunEnforcement) { "LOG-ONLY enforcement (no firewall changes)" } else { "LIVE enforcement (approved blocks apply)" }
if ($CheckOnly) { Info "Would register and start it in $mode." ; Write-Host ""; Write-Host "Check only: nothing was changed." -ForegroundColor Magenta; exit 0 }
if ($DryRunEnforcement) {
    $launcher = Join-Path $InstallDir "run-dryrun.cmd"
    Set-Content -Encoding ascii -LiteralPath $launcher -Value "@set SOC_ENFORCE_DRY_RUN=1`r`n@`"$venvPyw`" `"$InstallDir\agent_launcher.py`""
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$launcher`"" -WorkingDirectory $InstallDir
} else {
    Remove-Item (Join-Path $InstallDir "run-dryrun.cmd") -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute $venvPyw -Argument "`"$InstallDir\agent_launcher.py`"" -WorkingDirectory $InstallDir
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
