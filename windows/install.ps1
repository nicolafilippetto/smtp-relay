<#
.SYNOPSIS
    Installs and starts the SMTP Relay Windows services.

.DESCRIPTION
    Invoked by the Inno Setup installer (and re-runnable by hand from an
    elevated PowerShell). Idempotent: safe to run again to repair or upgrade
    an existing install. It never overwrites an existing config.env, so the
    encryption keys and the database survive re-installs.

    Everything is logged to <InstallDir>\install-log.txt (with a fallback to
    %TEMP%) so a failed install can always be diagnosed afterwards.

.PARAMETER InstallDir
    Directory holding this script, the WinSW service exes/XMLs and the app\
    bundle. Defaults to the script's own directory.

.PARAMETER DataDir
    Mutable data root. Must match the launcher default (ProgramData).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = $PSScriptRoot,
    [string]$DataDir = (Join-Path $env:ProgramData 'smtp-relay')
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This installer must be run as Administrator.'
    }
}

# Run a native exe, capturing stdout+stderr as text, WITHOUT letting its stderr
# output trigger PowerShell's $ErrorActionPreference='Stop' terminating-error
# behaviour. (Many tools — alembic, WinSW — log informational lines to stderr;
# under 'Stop' that would otherwise abort the whole script.) The caller checks
# $LASTEXITCODE for the real success/failure.
function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        return (& $Exe @Arguments 2>&1)
    } finally {
        $ErrorActionPreference = $prev
    }
}

# Like Invoke-Native but throws if the exit code is non-zero.
function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments, [string]$What)
    Write-Host "  > $Exe $($Arguments -join ' ')"
    $output = Invoke-Native -Exe $Exe -Arguments $Arguments
    $output | ForEach-Object { Write-Host "    $_" }
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (exit code $LASTEXITCODE). See output above."
    }
    return $output
}

# --- Create the data dir, then start logging ---------------------------------
# Only config.env and the data\ subfolder are ACL-locked (done later); the
# directory root, the logs and install-log.txt are left readable. The one-time
# admin password that may appear in install-log.txt must be changed on first
# login anyway, so it is not treated as a durable secret.
try { New-Item -ItemType Directory -Force -Path $DataDir | Out-Null } catch { }

$logFile = Join-Path $DataDir 'install-log.txt'
try {
    Start-Transcript -Path $logFile -Force | Out-Null
} catch {
    $logFile = Join-Path $env:TEMP 'smtp-relay-install-log.txt'
    Start-Transcript -Path $logFile -Force | Out-Null
}
# Remove the install log written by older versions into the program folder, so
# there is only ever one (current) install-log.txt and no confusing leftover.
Remove-Item (Join-Path $InstallDir 'install-log.txt') -Force -ErrorAction SilentlyContinue

$AppExe     = Join-Path $InstallDir 'app\smtp-relay.exe'
$Template   = Join-Path $InstallDir 'config.env.template'
$ConfigPath = Join-Path $DataDir 'config.env'

$Services = @(
    @{ Id = 'smtp-relay-relay'; Winsw = (Join-Path $InstallDir 'smtp-relay-relay.exe') },
    @{ Id = 'smtp-relay-ui';    Winsw = (Join-Path $InstallDir 'smtp-relay-ui.exe') }
)

$tempPassword = $null
try {
    Write-Host '== SMTP Relay installer ==' -ForegroundColor Cyan
    Write-Host "InstallDir: $InstallDir"
    Write-Host "DataDir:    $DataDir"
    Write-Host "Log file:   $logFile"

    Assert-Admin

    if (-not (Test-Path $AppExe))   { throw "Application executable not found at $AppExe" }
    foreach ($svc in $Services) {
        if (-not (Test-Path $svc.Winsw)) { throw "Service wrapper not found at $($svc.Winsw)" }
    }

    # --- 1. Data directory tree ----------------------------------------------
    foreach ($sub in @('data', 'data\archive', 'logs\relay', 'logs\ui')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $DataDir $sub) | Out-Null
    }
    # Re-enable inheritance on the data tree first. This repairs a directory that
    # a previous (buggy) build may have left with a broken ACL that blocked even
    # SYSTEM/Administrators, so the migration below can always open the database.
    # The protective tightening is re-applied at the end (step 8).
    Invoke-Native -Exe 'icacls' -Arguments @((Join-Path $DataDir 'data'), '/reset', '/T', '/C') | Out-Null
    # Remove any stale first-login note so its presence after this run reliably
    # means "a new admin was created this time" (used by the installer to offer
    # opening it only on a fresh install, not on a reinstall).
    Remove-Item (Join-Path $DataDir 'FIRST-LOGIN.txt') -Force -ErrorAction SilentlyContinue
    # NB: the data\ and config.env ACLs are tightened LATER (step 8), AFTER the
    # migration has created/opened the database. Locking them here broke SQLite
    # ("unable to open database file") during migrate.

    # --- 2. Stop / remove existing services (idempotent) ---------------------
    foreach ($svc in $Services) {
        if (Get-Service -Name $svc.Id -ErrorAction SilentlyContinue) {
            Write-Host "Removing existing service $($svc.Id)..."
            Invoke-Native -Exe $svc.Winsw -Arguments @('stop')      | ForEach-Object { Write-Host "    $_" }
            Invoke-Native -Exe $svc.Winsw -Arguments @('uninstall') | ForEach-Object { Write-Host "    $_" }
            Start-Sleep -Seconds 2
        }
    }

    # --- 3. config.env + key generation (only on first install) --------------
    if (-not (Test-Path $ConfigPath)) {
        Write-Host 'Creating config.env and generating secret keys...'
        Copy-Item $Template $ConfigPath
        $generated = Invoke-Native -Exe $AppExe -Arguments @('genkey')
        if ($LASTEXITCODE -ne 0) { throw 'genkey failed; cannot create config.env.' }
        foreach ($line in $generated) {
            if ("$line" -match '^(ENCRYPTION_KEY|SECRET_KEY)=(.*)$') {
                $name = $Matches[1]; $value = $Matches[2]
                (Get-Content $ConfigPath) -replace "^$name=.*$", "$name=$value" |
                    Set-Content $ConfigPath -Encoding UTF8
            }
        }
    } else {
        Write-Host 'Existing config.env found — keeping current keys.'
    }

    # --- 4. Migrate + bootstrap ----------------------------------------------
    Write-Host 'Applying database migrations and bootstrapping admin user...'
    $migrateOutput = Invoke-Native -Exe $AppExe -Arguments @('migrate')
    $migrateOutput | ForEach-Object { Write-Host "    $_" }
    if ($LASTEXITCODE -ne 0) { throw 'Database migration / bootstrap failed.' }

    for ($i = 0; $i -lt $migrateOutput.Count; $i++) {
        if ("$($migrateOutput[$i])" -match 'temporary password') {
            for ($j = $i + 1; $j -lt $migrateOutput.Count; $j++) {
                $cand = "$($migrateOutput[$j])".Trim()
                if ($cand) { $tempPassword = $cand; break }
            }
            break
        }
    }

    # --- 5. Install services (LocalSystem) -----------------------------------
    foreach ($svc in $Services) {
        Write-Host "Installing service $($svc.Id)..."
        Invoke-Checked -Exe $svc.Winsw -Arguments @('install') -What "Service install ($($svc.Id))" | Out-Null
    }

    # --- 6. Firewall rule (SMTP port, LAN only) ------------------------------
    $smtpPort = 2525
    $ruleName = 'SMTP Relay (inbound 2525)'
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "Adding firewall rule for TCP $smtpPort (Private/Domain profiles)..."
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
        -LocalPort $smtpPort -Action Allow -Profile Private,Domain | Out-Null

    # Web UI: allowed from the LAN by default (the app itself rejects any
    # non-private client IP). Restrict to the Private + Domain firewall profiles
    # so it is never opened on a Public network. To keep the panel loopback-only,
    # set SMTP_UI_ALLOW_LAN=0 in config.env and this rule is harmless.
    $uiPort = 8000
    $uiRule = 'SMTP Relay UI (inbound 8000, LAN)'
    Get-NetFirewallRule -DisplayName $uiRule -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "Adding firewall rule for TCP $uiPort (Private/Domain profiles)..."
    New-NetFirewallRule -DisplayName $uiRule -Direction Inbound -Protocol TCP `
        -LocalPort $uiPort -Action Allow -Profile Private,Domain | Out-Null

    # --- 7. Start services + verify ------------------------------------------
    foreach ($svc in $Services) {
        Write-Host "Starting service $($svc.Id)..."
        Invoke-Native -Exe $svc.Winsw -Arguments @('start') | ForEach-Object { Write-Host "    $_" }
    }
    Start-Sleep -Seconds 3

    $allRunning = $true
    foreach ($svc in $Services) {
        $state = (Get-Service -Name $svc.Id -ErrorAction SilentlyContinue).Status
        Write-Host "  $($svc.Id): $state"
        if ($state -ne 'Running') { $allRunning = $false }
    }

    # --- 8. Tighten ACLs (AFTER migrate + services are running) --------------
    # Restrict config.env and the data\ subfolder (keys, database, mail archive)
    # to administrators by REMOVING standard users, without rebuilding the ACL
    # (which broke SQLite). We first convert inherited ACEs to explicit so the
    # removal sticks, then drop BUILTIN\Users (S-1-5-32-545) and Authenticated
    # Users (S-1-5-11). SYSTEM and Administrators keep their existing full
    # access, so the services (LocalSystem) are unaffected. Best-effort.
    Write-Host 'Restricting access to config.env and the data folder...'
    $dataSub = Join-Path $DataDir 'data'
    foreach ($target in @($dataSub, $ConfigPath)) {
        Invoke-Native -Exe 'icacls' -Arguments @($target, '/inheritance:d', '/T', '/C') | Out-Null
        Invoke-Native -Exe 'icacls' -Arguments @(
            $target, '/remove:g', '*S-1-5-32-545', '*S-1-5-11', '/T', '/C'
        ) | Out-Null
    }

    # --- First-login details -------------------------------------------------
    if ($tempPassword) {
        $firstLogin = Join-Path $DataDir 'FIRST-LOGIN.txt'
        @(
            'SMTP Relay - first login',
            '=========================',
            '',
            'Open the admin panel:   http://127.0.0.1:8000',
            'Username:               admin',
            "Temporary password:     $tempPassword",
            '',
            'You will be required to change this password and enrol two-factor',
            'authentication (TOTP) on first login. Delete this file afterwards.'
        ) | Set-Content -Path $firstLogin -Encoding UTF8
    }

    Write-Host ''
    if ($allRunning) {
        Write-Host '== Installation complete — services are running ==' -ForegroundColor Green
    } else {
        Write-Host '== Installation finished, but a service is NOT running ==' -ForegroundColor Yellow
        Write-Host "Check the service logs in $DataDir\logs and $logFile"
    }
    Write-Host 'Admin panel:  http://127.0.0.1:8000'
    Write-Host 'Username:     admin'
    if ($tempPassword) {
        Write-Host "Temp password: $tempPassword" -ForegroundColor Yellow
        Write-Host "(also saved to $(Join-Path $DataDir 'FIRST-LOGIN.txt'))"
    } else {
        Write-Host 'Existing admin user preserved (no new password generated).'
    }
}
catch {
    Write-Host ''
    Write-Host '== Installation FAILED ==' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "Full log: $logFile"
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

try { Stop-Transcript | Out-Null } catch { }
