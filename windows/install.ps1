<#
.SYNOPSIS
    Installs and starts the SMTP Relay Windows services.

.DESCRIPTION
    Invoked by the Inno Setup installer (and re-runnable by hand from an
    elevated PowerShell). Idempotent: safe to run again to repair or upgrade
    an existing install. It never overwrites an existing config.env, so the
    encryption keys and the database survive re-installs.

    Steps:
      1. Stop/remove any existing services.
      2. Create the data/log directory tree under C:\ProgramData\smtp-relay.
      3. Create config.env (from template) and generate the secret keys — once.
      4. Run database migrations and bootstrap the admin user.
      5. Install both Windows services (low-privilege per-service accounts).
      6. Lock down the data directory ACLs.
      7. Add a firewall rule for the SMTP port (LAN only).
      8. Start the services and print the first-login details.

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

Assert-Admin

$AppExe      = Join-Path $InstallDir 'app\smtp-relay.exe'
$Template    = Join-Path $InstallDir 'config.env.template'
$ConfigPath  = Join-Path $DataDir 'config.env'

$Services = @(
    @{ Id = 'smtp-relay-relay'; Winsw = (Join-Path $InstallDir 'smtp-relay-relay.exe') },
    @{ Id = 'smtp-relay-ui';    Winsw = (Join-Path $InstallDir 'smtp-relay-ui.exe') }
)

if (-not (Test-Path $AppExe)) { throw "Application executable not found at $AppExe" }

Write-Host '== SMTP Relay installer ==' -ForegroundColor Cyan

# --- 1. Stop / remove existing services (idempotent) -------------------------
foreach ($svc in $Services) {
    if (Get-Service -Name $svc.Id -ErrorAction SilentlyContinue) {
        Write-Host "Removing existing service $($svc.Id)..."
        & $svc.Winsw stop   | Out-Null
        & $svc.Winsw uninstall | Out-Null
        Start-Sleep -Seconds 2
    }
}

# --- 2. Data directory tree --------------------------------------------------
foreach ($sub in @('data', 'data\archive', 'logs\relay', 'logs\ui')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $DataDir $sub) | Out-Null
}

# --- 3. config.env + key generation (only on first install) ------------------
if (-not (Test-Path $ConfigPath)) {
    Write-Host 'Creating config.env and generating secret keys...'
    Copy-Item $Template $ConfigPath
    $generated = & $AppExe genkey
    foreach ($line in $generated) {
        if ($line -match '^(ENCRYPTION_KEY|SECRET_KEY)=(.*)$') {
            $name = $Matches[1]; $value = $Matches[2]
            # Replace the empty placeholder line with the generated value.
            (Get-Content $ConfigPath) `
                -replace "^$name=.*$", "$name=$value" `
                | Set-Content $ConfigPath -Encoding UTF8
        }
    }
} else {
    Write-Host 'Existing config.env found — keeping current keys.'
}

# --- 4. Migrate + bootstrap --------------------------------------------------
Write-Host 'Applying database migrations and bootstrapping admin user...'
$migrateOutput = & $AppExe migrate 2>&1
$migrateOutput | ForEach-Object { Write-Host "  $_" }

# Capture the one-time admin password printed on a fresh database.
$tempPassword = $null
for ($i = 0; $i -lt $migrateOutput.Count; $i++) {
    if ($migrateOutput[$i] -match 'temporary password') {
        # The password is on the following non-empty, indented line.
        for ($j = $i + 1; $j -lt $migrateOutput.Count; $j++) {
            $cand = ($migrateOutput[$j] -as [string]).Trim()
            if ($cand) { $tempPassword = $cand; break }
        }
        break
    }
}

# --- 5. Install services -----------------------------------------------------
foreach ($svc in $Services) {
    Write-Host "Installing service $($svc.Id)..."
    & $svc.Winsw install | Out-Null
}

# --- 6. Lock down data directory ACLs ----------------------------------------
# Both services share the same SQLite database, so BOTH per-service accounts
# need write access to data and logs. Grant Modify with inheritance.
Write-Host 'Setting data directory permissions...'
foreach ($svc in $Services) {
    foreach ($dir in @((Join-Path $DataDir 'data'), (Join-Path $DataDir 'logs'))) {
        & icacls $dir /grant "NT SERVICE\$($svc.Id):(OI)(CI)M" /T /C | Out-Null
    }
}

# --- 7. Firewall rule (SMTP port, LAN only) ----------------------------------
$smtpPort = 2525
$ruleName = 'SMTP Relay (inbound 2525)'
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host "Adding firewall rule for TCP $smtpPort (Private/Domain profiles)..."
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
    -LocalPort $smtpPort -Action Allow -Profile Private,Domain | Out-Null
# The web UI binds to 127.0.0.1 only, so it needs no firewall rule.

# --- 8. Start services -------------------------------------------------------
foreach ($svc in $Services) {
    Write-Host "Starting service $($svc.Id)..."
    & $svc.Winsw start | Out-Null
}

# --- First-login details -----------------------------------------------------
$firstLogin = Join-Path $DataDir 'FIRST-LOGIN.txt'
if ($tempPassword) {
    @(
        'SMTP Relay — first login',
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
Write-Host '== Installation complete ==' -ForegroundColor Green
Write-Host 'Admin panel:  http://127.0.0.1:8000'
Write-Host 'Username:     admin'
if ($tempPassword) {
    Write-Host "Temp password: $tempPassword" -ForegroundColor Yellow
    Write-Host "(also saved to $firstLogin)"
} else {
    Write-Host 'Existing admin user preserved (no new password generated).'
}
