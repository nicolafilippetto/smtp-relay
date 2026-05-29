<#
.SYNOPSIS
    Installs and starts the SMTP Relay Windows services.

.DESCRIPTION
    Invoked by the Inno Setup installer (and re-runnable by hand from an
    elevated PowerShell). Idempotent: safe to run again to repair or upgrade
    an existing install. It never overwrites an existing config.env, so the
    encryption keys and the database survive re-installs.

    Everything is logged to <DataDir>\install-log.txt so a failed install can
    be diagnosed afterwards.

    Steps:
      1. Stop/remove any existing services.
      2. Create the data/log directory tree under C:\ProgramData\smtp-relay.
      3. Create config.env (from template) and generate the secret keys — once.
      4. Run database migrations and bootstrap the admin user.
      5. Install both Windows services (LocalSystem account).
      6. Add a firewall rule for the SMTP port (LAN only).
      7. Start the services, verify they are running, print first-login details.

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

# Run an external command and fail loudly if it returns a non-zero exit code.
# ($ErrorActionPreference='Stop' does NOT catch native exe failures.)
function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments, [string]$What)
    Write-Host "  > $Exe $($Arguments -join ' ')"
    $output = & $Exe @Arguments 2>&1
    $output | ForEach-Object { Write-Host "    $_" }
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (exit code $LASTEXITCODE). See output above."
    }
    return $output
}

function Pause-IfInteractive {
    if ([Environment]::UserInteractive) {
        Write-Host ''
        Write-Host 'Press any key to close this window...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}

Assert-Admin

$AppExe     = Join-Path $InstallDir 'app\smtp-relay.exe'
$Template   = Join-Path $InstallDir 'config.env.template'
$ConfigPath = Join-Path $DataDir 'config.env'

$Services = @(
    @{ Id = 'smtp-relay-relay'; Winsw = (Join-Path $InstallDir 'smtp-relay-relay.exe') },
    @{ Id = 'smtp-relay-ui';    Winsw = (Join-Path $InstallDir 'smtp-relay-ui.exe') }
)

# Make sure the data + log tree exists before we start the transcript there.
foreach ($sub in @('data', 'data\archive', 'logs\relay', 'logs\ui')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $DataDir $sub) | Out-Null
}

$logFile = Join-Path $DataDir 'install-log.txt'
Start-Transcript -Path $logFile -Force | Out-Null

$tempPassword = $null
try {
    Write-Host '== SMTP Relay installer ==' -ForegroundColor Cyan
    Write-Host "InstallDir: $InstallDir"
    Write-Host "DataDir:    $DataDir"

    if (-not (Test-Path $AppExe))   { throw "Application executable not found at $AppExe" }
    foreach ($svc in $Services) {
        if (-not (Test-Path $svc.Winsw)) { throw "Service wrapper not found at $($svc.Winsw)" }
    }

    # --- 1. Stop / remove existing services (idempotent) ---------------------
    foreach ($svc in $Services) {
        if (Get-Service -Name $svc.Id -ErrorAction SilentlyContinue) {
            Write-Host "Removing existing service $($svc.Id)..."
            & $svc.Winsw stop      2>&1 | ForEach-Object { Write-Host "    $_" }
            & $svc.Winsw uninstall 2>&1 | ForEach-Object { Write-Host "    $_" }
            Start-Sleep -Seconds 2
        }
    }

    # --- 2. config.env + key generation (only on first install) --------------
    if (-not (Test-Path $ConfigPath)) {
        Write-Host 'Creating config.env and generating secret keys...'
        Copy-Item $Template $ConfigPath
        $generated = & $AppExe genkey
        if ($LASTEXITCODE -ne 0) { throw 'genkey failed; cannot create config.env.' }
        foreach ($line in $generated) {
            if ($line -match '^(ENCRYPTION_KEY|SECRET_KEY)=(.*)$') {
                $name = $Matches[1]; $value = $Matches[2]
                (Get-Content $ConfigPath) -replace "^$name=.*$", "$name=$value" |
                    Set-Content $ConfigPath -Encoding UTF8
            }
        }
    } else {
        Write-Host 'Existing config.env found — keeping current keys.'
    }

    # --- 3. Migrate + bootstrap ----------------------------------------------
    Write-Host 'Applying database migrations and bootstrapping admin user...'
    $migrateOutput = & $AppExe migrate 2>&1
    $migrateOutput | ForEach-Object { Write-Host "    $_" }
    if ($LASTEXITCODE -ne 0) { throw 'Database migration / bootstrap failed.' }

    for ($i = 0; $i -lt $migrateOutput.Count; $i++) {
        if ($migrateOutput[$i] -match 'temporary password') {
            for ($j = $i + 1; $j -lt $migrateOutput.Count; $j++) {
                $cand = ($migrateOutput[$j] -as [string]).Trim()
                if ($cand) { $tempPassword = $cand; break }
            }
            break
        }
    }

    # --- 4. Install services (LocalSystem) -----------------------------------
    foreach ($svc in $Services) {
        Write-Host "Installing service $($svc.Id)..."
        Invoke-Checked -Exe $svc.Winsw -Arguments @('install') -What "Service install ($($svc.Id))" | Out-Null
    }

    # --- 5. Firewall rule (SMTP port, LAN only) ------------------------------
    $smtpPort = 2525
    $ruleName = 'SMTP Relay (inbound 2525)'
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "Adding firewall rule for TCP $smtpPort (Private/Domain profiles)..."
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
        -LocalPort $smtpPort -Action Allow -Profile Private,Domain | Out-Null
    # The web UI binds to 127.0.0.1 only, so it needs no firewall rule.

    # --- 6. Start services + verify ------------------------------------------
    foreach ($svc in $Services) {
        Write-Host "Starting service $($svc.Id)..."
        & $svc.Winsw start 2>&1 | ForEach-Object { Write-Host "    $_" }
    }
    Start-Sleep -Seconds 3

    $allRunning = $true
    foreach ($svc in $Services) {
        $state = (Get-Service -Name $svc.Id -ErrorAction SilentlyContinue).Status
        Write-Host "  $($svc.Id): $state"
        if ($state -ne 'Running') { $allRunning = $false }
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
    Write-Host "== Installation FAILED ==" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "Full log: $logFile"
    Stop-Transcript | Out-Null
    Pause-IfInteractive
    exit 1
}

Stop-Transcript | Out-Null
Pause-IfInteractive
