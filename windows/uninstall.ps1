<#
.SYNOPSIS
    Stops and removes the SMTP Relay Windows services.

.DESCRIPTION
    Invoked by the Windows uninstaller (and re-runnable by hand from an
    elevated PowerShell). By default it PRESERVES the data directory
    (C:\ProgramData\smtp-relay) because it holds the database, the mail
    archive and the encryption keys. Pass -RemoveData to delete it too.

.PARAMETER InstallDir
    Directory holding the WinSW service exes. Defaults to the script's dir.

.PARAMETER DataDir
    Mutable data root.

.PARAMETER RemoveData
    Also delete the data directory (irreversible — destroys DB + keys).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = $PSScriptRoot,
    [string]$DataDir = (Join-Path $env:ProgramData 'smtp-relay'),
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This uninstaller must be run as Administrator.'
    }
}

Assert-Admin

$Services = @(
    @{ Id = 'smtp-relay-relay'; Winsw = (Join-Path $InstallDir 'smtp-relay-relay.exe') },
    @{ Id = 'smtp-relay-ui';    Winsw = (Join-Path $InstallDir 'smtp-relay-ui.exe') }
)

Write-Host '== SMTP Relay uninstaller ==' -ForegroundColor Cyan

# --- Stop and remove services ------------------------------------------------
foreach ($svc in $Services) {
    if (Get-Service -Name $svc.Id -ErrorAction SilentlyContinue) {
        Write-Host "Removing service $($svc.Id)..."
        & $svc.Winsw stop      | Out-Null
        & $svc.Winsw uninstall | Out-Null
    }
}

# --- Firewall rule -----------------------------------------------------------
foreach ($rule in @('SMTP Relay (inbound 2525)', 'SMTP Relay UI (inbound 8000, LAN)')) {
    Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

# --- Data directory ----------------------------------------------------------
if ($RemoveData) {
    Write-Host "Removing data directory $DataDir (database, archive and keys)..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force -Path $DataDir -ErrorAction SilentlyContinue
} else {
    Write-Host "Data directory preserved: $DataDir" -ForegroundColor Green
    Write-Host '(Delete it manually, or re-run with -RemoveData, to erase the database and keys.)'
}

Write-Host '== Uninstall complete ==' -ForegroundColor Green
