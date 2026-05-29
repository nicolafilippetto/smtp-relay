<#
.SYNOPSIS
    Start / stop / restart / show the SMTP Relay services. Backs the Start-Menu
    shortcuts created by the installer.

.DESCRIPTION
    Self-elevating: starting/stopping a Windows service needs Administrator
    rights, so the script relaunches itself elevated (a UAC prompt appears) if
    not already elevated.

.PARAMETER Action
    start | stop | restart | status (default: status).
#>
[CmdletBinding()]
param(
    [ValidateSet('start', 'stop', 'restart', 'status')]
    [string]$Action = 'status'
)

$services = @('smtp-relay-relay', 'smtp-relay-ui')

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 'status' is read-only and does not require elevation. The others do.
if ($Action -ne 'status' -and -not (Test-Admin)) {
    $psi = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action $Action"
    Start-Process -FilePath 'powershell.exe' -ArgumentList $psi -Verb RunAs
    return
}

switch ($Action) {
    'start'   { foreach ($s in $services) { Start-Service  $s -ErrorAction SilentlyContinue } }
    'stop'    { foreach ($s in $services) { Stop-Service   $s -ErrorAction SilentlyContinue } }
    'restart' { foreach ($s in $services) { Restart-Service $s -ErrorAction SilentlyContinue } }
}

Write-Host ''
Write-Host 'SMTP Relay services:' -ForegroundColor Cyan
foreach ($s in $services) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host ("  {0,-18} {1}" -f $svc.Name, $svc.Status)
    } else {
        Write-Host ("  {0,-18} NOT INSTALLED" -f $s) -ForegroundColor Yellow
    }
}
Write-Host ''
Write-Host 'Admin panel: http://127.0.0.1:8000'
Write-Host ''
Write-Host 'Press any key to close...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
