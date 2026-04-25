#Requires -Version 5.1
<#
.SYNOPSIS
    WireSeal - Windows uninstaller (PowerShell venv install)

.DESCRIPTION
    Counterpart to install-windows.ps1. Removes:
      * Wrapper:           C:\Program Files\WireSeal\wireseal.cmd
      * Install dir:       C:\Program Files\WireSeal
      * Virtualenv:        <repo>\.venv
      * Firewall rule:     WireSeal-WireGuard-UDP-51820
      * Tunnel service:    WireGuardTunnel$wg0 (sc stop + wireguard.exe /uninstalltunnelservice)
      * PATH entry:        C:\Program Files\WireSeal

    With -Purge, also removes the vault data dir at %APPDATA%\WireSeal.

    Run from an elevated PowerShell prompt:
        Set-ExecutionPolicy Bypass -Scope Process -Force
        .\scripts\uninstall-windows.ps1
        .\scripts\uninstall-windows.ps1 -Purge -Yes

.NOTES
    For users who installed via the WireSeal-x64-Setup.exe (NSIS) installer,
    use Add/Remove Programs or the bundled uninstall.exe instead - that path
    is owned by the installer.
#>

param(
    [switch]$Purge,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoDir    = Split-Path -Parent $PSScriptRoot
$VenvDir    = Join-Path $RepoDir '.venv'
$InstallDir = 'C:\Program Files\WireSeal'
$WrapperCmd = Join-Path $InstallDir 'wireseal.cmd'
$FirewallRule = 'WireSeal-WireGuard-UDP-51820'
$TunnelService = 'WireGuardTunnel$wg0'

function Write-Info { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Yellow }
function Write-Err  { param($msg) Write-Host "[wireseal] ERROR: $msg" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Admin check
# ---------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "Run from an elevated (Administrator) PowerShell prompt."
    exit 1
}

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
if (-not $Yes) {
    Write-Host ""
    Write-Warn "This will remove WireSeal from this machine."
    Write-Host "  - Wrapper:        $WrapperCmd"
    Write-Host "  - Install dir:    $InstallDir"
    Write-Host "  - Virtualenv:     $VenvDir"
    Write-Host "  - Firewall rule:  $FirewallRule"
    Write-Host "  - Tunnel service: $TunnelService (if registered)"
    Write-Host "  - PATH entry:     $InstallDir"
    if ($Purge) {
        Write-Warn "  - Vault data:     $env:APPDATA\WireSeal  (-Purge specified)"
    } else {
        Write-Info "  Vault data preserved ($env:APPDATA\WireSeal). Pass -Purge to also delete."
    }
    Write-Host ""
    $ans = Read-Host "Continue? [y/N]"
    if ($ans -notmatch '^[Yy]$') {
        Write-Info "Cancelled."
        exit 0
    }
}

# ---------------------------------------------------------------------------
# Stop + remove WireGuard tunnel service
# ---------------------------------------------------------------------------
$wgPath = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
$svc = Get-Service -Name $TunnelService -ErrorAction SilentlyContinue
if ($svc) {
    Write-Info "Stopping tunnel service: $TunnelService"
    & sc.exe stop $TunnelService 2>$null | Out-Null
    if (Test-Path $wgPath) {
        # Locate the .conf - best-effort; ignore errors.
        $confDir = Join-Path $env:ProgramData 'WireSeal\tunnels'
        $conf = Join-Path $confDir 'wg0.conf'
        if (Test-Path $conf) {
            & $wgPath '/uninstalltunnelservice' 'wg0' 2>$null | Out-Null
        } else {
            & sc.exe delete $TunnelService 2>$null | Out-Null
        }
    } else {
        & sc.exe delete $TunnelService 2>$null | Out-Null
    }
}

# ---------------------------------------------------------------------------
# Remove API background-service Scheduled Task (registered via
# `wireseal service install`).
# ---------------------------------------------------------------------------
$ApiTaskName = 'WireSeal-API'
& schtasks.exe /End    /TN $ApiTaskName 2>$null | Out-Null
& schtasks.exe /Delete /F /TN $ApiTaskName 2>$null | Out-Null
Write-Info "Removed scheduled task: $ApiTaskName (if present)"

# ---------------------------------------------------------------------------
# Remove firewall rule
# ---------------------------------------------------------------------------
if (Get-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -Name $FirewallRule -ErrorAction SilentlyContinue
    Write-Info "Removed firewall rule: $FirewallRule"
}

# ---------------------------------------------------------------------------
# Remove PATH entry
# ---------------------------------------------------------------------------
$SysPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
if ($SysPath -like "*$InstallDir*") {
    $newPath = ($SysPath -split ';' | Where-Object { $_ -and ($_ -ne $InstallDir) }) -join ';'
    [System.Environment]::SetEnvironmentVariable('PATH', $newPath, 'Machine')
    Write-Info "Removed $InstallDir from system PATH"
}

# ---------------------------------------------------------------------------
# Remove install dir + venv
# ---------------------------------------------------------------------------
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Info "Removed install dir: $InstallDir"
}

if (Test-Path $VenvDir) {
    Remove-Item -Recurse -Force $VenvDir -ErrorAction SilentlyContinue
    Write-Info "Removed virtualenv: $VenvDir"
}

# ---------------------------------------------------------------------------
# Optional: remove vault data
# ---------------------------------------------------------------------------
if ($Purge) {
    $VaultDir = Join-Path $env:APPDATA 'WireSeal'
    if (Test-Path $VaultDir) {
        Remove-Item -Recurse -Force $VaultDir -ErrorAction SilentlyContinue
        Write-Info "Removed vault data: $VaultDir"
    }
}

Write-Host ""
Write-Info "WireSeal uninstalled."
if (-not $Purge) {
    Write-Host "  Vault data preserved at $env:APPDATA\WireSeal. Delete manually if no longer needed."
}
Write-Host ""
