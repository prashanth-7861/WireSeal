#Requires -Version 5.1
<#
.SYNOPSIS
    WireSeal - Windows setup & launcher

.DESCRIPTION
    Installs prerequisites (Python, WireGuard), creates a virtual environment,
    installs WireSeal and its dependencies, then registers wireseal.cmd in
    C:\Program Files\WireSeal so it is available system-wide.

    Run from an elevated (Administrator) PowerShell prompt:
        Set-ExecutionPolicy Bypass -Scope Process -Force
        .\scripts\install-windows.ps1

.NOTES
    Requires Windows 10 1903+ or Windows 11.
    WireGuard on Windows uses the official kernel driver (wintun).
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoDir   = Split-Path -Parent $PSScriptRoot
$VenvDir   = Join-Path $RepoDir '.venv'
$InstallDir = 'C:\Program Files\WireSeal'

# ---------------------------------------------------------------------------
# Uninstall passthrough - `.\install-windows.ps1 -Uninstall [-Purge] [-Yes]`
# ---------------------------------------------------------------------------
if ($Uninstall) {
    $UninstallScript = Join-Path $PSScriptRoot 'uninstall-windows.ps1'
    if (-not (Test-Path $UninstallScript)) {
        Write-Host "[wireseal] ERROR: uninstall-windows.ps1 not found at $UninstallScript" -ForegroundColor Red
        exit 1
    }
    $args = @()
    if ($Purge) { $args += '-Purge' }
    if ($Yes)   { $args += '-Yes' }
    & $UninstallScript @args
    exit $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# Detect existing install - offer reinstall / uninstall / cancel.
# ---------------------------------------------------------------------------
$WrapperCmdPath = Join-Path $InstallDir 'wireseal.cmd'
if ((Test-Path $WrapperCmdPath) -and (Test-Path $VenvDir)) {
    $installedVer = "unknown"
    try {
        $venvWireseal = Join-Path $VenvDir 'Scripts\wireseal.exe'
        if (Test-Path $venvWireseal) {
            $verOut = & $venvWireseal --version 2>$null
            if ($verOut) { $installedVer = ($verOut -split '\s+')[-1] }
        }
    } catch { }
    Write-Host ""
    Write-Host "[wireseal] Existing install detected (version: $installedVer)." -ForegroundColor Yellow
    Write-Host "  [r] Reinstall (overwrite venv + wrapper, keep vault)"
    Write-Host "  [u] Uninstall (run uninstall-windows.ps1)"
    Write-Host "  [c] Cancel"
    $choice = Read-Host "Choose [r/u/c]"
    switch -Regex ($choice) {
        '^[rR]$' { Write-Host "[wireseal] Proceeding with reinstall..." -ForegroundColor Green }
        '^[uU]$' {
            $UninstallScript = Join-Path $PSScriptRoot 'uninstall-windows.ps1'
            & $UninstallScript
            exit $LASTEXITCODE
        }
        default {
            Write-Host "[wireseal] Cancelled."
            exit 0
        }
    }
}

function Write-Info  { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[wireseal] ERROR: $msg" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# 1. Admin check
# ---------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "Run this script from an elevated (Administrator) PowerShell prompt."
    exit 1
}

Write-Info "Windows $([System.Environment]::OSVersion.Version) - setup starting"

# ---------------------------------------------------------------------------
# 2. Install WireGuard for Windows (official installer via winget)
# ---------------------------------------------------------------------------
$wgPath = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
if (-not (Test-Path $wgPath)) {
    Write-Info "Installing WireGuard for Windows..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id WireGuard.WireGuard --silent --accept-source-agreements --accept-package-agreements
    } else {
        Write-Warn "winget not available. Download WireGuard from https://www.wireguard.com/install/"
        Write-Warn "Install it, then re-run this script."
        exit 1
    }
} else {
    Write-Info "WireGuard already installed: $wgPath"
}

# ---------------------------------------------------------------------------
# 3. Find or install Python 3.12 - 3.14
# ---------------------------------------------------------------------------
$Python = $null
$MinMinor = 12
$MaxMinor = 14

foreach ($candidate in @('python3.14','python3.13','python3.12','python','py')) {
    try {
        $verOutput = & $candidate --version 2>&1
        if ($verOutput -match 'Python 3\.(\d+)') {
            $minor = [int]$Matches[1]
            if ($minor -ge $MinMinor -and $minor -le $MaxMinor) {
                $Python = $candidate
                break
            }
        }
    } catch { }
}

if (-not $Python) {
    Write-Info "Python 3.12-3.14 not found. Installing via winget..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Python.Python.3.13 --silent --accept-source-agreements --accept-package-agreements
        $env:PATH += ";$env:LocalAppData\Programs\Python\Python313"
        $Python = 'python'
    } else {
        Write-Err "Cannot install Python automatically. Download from https://python.org and re-run."
        exit 1
    }
}

$pyVersion = & $Python --version 2>&1
Write-Info "Using Python: $Python ($pyVersion)"

# ---------------------------------------------------------------------------
# 4. Create virtual environment
# ---------------------------------------------------------------------------
if (-not (Test-Path $VenvDir)) {
    Write-Info "Creating virtual environment at $VenvDir ..."
    & $Python -m venv $VenvDir
}

$VenvPip    = Join-Path $VenvDir 'Scripts\pip.exe'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'

# ---------------------------------------------------------------------------
# 5. Install Python dependencies
# ---------------------------------------------------------------------------
Write-Info "Installing Python dependencies (this may take a minute)..."
& $VenvPip install --quiet --upgrade pip
& $VenvPip install --quiet -r (Join-Path $RepoDir 'requirements-dev.txt')
& $VenvPip install --quiet -e $RepoDir

# Locate the installed wireseal entry-point script
$WireSealExe = Join-Path $VenvDir 'Scripts\wireseal.exe'
if (-not (Test-Path $WireSealExe)) {
    # Fallback: use python -m invocation via wrapper
    $WireSealExe = $null
}

# ---------------------------------------------------------------------------
# 6. Install system-wide CMD wrapper
# ---------------------------------------------------------------------------
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

$WrapperCmd = Join-Path $InstallDir 'wireseal.cmd'
if ($WireSealExe) {
    Set-Content -Path $WrapperCmd -Value "@echo off`r`n`"$WireSealExe`" %*"
} else {
    Set-Content -Path $WrapperCmd -Value "@echo off`r`n`"$VenvPython`" -m wireseal.main %*"
}
Write-Info "Installed wrapper: $WrapperCmd"

# Add to system PATH if not already present
$SysPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
if ($SysPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable('PATH', "$SysPath;$InstallDir", 'Machine')
    $env:PATH += ";$InstallDir"
    Write-Info "Added $InstallDir to system PATH (restart terminal to pick up)"
}

# ---------------------------------------------------------------------------
# 7. Windows Firewall - deferred to runtime
#
# We previously pre-opened UDP 51820 here, but that hardcoded the port and
# left a stale rule behind when the user picked a different one at vault
# init. Firewall management is now owned by the platform adapter:
# `wireseal init` (or `wireseal serve`) reads the chosen port from the
# unlocked vault and creates/updates `wireseal-wg0-in` accordingly.
# ---------------------------------------------------------------------------
Write-Info "Firewall rule will be added by 'wireseal init' using your chosen port."

# ---------------------------------------------------------------------------
# 8. Run self-test
# ---------------------------------------------------------------------------
Write-Info "Running unit tests to verify installation..."
$PytestExe = Join-Path $VenvDir 'Scripts\pytest.exe'
& $PytestExe --tb=short -q -m 'not integration' $RepoDir 2>&1 | Select-Object -Last 5

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Info "WireSeal installed successfully."
Write-Host ""
Write-Host "  Open a NEW Administrator PowerShell or CMD, then:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Initialize server:     wireseal init --subnet 10.0.0.1/24 --port 51820"
Write-Host "  Add a client:          wireseal add-client alice"
Write-Host "  Show QR (for iPhone):  wireseal show-qr alice"
Write-Host "  List clients:          wireseal list-clients"
Write-Host "  Check status:          wireseal status"
Write-Host ""
Write-Host "Note: WireGuard on Windows uses the Tunnel Service (wintun driver)."
Write-Host "      The 'wireseal init' command will create and register the tunnel."
Write-Host ""
