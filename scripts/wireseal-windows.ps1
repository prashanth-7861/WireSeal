#Requires -Version 5.1
<#
.SYNOPSIS
    WireSeal - Windows one-liner installer

.DESCRIPTION
    Downloads source, installs deps, configures firewall, sets up the app.

.NOTES
    Usage (run in Administrator PowerShell):
        irm https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-windows.ps1 | iex

    Or download and run:
        Invoke-WebRequest -Uri https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-windows.ps1 -OutFile wireseal-windows.ps1
        .\wireseal-windows.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Version     = "0.3.7"
$Repo        = "https://github.com/prashanth-7861/WireSeal.git"
$InstallDir  = "$env:ProgramFiles\WireSeal"
$VenvDir     = Join-Path $InstallDir '.venv'
$MinMinor    = 12
$MaxMinor    = 14

function Write-Info  { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[wireseal] $msg" -ForegroundColor Red; exit 1 }

# ── Admin check ───────────────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Run this script from an elevated (Administrator) PowerShell prompt."
}

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  WireSeal v$Version - Secure WireGuard Management" -ForegroundColor Cyan
Write-Host "  Platform: Windows $([System.Environment]::OSVersion.Version)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# ── Install WireGuard ─────────────────────────────────────────────────────
$wgPath = Join-Path $env:ProgramFiles 'WireGuard\wireguard.exe'
if (-not (Test-Path $wgPath)) {
    Write-Info "Installing WireGuard..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id WireGuard.WireGuard --silent --accept-source-agreements --accept-package-agreements
    } else {
        Write-Warn "winget not available. Download WireGuard from https://www.wireguard.com/install/"
        Write-Warn "Install it manually, then re-run this script."
        exit 1
    }
    Write-Ok "WireGuard installed."
} else {
    Write-Ok "WireGuard already installed."
}

# ── Install Git ───────────────────────────────────────────────────────────
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Info "Installing Git..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Git.Git --silent --accept-source-agreements --accept-package-agreements
        $env:PATH += ";$env:ProgramFiles\Git\cmd"
    } else {
        Write-Fail "Git not found and winget unavailable. Install Git from https://git-scm.com"
    }
    Write-Ok "Git installed."
} else {
    Write-Ok "Git already installed."
}

# ── Find or install Python ────────────────────────────────────────────────
$Python = $null
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
        $env:PATH += ";$env:LocalAppData\Programs\Python\Python313;$env:LocalAppData\Programs\Python\Python313\Scripts"
        $Python = 'python'
    } else {
        Write-Fail "Cannot install Python automatically. Download from https://python.org and re-run."
    }
}

$pyVersion = & $Python --version 2>&1
Write-Ok "Using Python: $Python ($pyVersion)"

# ── Clone or update repo ──────────────────────────────────────────────────
if (Test-Path (Join-Path $InstallDir '.git')) {
    Write-Info "Updating existing installation..."
    git -C $InstallDir pull --ff-only 2>&1 | Out-Null
} else {
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
    }
    Write-Info "Cloning WireSeal to $InstallDir..."
    git clone --depth 1 $Repo $InstallDir
}
Write-Ok "Source code ready."

# ── Create venv + install deps ────────────────────────────────────────────
if (-not (Test-Path $VenvDir)) {
    Write-Info "Creating virtual environment..."
    & $Python -m venv $VenvDir
}

$VenvPip    = Join-Path $VenvDir 'Scripts\pip.exe'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'

Write-Info "Installing Python dependencies..."
& $VenvPip install --quiet --upgrade pip
& $VenvPip install --quiet -e $InstallDir
& $VenvPip install --quiet pywebview

# Build dashboard if npm available
$DashDist = Join-Path $InstallDir 'Dashboard\dist'
if (-not (Test-Path $DashDist)) {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Info "Building dashboard..."
        Push-Location (Join-Path $InstallDir 'Dashboard')
        npm ci --silent 2>&1 | Out-Null
        npm run build --silent 2>&1 | Out-Null
        Pop-Location
    } else {
        Write-Warn "npm not found - dashboard will use pre-built files if available."
    }
}
Write-Ok "Python dependencies installed."

# ── Create system-wide launchers ──────────────────────────────────────────
$WrapperDir = Join-Path $env:ProgramFiles 'WireSeal\bin'
if (-not (Test-Path $WrapperDir)) {
    New-Item -ItemType Directory -Path $WrapperDir -Force | Out-Null
}

# CLI launcher
$CliWrapper = Join-Path $WrapperDir 'wireseal.cmd'
Set-Content -Path $CliWrapper -Value "@echo off`r`n`"$VenvPython`" -m wireseal.main %*"

# GUI launcher
$GuiWrapper = Join-Path $WrapperDir 'wireseal-gui.cmd'
$guiPyCmd = "$VenvPython -c `"import sys; sys.path.insert(0, r'$InstallDir\src'); from wireseal.api import serve; serve()`""
Set-Content -Path $GuiWrapper -Value "@echo off`r`n$guiPyCmd"

# Add to system PATH
$SysPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
if ($SysPath -notlike "*$WrapperDir*") {
    [System.Environment]::SetEnvironmentVariable('PATH', "$SysPath;$WrapperDir", 'Machine')
    $env:PATH += ";$WrapperDir"
    Write-Ok "Added $WrapperDir to system PATH."
}
Write-Ok "Installed: wireseal.cmd (CLI)"
Write-Ok "Installed: wireseal-gui.cmd (Desktop GUI)"

# ── Windows Firewall ──────────────────────────────────────────────────────
$RuleName = 'WireSeal-WireGuard-UDP-51820'
if (-not (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $RuleName `
        -DisplayName 'WireSeal WireGuard (UDP 51820)' `
        -Direction Inbound `
        -Protocol UDP `
        -LocalPort 51820 `
        -Action Allow `
        -Profile Any | Out-Null
    Write-Ok "Firewall rule added: UDP 51820 inbound."
} else {
    Write-Ok "Firewall rule already exists."
}

# ── SSH Firewall Rule ────────────────────────────────────────────────────
$SshRule = 'WireSeal-SSH-TCP-22'
if (-not (Get-NetFirewallRule -Name $SshRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $SshRule `
        -DisplayName 'WireSeal SSH (TCP 22)' `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 22 `
        -Action Allow `
        -Profile Any | Out-Null
    Write-Ok "Firewall rule added: TCP 22 (SSH) inbound."
} else {
    Write-Ok "SSH firewall rule already exists."
}

# ── Enable IP forwarding (routing) ────────────────────────────────────────
$ipFwd = (Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.Forwarding -eq 'Enabled' })
if (-not $ipFwd) {
    Write-Info "Enabling IP forwarding..."
    Set-NetIPInterface -AddressFamily IPv4 -Forwarding Enabled -ErrorAction SilentlyContinue
    # Also set via registry for persistence
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1 -Type DWord
    Write-Ok "IP forwarding enabled."
} else {
    Write-Ok "IP forwarding already enabled."
}

# ── Enable OpenSSH Server ────────────────────────────────────────────────
Write-Info "Checking OpenSSH Server..."
$sshCap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction SilentlyContinue
if ($sshCap -and $sshCap.State -ne 'Installed') {
    Write-Info "Installing OpenSSH Server..."
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction SilentlyContinue | Out-Null
    Write-Ok "OpenSSH Server installed."
} else {
    Write-Ok "OpenSSH Server already installed."
}

# Start and enable sshd
$sshdStatus = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($sshdStatus) {
    if ($sshdStatus.Status -ne 'Running') {
        Set-Service -Name sshd -StartupType Automatic
        Start-Service sshd -ErrorAction SilentlyContinue
        Write-Ok "SSH server started."
    } else {
        Write-Ok "SSH server already running."
    }
} else {
    Write-Warn "sshd service not found. OpenSSH may need a restart to activate."
}

# ── NAT for VPN subnet ───────────────────────────────────────────────────
$existingNat = Get-NetNat -Name 'wireseal-nat' -ErrorAction SilentlyContinue
if (-not $existingNat) {
    Write-Info "Configuring NAT for VPN subnet..."
    try {
        New-NetNat -Name 'wireseal-nat' -InternalIPInterfaceAddressPrefix '10.0.0.0/24' -ErrorAction Stop | Out-Null
        Write-Ok "NAT configured for 10.0.0.0/24."
    } catch {
        Write-Warn "NAT setup skipped (may be configured during wireseal init)."
    }
} else {
    Write-Ok "NAT already configured."
}

# ── Network Doctor Summary ───────────────────────────────────────────────
Write-Host ""
Write-Info "Network Status:"
Write-Host "  IP Forwarding: $( if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name IPEnableRouter -ErrorAction SilentlyContinue).IPEnableRouter -eq 1) { 'enabled' } else { 'DISABLED' } )"
Write-Host "  Firewall UDP 51820: $( if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) { 'open' } else { 'CLOSED' } )"
Write-Host "  Firewall TCP 22: $( if (Get-NetFirewallRule -Name $SshRule -ErrorAction SilentlyContinue) { 'open' } else { 'CLOSED' } )"
Write-Host "  SSH Server: $( if ($sshdStatus -and $sshdStatus.Status -eq 'Running') { 'running' } else { 'not running' } )"
Write-Host "  NAT: $( if (Get-NetNat -Name 'wireseal-nat' -ErrorAction SilentlyContinue) { 'active' } else { 'not configured' } )"
Write-Host ""

# ── Done ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
Write-Host "  Open a NEW Administrator PowerShell, then:" -ForegroundColor White
Write-Host ""
Write-Host "  Quick Start:" -ForegroundColor White
Write-Host "    CLI:        wireseal init" -ForegroundColor Cyan
Write-Host "    Dashboard:  wireseal-gui" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Commands:" -ForegroundColor White
Write-Host "    wireseal init                  Initialize server + vault"
Write-Host "    wireseal add-client alice       Add a VPN client"
Write-Host "    wireseal show-qr alice          Show QR code for mobile"
Write-Host "    wireseal status                 Check connected peers"
Write-Host "    wireseal-gui                    Open web dashboard"
Write-Host ""
Write-Host "  Update:" -ForegroundColor White
Write-Host "    Re-run this script to update to the latest version."
Write-Host ""
