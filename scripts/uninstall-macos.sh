#!/usr/bin/env bash
# WireSeal — macOS uninstaller
# Removes the system wrapper, virtualenv, launchd plists, pf anchor, and
# (optionally) the vault data dir.
# Usage:
#   sudo bash uninstall-macos.sh             # remove binaries; keep vault
#   sudo bash uninstall-macos.sh --purge     # also remove ~/Library/Application Support/WireSeal
#   sudo bash uninstall-macos.sh --yes       # non-interactive (assumes yes)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$REPO_DIR/.venv"
WRAPPER_SYS="/usr/local/bin/wireseal"
WRAPPER_USER="$HOME/.local/bin/wireseal"
LAUNCHD_DNS_LABEL="com.wireseal.dns"
LAUNCHD_DNS_PLIST="/Library/LaunchDaemons/${LAUNCHD_DNS_LABEL}.plist"
PF_ANCHOR="wireseal"

PURGE=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --purge)  PURGE=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --help|-h) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "Unknown flag: $arg" >&2; exit 2 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[wireseal]${NC} $*"; }
warn()  { echo -e "${YELLOW}[wireseal]${NC} $*"; }
error() { echo -e "${RED}[wireseal] ERROR:${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "Run with sudo: sudo bash uninstall-macos.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
if [[ $ASSUME_YES -ne 1 ]]; then
    echo ""
    warn  "This will remove WireSeal from this machine."
    echo  "  - System wrapper:  $WRAPPER_SYS"
    echo  "  - User wrapper:    $WRAPPER_USER (if present)"
    echo  "  - Virtualenv:      $VENV_DIR"
    echo  "  - launchd plist:   $LAUNCHD_DNS_PLIST (if present)"
    echo  "  - pf anchor:       $PF_ANCHOR (if present)"
    if [[ $PURGE -eq 1 ]]; then
        warn "  - Vault data:      ~/Library/Application Support/WireSeal  (--purge specified)"
    else
        info "  Vault data preserved (~/Library/Application Support/WireSeal). Pass --purge to also delete."
    fi
    echo ""
    read -rp "Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "Cancelled."; exit 0; }
fi

# ---------------------------------------------------------------------------
# Stop tunnel + DNS updater
# ---------------------------------------------------------------------------
if command -v wg-quick &>/dev/null; then
    wg-quick down wg0 2>/dev/null || true
fi

if [[ -f "$LAUNCHD_DNS_PLIST" ]]; then
    launchctl bootout "system/${LAUNCHD_DNS_LABEL}" 2>/dev/null || true
    rm -f "$LAUNCHD_DNS_PLIST"
    info "Removed launchd plist: $LAUNCHD_DNS_PLIST"
fi

# Remove the API server LaunchDaemon installed via `wireseal service install`.
LAUNCHD_API_LABEL="com.wireseal.api"
LAUNCHD_API_PLIST="/Library/LaunchDaemons/${LAUNCHD_API_LABEL}.plist"
if [[ -f "$LAUNCHD_API_PLIST" ]]; then
    launchctl bootout "system/${LAUNCHD_API_LABEL}" 2>/dev/null || true
    rm -f "$LAUNCHD_API_PLIST"
    info "Removed launchd plist: $LAUNCHD_API_PLIST"
fi

# ---------------------------------------------------------------------------
# Flush pf anchor
# ---------------------------------------------------------------------------
if command -v pfctl &>/dev/null; then
    pfctl -a "$PF_ANCHOR" -F all 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Remove wrappers + venv
# ---------------------------------------------------------------------------
for w in "$WRAPPER_SYS" "$WRAPPER_USER"; do
    if [[ -f "$w" ]]; then
        rm -f "$w"
        info "Removed wrapper: $w"
    fi
done

if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
    info "Removed virtualenv: $VENV_DIR"
fi

# ---------------------------------------------------------------------------
# Optional: remove vault data
# ---------------------------------------------------------------------------
if [[ $PURGE -eq 1 ]]; then
    REAL_USER="${SUDO_USER:-$USER}"
    REAL_HOME="$(eval echo "~$REAL_USER")"
    VAULT_DIR="$REAL_HOME/Library/Application Support/WireSeal"
    if [[ -d "$VAULT_DIR" ]]; then
        rm -rf "$VAULT_DIR"
        info "Removed vault data: $VAULT_DIR"
    fi
fi

echo ""
info "WireSeal uninstalled."
if [[ $PURGE -ne 1 ]]; then
    echo "  Vault data preserved at ~/Library/Application Support/WireSeal. Delete manually if no longer needed."
fi
echo ""
