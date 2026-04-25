#!/usr/bin/env bash
# WireSeal — Linux uninstaller
# Removes the system wrapper, virtualenv, and (optionally) the vault data dir.
# Usage:
#   sudo bash uninstall-linux.sh            # remove binaries; keep vault
#   sudo bash uninstall-linux.sh --purge    # also remove ~/.config/wireseal
#   sudo bash uninstall-linux.sh --yes      # non-interactive (assumes yes)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$REPO_DIR/.venv"
WRAPPER="/usr/local/bin/wireseal"
SYSTEMD_UNIT="/etc/systemd/system/wireseal.service"
DNS_UPDATER_UNIT="/etc/systemd/system/wireseal-dns.service"
NFTABLES_TABLE="wireseal"

PURGE=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --help|-h)
            sed -n '2,8p' "$0"; exit 0 ;;
        *) echo "Unknown flag: $arg" >&2; exit 2 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[wireseal]${NC} $*"; }
warn()  { echo -e "${YELLOW}[wireseal]${NC} $*"; }
error() { echo -e "${RED}[wireseal] ERROR:${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "Run with sudo: sudo bash uninstall-linux.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
if [[ $ASSUME_YES -ne 1 ]]; then
    echo ""
    warn  "This will remove WireSeal from this machine."
    echo  "  - System wrapper: $WRAPPER"
    echo  "  - Virtualenv:     $VENV_DIR"
    echo  "  - systemd units:  $SYSTEMD_UNIT, $DNS_UPDATER_UNIT (if present)"
    echo  "  - nftables table: $NFTABLES_TABLE (if present)"
    if [[ $PURGE -eq 1 ]]; then
        warn "  - Vault data:     ~/.config/wireseal  (--purge specified)"
    else
        info "  Vault data preserved (~/.config/wireseal). Pass --purge to also delete."
    fi
    echo ""
    read -rp "Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "Cancelled."; exit 0; }
fi

# ---------------------------------------------------------------------------
# Stop running tunnel + services
# ---------------------------------------------------------------------------
if command -v wg-quick &>/dev/null; then
    wg-quick down wg0 2>/dev/null || true
fi

if command -v systemctl &>/dev/null; then
    for unit in wireseal.service wireseal-api.service wireseal-dns.service; do
        if systemctl list-unit-files "$unit" &>/dev/null; then
            systemctl stop    "$unit" 2>/dev/null || true
            systemctl disable "$unit" 2>/dev/null || true
        fi
    done
fi

# ---------------------------------------------------------------------------
# Drop nftables rules (table wireseal)
# ---------------------------------------------------------------------------
if command -v nft &>/dev/null; then
    nft delete table inet "$NFTABLES_TABLE" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Remove sudoers drop-in (if present)
# ---------------------------------------------------------------------------
SUDOERS_DROPIN="/etc/sudoers.d/wireseal"
if [[ -f "$SUDOERS_DROPIN" ]]; then
    rm -f "$SUDOERS_DROPIN"
    info "Removed sudoers drop-in: $SUDOERS_DROPIN"
fi

# ---------------------------------------------------------------------------
# Remove systemd units
# ---------------------------------------------------------------------------
API_SERVICE_UNIT="/etc/systemd/system/wireseal-api.service"
for unit_path in "$SYSTEMD_UNIT" "$API_SERVICE_UNIT" "$DNS_UPDATER_UNIT"; do
    if [[ -f "$unit_path" ]]; then
        rm -f "$unit_path"
        info "Removed: $unit_path"
    fi
done
if command -v systemctl &>/dev/null; then
    systemctl daemon-reload 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Remove wrapper + venv
# ---------------------------------------------------------------------------
if [[ -f "$WRAPPER" ]]; then
    rm -f "$WRAPPER"
    info "Removed wrapper: $WRAPPER"
fi

if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
    info "Removed virtualenv: $VENV_DIR"
fi

# ---------------------------------------------------------------------------
# Optional: remove vault data
# ---------------------------------------------------------------------------
if [[ $PURGE -eq 1 ]]; then
    # The script may run via sudo, so use $SUDO_USER's home, not root's.
    REAL_USER="${SUDO_USER:-$USER}"
    REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
    VAULT_DIR="$REAL_HOME/.config/wireseal"
    if [[ -d "$VAULT_DIR" ]]; then
        rm -rf "$VAULT_DIR"
        info "Removed vault data: $VAULT_DIR"
    fi
fi

echo ""
info "WireSeal uninstalled."
if [[ $PURGE -ne 1 ]]; then
    echo "  Vault data preserved at ~/.config/wireseal. Delete manually if no longer needed."
fi
echo ""
