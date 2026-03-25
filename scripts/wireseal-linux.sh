#!/usr/bin/env bash
set -euo pipefail

# WireSeal — Linux one-liner installer
# Downloads source, installs deps, configures network, runs the app.
#
# Usage:
#   curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-linux.sh
#   chmod +x wireseal-linux.sh
#   sudo ./wireseal-linux.sh

VERSION="0.3.5"
REPO="https://github.com/prashanth-7861/WireSeal.git"
INSTALL_DIR="/opt/wireseal"
VENV_DIR="$INSTALL_DIR/.venv"
MIN_PYTHON_MINOR=12
MAX_PYTHON_MINOR=14

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[wireseal]${NC} $1"; }
ok()    { echo -e "${GREEN}[wireseal]${NC} $1"; }
warn()  { echo -e "${YELLOW}[wireseal]${NC} $1"; }
fail()  { echo -e "${RED}[wireseal]${NC} $1"; exit 1; }

# ── Root check ──────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Run as root: sudo $0"

# ── Detect distro ──────────────────────────────────────────────────────────
detect_distro() {
    if command -v pacman &>/dev/null; then
        echo "arch"
    elif command -v apt-get &>/dev/null; then
        echo "debian"
    elif command -v dnf &>/dev/null; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)

# ── Install system dependencies ────────────────────────────────────────────
install_deps() {
    case "$DISTRO" in
        arch)
            info "Installing system packages (pacman)..."
            pacman -Sy --needed --noconfirm \
                python python-pip python-gobject \
                webkit2gtk wireguard-tools git nftables openssh
            ;;
        debian)
            info "Installing system packages (apt)..."
            apt-get update -qq
            apt-get install -y \
                python3 python3-pip python3-venv python3-gi \
                gir1.2-webkit2-4.1 gir1.2-gtk-3.0 libwebkit2gtk-4.1-dev \
                wireguard-tools git nftables openssh-server
            ;;
        fedora)
            info "Installing system packages (dnf)..."
            dnf install -y \
                python3 python3-pip python3-gobject \
                webkit2gtk4.1 wireguard-tools git nftables openssh-server
            ;;
        *)
            fail "Unsupported distro. Supported: Arch/Manjaro, Debian/Ubuntu, Fedora/RHEL."
            ;;
    esac
    ok "System packages installed."
}

# ── Find suitable Python ──────────────────────────────────────────────────
find_python() {
    for candidate in python3.14 python3.13 python3.12 python3 python; do
        if command -v "$candidate" &>/dev/null; then
            local ver maj
            ver=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
            maj=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
            if [[ $maj -eq 3 && $ver -ge $MIN_PYTHON_MINOR && $ver -le $MAX_PYTHON_MINOR ]]; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

# ── Clone or update repo ──────────────────────────────────────────────────
setup_repo() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Updating existing installation..."
        git -C "$INSTALL_DIR" pull --ff-only || warn "Pull failed — using existing version."
    else
        info "Cloning WireSeal to $INSTALL_DIR..."
        git clone --depth 1 "$REPO" "$INSTALL_DIR"
    fi
}

# ── Python venv + pip deps ────────────────────────────────────────────────
setup_venv() {
    local PYTHON
    PYTHON=$(find_python) || fail "Python 3.12–3.14 not found. Install it and re-run."
    info "Using Python: $PYTHON ($($PYTHON --version))"

    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating virtual environment..."
        $PYTHON -m venv "$VENV_DIR" --system-site-packages
    fi

    info "Installing Python dependencies..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -e "$INSTALL_DIR"
    "$VENV_DIR/bin/pip" install --quiet pywebview

    # Build dashboard if Node.js available and not already built
    if [[ ! -d "$INSTALL_DIR/Dashboard/dist" ]]; then
        if command -v npm &>/dev/null; then
            info "Building dashboard..."
            (cd "$INSTALL_DIR/Dashboard" && npm ci --silent && npm run build --silent)
        else
            warn "npm not found — dashboard will use pre-built files if available."
        fi
    fi

    ok "Python dependencies installed."
}

# ── Create system-wide launchers ─────────────────────────────────────────
create_launcher() {
    cat > /usr/local/bin/wireseal << 'LAUNCHER'
#!/usr/bin/env bash
exec /opt/wireseal/.venv/bin/python -m wireseal.main "$@"
LAUNCHER
    chmod +x /usr/local/bin/wireseal

    cat > /usr/local/bin/wireseal-gui << 'LAUNCHER'
#!/usr/bin/env bash
exec /opt/wireseal/.venv/bin/python -c "
import sys; sys.path.insert(0, '/opt/wireseal/src')
from wireseal.api import serve
serve()
"
LAUNCHER
    chmod +x /usr/local/bin/wireseal-gui

    ok "Installed: /usr/local/bin/wireseal (CLI)"
    ok "Installed: /usr/local/bin/wireseal-gui (Desktop GUI)"
}

# ── Network setup (IP forwarding, SSH, firewalld, nftables cleanup) ──────
setup_network() {
    info "Configuring network..."

    # ── 1. IP forwarding (persistent) ──
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]]; then
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        mkdir -p /etc/sysctl.d
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
        sysctl -p /etc/sysctl.d/99-wireguard.conf > /dev/null 2>&1
        ok "IP forwarding enabled."
    else
        ok "IP forwarding already enabled."
    fi

    # ── 2. Clean up stale nftables rules that block traffic ──
    # Previous versions used 'policy drop' on input which conflicts with firewalld
    # and locks users out of SSH. Remove all wireseal nftables tables.
    if command -v nft &>/dev/null; then
        for table in "inet wg_filter" "inet wg_forward" "ip wg_nat"; do
            nft delete table $table 2>/dev/null || true
        done
        # Also remove stale rules file
        rm -f /etc/nftables.d/wireguard.nft 2>/dev/null
        ok "Cleaned stale nftables rules."
    fi

    # ── 3. Enable nftables service ──
    if command -v systemctl &>/dev/null; then
        systemctl enable --now nftables 2>/dev/null || true
    fi

    # ── 4. Firewalld configuration ──
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
        info "Configuring firewalld..."

        # Open WireGuard UDP port
        if ! firewall-cmd --query-port=51820/udp &>/dev/null 2>&1; then
            firewall-cmd --add-port=51820/udp --permanent &>/dev/null
            ok "Firewalld: opened UDP 51820."
        else
            ok "Firewalld: UDP 51820 already open."
        fi

        # Enable masquerade for VPN NAT
        if ! firewall-cmd --query-masquerade &>/dev/null 2>&1; then
            firewall-cmd --add-masquerade --permanent &>/dev/null
            ok "Firewalld: enabled masquerade (NAT)."
        else
            ok "Firewalld: masquerade already enabled."
        fi

        # Reload to apply permanent rules
        firewall-cmd --reload &>/dev/null
        ok "Firewalld configured."
    else
        warn "firewalld not running — nftables rules will be applied by wireseal init."
    fi

    # ── 5. SSH server ──
    info "Enabling SSH server..."
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        ok "SSH server already running."
    else
        systemctl enable --now sshd 2>/dev/null || \
        systemctl enable --now ssh 2>/dev/null || \
        warn "Could not start SSH server."
        ok "SSH server started."
    fi

    # ── 6. Verify WireGuard tunnel (if already initialized) ──
    if [[ -f /etc/wireguard/wg0.conf ]]; then
        info "WireGuard config found. Checking tunnel..."
        if ! wg show wg0 &>/dev/null; then
            wg-quick up wg0 2>/dev/null && ok "WireGuard tunnel started." || warn "Could not start wg0 — run 'sudo wireseal init' first."
        else
            ok "WireGuard tunnel already running."
        fi
    fi

    # ── 7. Network diagnostic summary ──
    echo ""
    info "Network status:"
    echo -e "  IP forwarding:  $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
        echo -e "  Firewalld:      active"
        echo -e "  UDP 51820:      $(firewall-cmd --query-port=51820/udp &>/dev/null && echo 'open' || echo 'CLOSED')"
        echo -e "  Masquerade:     $(firewall-cmd --query-masquerade &>/dev/null && echo 'enabled' || echo 'DISABLED')"
    else
        echo -e "  Firewalld:      not running"
    fi
    echo -e "  SSH:            $(systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo 'not running')"
    if command -v wg &>/dev/null; then
        echo -e "  WireGuard:      $(wg show wg0 &>/dev/null 2>&1 && echo 'running' || echo 'not running')"
    fi
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  WireSeal v${VERSION} — Secure WireGuard Management${NC}"
echo -e "${CYAN}  Platform: Linux ($DISTRO)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

install_deps
setup_repo
setup_venv
create_launcher
setup_network

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Quick Start:${NC}"
echo -e "  ${CYAN}CLI:${NC}       sudo wireseal init"
echo -e "  ${CYAN}Dashboard:${NC} sudo wireseal-gui"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "  sudo wireseal init                  Initialize server + vault"
echo -e "  sudo wireseal add-client alice       Add a VPN client"
echo -e "  sudo wireseal show-qr alice          Show QR code for mobile"
echo -e "  sudo wireseal status                 Check connected peers"
echo -e "  sudo wireseal-gui                    Open web dashboard"
echo ""
echo -e "  ${BOLD}Update:${NC}"
echo -e "  sudo $0                             Re-run this script to update"
echo ""
