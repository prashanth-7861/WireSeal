#!/usr/bin/env bash
set -euo pipefail

# WireSeal — Linux launcher
# Downloads source, installs deps, runs the app.
# Usage: chmod +x wireseal-linux.sh && sudo ./wireseal-linux.sh

REPO="https://github.com/prashanth-7861/WireSeal.git"
INSTALL_DIR="/opt/wireseal"
VENV_DIR="$INSTALL_DIR/.venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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
info "Detected distro: $DISTRO"

# ── Install system dependencies ────────────────────────────────────────────
install_deps() {
    case "$DISTRO" in
        arch)
            info "Installing system packages (pacman)..."
            pacman -S --needed --noconfirm \
                python python-pip python-gobject \
                webkit2gtk wireguard-tools git nftables openssh
            ;;
        debian)
            info "Installing system packages (apt)..."
            apt-get update -qq
            apt-get install -y \
                python3 python3-pip python3-venv python3-gi \
                gir1.2-webkit2-4.1 gir1.2-gtk-3.0 \
                wireguard-tools git nftables openssh-server
            ;;
        fedora)
            info "Installing system packages (dnf)..."
            dnf install -y \
                python3 python3-pip python3-gobject \
                webkit2gtk4.1 wireguard-tools git nftables openssh-server
            ;;
        *)
            fail "Unsupported distro. Install manually: python3, python-gobject, webkit2gtk, wireguard-tools, git"
            ;;
    esac
    ok "System packages installed."
}

# ── Clone or update repo ──────────────────────────────────────────────────
setup_repo() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Updating existing installation..."
        git -C "$INSTALL_DIR" pull --ff-only
    else
        info "Cloning WireSeal to $INSTALL_DIR..."
        git clone "$REPO" "$INSTALL_DIR"
    fi
}

# ── Python venv + pip deps ────────────────────────────────────────────────
setup_venv() {
    local PYTHON
    PYTHON=$(command -v python3 || command -v python)
    [[ -z "$PYTHON" ]] && fail "Python 3 not found"

    local PY_VER
    PY_VER=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    info "Python version: $PY_VER"

    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating virtual environment..."
        $PYTHON -m venv "$VENV_DIR" --system-site-packages
    fi

    info "Installing Python dependencies..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -e "$INSTALL_DIR"
    "$VENV_DIR/bin/pip" install --quiet pywebview

    # Build dashboard if not already built
    if [[ ! -d "$INSTALL_DIR/Dashboard/dist" ]]; then
        if command -v npm &>/dev/null; then
            info "Building dashboard..."
            (cd "$INSTALL_DIR/Dashboard" && npm ci --silent && npm run build --silent)
        else
            warn "npm not found — dashboard won't be available. Install Node.js to enable."
        fi
    fi

    ok "Python dependencies installed."
}

# ── Create system-wide launcher ───────────────────────────────────────────
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

# ── Network setup (IP forwarding, SSH, firewalld) ────────────────────────
setup_network() {
    # Enable IP forwarding
    info "Enabling IP forwarding..."
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
        sysctl -p /etc/sysctl.d/99-wireguard.conf > /dev/null
        ok "IP forwarding enabled."
    else
        ok "IP forwarding already enabled."
    fi

    # Enable SSH server
    info "Enabling SSH server..."
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        ok "SSH server already running."
    else
        systemctl enable --now sshd 2>/dev/null || systemctl enable --now ssh 2>/dev/null || warn "Could not start SSH server."
        ok "SSH server started."
    fi

    # Open WireGuard port in firewalld (if present)
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        info "Opening UDP 51820 in firewalld..."
        if ! firewall-cmd --query-port=51820/udp &>/dev/null; then
            firewall-cmd --add-port=51820/udp --permanent &>/dev/null
            firewall-cmd --reload &>/dev/null
            ok "Firewalld port 51820/udp opened."
        else
            ok "Firewalld port already open."
        fi
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  WireSeal — Secure WireGuard Management${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

install_deps
setup_repo
setup_venv
create_launcher
setup_network

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}CLI:${NC}  sudo wireseal --help"
echo -e "  ${CYAN}GUI:${NC}  sudo wireseal-gui"
echo ""
echo -e "  ${YELLOW}First time?${NC} Run: sudo wireseal init"
echo -e "  ${YELLOW}Dashboard:${NC} Run: sudo wireseal-gui"
echo ""
