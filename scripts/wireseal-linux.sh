#!/usr/bin/env bash
set -euo pipefail

# WireSeal — Linux installer + network doctor
# Detects system, installs deps, diagnoses networking, fixes issues, starts app.
#
# Usage:
#   curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-linux.sh
#   chmod +x wireseal-linux.sh
#   sudo ./wireseal-linux.sh

VERSION="0.3.7"
REPO="https://github.com/prashanth-7861/WireSeal.git"
INSTALL_DIR="/opt/wireseal"
VENV_DIR="$INSTALL_DIR/.venv"
WG_PORT=51820
WG_IFACE="wg0"
MIN_PYTHON_MINOR=12
MAX_PYTHON_MINOR=14

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

ERRORS=0
FIXES=0

info()    { echo -e "  ${CYAN}...${NC} $1"; }
ok()      { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!!]${NC} $1"; }
err()     { echo -e "  ${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }
fixed()   { echo -e "  ${GREEN}[FIXED]${NC} $1"; FIXES=$((FIXES + 1)); }
section() { echo ""; echo -e "${BOLD}── $1 ──${NC}"; }

# ═══════════════════════════════════════════════════════════════════════════
# 1. SYSTEM DETECTION
# ═══════════════════════════════════════════════════════════════════════════

[[ $EUID -ne 0 ]] && { echo -e "${RED}Run as root: sudo $0${NC}"; exit 1; }

detect_system() {
    # Distro
    if command -v pacman &>/dev/null; then
        DISTRO="arch"
        PKG_MGR="pacman"
        PKG_INSTALL="pacman -S --needed --noconfirm"
    elif command -v apt-get &>/dev/null; then
        DISTRO="debian"
        PKG_MGR="apt"
        PKG_INSTALL="apt-get install -y"
    elif command -v dnf &>/dev/null; then
        DISTRO="fedora"
        PKG_MGR="dnf"
        PKG_INSTALL="dnf install -y"
    else
        DISTRO="unknown"
        PKG_MGR="unknown"
        PKG_INSTALL=""
    fi

    # Architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH_LABEL="x86_64 (64-bit)" ;;
        aarch64) ARCH_LABEL="ARM64 (aarch64)" ;;
        armv7l)  ARCH_LABEL="ARMv7 (32-bit)" ;;
        i686)    ARCH_LABEL="x86 (32-bit)" ;;
        *)       ARCH_LABEL="$ARCH" ;;
    esac

    # Kernel
    KERNEL=$(uname -r)

    # Firewall system
    FIREWALL_SYSTEM="none"
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
        FIREWALL_SYSTEM="firewalld"
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_SYSTEM="ufw"
    elif command -v nft &>/dev/null; then
        FIREWALL_SYSTEM="nftables"
    elif command -v iptables &>/dev/null; then
        FIREWALL_SYSTEM="iptables"
    fi

    # Init system
    INIT_SYSTEM="unknown"
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    elif [[ -f /sbin/openrc ]]; then
        INIT_SYSTEM="openrc"
    fi

    # Outbound interface
    PUB_IFACE=""
    if command -v ip &>/dev/null; then
        PUB_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "")
    fi

    # SSH service name varies by distro
    if [[ "$DISTRO" == "debian" ]]; then
        SSH_SVC="ssh"
    else
        SSH_SVC="sshd"
    fi
}

detect_system

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  WireSeal v${VERSION} — Linux Installer + Network Doctor${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}System:${NC}     $DISTRO ($PKG_MGR)"
echo -e "  ${BOLD}Arch:${NC}       $ARCH_LABEL"
echo -e "  ${BOLD}Kernel:${NC}     $KERNEL"
echo -e "  ${BOLD}Firewall:${NC}   $FIREWALL_SYSTEM"
echo -e "  ${BOLD}Init:${NC}       $INIT_SYSTEM"
echo -e "  ${BOLD}Interface:${NC}  ${PUB_IFACE:-not detected}"

# ═══════════════════════════════════════════════════════════════════════════
# 2. INSTALL SYSTEM PACKAGES
# ═══════════════════════════════════════════════════════════════════════════

section "Installing system packages"

install_packages() {
    case "$DISTRO" in
        arch)
            pacman -Sy --needed --noconfirm \
                python python-pip python-gobject \
                webkit2gtk wireguard-tools git nftables openssh \
                fail2ban 2>&1 | tail -3
            ;;
        debian)
            apt-get update -qq
            apt-get install -y \
                python3 python3-pip python3-venv python3-gi \
                gir1.2-webkit2-4.1 gir1.2-gtk-3.0 libwebkit2gtk-4.1-dev \
                wireguard-tools git nftables openssh-server \
                fail2ban 2>&1 | tail -3
            ;;
        fedora)
            dnf install -y \
                python3 python3-pip python3-gobject \
                webkit2gtk4.1 wireguard-tools git nftables openssh-server \
                fail2ban 2>&1 | tail -3
            ;;
        *)
            err "Unsupported distro '$DISTRO'. Install manually: wireguard-tools nftables openssh python3"
            return 1
            ;;
    esac
}

# Check what's missing before installing
MISSING_PKGS=""
command -v wg        &>/dev/null || MISSING_PKGS+=" wireguard-tools"
command -v nft       &>/dev/null || MISSING_PKGS+=" nftables"
command -v git       &>/dev/null || MISSING_PKGS+=" git"
command -v sshd      &>/dev/null || { command -v /usr/sbin/sshd &>/dev/null || MISSING_PKGS+=" openssh"; }
command -v python3   &>/dev/null || MISSING_PKGS+=" python3"
command -v fail2ban-client &>/dev/null || MISSING_PKGS+=" fail2ban"

if [[ -n "$MISSING_PKGS" ]]; then
    info "Missing:$MISSING_PKGS — installing..."
    install_packages
    fixed "System packages installed."
else
    ok "All system packages present."
fi

# Verify critical tools exist after install
for tool in wg wg-quick nft git; do
    if ! command -v "$tool" &>/dev/null; then
        err "$tool still missing after install attempt. Install manually."
    fi
done

# ═══════════════════════════════════════════════════════════════════════════
# 3. PYTHON ENVIRONMENT
# ═══════════════════════════════════════════════════════════════════════════

section "Python environment"

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

PYTHON=$(find_python) || { err "Python 3.12–3.14 not found. Install it and re-run."; exit 1; }
ok "Python: $PYTHON ($($PYTHON --version))"

# ═══════════════════════════════════════════════════════════════════════════
# 4. CLONE / UPDATE SOURCE
# ═══════════════════════════════════════════════════════════════════════════

section "WireSeal source"

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Updating existing installation..."
    git -C "$INSTALL_DIR" fetch --all --quiet 2>/dev/null
    git -C "$INSTALL_DIR" reset --hard origin/main 2>/dev/null || \
    git -C "$INSTALL_DIR" pull --ff-only 2>/dev/null || \
    warn "Git update failed — using existing version."
    ok "Source updated."
else
    info "Cloning WireSeal..."
    git clone --depth 1 "$REPO" "$INSTALL_DIR" 2>/dev/null
    ok "Source cloned to $INSTALL_DIR"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. VIRTUAL ENV + DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════════════

section "Python dependencies"

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR" --system-site-packages
fi

info "Installing dependencies..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip 2>&1 | tail -1
"$VENV_DIR/bin/pip" install --quiet -e "$INSTALL_DIR" 2>&1 | tail -1
"$VENV_DIR/bin/pip" install --quiet pywebview 2>&1 | tail -1
ok "Python dependencies installed."

# ═══════════════════════════════════════════════════════════════════════════
# 6. SYSTEM LAUNCHERS
# ═══════════════════════════════════════════════════════════════════════════

section "System launchers"

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
ok "Installed: /usr/local/bin/wireseal-gui (Dashboard)"

# ═══════════════════════════════════════════════════════════════════════════
# 7. NETWORK DOCTOR — diagnose and fix every networking issue
# ═══════════════════════════════════════════════════════════════════════════

section "Network Doctor"

# ── 7a. IP Forwarding ────────────────────────────────────────────────────
info "Checking IP forwarding..."
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
if [[ "$IP_FWD" != "1" ]]; then
    warn "IP forwarding is OFF — VPN clients can't reach the internet."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-wireguard.conf << 'SYSCTL'
# WireSeal: enable IP forwarding for WireGuard VPN
net.ipv4.ip_forward = 1
SYSCTL
    sysctl --system > /dev/null 2>&1
    # Verify
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
        fixed "IP forwarding enabled (persistent)."
    else
        err "Could not enable IP forwarding."
    fi
else
    ok "IP forwarding: enabled"
fi

# ── 7b. Clean ALL stale/conflicting nftables rules ─────────────────────
info "Cleaning conflicting nftables rules..."
if command -v nft &>/dev/null; then
    # Delete wireseal-managed tables (old and new names)
    for table in "inet wg_filter" "inet wg_forward" "ip wg_nat"; do
        nft delete table $table 2>/dev/null && warn "Removed stale table: $table" || true
    done

    # CRITICAL: Delete the default 'inet filter' table if it has 'policy drop'
    # on input. Many distros (EndeavourOS, Arch) ship a default nftables config
    # with 'policy drop' that blocks ALL inbound traffic except SSH. This
    # conflicts with firewalld (which manages its own rules) and blocks
    # WireGuard UDP packets even when firewalld has port 51820 open.
    # The 'inet filter' table evaluates at priority 0, BEFORE firewalld's
    # tables at priority +10, so it drops packets before firewalld sees them.
    if [[ "$FIREWALL_SYSTEM" == "firewalld" ]]; then
        if nft list table inet filter &>/dev/null 2>&1; then
            # Check if it has policy drop on input
            if nft list chain inet filter input 2>/dev/null | grep -q "policy drop"; then
                nft delete table inet filter 2>/dev/null
                fixed "Removed conflicting 'inet filter' table (policy drop) — firewalld manages firewall rules."
            fi
        fi
    fi

    # Remove stale rules file that gets reloaded by nftables.service on boot
    rm -f /etc/nftables.d/wireguard.nft 2>/dev/null

    # Prevent the default nftables config from restoring the rogue table on reboot
    if [[ -f /etc/nftables.conf ]] && grep -q "policy drop" /etc/nftables.conf 2>/dev/null; then
        if [[ "$FIREWALL_SYSTEM" == "firewalld" ]]; then
            # Back up and replace with empty config — firewalld handles everything
            cp /etc/nftables.conf /etc/nftables.conf.bak.wireseal 2>/dev/null
            echo '#!/usr/sbin/nft -f' > /etc/nftables.conf
            echo '# Cleared by WireSeal — firewalld manages all firewall rules' >> /etc/nftables.conf
            fixed "Cleared /etc/nftables.conf (was restoring 'policy drop' on reboot)."
        fi
    fi

    ok "nftables: clean (no conflicting rules)"
fi

# ── 7c. Firewall configuration ──────────────────────────────────────────
info "Configuring firewall ($FIREWALL_SYSTEM)..."

case "$FIREWALL_SYSTEM" in
    firewalld)
        info "Configuring firewalld zones + policy..."

        # ── Public zone: WireGuard port + SSH + masquerade ──
        firewall-cmd --zone=public --add-port=${WG_PORT}/udp --permanent &>/dev/null
        firewall-cmd --zone=public --add-masquerade --permanent &>/dev/null
        firewall-cmd --zone=public --add-service=ssh --permanent &>/dev/null
        firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="10.0.0.0/24" accept' --permanent &>/dev/null
        ok "Firewalld: public zone — UDP $WG_PORT, SSH, masquerade, VPN subnet"

        # ── Trusted zone: add wg0 (accepts all VPN traffic) ──
        firewall-cmd --zone=trusted --add-interface=${WG_IFACE} --permanent &>/dev/null
        ok "Firewalld: trusted zone — $WG_IFACE"

        # ── Policy: trusted→public forwarding (VPN clients → internet) ──
        # Without this policy, VPN clients can reach the server but NOT
        # the internet. Firewalld does NOT forward between zones by default.
        # Uses policies (firewalld 0.9+) instead of --direct rules which
        # fail on nftables-based iptables (Arch, Fedora 39+).
        if ! firewall-cmd --permanent --info-policy=wg-internet &>/dev/null 2>&1; then
            firewall-cmd --permanent --new-policy=wg-internet &>/dev/null
            fixed "Firewalld: created wg-internet policy"
        fi
        firewall-cmd --permanent --policy=wg-internet --add-ingress-zone=trusted &>/dev/null
        firewall-cmd --permanent --policy=wg-internet --add-egress-zone=public &>/dev/null
        firewall-cmd --permanent --policy=wg-internet --set-target=ACCEPT &>/dev/null
        ok "Firewalld: wg-internet policy — trusted→public ACCEPT"

        # ── Reload ──
        firewall-cmd --reload &>/dev/null
        ok "Firewalld: all rules applied and reloaded"

        # ── Verify ──
        info "Firewalld status:"
        echo -e "    UDP $WG_PORT:    $(firewall-cmd --zone=public --query-port=${WG_PORT}/udp &>/dev/null && echo 'open' || echo 'CLOSED')"
        echo -e "    Masquerade:  $(firewall-cmd --zone=public --query-masquerade &>/dev/null && echo 'enabled' || echo 'DISABLED')"
        echo -e "    wg0 zone:    $(firewall-cmd --get-zone-of-interface=${WG_IFACE} 2>/dev/null || echo 'not assigned')"
        echo -e "    Policy:      $(firewall-cmd --info-policy=wg-internet &>/dev/null 2>&1 && echo 'wg-internet active' || echo 'MISSING')"
        ;;

    ufw)
        ufw allow ${WG_PORT}/udp &>/dev/null 2>&1
        # Enable forwarding in ufw
        if grep -q "DEFAULT_FORWARD_POLICY=\"DROP\"" /etc/default/ufw 2>/dev/null; then
            sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
            fixed "UFW: set forward policy to ACCEPT"
        fi
        # Add NAT masquerade rule to ufw before.rules
        if ! grep -q "WireSeal" /etc/ufw/before.rules 2>/dev/null; then
            if [[ -n "$PUB_IFACE" ]]; then
                cat >> /etc/ufw/before.rules << UNAT
# WireSeal NAT masquerade
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/24 -o $PUB_IFACE -j MASQUERADE
COMMIT
UNAT
                fixed "UFW: added NAT masquerade rule"
            fi
        fi
        ufw reload &>/dev/null 2>&1
        ok "UFW: configured"
        ;;

    nftables|iptables|none)
        # No high-level firewall manager — apply nftables rules directly
        if command -v nft &>/dev/null && [[ -n "$PUB_IFACE" ]]; then
            info "Applying nftables forward + NAT rules..."
            nft -f - << NFT_RULES
table inet wg_forward {
    chain forward {
        type filter hook forward priority 0; policy accept;
        iifname "$WG_IFACE" oifname "$PUB_IFACE" accept
        iifname "$PUB_IFACE" oifname "$WG_IFACE" ct state established,related accept
    }
}

table ip wg_nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        iifname "$WG_IFACE" oifname "$PUB_IFACE" masquerade
    }
}
NFT_RULES
            # Persist rules so they survive reboot
            mkdir -p /etc/nftables.d
            nft list ruleset > /etc/nftables.d/wireguard.nft 2>/dev/null
            ok "nftables: forward + NAT rules applied"
        elif command -v iptables &>/dev/null && [[ -n "$PUB_IFACE" ]]; then
            info "Applying iptables forward + NAT rules..."
            iptables -A FORWARD -i "$WG_IFACE" -o "$PUB_IFACE" -j ACCEPT 2>/dev/null
            iptables -A FORWARD -i "$PUB_IFACE" -o "$WG_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
            iptables -t nat -A POSTROUTING -o "$PUB_IFACE" -j MASQUERADE 2>/dev/null
            ok "iptables: forward + NAT rules applied"
        else
            warn "No firewall tool available and no outbound interface detected."
        fi
        ;;
esac

# ── 7d. SSH Server ──────────────────────────────────────────────────────
info "Checking SSH server..."

# Is sshd binary present?
SSHD_BIN=""
for loc in /usr/sbin/sshd /usr/bin/sshd; do
    [[ -x "$loc" ]] && SSHD_BIN="$loc" && break
done
if [[ -z "$SSHD_BIN" ]] && command -v sshd &>/dev/null; then
    SSHD_BIN=$(command -v sshd)
fi

if [[ -z "$SSHD_BIN" ]]; then
    warn "sshd not found — installing..."
    case "$DISTRO" in
        arch)   pacman -S --needed --noconfirm openssh 2>&1 | tail -1 ;;
        debian) apt-get install -y openssh-server 2>&1 | tail -1 ;;
        fedora) dnf install -y openssh-server 2>&1 | tail -1 ;;
    esac
    fixed "OpenSSH installed."
fi

# Is sshd running?
SSH_RUNNING=false
if systemctl is-active "$SSH_SVC" &>/dev/null; then
    SSH_RUNNING=true
    ok "SSH server: running ($SSH_SVC)"
else
    warn "SSH server not running."
    systemctl enable --now "$SSH_SVC" 2>/dev/null && {
        fixed "SSH server started ($SSH_SVC)."
        SSH_RUNNING=true
    } || {
        # Try alternate service name
        ALT_SVC=$([[ "$SSH_SVC" == "sshd" ]] && echo "ssh" || echo "sshd")
        systemctl enable --now "$ALT_SVC" 2>/dev/null && {
            fixed "SSH server started ($ALT_SVC)."
            SSH_RUNNING=true
            SSH_SVC="$ALT_SVC"
        } || err "Could not start SSH server."
    }
fi

# Is SSH port 22 actually listening?
if $SSH_RUNNING; then
    if ss -tlnp 2>/dev/null | grep -q ":22 "; then
        ok "SSH port 22: listening"
    else
        warn "SSH service running but port 22 not listening. Checking config..."
        # Check if Port is set to something else
        SSH_PORT=$(grep -oP '^\s*Port\s+\K\d+' /etc/ssh/sshd_config 2>/dev/null || echo "22")
        if [[ "$SSH_PORT" != "22" ]]; then
            warn "SSH configured on port $SSH_PORT instead of 22."
        else
            systemctl restart "$SSH_SVC" 2>/dev/null
            sleep 1
            if ss -tlnp 2>/dev/null | grep -q ":22 "; then
                fixed "SSH port 22 now listening after restart."
            else
                err "SSH port 22 still not listening."
            fi
        fi
    fi
fi

# Open SSH port in firewall for VPN clients
case "$FIREWALL_SYSTEM" in
    firewalld)
        if ! firewall-cmd --query-service=ssh &>/dev/null 2>&1; then
            firewall-cmd --add-service=ssh --permanent &>/dev/null
            firewall-cmd --reload &>/dev/null
            fixed "Firewalld: opened SSH service"
        fi
        ;;
    ufw)
        ufw allow ssh &>/dev/null 2>&1
        ;;
esac

# ── 7e. WireGuard Tunnel ────────────────────────────────────────────────
info "Checking WireGuard..."

WG_RUNNING=false
if wg show "$WG_IFACE" &>/dev/null 2>&1; then
    WG_RUNNING=true
    PEER_COUNT=$(wg show "$WG_IFACE" peers 2>/dev/null | wc -l)
    ok "WireGuard $WG_IFACE: running ($PEER_COUNT peers configured)"
elif [[ -f /etc/wireguard/${WG_IFACE}.conf ]]; then
    warn "WireGuard config exists but tunnel is DOWN."
    # Try to bring it up
    # First, bring down if stale interface exists
    wg-quick down "$WG_IFACE" 2>/dev/null || true
    sleep 1
    if wg-quick up "$WG_IFACE" 2>/dev/null; then
        WG_RUNNING=true
        fixed "WireGuard tunnel $WG_IFACE started."
    else
        err "Could not start WireGuard tunnel. Check: /etc/wireguard/${WG_IFACE}.conf"
        info "Try: sudo wg-quick up $WG_IFACE"
        # Show the error
        wg-quick up "$WG_IFACE" 2>&1 | head -5 || true
    fi
else
    info "No WireGuard config yet. Run 'sudo wireseal init' to create one."
fi

# ── 7f. Verify VPN traffic flow (if tunnel is running) ──────────────────
if $WG_RUNNING && [[ -n "$PUB_IFACE" ]]; then
    info "Verifying VPN traffic flow..."

    # Check that wg0 has an IP
    WG_IP=$(ip -4 addr show "$WG_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "")
    if [[ -n "$WG_IP" ]]; then
        ok "WireGuard IP: $WG_IP"
    else
        err "WireGuard interface $WG_IFACE has no IP address."
    fi

    # Check NAT is working
    NAT_OK=false
    if command -v nft &>/dev/null; then
        if nft list table ip wg_nat &>/dev/null 2>&1; then
            NAT_OK=true
        fi
    fi
    if ! $NAT_OK && command -v iptables &>/dev/null; then
        if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE"; then
            NAT_OK=true
        fi
    fi
    if [[ "$FIREWALL_SYSTEM" == "firewalld" ]]; then
        if firewall-cmd --query-masquerade &>/dev/null 2>&1; then
            NAT_OK=true
        fi
    fi

    if $NAT_OK; then
        ok "NAT masquerade: active"
    else
        err "NAT masquerade: NOT active — VPN clients won't have internet."
        info "Applying emergency NAT rule..."
        if command -v nft &>/dev/null; then
            nft add table ip wg_nat 2>/dev/null || true
            nft "add chain ip wg_nat postrouting { type nat hook postrouting priority 100; policy accept; }" 2>/dev/null || true
            nft add rule ip wg_nat postrouting iifname "$WG_IFACE" oifname "$PUB_IFACE" masquerade 2>/dev/null || true
            fixed "Emergency NAT rule applied via nft."
        elif command -v iptables &>/dev/null; then
            iptables -t nat -A POSTROUTING -o "$PUB_IFACE" -j MASQUERADE 2>/dev/null
            fixed "Emergency NAT rule applied via iptables."
        fi
    fi

    # Check that FORWARD chain allows VPN traffic
    FWD_OK=false
    if command -v nft &>/dev/null; then
        if nft list table inet wg_forward &>/dev/null 2>&1; then
            FWD_OK=true
        fi
    fi
    if ! $FWD_OK && command -v iptables &>/dev/null; then
        if iptables -L FORWARD -n 2>/dev/null | grep -q "$WG_IFACE"; then
            FWD_OK=true
        fi
    fi
    if [[ "$FIREWALL_SYSTEM" == "firewalld" ]]; then
        # firewalld handles forwarding via direct rules or masquerade
        FWD_OK=true
    fi

    if $FWD_OK; then
        ok "Forwarding rules: active"
    else
        warn "No explicit forwarding rules found."
        # Check if default FORWARD policy is ACCEPT
        if command -v iptables &>/dev/null; then
            FWD_POLICY=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "unknown")
            if [[ "$FWD_POLICY" == "ACCEPT" ]]; then
                ok "iptables FORWARD policy is ACCEPT — traffic should flow."
            fi
        fi
    fi
fi

# ── 7g. DNS check ───────────────────────────────────────────────────────
info "Checking DNS configuration..."
if [[ -f /etc/wireguard/${WG_IFACE}.conf ]]; then
    # Check what DNS the server config sets for clients
    # Client configs are in the vault, but check if the rendered configs have bad DNS
    WG_SERVER_IP=$(grep -oP 'Address\s*=\s*\K[\d.]+' /etc/wireguard/${WG_IFACE}.conf 2>/dev/null || echo "")
    if [[ -n "$WG_SERVER_IP" ]]; then
        ok "WireGuard server IP: $WG_SERVER_IP"
        # Warn if a local DNS resolver is running on the WG IP
        if ss -ulnp 2>/dev/null | grep -q ":53 "; then
            ok "DNS resolver listening on port 53."
        else
            info "No local DNS on port 53 — client DNS should point to 1.1.1.1 / 8.8.8.8"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 8. PORT REACHABILITY TEST
# ═══════════════════════════════════════════════════════════════════════════

section "Port check"

# Check if WireGuard port is listening
if ss -ulnp 2>/dev/null | grep -q ":${WG_PORT} "; then
    ok "UDP $WG_PORT: listening"
else
    if $WG_RUNNING; then
        warn "WireGuard is running but UDP $WG_PORT not showing in ss. This may be normal (kernel module)."
    else
        info "UDP $WG_PORT: not listening (tunnel not running yet)"
    fi
fi

# Check if something else is blocking the port
if [[ "$FIREWALL_SYSTEM" == "firewalld" ]]; then
    if firewall-cmd --query-port=${WG_PORT}/udp &>/dev/null 2>&1; then
        ok "Firewalld: UDP $WG_PORT allowed"
    else
        err "Firewalld: UDP $WG_PORT BLOCKED"
        firewall-cmd --add-port=${WG_PORT}/udp --permanent &>/dev/null
        firewall-cmd --reload &>/dev/null
        fixed "Firewalld: opened UDP $WG_PORT"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 9. SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}  All checks passed!${NC} ($FIXES fixes applied)"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
else
    echo -e "${RED}  $ERRORS issue(s) remain${NC} ($FIXES fixes applied)"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi

echo ""
echo -e "  ${BOLD}Status:${NC}"
echo -e "  IP forwarding:  $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"

case "$FIREWALL_SYSTEM" in
    firewalld)
        echo -e "  Firewall:       firewalld (active)"
        echo -e "  UDP $WG_PORT:      $(firewall-cmd --query-port=${WG_PORT}/udp &>/dev/null 2>&1 && echo -e "${GREEN}open${NC}" || echo -e "${RED}CLOSED${NC}")"
        echo -e "  Masquerade:     $(firewall-cmd --query-masquerade &>/dev/null 2>&1 && echo -e "${GREEN}enabled${NC}" || echo -e "${RED}DISABLED${NC}")"
        ;;
    ufw)
        echo -e "  Firewall:       ufw (active)"
        ;;
    *)
        echo -e "  Firewall:       $FIREWALL_SYSTEM"
        ;;
esac

echo -e "  SSH:            $(systemctl is-active $SSH_SVC 2>/dev/null || echo 'not running')"
echo -e "  WireGuard:      $($WG_RUNNING && echo -e "${GREEN}running${NC}" || echo -e "${YELLOW}not running${NC}")"

echo ""
echo -e "  ${BOLD}Quick Start:${NC}"
if ! $WG_RUNNING; then
    echo -e "  ${CYAN}1.${NC} sudo wireseal init                  ${DIM}# Create server + vault${NC}"
    echo -e "  ${CYAN}2.${NC} sudo wireseal add-client myphone     ${DIM}# Add a VPN client${NC}"
    echo -e "  ${CYAN}3.${NC} sudo wireseal show-qr myphone        ${DIM}# Scan QR on phone${NC}"
    echo -e "  ${CYAN}4.${NC} sudo wireseal-gui                    ${DIM}# Open web dashboard${NC}"
else
    echo -e "  ${CYAN}Dashboard:${NC}  sudo wireseal-gui"
    echo -e "  ${CYAN}Add client:${NC} sudo wireseal add-client myphone"
    echo -e "  ${CYAN}Show QR:${NC}    sudo wireseal show-qr myphone"
    echo -e "  ${CYAN}Status:${NC}     sudo wireseal status"
fi

echo ""
echo -e "  ${BOLD}Update:${NC}  sudo $0"
echo -e "  ${BOLD}Diagnose:${NC} sudo $0  ${DIM}(re-run anytime to fix issues)${NC}"
echo ""
