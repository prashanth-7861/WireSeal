#!/usr/bin/env bash
set -euo pipefail

# WireSeal — macOS one-liner installer
# Downloads source, installs deps via Homebrew, sets up the app.
#
# Usage:
#   curl -LO https://github.com/prashanth-7861/WireSeal/releases/latest/download/wireseal-macos.sh
#   chmod +x wireseal-macos.sh
#   ./wireseal-macos.sh

VERSION="0.3.5"
REPO="https://github.com/prashanth-7861/WireSeal.git"
INSTALL_DIR="$HOME/.wireseal"
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

# ── macOS check ───────────────────────────────────────────────────────────
[[ "$(uname)" != "Darwin" ]] && fail "This script is for macOS only."
MACOS_VER=$(sw_vers -productVersion)
info "macOS $MACOS_VER detected"

# ── Homebrew check ────────────────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
    fail "Homebrew not found. Install it first: https://brew.sh"
fi

# ── Install system deps ──────────────────────────────────────────────────
install_deps() {
    info "Installing system packages via Homebrew..."
    brew install wireguard-tools wireguard-go git 2>/dev/null || true
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

install_python() {
    if ! find_python &>/dev/null; then
        info "Installing Python 3.13 via Homebrew..."
        brew install python@3.13
    fi
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
    PYTHON=$(find_python) || fail "Python 3.12–3.14 not found even after install attempt."
    info "Using Python: $PYTHON ($($PYTHON --version))"

    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating virtual environment..."
        $PYTHON -m venv "$VENV_DIR"
    fi

    info "Installing Python dependencies..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -e "$INSTALL_DIR"
    "$VENV_DIR/bin/pip" install --quiet pywebview

    # Build dashboard if Node.js available
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

# ── Create launchers ─────────────────────────────────────────────────────
create_launcher() {
    # Try /usr/local/bin first, fall back to ~/.local/bin
    local BIN_DIR="/usr/local/bin"
    local NEED_SUDO=""

    if [[ ! -w "$BIN_DIR" ]]; then
        BIN_DIR="$HOME/.local/bin"
        mkdir -p "$BIN_DIR"
    fi

    cat > "$BIN_DIR/wireseal" << LAUNCHER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" -m wireseal.main "\$@"
LAUNCHER
    chmod +x "$BIN_DIR/wireseal"

    cat > "$BIN_DIR/wireseal-gui" << LAUNCHER
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" -c "
import sys; sys.path.insert(0, '$INSTALL_DIR/src')
from wireseal.api import serve
serve()
"
LAUNCHER
    chmod +x "$BIN_DIR/wireseal-gui"

    ok "Installed: $BIN_DIR/wireseal (CLI)"
    ok "Installed: $BIN_DIR/wireseal-gui (Desktop GUI)"

    # Check PATH
    if [[ "$BIN_DIR" == "$HOME/.local/bin" ]] && [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        warn "Add to your shell profile: export PATH=\"$BIN_DIR:\$PATH\""
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  WireSeal v${VERSION} — Secure WireGuard Management${NC}"
echo -e "${CYAN}  Platform: macOS $MACOS_VER${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

install_deps
install_python
setup_repo
setup_venv
create_launcher

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
echo -e "  ${BOLD}Note:${NC} On macOS, also install the WireGuard app from the"
echo -e "  Mac App Store for a GUI tunnel manager."
echo ""
echo -e "  ${BOLD}Update:${NC}"
echo -e "  $0                                  Re-run to update"
echo ""
