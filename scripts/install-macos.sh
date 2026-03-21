#!/usr/bin/env bash
# WireSeal – macOS setup & launcher
# Requires: macOS 12+, Homebrew, Python 3.12-3.14
# WireGuard on macOS runs as a userspace app (wireguard-go via brew).
# Usage: bash install-macos.sh   (no sudo needed for setup; wireseal itself needs sudo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$REPO_DIR/.venv"
MIN_PYTHON_MINOR=12
MAX_PYTHON_MINOR=14

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[wireseal]${NC} $*"; }
warn()  { echo -e "${YELLOW}[wireseal]${NC} $*"; }
error() { echo -e "${RED}[wireseal] ERROR:${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# 1. macOS version check
# ---------------------------------------------------------------------------
MACOS_VER=$(sw_vers -productVersion)
info "macOS $MACOS_VER detected"

# ---------------------------------------------------------------------------
# 2. Homebrew check
# ---------------------------------------------------------------------------
if ! command -v brew &>/dev/null; then
    error "Homebrew not found. Install it from https://brew.sh then re-run."
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Install system dependencies via Homebrew
# ---------------------------------------------------------------------------
install_if_missing() {
    local formula="$1"
    if ! brew list --formula "$formula" &>/dev/null; then
        info "Installing $formula via Homebrew..."
        brew install "$formula"
    else
        info "$formula already installed"
    fi
}

install_if_missing wireguard-tools
# wireguard-go provides the userspace WireGuard tunnel driver on macOS
install_if_missing wireguard-go

# ---------------------------------------------------------------------------
# 4. Find a suitable Python (3.12 – 3.14)
# ---------------------------------------------------------------------------
PYTHON=""
for candidate in python3.14 python3.13 python3.12 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo 0)
        maj=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo 0)
        if [[ $maj -eq 3 && $ver -ge $MIN_PYTHON_MINOR && $ver -le $MAX_PYTHON_MINOR ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    warn "Python 3.12–3.14 not found in PATH. Trying Homebrew..."
    brew install python@3.13 2>/dev/null || true
    PYTHON="$(brew --prefix)/bin/python3.13"
fi

if [[ ! -x "$PYTHON" ]]; then
    error "Could not find or install Python 3.12–3.14. Install manually from https://python.org"
    exit 1
fi
info "Using Python: $PYTHON ($($PYTHON --version))"

# ---------------------------------------------------------------------------
# 5. Create virtual environment
# ---------------------------------------------------------------------------
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

VENV_PIP="$VENV_DIR/bin/pip"

# ---------------------------------------------------------------------------
# 6. Install Python dependencies
# ---------------------------------------------------------------------------
info "Installing Python dependencies (this may take a minute)..."
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet -r "$REPO_DIR/requirements-dev.txt"
"$VENV_PIP" install --quiet -e "$REPO_DIR"

# ---------------------------------------------------------------------------
# 7. Install system-wide wrapper
# ---------------------------------------------------------------------------
WRAPPER=/usr/local/bin/wireseal
if [[ -w /usr/local/bin ]]; then
    cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/wireseal" "\$@"
EOF
    chmod +x "$WRAPPER"
    info "Installed system wrapper: $WRAPPER"
else
    warn "/usr/local/bin is not writable. Run with sudo to install system wrapper, or use:"
    warn "  $VENV_DIR/bin/wireseal <command>"
    # Install to user bin instead
    mkdir -p "$HOME/.local/bin"
    cat > "$HOME/.local/bin/wireseal" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/wireseal" "\$@"
EOF
    chmod +x "$HOME/.local/bin/wireseal"
    info "Installed user wrapper: $HOME/.local/bin/wireseal"
    info "Make sure ~/.local/bin is in your PATH (add to ~/.zshrc: export PATH=\"\$HOME/.local/bin:\$PATH\")"
fi

# ---------------------------------------------------------------------------
# 8. Run self-test
# ---------------------------------------------------------------------------
info "Running unit tests to verify installation..."
"$VENV_DIR/bin/pytest" --tb=short -q -m "not integration" "$REPO_DIR" 2>&1 | tail -5

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
info "WireSeal installed successfully."
echo ""
echo "  Initialize a server:       sudo wireseal init --subnet 10.0.0.1/24 --port 51820"
echo "  Add a client (iPhone):     sudo wireseal add-client alice"
echo "  Show QR code for import:   sudo wireseal show-qr alice"
echo "  List clients:              sudo wireseal list-clients"
echo "  Check status:              sudo wireseal status"
echo ""
echo "Note: On macOS, WireGuard tunnels require the WireGuard macOS app or wg-quick."
echo "Install the WireGuard app from the Mac App Store for a GUI, or use wg-quick"
echo "from wireguard-tools for CLI management."
echo ""
