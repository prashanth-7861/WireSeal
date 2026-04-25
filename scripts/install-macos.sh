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

# ---------------------------------------------------------------------------
# Uninstall passthrough — `bash install-macos.sh --uninstall [--purge] [--yes]`
# ---------------------------------------------------------------------------
for arg in "$@"; do
    if [[ "$arg" == "--uninstall" || "$arg" == "-u" ]]; then
        shift_args=()
        for a in "$@"; do
            [[ "$a" == "--uninstall" || "$a" == "-u" ]] && continue
            shift_args+=("$a")
        done
        exec bash "$SCRIPT_DIR/uninstall-macos.sh" "${shift_args[@]}"
    fi
done

# ---------------------------------------------------------------------------
# Detect existing install — offer reinstall / upgrade / cancel.
# ---------------------------------------------------------------------------
if [[ -x /usr/local/bin/wireseal && -d "$VENV_DIR" ]]; then
    INSTALLED_VER="$("$VENV_DIR/bin/wireseal" --version 2>/dev/null | awk '{print $NF}' || echo unknown)"
    echo ""
    echo "[wireseal] Existing install detected (version: $INSTALLED_VER)."
    echo "  [r] Reinstall (overwrite venv + wrapper, keep vault)"
    echo "  [u] Uninstall (run uninstall-macos.sh)"
    echo "  [c] Cancel"
    read -rp "Choose [r/u/c]: " choice
    case "$choice" in
        r|R) echo "[wireseal] Proceeding with reinstall..." ;;
        u|U) exec bash "$SCRIPT_DIR/uninstall-macos.sh" ;;
        *)   echo "[wireseal] Cancelled."; exit 0 ;;
    esac
fi

# ---------------------------------------------------------------------------
# Release-asset integrity verification (SHA-256 + Ed25519 signature).
#
# Call `verify_release_asset "<file>" "<sha256_url>" "<sig_url>"` after every
# download of a pre-built release asset. Both a SHA-256 manifest and Ed25519
# signature are required. Missing, mismatched, or forged artifacts cause the
# downloaded file to be deleted and the script to exit with a pointer to the
# releases page for manual verification.
# ---------------------------------------------------------------------------
RELEASES_URL="https://github.com/prashanth-7861/WireSeal/releases"

# TODO: replace with real Ed25519 pubkey before v0.7.14 release
WIRESEAL_RELEASE_PUBKEY_B64='AAAAC3NzaC1lZDI1NTE5AAAAIPLACEHOLDER_REPLACE_BEFORE_RELEASE_v0_7_14====='

verify_release_asset() {
    local asset="$1"
    local sha256_url="$2"
    local sig_url="$3"
    local sha256_file="${asset}.sha256"
    local sig_file="${asset}.sig"
    local pubkey_file
    pubkey_file="$(mktemp)"

    if ! curl -fsSL -o "$sha256_file" "$sha256_url"; then
        rm -f "$asset" "$sha256_file" "$pubkey_file"
        error "Failed to download SHA-256 manifest for $asset — refusing to proceed."
        error "Verify manually: $RELEASES_URL"
        exit 1
    fi
    if ! curl -fsSL -o "$sig_file" "$sig_url"; then
        rm -f "$asset" "$sha256_file" "$sig_file" "$pubkey_file"
        error "Failed to download signature for $asset — refusing to proceed."
        error "Verify manually: $RELEASES_URL"
        exit 1
    fi

    # macOS ships `shasum` by default; fall back to sha256sum if coreutils installed.
    if command -v sha256sum &>/dev/null; then
        if ! (cd "$(dirname "$asset")" && sha256sum -c "$(basename "$sha256_file")"); then
            rm -f "$asset" "$sha256_file" "$sig_file" "$pubkey_file"
            error "SHA-256 mismatch for $asset — deleted."
            error "Manual verification: $RELEASES_URL"
            exit 1
        fi
    else
        if ! (cd "$(dirname "$asset")" && shasum -a 256 -c "$(basename "$sha256_file")"); then
            rm -f "$asset" "$sha256_file" "$sig_file" "$pubkey_file"
            error "SHA-256 mismatch for $asset — deleted."
            error "Manual verification: $RELEASES_URL"
            exit 1
        fi
    fi

    printf '%s' "$WIRESEAL_RELEASE_PUBKEY_B64" | base64 -D > "$pubkey_file" 2>/dev/null \
        || printf '%s' "$WIRESEAL_RELEASE_PUBKEY_B64" | base64 -d > "$pubkey_file" 2>/dev/null \
        || true
    if ! openssl pkeyutl -verify -pubin -inkey "$pubkey_file" \
            -rawin -in "$asset" -sigfile "$sig_file" &>/dev/null; then
        rm -f "$asset" "$sha256_file" "$sig_file" "$pubkey_file"
        error "Ed25519 signature verification failed for $asset — deleted."
        error "Manual verification: $RELEASES_URL"
        exit 1
    fi

    rm -f "$pubkey_file"
    info "Verified $asset (SHA-256 + Ed25519 signature)"
}

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
