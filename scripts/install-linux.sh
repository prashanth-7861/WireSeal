#!/usr/bin/env bash
# WireSeal – Linux setup & launcher
# Supports: Arch/Manjaro, Fedora/RHEL/Rocky, Debian/Ubuntu
# Run as root or with sudo available.
# Usage: sudo bash install-linux.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$REPO_DIR/.venv"
MIN_PYTHON_MINOR=12
MAX_PYTHON_MINOR=14

# ---------------------------------------------------------------------------
# Uninstall passthrough
#
# Allow `bash install-linux.sh --uninstall [--purge] [--yes]` so users have a
# single discoverable entry point. Forward all remaining args to the dedicated
# uninstaller and exit.
# ---------------------------------------------------------------------------
for arg in "$@"; do
    if [[ "$arg" == "--uninstall" || "$arg" == "-u" ]]; then
        shift_args=()
        for a in "$@"; do
            [[ "$a" == "--uninstall" || "$a" == "-u" ]] && continue
            shift_args+=("$a")
        done
        exec bash "$SCRIPT_DIR/uninstall-linux.sh" "${shift_args[@]}"
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
    echo "  [u] Uninstall (run uninstall-linux.sh)"
    echo "  [c] Cancel"
    read -rp "Choose [r/u/c]: " choice
    case "$choice" in
        r|R) echo "[wireseal] Proceeding with reinstall..." ;;
        u|U) exec bash "$SCRIPT_DIR/uninstall-linux.sh" ;;
        *)   echo "[wireseal] Cancelled."; exit 0 ;;
    esac
fi

# ---------------------------------------------------------------------------
# Release-asset integrity verification (SHA-256 + Ed25519 signature).
#
# This infrastructure is invoked by verify_release_asset() whenever the script
# downloads a pre-built asset (e.g. via curl from a GitHub release). Both a
# SHA-256 manifest and an Ed25519 signature are required — the SHA-256 catches
# transport corruption, the signature guarantees authorship.
#
# Integration points (when release-asset flows are added): call
# `verify_release_asset "<file>" "<sha256_url>" "<sig_url>"` immediately after
# the download completes. On any failure the asset is deleted and the script
# exits with an actionable pointer to the releases page.
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

    if ! (cd "$(dirname "$asset")" && sha256sum -c "$(basename "$sha256_file")"); then
        rm -f "$asset" "$sha256_file" "$sig_file" "$pubkey_file"
        error "SHA-256 mismatch for $asset — deleted."
        error "Manual verification: $RELEASES_URL"
        exit 1
    fi

    printf '%s' "$WIRESEAL_RELEASE_PUBKEY_B64" | base64 -d > "$pubkey_file" 2>/dev/null || true
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
# 1. Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo bash install-linux.sh)"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Detect distro and install system packages
# ---------------------------------------------------------------------------
if command -v pacman &>/dev/null; then
    DISTRO="arch"
elif command -v dnf &>/dev/null; then
    DISTRO="fedora"
elif command -v apt-get &>/dev/null; then
    DISTRO="debian"
else
    DISTRO="unknown"
fi

install_system_deps() {
    info "Installing system dependencies (distro: $DISTRO)..."
    case "$DISTRO" in
        arch)
            pacman -Sy --noconfirm wireguard-tools nftables python python-pip ;;
        fedora)
            dnf install -y wireguard-tools nftables python3 python3-pip ;;
        debian)
            apt-get update -qq
            apt-get install -y wireguard wireguard-tools nftables python3 python3-pip python3-venv ;;
        *)
            warn "Unknown distro. Install wireguard-tools, nftables, python3 >= 3.12 manually."
            ;;
    esac
}

# Only install if wireguard-tools or python missing
if ! command -v wg &>/dev/null || ! command -v python3 &>/dev/null; then
    install_system_deps
fi

# ---------------------------------------------------------------------------
# 3. Find a suitable Python (3.12 – 3.14)
# ---------------------------------------------------------------------------
PYTHON=""
for candidate in python3.14 python3.13 python3.12 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(sys.version_info.minor)")
        maj=$("$candidate" -c "import sys; print(sys.version_info.major)")
        if [[ $maj -eq 3 && $ver -ge $MIN_PYTHON_MINOR && $ver -le $MAX_PYTHON_MINOR ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    error "Python 3.12–3.14 not found. Install it and re-run."
    exit 1
fi
info "Using Python: $PYTHON ($($PYTHON --version))"

# ---------------------------------------------------------------------------
# 4. Create virtual environment
# ---------------------------------------------------------------------------
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# ---------------------------------------------------------------------------
# 5. Install dependencies
# ---------------------------------------------------------------------------
info "Installing Python dependencies (this may take a minute)..."
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet -r "$REPO_DIR/requirements-dev.txt"
"$VENV_PIP" install --quiet -e "$REPO_DIR"

# ---------------------------------------------------------------------------
# 6. Install wireseal system-wide wrapper
# ---------------------------------------------------------------------------
WRAPPER=/usr/local/bin/wireseal
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/wireseal" "\$@"
EOF
chmod +x "$WRAPPER"
info "Installed system wrapper: $WRAPPER"

# ---------------------------------------------------------------------------
# 7. Enable & start nftables (needed for firewall rules)
# ---------------------------------------------------------------------------
if command -v systemctl &>/dev/null; then
    systemctl enable --now nftables 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 8. Run self-test (no vault required)
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
echo "  Add a client:              sudo wireseal add-client alice"
echo "  Show QR code (for iPhone): sudo wireseal show-qr alice"
echo "  List clients:              sudo wireseal list-clients"
echo "  Check status:              sudo wireseal status"
echo ""
