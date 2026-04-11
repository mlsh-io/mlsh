#!/bin/sh
set -e

# mlsh installer
# Usage: curl -sSL https://get.mlsh.io | sh -
#
# Environment variables:
#   INSTALL_MLSH_VERSION   - specific version to install (e.g. "v0.1.0"), default: latest
#   INSTALL_MLSH_BIN_DIR   - directory to install into, default: /usr/local/bin
#   INSTALL_MLSH_SKIP_DAEMON - if set to "true", skip mlshtund symlink

GITHUB_REPO="mlsh-io/mlsh"
BIN_NAME="mlsh"
DAEMON_NAME="mlshtund"

# --- logging helpers ---
info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*" >&2; }
fatal() { echo "[ERROR] $*" >&2; exit 1; }

# --- detect OS ---
detect_os() {
    case "$(uname -s)" in
        Darwin)  echo "darwin" ;;
        Linux)   echo "linux" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) fatal "Unsupported operating system: $(uname -s)" ;;
    esac
}

# --- detect architecture ---
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64" ;;
        arm64|aarch64)  echo "aarch64" ;;
        *) fatal "Unsupported architecture: $(uname -m)" ;;
    esac
}

# --- map OS/arch to Rust target triple ---
get_target() {
    local os="$1"
    local arch="$2"

    case "${os}-${arch}" in
        darwin-aarch64) echo "aarch64-apple-darwin" ;;
        darwin-x86_64)  echo "x86_64-apple-darwin" ;;
        linux-x86_64)   echo "x86_64-unknown-linux-musl" ;;
        linux-aarch64)  echo "aarch64-unknown-linux-musl" ;;
        windows-x86_64) echo "x86_64-pc-windows-msvc" ;;
        *) fatal "No prebuilt binary for ${os}/${arch}" ;;
    esac
}

# --- find a downloader ---
verify_downloader() {
    if command -v curl >/dev/null 2>&1; then
        DOWNLOADER="curl"
        return
    fi
    if command -v wget >/dev/null 2>&1; then
        DOWNLOADER="wget"
        return
    fi
    fatal "curl or wget is required"
}

# --- download a URL to a file ---
download() {
    local url="$1"
    local dest="$2"
    case "${DOWNLOADER}" in
        curl) curl -fsSL -o "$dest" "$url" ;;
        wget) wget -qO "$dest" "$url" ;;
    esac
}

# --- resolve latest version from GitHub API ---
get_latest_version() {
    local url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local tmp
    tmp="$(mktemp)"
    download "$url" "$tmp"
    # extract tag_name without jq dependency
    TAG=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp" | head -n1)
    rm -f "$tmp"
    if [ -z "$TAG" ]; then
        fatal "Could not determine latest release. Set INSTALL_MLSH_VERSION explicitly."
    fi
    echo "$TAG"
}

# --- main ---
main() {
    verify_downloader

    OS=$(detect_os)
    ARCH=$(detect_arch)
    TARGET=$(get_target "$OS" "$ARCH")

    VERSION="${INSTALL_MLSH_VERSION:-}"
    if [ -z "$VERSION" ]; then
        info "Finding latest release..."
        VERSION=$(get_latest_version)
    fi
    info "Installing mlsh ${VERSION} for ${TARGET}"

    BIN_DIR="${INSTALL_MLSH_BIN_DIR:-/usr/local/bin}"

    # determine archive extension
    case "$OS" in
        windows) EXT="zip" ;;
        *)       EXT="tar.gz" ;;
    esac

    ARCHIVE="mlsh-cli-${TARGET}.${EXT}"
    URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${ARCHIVE}"

    TMP_DIR=$(mktemp -d)
    trap "rm -rf ${TMP_DIR}" EXIT

    info "Downloading ${URL}"
    download "$URL" "${TMP_DIR}/${ARCHIVE}"

    # --- verify checksum if available ---
    CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/checksums.txt"
    if download "$CHECKSUM_URL" "${TMP_DIR}/checksums.txt" 2>/dev/null; then
        info "Verifying checksum..."
        EXPECTED=$(grep "${ARCHIVE}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            if command -v sha256sum >/dev/null 2>&1; then
                ACTUAL=$(sha256sum "${TMP_DIR}/${ARCHIVE}" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then
                ACTUAL=$(shasum -a 256 "${TMP_DIR}/${ARCHIVE}" | awk '{print $1}')
            else
                warn "No sha256sum or shasum found, skipping checksum verification"
                ACTUAL="$EXPECTED"
            fi
            if [ "$EXPECTED" != "$ACTUAL" ]; then
                fatal "Checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}"
            fi
            info "Checksum OK"
        fi
    fi

    # --- extract ---
    info "Extracting..."
    case "$EXT" in
        tar.gz)
            tar xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"
            ;;
        zip)
            unzip -qo "${TMP_DIR}/${ARCHIVE}" -d "${TMP_DIR}"
            ;;
    esac

    # --- install ---
    SUDO=""
    if [ "$(id -u)" -ne 0 ] && [ ! -w "$BIN_DIR" ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
            info "Elevated permissions required to install to ${BIN_DIR}"
        else
            fatal "Cannot write to ${BIN_DIR} and sudo is not available. Set INSTALL_MLSH_BIN_DIR to a writable directory."
        fi
    fi

    $SUDO mkdir -p "$BIN_DIR"

    case "$OS" in
        windows)
            $SUDO cp "${TMP_DIR}/mlsh.exe" "${BIN_DIR}/mlsh.exe"
            $SUDO cp "${TMP_DIR}/mlshtund.exe" "${BIN_DIR}/mlshtund.exe"
            ;;
        *)
            $SUDO install -m 755 "${TMP_DIR}/mlsh" "${BIN_DIR}/mlsh"
            if [ "${INSTALL_MLSH_SKIP_DAEMON:-}" != "true" ]; then
                $SUDO ln -sf "${BIN_DIR}/mlsh" "${BIN_DIR}/mlshtund"
            fi
            ;;
    esac

    info "Installed mlsh to ${BIN_DIR}/mlsh"

    # --- verify ---
    if command -v mlsh >/dev/null 2>&1; then
        info "$(mlsh --version 2>/dev/null || echo 'mlsh installed successfully')"
    else
        warn "mlsh was installed to ${BIN_DIR} but is not in your PATH"
        warn "Add it with: export PATH=\"${BIN_DIR}:\$PATH\""
    fi
}

main "$@"
