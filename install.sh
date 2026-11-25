#!/bin/bash
# Channel404 Manager
# Copyright (C) t.me/nkka404
set -u

REPO="nyeinkokoaung404/channel404-manager"
TAG="v1.0.2"
RELEASE_BASE="${C404_RELEASE_BASE:-https://github.com/$REPO/releases/download/$TAG}"
MENU_BIN="${MENU_BIN:-/usr/local/bin/menu}"

fail() { echo "❌ $*" >&2; exit 1; }
info() { echo "ℹ️ $*"; }

[[ $EUID -eq 0 ]] || fail "Run as root (sudo -i first)."

# --- Architecture -------------------------------------------------------
ARCH="${C404_ARCH:-}"
if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) fail "Unsupported architecture: $(uname -m) — Channel404 Manager ships amd64 and arm64 binaries only." ;;
    esac
fi
case "$ARCH" in
    amd64|arm64) ;;
    *) fail "Unsupported architecture: $ARCH — Channel404 Manager ships amd64 and arm64 binaries only." ;;
esac

APP_FILE="channel404-linux-$ARCH"
APP_URL="${C404_APP_URL:-$RELEASE_BASE/$APP_FILE}"
SHA256SUMS_URL="${C404_SHA256SUMS_URL:-$RELEASE_BASE/SHA256SUMS}"

MISSING=()
for cmd in curl sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING+=("$cmd")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "Installing missing tools: ${MISSING[*]}"
    apt-get update >/dev/null 2>&1 || echo "⚠️ apt update had errors (a third-party repo may be broken) — trying install anyway..."
    apt-get install -y "${MISSING[@]}" >/dev/null 2>&1 || fail "Cannot install: ${MISSING[*]}. Install them manually and re-run."
fi

TMP_DIR="$(mktemp -d)" || fail "Cannot create temp dir."
trap 'rm -rf "$TMP_DIR"' EXIT

# --- Download -----------------------------------------------------------
info "Downloading $APP_FILE ($ARCH) ..."
curl -fLsS -o "$TMP_DIR/$APP_FILE" "$APP_URL" || fail "Download failed: $APP_URL — is the v$TAG release published yet?"

# --- Checksum -----------------------------------------------------------
if [[ -n "${C404_APP_SHA256:-}" ]]; then
    APP_SHA256="$C404_APP_SHA256"
else
    info "Fetching published checksums..."
    curl -fLsS -o "$TMP_DIR/SHA256SUMS" "$SHA256SUMS_URL" || fail "Cannot fetch checksums: $SHA256SUMS_URL"
    APP_SHA256="$(awk -v f="$APP_FILE" '$2 == f { print $1 }' "$TMP_DIR/SHA256SUMS")"
    [[ -n "$APP_SHA256" ]] || fail "No checksum entry for $APP_FILE in the published SHA256SUMS."
fi
info "Verifying checksum..."
echo "$APP_SHA256  $TMP_DIR/$APP_FILE" | sha256sum -c - >/dev/null 2>&1 \
    || fail "Checksum mismatch — the download may be corrupted or tampered with. Aborting."
info "Checksum OK."

# --- Architecture sanity check (best effort, when `file` exists) --------
if command -v file >/dev/null 2>&1; then
    case "$ARCH" in
        amd64) file "$TMP_DIR/$APP_FILE" | grep -q "x86-64" || fail "Downloaded binary is not an x86-64 executable — wrong architecture. Aborting." ;;
        arm64) file "$TMP_DIR/$APP_FILE" | grep -q "ARM aarch64" || fail "Downloaded binary is not an ARM aarch64 executable — wrong architecture. Aborting." ;;
    esac
fi

# --- Install ------------------------------------------------------------
chmod +x "$TMP_DIR/$APP_FILE"
info "Installing Channel404 Manager to $MENU_BIN ..."
install -m 0755 "$TMP_DIR/$APP_FILE" "$MENU_BIN" || fail "Cannot install to $MENU_BIN."
[[ -x "$MENU_BIN" ]] || fail "Install finished but $MENU_BIN is missing."

# --- First-time setup ----------------------------------------------------
if [[ "${C404_SETUP:-1}" == "0" ]]; then
    info "C404_SETUP=0 — skipping --install-setup (test mode)."
else
    "$MENU_BIN" --install-setup || fail "First-time setup failed."
fi

echo "✅ Channel404 Manager installed."
echo "Run: menu"
printf '\033[1;36m👨‍💻 Developed by t.me/nkka404\033[0m\n'
