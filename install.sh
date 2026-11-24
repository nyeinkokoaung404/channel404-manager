#!/bin/bash
# Channel404 Manager
# Copyright (C) t.me/nkka404
set -u

REPO="nyeinkokoaung404/channel404-manager"
APP_FILE="channel404-manager.run"
APP_URL="${C404_APP_URL:-https://raw.githubusercontent.com/$REPO/main/$APP_FILE}"
APP_SHA256="935ea2bc13ec376307e93ceae4331edce220a077d20c45f7215c11b9801f43bc"
MENU_BIN="${MENU_BIN:-/usr/local/bin/menu}"

fail() { echo "❌ $*" >&2; exit 1; }
info() { echo "ℹ️ $*"; }

[[ $EUID -eq 0 ]] || fail "Run as root (sudo -i first)."

MISSING=()
for cmd in curl sha256sum tar gzip; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING+=("$cmd")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "Installing missing tools: ${MISSING[*]}"
    apt-get update >/dev/null 2>&1 || echo "⚠️ apt update had errors (a third-party repo may be broken) — trying install anyway..."
    apt-get install -y "${MISSING[@]}" >/dev/null 2>&1 || fail "Cannot install: ${MISSING[*]}. Install them manually and re-run."
fi

TMP_DIR="$(mktemp -d)" || fail "Cannot create temp dir."
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading $APP_FILE ..."
curl -fLsS -o "$TMP_DIR/$APP_FILE" "$APP_URL" || fail "Download failed: $APP_URL — is the file on GitHub main yet?"

if [[ -n "$APP_SHA256" ]]; then
    info "Verifying checksum..."
    echo "$APP_SHA256  $TMP_DIR/$APP_FILE" | sha256sum -c - >/dev/null 2>&1 \
        || fail "Checksum mismatch — the download may be corrupted or tampered with. Aborting."
    info "Checksum OK."
fi

chmod +x "$TMP_DIR/$APP_FILE"
info "Installing Channel404 Manager..."
"$TMP_DIR/$APP_FILE" || fail "Installer failed."

[[ -x "$MENU_BIN" ]] || fail "Install finished but $MENU_BIN is missing."
