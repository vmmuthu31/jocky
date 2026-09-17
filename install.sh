#!/usr/bin/env sh
# JOCKY installer — macOS & Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh
set -e

REPO="vmmuthu31/jocky"
BIN_NAME="jocky-compile"
INSTALL_DIR="${JOCKY_INSTALL_DIR:-/usr/local/bin}"

# Detect OS + arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64)  ARTIFACT="jocky-linux-x86_64" ;;
      aarch64) ARTIFACT="jocky-linux-arm64" ;;
      *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      x86_64)  ARTIFACT="jocky-macos-x86_64" ;;
      arm64)   ARTIFACT="jocky-macos-arm64" ;;
      *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS" && exit 1 ;;
esac

# Get latest release tag
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | cut -d'"' -f4)

if [ -z "$LATEST" ]; then
  echo "Could not fetch latest release. Check https://github.com/${REPO}/releases"
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARTIFACT}"

echo "Installing JOCKY ${LATEST} (${ARTIFACT})..."
echo "From: ${URL}"
echo "To:   ${INSTALL_DIR}/${BIN_NAME}"

TMP="$(mktemp)"
curl -fsSL "$URL" -o "$TMP"
chmod +x "$TMP"

# Try to install without sudo, fall back with sudo
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}"
else
  echo "Need sudo to write to ${INSTALL_DIR}:"
  sudo mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}"
fi

echo ""
echo "✓ JOCKY installed → ${INSTALL_DIR}/${BIN_NAME}"
echo ""
echo "Quick start:"
echo "  jocky-compile --help"
echo "  jocky-compile new triage --output my_scan.jocky"
echo "  jocky-compile compile --input my_scan.jocky --output out.ll --target linux"
