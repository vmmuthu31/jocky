#!/usr/bin/env sh
# JOCKY installer — downloads the latest release binary for the current platform.
# Usage: curl -fsSL https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.sh | sh

set -e

REPO="vmmuthu31/jocky"
INSTALL_DIR="/usr/local/bin"
BINARY="jocky-compile"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64)  ASSET="jocky-macos-arm64" ;;
      x86_64) ASSET="jocky-macos-x86_64" ;;
      *)      echo "Unsupported macOS architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64)  ASSET="jocky-linux-x86_64" ;;
      aarch64) ASSET="jocky-linux-arm64" ;;
      arm64)   ASSET="jocky-linux-arm64" ;;
      *)       echo "Unsupported Linux architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS"
    echo "On Windows, run: irm https://raw.githubusercontent.com/vmmuthu31/jocky/main/install.ps1 | iex"
    exit 1
    ;;
esac

# Fetch the latest release tag
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "Could not determine latest release. Check https://github.com/${REPO}/releases"
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
TMP="$(mktemp)"

echo "Downloading JOCKY ${LATEST} (${ASSET})..."
curl -fsSL "$URL" -o "$TMP"
chmod +x "$TMP"

# Install — try /usr/local/bin, fall back to ~/bin
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP" "${INSTALL_DIR}/${BINARY}"
  echo "Installed to ${INSTALL_DIR}/${BINARY}"
else
  mkdir -p "$HOME/.local/bin"
  mv "$TMP" "$HOME/.local/bin/${BINARY}"
  INSTALL_DIR="$HOME/.local/bin"
  echo "Installed to ${INSTALL_DIR}/${BINARY}"
  echo "Add the following to your shell profile if not already present:"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "Verify with:"
echo "  ${BINARY} --help"
echo ""
echo "Quick start (development mode):"
echo "  JOCKY_ALLOW_DEV_KEY=1 ${BINARY} compile --input scan.jocky --output scan.ll --target linux"
