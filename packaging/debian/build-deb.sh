#!/usr/bin/env bash
# Build a .deb package for JOCKY
# Usage: ./packaging/debian/build-deb.sh <binary-path> <version>
set -euo pipefail

BIN="${1:-../compiler/target/release/jocky-compile}"
VERSION="${2:-1.0.0}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
PKG="jocky_${VERSION}_${ARCH}"

mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/bin"
mkdir -p "$PKG/usr/share/doc/jocky"
mkdir -p "$PKG/usr/share/jocky/examples"

# Binary
cp "$BIN" "$PKG/usr/bin/jocky-compile"
chmod 755 "$PKG/usr/bin/jocky-compile"

# Control
sed "s/Version: .*/Version: $VERSION/" \
    "$(dirname "$0")/control" > "$PKG/DEBIAN/control"
echo "Architecture: $ARCH" >> "$PKG/DEBIAN/control"

# Changelog / copyright
cp ../../README.md "$PKG/usr/share/doc/jocky/README.md" 2>/dev/null || true
cat > "$PKG/usr/share/doc/jocky/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: jocky
Source: https://github.com/vmmuthu31/jocky
License: MIT
EOF

# Post-install script
cat > "$PKG/DEBIAN/postinst" << 'EOF'
#!/bin/sh
echo "JOCKY installed. Run: jocky-compile --help"
echo "Docs: https://github.com/vmmuthu31/jocky/blob/main/docs/getting-started.md"
EOF
chmod 755 "$PKG/DEBIAN/postinst"

dpkg-deb --build "$PKG"
echo "Built: ${PKG}.deb"
