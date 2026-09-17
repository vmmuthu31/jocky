#!/usr/bin/env bash
# Build a .rpm package for JOCKY (requires rpmbuild)
set -euo pipefail

BIN="${1:-../../compiler/target/release/jocky-compile}"
VERSION="${2:-1.0.0}"

mkdir -p ~/rpmbuild/{SPECS,SOURCES,BUILD,RPMS,SRPMS}
cp "$BIN" ~/rpmbuild/SOURCES/jocky-compile
chmod 755 ~/rpmbuild/SOURCES/jocky-compile

sed "s/^Version:.*/Version:        $VERSION/" jocky.spec > ~/rpmbuild/SPECS/jocky.spec

rpmbuild -bb ~/rpmbuild/SPECS/jocky.spec
echo "RPM built in ~/rpmbuild/RPMS/"
find ~/rpmbuild/RPMS -name "*.rpm" | tail -1
