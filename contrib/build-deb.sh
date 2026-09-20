#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=$(grep '^version = ' "$SCRIPT_DIR/Cargo.toml" | cut -d '"' -f2)
ARCH="amd64"
PACKAGE_NAME="cable-uhid-bridge_${VERSION}_${ARCH}"
BUILD_DIR="$SCRIPT_DIR/target/debian/$PACKAGE_NAME"

echo "Building Debian package: $PACKAGE_NAME.deb"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "Error: 'dpkg-deb' is required to build .deb packages."
    echo "On Debian/Ubuntu: sudo apt install dpkg"
    echo "On Arch Linux: yay -S dpkg"
    exit 1
fi

# 1. Ensure release binary is compiled
if [ ! -f "$SCRIPT_DIR/target/release/cable-uhid-bridge" ]; then
    echo "Compiling release binary..."
    cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"
fi

# 2. Prepare staging directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/lib/systemd/user"
mkdir -p "$BUILD_DIR/usr/lib/udev/rules.d"
mkdir -p "$BUILD_DIR/usr/lib/modules-load.d"
mkdir -p "$BUILD_DIR/usr/share/doc/cable-uhid-bridge"

# 3. Copy assets
install -m 755 "$SCRIPT_DIR/target/release/cable-uhid-bridge" "$BUILD_DIR/usr/bin/cable-uhid-bridge"
install -m 644 "$SCRIPT_DIR/contrib/cable-uhid-bridge.service" "$BUILD_DIR/usr/lib/systemd/user/cable-uhid-bridge.service"
install -m 644 "$SCRIPT_DIR/contrib/70-uhid.rules" "$BUILD_DIR/usr/lib/udev/rules.d/70-uhid.rules"
install -m 644 "$SCRIPT_DIR/contrib/uhid.conf" "$BUILD_DIR/usr/lib/modules-load.d/uhid.conf"
install -m 644 "$SCRIPT_DIR/README.md" "$BUILD_DIR/usr/share/doc/cable-uhid-bridge/README.md"
install -m 644 "$SCRIPT_DIR/LICENSE-MIT" "$BUILD_DIR/usr/share/doc/cable-uhid-bridge/copyright"

# 4. Copy package control scripts
sed "s/^Version: .*/Version: $VERSION/" "$SCRIPT_DIR/contrib/debian/control" > "$BUILD_DIR/DEBIAN/control"
install -m 755 "$SCRIPT_DIR/contrib/debian/postinst" "$BUILD_DIR/DEBIAN/postinst"
install -m 755 "$SCRIPT_DIR/contrib/debian/postrm" "$BUILD_DIR/DEBIAN/postrm"

# 5. Build package
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$SCRIPT_DIR/target/debian/$PACKAGE_NAME.deb"
echo "✅ Debian package created: $SCRIPT_DIR/target/debian/$PACKAGE_NAME.deb"
