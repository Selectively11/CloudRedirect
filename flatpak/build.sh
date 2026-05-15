#!/bin/bash
# Build script for CloudRedirect Flatpak
# Run this on a Linux system with flatpak-builder installed

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== CloudRedirect Flatpak Build ==="

# Check prerequisites - try native flatpak-builder first, then flatpak version
FLATPAK_BUILDER=""
if command -v flatpak-builder &> /dev/null; then
    FLATPAK_BUILDER="flatpak-builder"
elif flatpak list | grep -q "org.flatpak.Builder"; then
    FLATPAK_BUILDER="flatpak run org.flatpak.Builder"
else
    echo "Error: flatpak-builder not found. Install with:"
    echo "  flatpak install --user flathub org.flatpak.Builder"
    echo "  # or"
    echo "  sudo dnf install flatpak-builder  # Fedora"
    echo "  sudo apt install flatpak-builder  # Debian/Ubuntu"
    exit 1
fi

# Check for required runtime
if ! flatpak list --runtime | grep -q "org.kde.Platform.*6.7"; then
    echo "Installing KDE Platform 6.7 runtime..."
    flatpak install --user -y flathub org.kde.Platform//6.7 org.kde.Sdk//6.7
fi

# Check if .so exists
if [ ! -f "$SCRIPT_DIR/cloud_redirect.so" ]; then
    echo ""
    echo "Error: cloud_redirect.so not found in $SCRIPT_DIR"
    echo ""
    echo "You need to build the 32-bit .so separately. On a system with 32-bit support:"
    echo "  cd $PROJECT_ROOT"
    echo "  mkdir -p build-linux32 && cd build-linux32"
    echo "  cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32"
    echo "  make cloud_redirect"
    echo "  cp cloud_redirect.so $SCRIPT_DIR/"
    echo ""
    echo "Or copy a pre-built .so to: $SCRIPT_DIR/cloud_redirect.so"
    exit 1
fi

echo "Building Flatpak..."
cd "$SCRIPT_DIR"

$FLATPAK_BUILDER \
    --user \
    --install \
    --force-clean \
    build-dir \
    org.cloudredirect.CloudRedirect.yml

echo ""
echo "=== Build Complete ==="
echo ""
echo "Run with:"
echo "  flatpak run org.cloudredirect.CloudRedirect"
echo ""
echo "To create a distributable bundle:"
echo "  flatpak build-bundle ~/.local/share/flatpak/repo cloudredirect.flatpak org.cloudredirect.CloudRedirect"
