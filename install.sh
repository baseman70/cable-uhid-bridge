#!/usr/bin/env bash
# ==============================================================================
# cable-uhid-bridge Installer
# https://github.com/baseman70/cable-uhid-bridge
# ==============================================================================
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DEST="$HOME/.local/bin"
SERVICE_DEST="$HOME/.config/systemd/user"
UDEV_RULE_SRC="$SCRIPT_DIR/contrib/70-uhid.rules"
UDEV_RULE_DEST="/etc/udev/rules.d/70-uhid.rules"
MODULES_CONF="/etc/modules-load.d/uhid.conf"

print_header() {
    echo -e "${BOLD}${BLUE}==========================================================${NC}"
    echo -e "${BOLD}${BLUE}  cable-uhid-bridge: Installer & Service Manager          ${NC}"
    echo -e "${BOLD}${BLUE}==========================================================${NC}\n"
}

uninstall() {
    print_header
    echo -e "${YELLOW}Uninstalling cable-uhid-bridge...${NC}"

    if systemctl --user is-active --quiet cable-uhid-bridge.service 2>/dev/null; then
        echo -e "Stopping systemd user service..."
        systemctl --user stop cable-uhid-bridge.service || true
    fi

    if systemctl --user is-enabled --quiet cable-uhid-bridge.service 2>/dev/null; then
        echo -e "Disabling systemd user service..."
        systemctl --user disable cable-uhid-bridge.service || true
    fi

    if [ -f "$SERVICE_DEST/cable-uhid-bridge.service" ]; then
        echo -e "Removing service unit: $SERVICE_DEST/cable-uhid-bridge.service"
        rm -f "$SERVICE_DEST/cable-uhid-bridge.service"
        systemctl --user daemon-reload
    fi

    if [ -f "$BIN_DEST/cable-uhid-bridge" ]; then
        echo -e "Removing binary: $BIN_DEST/cable-uhid-bridge"
        rm -f "$BIN_DEST/cable-uhid-bridge"
    fi

    echo -e "\n${GREEN}✅ User-level components uninstalled successfully.${NC}"
    echo -e "${YELLOW}Note: The udev rule ($UDEV_RULE_DEST) was preserved.${NC}"
    echo -e "To remove it completely, run: ${BOLD}sudo rm -f $UDEV_RULE_DEST && sudo udevadm control --reload-rules${NC}\n"
    exit 0
}

# Handle --uninstall
if [[ "${1:-}" == "--uninstall" ]] || [[ "${1:-}" == "-u" ]]; then
    uninstall
fi

print_header

# 1. Preflight checks
echo -e "${BOLD}[1/5] Checking system prerequisites...${NC}"

# Check for Rust / Cargo
if ! command -v cargo >/dev/null 2>&1; then
    echo -e "  ${RED}✗ Cargo is not installed.${NC}"
    echo -e "  Please install Rust via rustup: ${BOLD}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Rust & Cargo found."

# Check for C build dependencies
MISSING_DEPS=()

if ! command -v pkg-config >/dev/null 2>&1 && ! command -v pkgconf >/dev/null 2>&1; then
    MISSING_DEPS+=("pkg-config")
else
    if ! pkg-config --exists dbus-1 2>/dev/null; then
        MISSING_DEPS+=("libdbus-1-dev (dbus development headers)")
    fi
    if ! pkg-config --exists xkbcommon 2>/dev/null; then
        MISSING_DEPS+=("libxkbcommon-dev (Wayland/X11 keyboard headers)")
    fi
fi

# Check for libclang (needed by bindgen / uhidrs-sys)
HAS_LIBCLANG=false
if [ -n "${LIBCLANG_PATH:-}" ] && [ -d "$LIBCLANG_PATH" ]; then
    HAS_LIBCLANG=true
elif command -v llvm-config >/dev/null 2>&1; then
    HAS_LIBCLANG=true
elif ldconfig -p 2>/dev/null | grep -q "libclang\.so"; then
    HAS_LIBCLANG=true
elif ls /usr/lib*/libclang*.so* >/dev/null 2>&1 || ls /usr/lib/llvm-*/lib/libclang*.so* >/dev/null 2>&1; then
    HAS_LIBCLANG=true
fi

if [ "$HAS_LIBCLANG" = false ]; then
    MISSING_DEPS+=("libclang-dev (LLVM/Clang development library)")
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}! Missing required C build dependencies:${NC}"
    for dep in "${MISSING_DEPS[@]}"; do
        echo -e "    - $dep"
    done
    echo ""

    if command -v apt-get >/dev/null 2>&1; then
        INSTALL_CMD="sudo apt update && sudo apt install -y build-essential pkg-config libdbus-1-dev libclang-dev libxkbcommon-dev"
        echo -e "  To install missing packages on Debian/Ubuntu/Pop!_OS, run:\n    ${BOLD}$INSTALL_CMD${NC}\n"
        if [ -t 0 ]; then
            read -rp "  Would you like to install them now using apt? [y/N] " response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                sudo apt update && sudo apt install -y build-essential pkg-config libdbus-1-dev libclang-dev libxkbcommon-dev
            else
                echo -e "  ${RED}Aborting install until prerequisites are installed.${NC}"
                exit 1
            fi
        else
            exit 1
        fi
    elif command -v pacman >/dev/null 2>&1; then
        INSTALL_CMD="sudo pacman -S --needed base-devel pkgconf dbus clang libxkbcommon"
        echo -e "  To install missing packages on Arch/Manjaro, run:\n    ${BOLD}$INSTALL_CMD${NC}\n"
        if [ -t 0 ]; then
            read -rp "  Would you like to install them now using pacman? [y/N] " response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                sudo pacman -S --needed base-devel pkgconf dbus clang libxkbcommon
            else
                echo -e "  ${RED}Aborting install until prerequisites are installed.${NC}"
                exit 1
            fi
        else
            exit 1
        fi
    elif command -v dnf >/dev/null 2>&1; then
        INSTALL_CMD="sudo dnf install -y gcc pkgconf-pkg-config dbus-devel clang-devel libxkbcommon-devel"
        echo -e "  To install missing packages on Fedora/RHEL, run:\n    ${BOLD}$INSTALL_CMD${NC}\n"
        if [ -t 0 ]; then
            read -rp "  Would you like to install them now using dnf? [y/N] " response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                sudo dnf install -y gcc pkgconf-pkg-config dbus-devel clang-devel libxkbcommon-devel
            else
                echo -e "  ${RED}Aborting install until prerequisites are installed.${NC}"
                exit 1
            fi
        else
            exit 1
        fi
    else
        echo -e "  ${RED}Please install the missing C libraries listed above using your system package manager.${NC}"
        exit 1
    fi
fi
echo -e "  ${GREEN}✓${NC} C build libraries (libdbus, libclang, libxkbcommon) verified."

# Check for Bluetooth
if command -v bluetoothctl >/dev/null 2>&1; then
    if bluetoothctl show 2>&1 | grep -q "Powered: yes"; then
        echo -e "  ${GREEN}✓${NC} Bluetooth controller is powered on (required for caBLE BLE proximity)."
    else
        echo -e "  ${YELLOW}!${NC} Bluetooth is present but not powered on. Please ensure Bluetooth is enabled for caBLE proximity."
    fi
else
    echo -e "  ${YELLOW}!${NC} 'bluetoothctl' not found. Bluetooth LE proximity may not be available."
fi

# Check for uhid kernel module support in sysfs (do not rely on static devtmpfs /dev/uhid node)
if [ ! -d /sys/class/misc/uhid ]; then
    echo -e "  ${YELLOW}!${NC} uhid kernel module is not loaded. Loading module..."
    sudo modprobe uhid || {
        echo -e "  ${RED}✗ Failed to load uhid kernel module.${NC}"
        echo -e "  Please ensure your Linux kernel supports CONFIG_UHID."
        exit 1
    }
fi
echo -e "  ${GREEN}✓${NC} /dev/uhid kernel interface is active in sysfs."

# 2. Build release binary
echo -e "\n${BOLD}[2/5] Compiling release binary...${NC}"
cd "$SCRIPT_DIR"
cargo build --release --bin cable-uhid-bridge

# If the user service is currently running, stop it prior to replacing binary to avoid ETXTBSY
if systemctl --user is-active --quiet cable-uhid-bridge.service 2>/dev/null; then
    echo -e "  Stopping running service for binary update..."
    systemctl --user stop cable-uhid-bridge.service || true
fi

mkdir -p "$BIN_DEST"
install -m 755 "$SCRIPT_DIR/target/release/cable-uhid-bridge" "$BIN_DEST/cable-uhid-bridge"
echo -e "  ${GREEN}✓${NC} Installed binary to: ${BOLD}$BIN_DEST/cable-uhid-bridge${NC}"

# 3. Udev rule installation
echo -e "\n${BOLD}[3/5] Configuring udev rules for non-root /dev/uhid access...${NC}"
NEEDS_UDEV_UPDATE=false

if [ ! -f "$UDEV_RULE_DEST" ]; then
    NEEDS_UDEV_UPDATE=true
elif ! grep -q 'TAG+="uaccess"' "$UDEV_RULE_DEST"; then
    NEEDS_UDEV_UPDATE=true
fi

if [ "$NEEDS_UDEV_UPDATE" = true ]; then
    echo -e "  Configuring $UDEV_RULE_DEST (requires sudo for udev rules)..."
    sudo cp "$UDEV_RULE_SRC" "$UDEV_RULE_DEST"
    sudo chmod 644 "$UDEV_RULE_DEST"
fi

# Ensure module loads automatically on boot
if [ ! -f "$MODULES_CONF" ] || ! grep -q "^uhid" "$MODULES_CONF" 2>/dev/null; then
    echo -e "  Configuring automatic module loading on boot ($MODULES_CONF)..."
    echo "uhid" | sudo tee "$MODULES_CONF" >/dev/null || true
fi

sudo udevadm control --reload-rules
sudo udevadm trigger -s misc -a name=uhid || true
sudo udevadm settle || true

# Test /dev/uhid permissions for current user
if [ -w /dev/uhid ] && [ -r /dev/uhid ]; then
    echo -e "  ${GREEN}✓${NC} Udev rule active and /dev/uhid is read/writable by $USER."
else
    echo -e "  ${YELLOW}!${NC} Note: /dev/uhid may require a re-login or seat activation for dynamic ACLs."
fi

# 4. Systemd user service installation
echo -e "\n${BOLD}[4/5] Installing systemd user service...${NC}"
mkdir -p "$SERVICE_DEST"
install -m 644 "$SCRIPT_DIR/contrib/cable-uhid-bridge.service" "$SERVICE_DEST/cable-uhid-bridge.service"

systemctl --user daemon-reload
systemctl --user enable --now cable-uhid-bridge.service
echo -e "  ${GREEN}✓${NC} Service enabled and started: ${BOLD}cable-uhid-bridge.service${NC}"

# 5. Health verification
echo -e "\n${BOLD}[5/5] Verifying service status...${NC}"
sleep 1
if systemctl --user is-active --quiet cable-uhid-bridge.service; then
    echo -e "  ${GREEN}✓${NC} cable-uhid-bridge is running actively in the background!"
    echo -e "\n${BOLD}${GREEN}==========================================================${NC}"
    echo -e "${BOLD}${GREEN}  Installation Complete!                                 ${NC}"
    echo -e "${BOLD}${GREEN}==========================================================${NC}"
    echo -e "• Passkey requests in Firefox, Chrome, and Edge will now pop up automatically."
    echo -e "• View live service logs with: ${BOLD}journalctl --user -u cable-uhid-bridge -f${NC}"
    echo -e "• Stop the service anytime with: ${BOLD}systemctl --user stop cable-uhid-bridge${NC}"
    echo -e "• Restart service anytime with: ${BOLD}systemctl --user restart cable-uhid-bridge${NC}"
    echo -e "• Uninstall anytime with: ${BOLD}./install.sh --uninstall${NC}\n"
else
    echo -e "  ${RED}✗ Service failed to start.${NC}"
    echo -e "Check logs with: ${BOLD}journalctl --user -u cable-uhid-bridge -n 20${NC}"
    exit 1
fi
