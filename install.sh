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

# Check for uhid kernel support
if [ ! -c /dev/uhid ]; then
    echo -e "  ${YELLOW}!${NC} /dev/uhid character device does not exist yet. Attempting to load module..."
    sudo modprobe uhid || {
        echo -e "  ${RED}✗ Failed to load uhid kernel module.${NC}"
        exit 1
    }
fi
echo -e "  ${GREEN}✓${NC} /dev/uhid kernel interface is available."

# 2. Build release binary
echo -e "\n${BOLD}[2/5] Compiling release binary...${NC}"
if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${RED}Error: Cargo is not installed. Please install Rust (https://rustup.rs).${NC}"
    exit 1
fi

cd "$SCRIPT_DIR"
cargo build --release --bin cable-uhid-bridge

mkdir -p "$BIN_DEST"
cp "$SCRIPT_DIR/target/release/cable-uhid-bridge" "$BIN_DEST/cable-uhid-bridge"
chmod +x "$BIN_DEST/cable-uhid-bridge"
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
    
    # Ensure module loads automatically on boot
    if [ ! -f "$MODULES_CONF" ]; then
        echo "uhid" | sudo tee "$MODULES_CONF" >/dev/null || true
    fi

    sudo udevadm control --reload-rules
    sudo udevadm trigger -s misc -a name=uhid || true
    echo -e "  ${GREEN}✓${NC} Udev rule installed and reloaded."
else
    echo -e "  ${GREEN}✓${NC} Udev rule already properly configured."
fi

# 4. Systemd user service installation
echo -e "\n${BOLD}[4/5] Installing systemd user service...${NC}"
mkdir -p "$SERVICE_DEST"
cp "$SCRIPT_DIR/contrib/cable-uhid-bridge.service" "$SERVICE_DEST/cable-uhid-bridge.service"

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
    echo -e "• Uninstall anytime with: ${BOLD}./install.sh --uninstall${NC}\n"
else
    echo -e "  ${RED}✗ Service failed to start.${NC}"
    echo -e "Check logs with: ${BOLD}journalctl --user -u cable-uhid-bridge -n 20${NC}"
    exit 1
fi
