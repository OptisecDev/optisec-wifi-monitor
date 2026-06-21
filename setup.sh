#!/usr/bin/env bash
# Optisec WiFi Monitor - Setup Script for BlackArch Linux

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║     OPTISEC WiFi MONITOR - Setup Script       ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This setup script must be run as root.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Updating system packages...${NC}"
pacman -Sy --noconfirm 2>/dev/null || true

echo -e "${GREEN}[+] Installing system dependencies...${NC}"
pacman -S --noconfirm --needed \
    python python-pip \
    aircrack-ng \
    nmap \
    net-tools \
    wireless_tools \
    iw \
    2>/dev/null || true

echo -e "${GREEN}[+] Installing Python dependencies...${NC}"
pip install -r requirements.txt --break-system-packages 2>/dev/null || \
pip install -r requirements.txt

# Create config directory
CONFIG_DIR="/etc/optisec"
DATA_DIR="/var/lib/optisec"
mkdir -p "$CONFIG_DIR" "$DATA_DIR"

# Create default config
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    cat > "$CONFIG_DIR/config.json" << 'EOF'
{
    "monitor_interface": "wlan1",
    "internet_interface": "wlan0",
    "openrouter_api_key": "",
    "language": "en",
    "whitelist": [],
    "alert_thresholds": {
        "deauth_flood_count": 10,
        "deauth_flood_window": 60,
        "arp_rate_limit": 50,
        "new_device_alert": true
    },
    "web_port": 5000,
    "db_path": "/var/lib/optisec/optisec.db"
}
EOF
    echo -e "${GREEN}[+] Default config created at $CONFIG_DIR/config.json${NC}"
fi

# Create systemd service
cat > /etc/systemd/system/optisec-wifi.service << EOF
[Unit]
Description=Optisec WiFi Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python $(pwd)/main.py both
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}[+] Systemd service created.${NC}"
echo -e "${YELLOW}    Enable with: systemctl enable optisec-wifi${NC}"
echo -e "${YELLOW}    Start with:  systemctl start optisec-wifi${NC}"

# Set permissions
chmod +x main.py
chmod 700 "$CONFIG_DIR"
chmod 755 "$DATA_DIR"

echo ""
echo -e "${GREEN}[+] Setup complete!${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo "  sudo python main.py tui              # Rich TUI dashboard"
echo "  sudo python main.py web              # Flask web dashboard (port 5000)"
echo "  sudo python main.py both             # Both TUI + Web"
echo "  sudo python main.py config           # Interactive configuration"
echo ""
echo -e "${YELLOW}[!] Remember to set your OpenRouter API key in $CONFIG_DIR/config.json${NC}"
echo -e "${YELLOW}[!] Set monitor interface to monitor mode: airmon-ng start wlan1${NC}"
