#!/bin/bash

# WiFiSniper System Tools Installation Script
# This script installs all required system tools for WiFiSniper

echo "WiFiSniper - System Tools Installer"
echo "==================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)" >&2
   echo "Usage: sudo ./install_tools.sh"
   exit 1
fi

echo "Updating package lists..."
apt update

echo "Installing WiFiSniper system dependencies..."
echo ""

# Install aircrack-ng suite
echo "Installing aircrack-ng..."
apt install -y aircrack-ng

# Install network scanning tools
echo "Installing nmap..."
apt install -y nmap

# Install access point tools
echo "Installing hostapd and dnsmasq..."
apt install -y hostapd dnsmasq

# Install WPS tools
echo "Installing reaver..."
apt install -y reaver

# Install packet analysis tools
echo "Installing wireshark-common..."
apt install -y wireshark-common

# Install Bluetooth tools (optional)
echo "Installing Bluetooth tools..."
apt install -y bluetooth bluez-utils

echo ""
echo "Installation completed!"
echo ""
echo "Next steps:"
echo "1. Install Python dependencies: pip install -r requirements.txt"
echo "2. Run WiFiSniper: sudo python3 wifisniper.py"
echo ""
echo "Note: You may need to configure your wireless adapters for monitor mode."