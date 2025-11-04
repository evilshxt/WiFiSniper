"""
Monitor Mode Management Module
Handle enabling/disabling monitor mode on wireless adapters
"""

import subprocess
import re
from core.logger import Logger
from utils.helpers import run_command, ensure_root_privileges, get_user_confirmation

logger = Logger()

class MonitorModeManager:
    def __init__(self):
        self.logger = logger

    def scan_adapters(self):
        """
        Scan for available wireless adapters
        Returns list of adapter info dicts
        """
        self.logger.info("Scanning for wireless adapters...")

        success, output, error = run_command("iwconfig")
        if not success:
            self.logger.error("Failed to scan adapters")
            return []

        adapters = []
        lines = output.split('\n')

        for line in lines:
            if 'IEEE 802.11' in line or 'unassociated' in line:
                # Extract interface name
                match = re.match(r'(\w+)\s+', line)
                if match:
                    interface = match.group(1)
                    adapters.append({
                        'interface': interface,
                        'description': line.strip()
                    })

        if not adapters:
            self.logger.warning("No wireless adapters found")
        else:
            self.logger.success(f"Found {len(adapters)} wireless adapter(s)")

        return adapters

    def get_adapter_info(self, interface):
        """
        Get detailed information about a specific adapter
        """
        success, output, error = run_command(f"iwconfig {interface}")
        if not success:
            return None

        info = {
            'interface': interface,
            'mode': 'unknown',
            'frequency': 'unknown',
            'access_point': 'unknown',
            'bit_rate': 'unknown'
        }

        for line in output.split('\n'):
            line = line.strip()
            if 'Mode:' in line:
                mode_match = re.search(r'Mode:(\w+)', line)
                if mode_match:
                    info['mode'] = mode_match.group(1)
            elif 'Frequency:' in line:
                freq_match = re.search(r'Frequency:([\d\.]+)', line)
                if freq_match:
                    info['frequency'] = freq_match.group(1)
            elif 'Access Point:' in line:
                ap_match = re.search(r'Access Point: ([0-9A-Fa-f:]+)', line)
                if ap_match:
                    info['access_point'] = ap_match.group(1)
            elif 'Bit Rate=' in line:
                rate_match = re.search(r'Bit Rate=([\d\.]+)', line)
                if rate_match:
                    info['bit_rate'] = rate_match.group(1)

        return info

    def enable_monitor_mode(self, interface):
        """
        Enable monitor mode on the specified interface
        """
        if not ensure_root_privileges():
            return False

        self.logger.info(f"Enabling monitor mode on {interface}...")

        # First, kill any interfering processes
        self.logger.info("Killing interfering processes...")
        run_command("airmon-ng check kill")

        # Enable monitor mode
        success, output, error = run_command(f"airmon-ng start {interface}")
        if not success:
            self.logger.error(f"Failed to enable monitor mode: {error}")
            return False

        # Extract the monitor interface name (usually wlan0mon)
        monitor_interface = None
        for line in output.split('\n'):
            if 'monitor mode enabled' in line.lower():
                # Try to extract the monitor interface name
                match = re.search(r'(\w+mon)', line)
                if match:
                    monitor_interface = match.group(1)
                break

        if not monitor_interface:
            # Fallback: assume it's interface + "mon"
            monitor_interface = interface + "mon"

        self.logger.success(f"Monitor mode enabled on {monitor_interface}")
        return monitor_interface

    def disable_monitor_mode(self, interface):
        """
        Disable monitor mode on the specified interface
        """
        if not ensure_root_privileges():
            return False

        self.logger.info(f"Disabling monitor mode on {interface}...")

        success, output, error = run_command(f"airmon-ng stop {interface}")
        if not success:
            self.logger.error(f"Failed to disable monitor mode: {error}")
            return False

        self.logger.success(f"Monitor mode disabled on {interface}")

        # Restart network manager
        self.logger.info("Restarting network services...")
        run_command("service NetworkManager restart")

        return True

    def list_interfaces(self):
        """
        List all network interfaces with their status
        """
        success, output, error = run_command("ip link show")
        if not success:
            self.logger.error("Failed to list interfaces")
            return []

        interfaces = []
        lines = output.split('\n')

        for line in lines:
            if ': ' in line and '<' in line:
                parts = line.split(': ')
                if len(parts) >= 2:
                    interface_name = parts[1].split('@')[0].strip()
                    interfaces.append(interface_name)

        return interfaces

def scan_adapters():
    """
    Convenience function to scan adapters
    """
    manager = MonitorModeManager()
    return manager.scan_adapters()

def enable_monitor(interface):
    """
    Convenience function to enable monitor mode
    """
    manager = MonitorModeManager()
    return manager.enable_monitor_mode(interface)

def disable_monitor(interface):
    """
    Convenience function to disable monitor mode
    """
    manager = MonitorModeManager()
    return manager.disable_monitor_mode(interface)

def get_adapter_info(interface):
    """
    Convenience function to get adapter info
    """
    manager = MonitorModeManager()
    return manager.get_adapter_info(interface)