"""
Helper functions for WiFiSniper
Validation, formatting, and utility functions
"""

import re
import subprocess
import os
from colorama import Fore, Style
from prettytable import PrettyTable
from core.logger import Logger

logger = Logger()

def validate_mac_address(mac):
    """
    Validate MAC address format
    Returns True if valid, False otherwise
    """
    mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(mac_pattern, mac))

def validate_ip_address(ip):
    """
    Validate IP address format
    Returns True if valid, False otherwise
    """
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(ip_pattern, ip))

def validate_bssid(bssid):
    """
    Validate BSSID (same as MAC address)
    """
    return validate_mac_address(bssid)

def validate_channel(channel):
    """
    Validate Wi-Fi channel (1-14 for 2.4GHz, 36-165 for 5GHz)
    """
    try:
        ch = int(channel)
        return ch in list(range(1, 15)) + list(range(36, 166))
    except ValueError:
        return False

def validate_positive_integer(value):
    """
    Validate positive integer
    """
    try:
        val = int(value)
        return val > 0
    except ValueError:
        return False

def validate_non_negative_integer(value):
    """
    Validate non-negative integer (0 or positive)
    """
    try:
        val = int(value)
        return val >= 0
    except ValueError:
        return False

def get_validated_input(prompt, validator_func, error_msg="Invalid input. Please try again."):
    """
    Get user input with validation
    """
    while True:
        user_input = input(prompt).strip()
        if validator_func(user_input):
            return user_input
        else:
            logger.error(error_msg)

def get_user_confirmation(message, default=False):
    """
    Get user confirmation (y/n)
    Returns True for yes, False for no
    """
    default_text = "(Y/n)" if default else "(y/N)"
    while True:
        response = input(f"{message} {default_text}: ").strip().lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        elif response == '' and default is not None:
            return default
        else:
            print("Please enter 'y' for yes or 'n' for no.")

def run_command(cmd, shell=False, capture_output=True, timeout=30):
    """
    Run a system command safely
    Returns (success: bool, output: str, error: str)
    """
    try:
        if isinstance(cmd, str):
            cmd = cmd.split() if not shell else cmd

        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )

        success = result.returncode == 0
        output = result.stdout.strip() if result.stdout else ""
        error = result.stderr.strip() if result.stderr else ""

        return success, output, error

    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", "Command not found"
    except Exception as e:
        return False, "", f"Error running command: {str(e)}"

def format_table(headers, data, title=None):
    """
    Format data as a pretty table
    """
    table = PrettyTable()
    table.field_names = headers

    for row in data:
        table.add_row(row)

    if title:
        table.title = title

    return table

def display_network_table(networks):
    """
    Display Wi-Fi networks in a formatted table
    """
    if not networks:
        logger.warning("No networks found")
        return

    headers = ["#", "BSSID", "ESSID", "Channel", "Encryption", "Signal", "Clients"]
    table_data = []

    for i, network in enumerate(networks, 1):
        table_data.append([
            str(i),
            network.get('bssid', 'N/A'),
            network.get('essid', 'N/A'),
            str(network.get('channel', 'N/A')),
            network.get('encryption', 'N/A'),
            network.get('signal', 'N/A'),
            str(network.get('clients', 0))
        ])

    table = format_table(headers, table_data, "Wi-Fi Networks")
    print(table)

def display_client_table(clients):
    """
    Display connected clients in a formatted table
    """
    if not clients:
        logger.warning("No clients found")
        return

    headers = ["#", "MAC Address", "Signal", "Packets", "Probes"]
    table_data = []

    for i, client in enumerate(clients, 1):
        table_data.append([
            str(i),
            client.get('mac', 'N/A'),
            client.get('signal', 'N/A'),
            str(client.get('packets', 0)),
            client.get('probes', 'N/A')
        ])

    table = format_table(headers, table_data, "Connected Clients")
    print(table)

def parse_airodump_csv(csv_content):
    """
    Parse airodump-ng CSV output
    Returns dict with networks and clients
    """
    lines = csv_content.strip().split('\n')
    networks = []
    clients = []

    # Find the station section
    station_start = -1
    for i, line in enumerate(lines):
        if line.startswith('Station MAC'):
            station_start = i
            break

    # Parse networks (before stations)
    if station_start > 0:
        network_lines = lines[:station_start]
    else:
        network_lines = lines

    # Skip header lines
    for line in network_lines:
        if line.strip() and not line.startswith('BSSID') and ',' in line:
            parts = line.split(',')
            if len(parts) >= 14:  # Minimum fields for network
                network = {
                    'bssid': parts[0].strip(),
                    'first_time': parts[1].strip(),
                    'last_time': parts[2].strip(),
                    'channel': parts[3].strip(),
                    'speed': parts[4].strip(),
                    'privacy': parts[5].strip(),
                    'cipher': parts[6].strip(),
                    'authentication': parts[7].strip(),
                    'power': parts[8].strip(),
                    'beacons': parts[9].strip(),
                    'iv': parts[10].strip(),
                    'lan_ip': parts[11].strip(),
                    'id_length': parts[12].strip(),
                    'essid': parts[13].strip(),
                    'key': parts[14].strip() if len(parts) > 14 else ''
                }
                networks.append(network)

    # Parse clients (after stations header)
    if station_start >= 0:
        client_lines = lines[station_start + 1:]
        for line in client_lines:
            if line.strip() and not line.startswith('Station MAC') and ',' in line:
                parts = line.split(',')
                if len(parts) >= 6:
                    client = {
                        'mac': parts[0].strip(),
                        'first_time': parts[1].strip(),
                        'last_time': parts[2].strip(),
                        'power': parts[3].strip(),
                        'packets': parts[4].strip(),
                        'bssid': parts[5].strip(),
                        'probed_essids': parts[6].strip() if len(parts) > 6 else ''
                    }
                    clients.append(client)

    return {'networks': networks, 'clients': clients}

def kill_process_by_name(process_name):
    """
    Kill processes by name using pkill
    """
    try:
        subprocess.run(['pkill', '-f', process_name], capture_output=True)
        logger.info(f"Killed processes matching: {process_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to kill processes: {e}")
        return False

def check_root_privileges():
    """
    Check if running with root privileges
    """
    return os.geteuid() == 0

def ensure_root_privileges():
    """
    Ensure the script is running with root privileges
    """
    if not check_root_privileges():
        logger.error("This function requires root privileges")
        logger.info("Run with: sudo python wifisniper.py")
        return False
    return True

def create_directory_if_not_exists(directory):
    """
    Create directory if it doesn't exist
    """
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            logger.info(f"Created directory: {directory}")
            return True
        except Exception as e:
            logger.error(f"Failed to create directory {directory}: {e}")
            return False
    return True

def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal and invalid characters
    """
    # Remove path separators and other dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '', filename)
    # Limit length
    return sanitized[:255] if sanitized else "unnamed_file"

def format_bytes(bytes_value):
    """
    Format bytes into human readable format
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return ".1f"
        bytes_value /= 1024.0
    return ".1f"