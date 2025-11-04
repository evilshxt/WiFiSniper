"""
Network Scanner Module
Handle Wi-Fi network scanning using airodump-ng
"""

import time
import os
import subprocess
import tempfile
from core.logger import Logger
from utils.helpers import run_command, ensure_root_privileges, display_network_table, display_client_table, parse_airodump_csv, get_user_confirmation

logger = Logger()

class NetworkScanner:
    def __init__(self):
        self.logger = logger
        self.scan_process = None

    def scan_networks(self, interface, duration=10, channel=None, bssid=None):
        """
        Scan for Wi-Fi networks using airodump-ng
        """
        if not ensure_root_privileges():
            return None

        self.logger.info(f"Starting network scan on {interface}...")

        # Create temporary file for scan results
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.csv', delete=False) as temp_file:
            temp_csv = temp_file.name

        try:
            # Build airodump-ng command
            cmd = f"airodump-ng {interface} --output-format csv --write {temp_csv.rstrip('.csv')}"

            if channel:
                cmd += f" --channel {channel}"
            if bssid:
                cmd += f" --bssid {bssid}"

            self.logger.info(f"Running: {cmd}")
            self.logger.info(f"Scanning for {duration} seconds... (Press Ctrl+C to stop early)")

            # Run the scan
            self.scan_process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait for specified duration or until interrupted
            try:
                time.sleep(duration)
            except KeyboardInterrupt:
                self.logger.info("Scan interrupted by user")
            finally:
                # Stop the scan process
                if self.scan_process and self.scan_process.poll() is None:
                    self.scan_process.terminate()
                    try:
                        self.scan_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.scan_process.kill()

            # Read the CSV output
            csv_file = temp_csv.rstrip('.csv') + '-01.csv'
            if os.path.exists(csv_file):
                with open(csv_file, 'r') as f:
                    csv_content = f.read()

                # Parse the results
                parsed_data = parse_airodump_csv(csv_content)

                # Format and display results
                networks = parsed_data['networks']
                clients = parsed_data['clients']

                if networks:
                    self.logger.success(f"Found {len(networks)} network(s)")
                    display_network_table(networks)
                else:
                    self.logger.warning("No networks found")

                if clients:
                    self.logger.info(f"Found {len(clients)} client(s)")
                    display_client_table(clients)

                return parsed_data
            else:
                self.logger.error("Scan output file not found")
                return None

        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            return None
        finally:
            # Clean up temporary files
            try:
                if os.path.exists(temp_csv):
                    os.unlink(temp_csv)
                csv_file = temp_csv.rstrip('.csv') + '-01.csv'
                if os.path.exists(csv_file):
                    os.unlink(csv_file)
            except:
                pass

    def continuous_scan(self, interface, channel=None, bssid=None):
        """
        Perform continuous scanning until interrupted
        """
        if not ensure_root_privileges():
            return

        self.logger.info("Starting continuous network scan...")
        self.logger.info("Press Ctrl+C to stop scanning")

        try:
            while True:
                result = self.scan_networks(interface, duration=5, channel=channel, bssid=bssid)
                if result:
                    print("\n" + "="*60)
                    self.logger.info("Scan complete. Next scan in 5 seconds...")
                    print("="*60 + "\n")
                time.sleep(5)
        except KeyboardInterrupt:
            self.logger.info("Continuous scan stopped by user")
        except Exception as e:
            self.logger.error(f"Error during continuous scan: {e}")

    def scan_clients(self, interface, bssid, channel, duration=30):
        """
        Scan for clients connected to a specific network
        """
        if not ensure_root_privileges():
            return None

        self.logger.info(f"Scanning for clients on network {bssid} (channel {channel})...")

        result = self.scan_networks(interface, duration=duration, channel=channel, bssid=bssid)

        if result and result['clients']:
            # Filter clients connected to the target BSSID
            target_clients = [client for client in result['clients'] if client.get('bssid') == bssid]
            if target_clients:
                self.logger.success(f"Found {len(target_clients)} client(s) connected to {bssid}")
                display_client_table(target_clients)
                return target_clients
            else:
                self.logger.warning(f"No clients found connected to {bssid}")
                return []
        else:
            self.logger.warning("No client data available")
            return None

    def signal_analysis(self, interface, target_bssid=None, duration=60):
        """
        Analyze Wi-Fi signal strength over time
        """
        if not ensure_root_privileges():
            return None

        self.logger.info("Starting signal strength analysis...")

        signal_data = []
        start_time = time.time()

        try:
            while time.time() - start_time < duration:
                # Quick scan to get current signal levels
                result = self.scan_networks(interface, duration=2, bssid=target_bssid)

                if result and result['networks']:
                    current_time = time.time() - start_time

                    for network in result['networks']:
                        if not target_bssid or network.get('bssid') == target_bssid:
                            signal_entry = {
                                'time': current_time,
                                'bssid': network.get('bssid'),
                                'essid': network.get('essid'),
                                'signal': network.get('power', 'N/A'),
                                'channel': network.get('channel')
                            }
                            signal_data.append(signal_entry)

                time.sleep(1)  # Sample every second

            # Analyze collected data
            if signal_data:
                self.analyze_signal_data(signal_data)
                return signal_data
            else:
                self.logger.warning("No signal data collected")
                return None

        except KeyboardInterrupt:
            self.logger.info("Signal analysis interrupted by user")
            if signal_data:
                self.analyze_signal_data(signal_data)
                return signal_data
            return None
        except Exception as e:
            self.logger.error(f"Signal analysis error: {e}")
            return None

    def analyze_signal_data(self, signal_data):
        """
        Analyze collected signal strength data
        """
        if not signal_data:
            return

        # Group by BSSID
        networks = {}
        for entry in signal_data:
            bssid = entry['bssid']
            if bssid not in networks:
                networks[bssid] = []
            networks[bssid].append(entry)

        print("\n" + "="*60)
        print("SIGNAL STRENGTH ANALYSIS")
        print("="*60)

        for bssid, entries in networks.items():
            essid = entries[0]['essid'] if entries else 'Unknown'
            signals = [int(entry['signal']) for entry in entries if entry['signal'] != 'N/A']

            if signals:
                avg_signal = sum(signals) / len(signals)
                min_signal = min(signals)
                max_signal = max(signals)

                print(f"\nNetwork: {essid} ({bssid})")
                print(f"  Samples: {len(signals)}")
                print(f"  Average signal: {avg_signal:.1f} dBm")
                print(f"  Signal range: {min_signal} to {max_signal} dBm")
                print(f"  Channel: {entries[0]['channel']}")

                # Signal quality assessment
                if avg_signal >= -30:
                    quality = "Excellent"
                elif avg_signal >= -50:
                    quality = "Good"
                elif avg_signal >= -70:
                    quality = "Fair"
                else:
                    quality = "Poor"

                print(f"  Signal quality: {quality}")
            else:
                print(f"\nNetwork: {essid} ({bssid}) - No signal data available")

    def traffic_analysis(self, interface, duration=30, filter_bssid=None):
        """
        Analyze network traffic patterns
        """
        if not ensure_root_privileges():
            return None

        self.logger.info("Starting traffic analysis...")

        try:
            # Use tshark for packet capture and analysis
            cmd = f"tshark -i {interface} -a duration:{duration} -T fields"

            if filter_bssid:
                # Filter for specific BSSID
                cmd += f" -Y 'wlan.bssid == {filter_bssid}'"

            # Extract relevant fields
            cmd += " -e frame.time_relative -e wlan.bssid -e wlan.sa -e wlan.da -e frame.len"

            self.logger.info(f"Analyzing traffic for {duration} seconds...")

            success, output, error = run_command(cmd, timeout=duration + 5)

            if success and output:
                traffic_data = self.parse_traffic_data(output)
                self.display_traffic_analysis(traffic_data)
                return traffic_data
            else:
                self.logger.error(f"Traffic analysis failed: {error}")
                return None

        except Exception as e:
            self.logger.error(f"Traffic analysis error: {e}")
            return None

    def parse_traffic_data(self, tshark_output):
        """
        Parse tshark output for traffic analysis
        """
        lines = tshark_output.strip().split('\n')
        traffic_data = {
            'packets': [],
            'bssids': {},
            'total_bytes': 0,
            'time_span': 0
        }

        for line in lines:
            if '\t' in line:
                fields = line.split('\t')
                if len(fields) >= 5:
                    try:
                        packet = {
                            'time': float(fields[0]),
                            'bssid': fields[1] if fields[1] else 'N/A',
                            'src': fields[2] if fields[2] else 'N/A',
                            'dst': fields[3] if fields[3] else 'N/A',
                            'size': int(fields[4]) if fields[4].isdigit() else 0
                        }

                        traffic_data['packets'].append(packet)
                        traffic_data['total_bytes'] += packet['size']

                        # Track BSSID activity
                        bssid = packet['bssid']
                        if bssid not in traffic_data['bssids']:
                            traffic_data['bssids'][bssid] = {'packets': 0, 'bytes': 0}
                        traffic_data['bssids'][bssid]['packets'] += 1
                        traffic_data['bssids'][bssid]['bytes'] += packet['size']

                    except (ValueError, IndexError):
                        continue

        if traffic_data['packets']:
            traffic_data['time_span'] = traffic_data['packets'][-1]['time'] - traffic_data['packets'][0]['time']

        return traffic_data

    def display_traffic_analysis(self, traffic_data):
        """
        Display traffic analysis results
        """
        if not traffic_data or not traffic_data['packets']:
            self.logger.warning("No traffic data to analyze")
            return

        print("\n" + "="*60)
        print("TRAFFIC ANALYSIS REPORT")
        print("="*60)

        total_packets = len(traffic_data['packets'])
        total_bytes = traffic_data['total_bytes']
        duration = traffic_data['time_span']

        print(f"Total packets captured: {total_packets}")
        print(f"Total data transferred: {total_bytes} bytes ({total_bytes/1024:.1f} KB)")
        print(f"Analysis duration: {duration:.1f} seconds")

        if duration > 0:
            packets_per_sec = total_packets / duration
            bytes_per_sec = total_bytes / duration
            print(f"Packets per second: {packets_per_sec:.1f}")
            print(f"Data rate: {bytes_per_sec:.1f} bytes/sec ({bytes_per_sec/1024:.1f} KB/s)")

        # BSSID activity
        if traffic_data['bssids']:
            print(f"\nNetwork Activity ({len(traffic_data['bssids'])} networks):")
            sorted_bssids = sorted(traffic_data['bssids'].items(),
                                 key=lambda x: x[1]['packets'], reverse=True)

            for bssid, stats in sorted_bssids[:10]:  # Top 10
                percentage = (stats['packets'] / total_packets) * 100
                print(f"  {bssid}: {stats['packets']} packets ({percentage:.1f}%), {stats['bytes']} bytes")

    def get_network_details(self, networks, selection):
        """
        Get detailed information about a selected network
        """
        try:
            index = int(selection) - 1
            if 0 <= index < len(networks):
                return networks[index]
            else:
                self.logger.error("Invalid selection")
                return None
        except ValueError:
            self.logger.error("Invalid input")
            return None

def scan_networks(interface, duration=10, channel=None, bssid=None):
    """
    Convenience function for network scanning
    """
    scanner = NetworkScanner()
    return scanner.scan_networks(interface, duration, channel, bssid)

def continuous_scan(interface, channel=None, bssid=None):
    """
    Convenience function for continuous scanning
    """
    scanner = NetworkScanner()
    scanner.continuous_scan(interface, channel, bssid)

def scan_clients(interface, bssid, channel, duration=30):
    """
    Convenience function for client scanning
    """
    scanner = NetworkScanner()
    return scanner.scan_clients(interface, bssid, channel, duration)