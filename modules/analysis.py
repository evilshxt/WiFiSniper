"""
Network Analysis Module
Handle packet capture, client analysis, port scanning, and vulnerability assessment
"""

import os
import time
import json
from datetime import datetime
from core.logger import Logger
from utils.helpers import run_command, ensure_root_privileges, display_client_table, get_user_confirmation, validate_ip_address, format_bytes

logger = Logger()

class PacketCapture:
    def __init__(self):
        self.logger = logger

    def capture_packets(self, interface, duration=60, filter_expr="", output_file=None, use_scapy=False):
        """
        Capture network packets using Scapy or pyshark
        """
        if not ensure_root_privileges():
            return False

        self.logger.info("Starting packet capture...")
        self.logger.info(f"Interface: {interface}")
        self.logger.info(f"Duration: {duration} seconds")

        if filter_expr:
            self.logger.info(f"Filter: {filter_expr}")

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"capture_{timestamp}.pcap"

        try:
            if use_scapy:
                return self.capture_with_scapy(interface, duration, filter_expr, output_file)
            else:
                return self.capture_with_pyshark(interface, duration, filter_expr, output_file)

        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
            return False

    def capture_with_scapy(self, interface, duration, filter_expr, output_file):
        """
        Capture packets using Scapy
        """
        try:
            from scapy.all import sniff, wrpcap

            self.logger.info("Using Scapy for packet capture...")

            # Build filter
            scapy_filter = ""
            if filter_expr:
                # Convert common filter expressions to Scapy format
                scapy_filter = self.convert_filter_to_scapy(filter_expr)

            def packet_handler(packet):
                # Process packet (could add analysis here)
                pass

            self.logger.info("Capturing packets... (Ctrl+C to stop early)")

            packets = sniff(
                iface=interface,
                timeout=duration,
                filter=scapy_filter,
                prn=packet_handler
            )

            if packets:
                wrpcap(output_file, packets)
                self.logger.success(f"Captured {len(packets)} packets")
                self.logger.info(f"Saved to: {output_file}")

                # Basic analysis
                self.analyze_packets_scapy(packets)
                return output_file
            else:
                self.logger.warning("No packets captured")
                return None

        except ImportError:
            self.logger.error("Scapy not available, falling back to pyshark")
            return self.capture_with_pyshark(interface, duration, filter_expr, output_file)
        except Exception as e:
            self.logger.error(f"Scapy capture error: {e}")
            return False

    def capture_with_pyshark(self, interface, duration, filter_expr, output_file):
        """
        Capture packets using pyshark
        """
        try:
            import pyshark

            self.logger.info("Using pyshark for packet capture...")

            # Create capture object
            capture = pyshark.LiveCapture(
                interface=interface,
                output_file=output_file if output_file.endswith('.pcap') else output_file + '.pcap'
            )

            if filter_expr:
                capture.filter = filter_expr

            self.logger.info("Capturing packets... (Ctrl+C to stop early)")

            packets = []
            start_time = time.time()

            for packet in capture:
                packets.append(packet)

                # Check timeout
                if time.time() - start_time >= duration:
                    break

                # Progress update every 100 packets
                if len(packets) % 100 == 0:
                    self.logger.info(f"Captured {len(packets)} packets...")

            capture.close()

            if packets:
                self.logger.success(f"Captured {len(packets)} packets")
                self.logger.info(f"Saved to: {output_file}")

                # Basic analysis
                self.analyze_packets_pyshark(packets)
                return output_file
            else:
                self.logger.warning("No packets captured")
                return None

        except ImportError:
            self.logger.error("pyshark not available")
            return False
        except Exception as e:
            self.logger.error(f"pyshark capture error: {e}")
            return False

    def convert_filter_to_scapy(self, filter_expr):
        """
        Convert Wireshark-style filter to Scapy format
        """
        # Basic conversions
        conversions = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'arp': 'arp',
            'ip': 'ip',
            'port': 'port',
        }

        # This is a simplified conversion - real implementation would be more complex
        scapy_filter = filter_expr

        for ws_filter, scapy_filter_part in conversions.items():
            scapy_filter = scapy_filter.replace(ws_filter, scapy_filter_part)

        return scapy_filter

    def analyze_packets_scapy(self, packets):
        """
        Basic packet analysis with Scapy
        """
        if not packets:
            return

        analysis = {
            'total_packets': len(packets),
            'protocols': {},
            'ip_addresses': set(),
            'ports': set()
        }

        for packet in packets:
            # Count protocols
            if packet.haslayer('IP'):
                proto = packet['IP'].proto
                proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f'IP_{proto}')
                analysis['protocols'][proto_name] = analysis['protocols'].get(proto_name, 0) + 1

                # Collect IPs
                analysis['ip_addresses'].add(packet['IP'].src)
                analysis['ip_addresses'].add(packet['IP'].dst)

            # Collect ports
            if packet.haslayer('TCP'):
                analysis['ports'].add(packet['TCP'].sport)
                analysis['ports'].add(packet['TCP'].dport)
            elif packet.haslayer('UDP'):
                analysis['ports'].add(packet['UDP'].sport)
                analysis['ports'].add(packet['UDP'].dport)

        # Display analysis
        print("\nPacket Analysis Summary:")
        print(f"Total packets: {analysis['total_packets']}")
        print(f"Protocols: {analysis['protocols']}")
        print(f"Unique IP addresses: {len(analysis['ip_addresses'])}")
        print(f"Unique ports: {len(analysis['ports'])}")

    def analyze_packets_pyshark(self, packets):
        """
        Basic packet analysis with pyshark
        """
        if not packets:
            return

        analysis = {
            'total_packets': len(packets),
            'protocols': {},
            'ip_addresses': set(),
            'ports': set()
        }

        for packet in packets:
            try:
                # Count protocols
                if hasattr(packet, 'highest_layer'):
                    proto = packet.highest_layer
                    analysis['protocols'][proto] = analysis['protocols'].get(proto, 0) + 1

                # Collect IPs and ports
                if hasattr(packet, 'ip'):
                    analysis['ip_addresses'].add(packet.ip.src)
                    analysis['ip_addresses'].add(packet.ip.dst)

                if hasattr(packet, 'tcp'):
                    analysis['ports'].add(int(packet.tcp.srcport))
                    analysis['ports'].add(int(packet.tcp.dstport))
                elif hasattr(packet, 'udp'):
                    analysis['ports'].add(int(packet.udp.srcport))
                    analysis['ports'].add(int(packet.udp.dstport))

            except AttributeError:
                continue

        # Display analysis
        print("\nPacket Analysis Summary:")
        print(f"Total packets: {analysis['total_packets']}")
        print(f"Protocols: {analysis['protocols']}")
        print(f"Unique IP addresses: {len(analysis['ip_addresses'])}")
        print(f"Unique ports: {len(analysis['ports'])}")

class PortScanner:
    def __init__(self):
        self.logger = logger

    def scan_ports(self, target_ip, ports="1-1024", scan_type="tcp", timing="T4"):
        """
        Perform port scanning using nmap
        """
        if not ensure_root_privileges():
            return False

        if not validate_ip_address(target_ip):
            self.logger.error("Invalid target IP address")
            return False

        self.logger.info("Starting port scan...")
        self.logger.info(f"Target: {target_ip}")
        self.logger.info(f"Ports: {ports}")
        self.logger.info(f"Scan type: {scan_type}")

        # Build nmap command
        cmd = f"nmap -{scan_type} {target_ip} -p {ports} -{timing}"

        if scan_type.lower() == "tcp":
            cmd += " -sS"  # SYN scan
        elif scan_type.lower() == "udp":
            cmd += " -sU"  # UDP scan
        elif scan_type.lower() == "aggressive":
            cmd += " -A"  # Aggressive scan

        self.logger.info(f"Running: {cmd}")

        try:
            success, output, error = run_command(cmd, timeout=300)  # 5 minute timeout

            if success:
                self.logger.success("Port scan completed")
                print("\nScan Results:")
                print(output)

                # Parse results
                open_ports = self.parse_nmap_output(output)
                if open_ports:
                    self.logger.info(f"Found {len(open_ports)} open ports")
                    return open_ports
                else:
                    self.logger.info("No open ports found")
                    return []
            else:
                self.logger.error(f"Port scan failed: {error}")
                return False

        except Exception as e:
            self.logger.error(f"Port scan error: {e}")
            return False

    def parse_nmap_output(self, output):
        """
        Parse nmap output to extract open ports
        """
        open_ports = []

        lines = output.split('\n')
        in_port_section = False

        for line in lines:
            line = line.strip()

            if line.startswith('PORT'):
                in_port_section = True
                continue
            elif in_port_section and line == '':
                break
            elif in_port_section and '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'open':
                    port_info = parts[0].split('/')
                    if len(port_info) == 2:
                        port = {
                            'port': int(port_info[0]),
                            'protocol': port_info[1],
                            'state': parts[1],
                            'service': parts[2] if len(parts) > 2 else 'unknown'
                        }
                        open_ports.append(port)

        return open_ports

    def quick_scan(self, target_ip):
        """
        Perform a quick port scan (common ports)
        """
        return self.scan_ports(target_ip, ports="21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389")

    def full_scan(self, target_ip):
        """
        Perform a full port scan (1-65535)
        """
        return self.scan_ports(target_ip, ports="1-65535")

class VulnerabilityScanner:
    def __init__(self):
        self.logger = logger

    def scan_wifi_vulnerabilities(self, networks):
        """
        Scan for common Wi-Fi vulnerabilities
        """
        self.logger.info("Scanning for Wi-Fi vulnerabilities...")

        vulnerabilities = []

        for network in networks:
            net_vulns = self.check_network_vulnerabilities(network)
            if net_vulns:
                vulnerabilities.extend(net_vulns)

        if vulnerabilities:
            self.logger.warning(f"Found {len(vulnerabilities)} potential vulnerabilities")
            self.display_vulnerabilities(vulnerabilities)
        else:
            self.logger.success("No obvious vulnerabilities detected")

        return vulnerabilities

    def check_network_vulnerabilities(self, network):
        """
        Check a single network for vulnerabilities
        """
        vulnerabilities = []
        bssid = network.get('bssid', '')
        essid = network.get('essid', 'Unknown')
        encryption = network.get('privacy', 'Open')

        # Check for weak encryption
        if encryption in ['WEP', 'Open']:
            vulnerabilities.append({
                'type': 'weak_encryption',
                'severity': 'high',
                'network': f"{essid} ({bssid})",
                'description': f"Weak encryption: {encryption}",
                'recommendation': 'Use WPA3 or WPA2 with strong passwords'
            })

        # Check for WPS enabled (if detectable)
        if 'WPS' in encryption or network.get('wps', False):
            vulnerabilities.append({
                'type': 'wps_enabled',
                'severity': 'medium',
                'network': f"{essid} ({bssid})",
                'description': 'WPS is enabled',
                'recommendation': 'Disable WPS if not needed'
            })

        # Check signal strength (weak signal can indicate issues)
        signal = network.get('power', '0')
        try:
            signal_dbm = int(signal)
            if signal_dbm < -80:
                vulnerabilities.append({
                    'type': 'weak_signal',
                    'severity': 'low',
                    'network': f"{essid} ({bssid})",
                    'description': f"Very weak signal: {signal_dbm} dBm",
                    'recommendation': 'Move closer to access point or check antenna'
                })
        except ValueError:
            pass

        return vulnerabilities

    def display_vulnerabilities(self, vulnerabilities):
        """
        Display found vulnerabilities in a formatted way
        """
        severity_colors = {
            'high': 'red',
            'medium': 'yellow',
            'low': 'cyan'
        }

        print("\n" + "="*60)
        print("VULNERABILITY SCAN RESULTS")
        print("="*60)

        for vuln in vulnerabilities:
            severity = vuln['severity']
            color = severity_colors.get(severity, 'white')

            print(f"\n[{severity.upper()}] {vuln['network']}")
            print(f"Type: {vuln['type']}")
            print(f"Description: {vuln['description']}")
            print(f"Recommendation: {vuln['recommendation']}")

class ClientAnalyzer:
    def __init__(self):
        self.logger = logger

    def analyze_clients(self, clients, duration=300):
        """
        Analyze client behavior over time
        """
        if not clients:
            self.logger.warning("No clients to analyze")
            return None

        self.logger.info(f"Analyzing {len(clients)} clients for {duration} seconds...")

        # Track client activity
        client_activity = {}
        start_time = time.time()

        try:
            while time.time() - start_time < duration:
                # In a real implementation, this would continuously monitor
                # For now, we'll analyze the provided client data

                for client in clients:
                    mac = client.get('mac', 'unknown')
                    if mac not in client_activity:
                        client_activity[mac] = {
                            'first_seen': time.time(),
                            'last_seen': time.time(),
                            'packet_count': client.get('packets', 0),
                            'signal_history': [client.get('power', 0)],
                            'probes': client.get('probed_essids', '').split(',') if client.get('probed_essids') else []
                        }
                    else:
                        client_activity[mac]['last_seen'] = time.time()
                        client_activity[mac]['packet_count'] += client.get('packets', 0)
                        client_activity[mac]['signal_history'].append(client.get('power', 0))

                time.sleep(10)  # Update every 10 seconds

        except KeyboardInterrupt:
            self.logger.info("Client analysis interrupted")

        # Generate analysis report
        analysis = self.generate_client_report(client_activity)
        self.display_client_analysis(analysis)

        return analysis

    def generate_client_report(self, client_activity):
        """
        Generate detailed client analysis report
        """
        analysis = {
            'total_clients': len(client_activity),
            'active_clients': 0,
            'client_details': []
        }

        current_time = time.time()

        for mac, activity in client_activity.items():
            # Calculate activity metrics
            time_online = current_time - activity['first_seen']
            last_seen_seconds = current_time - activity['last_seen']

            is_active = last_seen_seconds < 300  # Active if seen in last 5 minutes
            if is_active:
                analysis['active_clients'] += 1

            # Signal analysis
            signals = activity['signal_history']
            avg_signal = sum(signals) / len(signals) if signals else 0

            client_detail = {
                'mac': mac,
                'time_online': time_online,
                'last_seen': last_seen_seconds,
                'is_active': is_active,
                'packet_count': activity['packet_count'],
                'avg_signal': avg_signal,
                'probes': activity['probes']
            }

            analysis['client_details'].append(client_detail)

        return analysis

    def display_client_analysis(self, analysis):
        """
        Display client analysis results
        """
        if not analysis:
            return

        print("\n" + "="*60)
        print("CLIENT ANALYSIS REPORT")
        print("="*60)

        print(f"Total clients observed: {analysis['total_clients']}")
        print(f"Currently active clients: {analysis['active_clients']}")

        print("\nClient Details:")
        for client in analysis['client_details'][:10]:  # Show top 10
            status = "ACTIVE" if client['is_active'] else "INACTIVE"
            print(f"\nMAC: {client['mac']}")
            print(f"Status: {status}")
            print(f"Time online: {client['time_online']:.1f} seconds")
            print(f"Average signal: {client['avg_signal']:.1f} dBm")
            print(f"Packets: {client['packet_count']}")
            if client['probes']:
                print(f"Probed networks: {', '.join(client['probes'][:3])}")

        if len(analysis['client_details']) > 10:
            print(f"\n... and {len(analysis['client_details']) - 10} more clients")

# Convenience functions
def capture_packets(interface, duration=60, filter_expr="", output_file=None, use_scapy=False):
    """Convenience function for packet capture"""
    capturer = PacketCapture()
    return capturer.capture_packets(interface, duration, filter_expr, output_file, use_scapy)

def scan_ports(target_ip, ports="1-1024", scan_type="tcp", timing="T4"):
    """Convenience function for port scanning"""
    scanner = PortScanner()
    return scanner.scan_ports(target_ip, ports, scan_type, timing)

def analyze_clients(clients, duration=300):
    """Convenience function for client analysis"""
    analyzer = ClientAnalyzer()
    return analyzer.analyze_clients(clients, duration)

def scan_vulnerabilities(networks):
    """Convenience function for vulnerability scanning"""
    scanner = VulnerabilityScanner()
    return scanner.scan_wifi_vulnerabilities(networks)