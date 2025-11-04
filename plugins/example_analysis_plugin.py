"""
Example analysis plugin for WiFiSniper
Demonstrates how to create custom analysis plugins
"""

from core.plugin_base import PluginBase
from modules.analysis import PortScanner
from utils.helpers import get_validated_input, get_user_confirmation

class AdvancedPortScannerPlugin(PluginBase):
    name = "Advanced Port Scanner"
    description = "Enhanced port scanning with service detection and OS fingerprinting"
    category = "analysis"
    version = "1.0.0"

    def run(self, **kwargs):
        """Main plugin execution"""
        print("\n" + "="*60)
        print("Advanced Port Scanner Plugin")
        print("="*60)

        # Get target
        target = get_validated_input("Enter target IP address: ",
                                   lambda x: len(x.split('.')) == 4 and all(i.isdigit() and 0 <= int(i) <= 255 for i in x.split('.')),
                                   "Invalid IP address format")

        # Scan options
        print("\nScan Options:")
        print("1. Quick scan (top 100 ports)")
        print("2. Full TCP scan (1-65535)")
        print("3. UDP scan (top 1000 ports)")
        print("4. Comprehensive scan (TCP + UDP + OS detection)")
        print("5. Custom port range")

        scan_choice = input("Choose scan type (1-5): ").strip()

        if scan_choice == "1":
            ports = "1-100"
            scan_type = "tcp"
            timing = "T4"
        elif scan_choice == "2":
            ports = "1-65535"
            scan_type = "tcp"
            timing = "T3"
        elif scan_choice == "3":
            ports = "1-1000"
            scan_type = "udp"
            timing = "T3"
        elif scan_choice == "4":
            ports = "1-1000"
            scan_type = "aggressive"
            timing = "T4"
        elif scan_choice == "5":
            ports = input("Enter port range (e.g., 80,443 or 1-1000): ").strip()
            scan_type = "tcp"
            timing = "T4"
        else:
            self.logger.error("Invalid choice")
            return

        # Additional options
        os_detect = False
        version_detect = False

        if scan_choice == "4":
            os_detect = True
            version_detect = True
        else:
            os_choice = input("Enable OS detection? (y/n): ").strip().lower()
            os_detect = os_choice == 'y'

            version_choice = input("Enable version detection? (y/n): ").strip().lower()
            version_detect = version_choice == 'y'

        if not get_user_confirmation(f"Start advanced port scan on {target}?"):
            self.logger.info("Port scan cancelled by user")
            return

        # Execute scan
        scanner = PortScanner()

        # Build custom nmap command for advanced features
        cmd = f"nmap -{scan_type} {target} -p {ports} -{timing}"

        if os_detect:
            cmd += " -O"
        if version_detect:
            cmd += " -sV"

        self.logger.info(f"Running advanced scan: {cmd}")

        success, output, error = scanner.scan_ports(target, ports, scan_type, timing)

        if success:
            self.logger.success("Advanced port scan completed")

            # Additional analysis
            if "open" in output.lower():
                self.logger.info("Open ports found - target may be vulnerable to further analysis")
            else:
                self.logger.info("No open ports found")

        else:
            self.logger.error("Advanced port scan failed")

    def get_menu_options(self):
        """Return menu options for this plugin"""
        return [
            {
                "name": "Run Advanced Port Scan",
                "function": self.run
            }
        ]