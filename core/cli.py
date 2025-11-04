from .ascii_art import print_banner
from .logger import Logger
from .dependency import check_dependencies
from .plugin_loader import plugin_loader, load_plugins
from colorama import Fore, Style
from utils.helpers import get_user_confirmation
import sys
import time
import os

class MenuSystem:
    def __init__(self):
        self.logger = Logger()

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')

    def print_header(self):
        """Print the application header"""
        self.clear_screen()
        print_banner()
        print(f"{Fore.RED}Made by evilshxt{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print()

    def get_user_choice(self, prompt, valid_choices):
        """Get validated user input for menu choices"""
        while True:
            try:
                choice = input(prompt).strip()
                if choice in valid_choices:
                    return choice
                else:
                    self.logger.error(f"Invalid choice. Please select from: {', '.join(valid_choices)}")
            except KeyboardInterrupt:
                print("\n")
                self.logger.info("Operation cancelled by user")
                return None
            except EOFError:
                print("\n")
                self.logger.info("End of input detected")
                return None

    def main_menu(self):
        """Display and handle the main menu"""
        while True:
            self.print_header()

            print(f"{Fore.GREEN}WiFiSniper v1.0 - Modular Wi-Fi Pentesting Toolkit{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print()
            print("[1] Wireless Attacks")
            print("[2] Password Cracking")
            print("[3] Network Analysis")
            print("[4] Utilities")
            print("[5] Plugins")
            print("[6] Exit")
            print()

            choice = self.get_user_choice("Select an option (1-6): ", ["1", "2", "3", "4", "5", "6"])

            if choice == "1":
                self.wireless_attacks_menu()
            elif choice == "2":
                self.password_cracking_menu()
            elif choice == "3":
                self.network_analysis_menu()
            elif choice == "4":
                self.utilities_menu()
            elif choice == "5":
                self.plugins_menu()
            elif choice == "6":
                self.logger.info("Thank you for using WiFiSniper!")
                print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                return

    def wireless_attacks_menu(self):
        """Wireless Attacks submenu"""
        while True:
            self.print_header()

            print(f"{Fore.GREEN}Wireless Attacks Menu{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*30}{Style.RESET_ALL}")
            print()
            print("[1] Enable Monitor Mode")
            print("[2] Scan Wi-Fi Networks")
            print("[3] Deauthenticate Users")
            print("[4] Handshake Capture")
            print("[5] Evil Twin Attack")
            print("[6] WPS Attacks")
            print("[7] Beacon Flood")
            print("[8] Bluetooth Attacks")
            print("[0] Back to Main Menu")
            print()

            choice = self.get_user_choice("Select an option (0-8): ", ["0", "1", "2", "3", "4", "5", "6", "7", "8"])

            if choice == "0":
                return
            elif choice == "1":
                self.handle_monitor_mode()
            elif choice == "2":
                self.handle_network_scan()
            elif choice == "3":
                self.handle_deauth_attack()
            elif choice == "4":
                self.handle_handshake_capture()
            elif choice == "5":
                self.handle_evil_twin()
            elif choice == "6":
                self.handle_wps_attack()
            elif choice == "7":
                self.handle_beacon_flood()
            elif choice == "8":
                self.handle_bluetooth_attack()

    def password_cracking_menu(self):
        """Password Cracking submenu"""
        while True:
            self.print_header()

            print(f"{Fore.GREEN}Password Cracking Menu{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*30}{Style.RESET_ALL}")
            print()
            print("[1] Crack WPA Handshake")
            print("[2] Generate Passwords")
            print("[0] Back to Main Menu")
            print()

            choice = self.get_user_choice("Select an option (0-2): ", ["0", "1", "2"])

            if choice == "0":
                return
            elif choice == "1":
                self.handle_wpa_cracking()
            elif choice == "2":
                self.handle_password_generation()

    def network_analysis_menu(self):
        """Network Analysis submenu"""
        while True:
            self.print_header()

            print(f"{Fore.GREEN}Network Analysis Menu{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*30}{Style.RESET_ALL}")
            print()
            print("[1] Packet Capture")
            print("[2] Client Analysis")
            print("[3] Port Scanning")
            print("[4] Signal Analysis")
            print("[5] Traffic Analysis")
            print("[6] Vulnerability Scanning")
            print("[0] Back to Main Menu")
            print()

            choice = self.get_user_choice("Select an option (0-6): ", ["0", "1", "2", "3", "4", "5", "6"])

            if choice == "0":
                return
            elif choice == "1":
                self.handle_packet_capture()
            elif choice == "2":
                self.handle_client_analysis()
            elif choice == "3":
                self.handle_port_scanning()
            elif choice == "4":
                self.handle_signal_analysis()
            elif choice == "5":
                self.handle_traffic_analysis()
            elif choice == "6":
                self.handle_vulnerability_scan()

    def utilities_menu(self):
        """Utilities submenu"""
        while True:
            self.print_header()

            print(f"{Fore.GREEN}Utilities Menu{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*20}{Style.RESET_ALL}")
            print()
            print("[1] Check Dependencies")
            print("[2] Adapter Management")
            print("[3] Logs and Reports")
            print("[4] Configuration")
            print("[5] Help and About")
            print("[0] Back to Main Menu")
            print()

            choice = self.get_user_choice("Select an option (0-5): ", ["0", "1", "2", "3", "4", "5"])

            if choice == "0":
                return
            elif choice == "1":
                self.handle_dependency_check()
            elif choice == "2":
                self.handle_adapter_management()
            elif choice == "3":
                self.handle_logs_reports()
            elif choice == "4":
                self.handle_configuration()
            elif choice == "5":
                self.handle_help_about()

    # Placeholder methods for menu handlers - will be implemented in respective modules
    def handle_monitor_mode(self):
        from modules.monitor_mode import MonitorModeManager, scan_adapters

        print("\n" + "="*50)
        print("Monitor Mode Management")
        print("="*50)

        # Scan for adapters
        adapters = scan_adapters()
        if not adapters:
            self.logger.error("No wireless adapters found")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable adapters:")
        for i, adapter in enumerate(adapters, 1):
            print(f"{i}. {adapter['interface']} - {adapter['description']}")

        choice = self.get_user_choice("\nSelect adapter (number): ", [str(i) for i in range(1, len(adapters) + 1)])

        selected_adapter = adapters[int(choice) - 1]['interface']

        # Get current status
        manager = MonitorModeManager()
        info = manager.get_adapter_info(selected_adapter)

        print(f"\nCurrent status of {selected_adapter}:")
        print(f"Mode: {info['mode'] if info else 'Unknown'}")

        # Ask what to do
        print("\nOptions:")
        print("1. Enable Monitor Mode")
        print("2. Disable Monitor Mode")
        print("3. View Detailed Info")

        action = self.get_user_choice("Choose action (1-3): ", ["1", "2", "3"])

        if action == "1":
            monitor_interface = manager.enable_monitor_mode(selected_adapter)
            if monitor_interface:
                self.logger.success(f"Monitor mode enabled: {monitor_interface}")
            else:
                self.logger.error("Failed to enable monitor mode")
        elif action == "2":
            if manager.disable_monitor_mode(selected_adapter):
                self.logger.success("Monitor mode disabled")
            else:
                self.logger.error("Failed to disable monitor mode")
        elif action == "3":
            if info:
                print(f"\nDetailed info for {selected_adapter}:")
                for key, value in info.items():
                    print(f"{key.capitalize()}: {value}")
            else:
                self.logger.error("Could not retrieve adapter information")

        input("\nPress Enter to continue...")

    def handle_network_scan(self):
        from modules.scanner import NetworkScanner
        from modules.monitor_mode import scan_adapters

        print("\n" + "="*50)
        print("Wi-Fi Network Scanner")
        print("="*50)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.warning("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(monitor_interfaces) + 1)])

        selected_interface = monitor_interfaces[int(choice) - 1]

        # Scan options
        print("\nScan Options:")
        print("1. Quick Scan (10 seconds)")
        print("2. Normal Scan (30 seconds)")
        print("3. Long Scan (60 seconds)")
        print("4. Continuous Scan (until stopped)")

        scan_choice = self.get_user_choice("Choose scan type (1-4): ", ["1", "2", "3", "4"])

        duration_map = {
            "1": 10,
            "2": 30,
            "3": 60
        }

        scanner = NetworkScanner()

        if scan_choice in duration_map:
            duration = duration_map[scan_choice]
            self.logger.info(f"Starting {duration} second scan...")
            result = scanner.scan_networks(selected_interface, duration=duration)
        else:
            # Continuous scan
            self.logger.info("Starting continuous scan (Ctrl+C to stop)...")
            try:
                scanner.continuous_scan(selected_interface)
            except KeyboardInterrupt:
                self.logger.info("Continuous scan stopped")

        input("\nPress Enter to continue...")

    def handle_deauth_attack(self):
        from modules.attack import AttackManager
        from modules.monitor_mode import scan_adapters
        from utils.helpers import get_validated_input

        print("\n" + "="*50)
        print("Deauthentication Attack")
        print("="*50)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.warning("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(monitor_interfaces) + 1)])

        selected_interface = monitor_interfaces[int(choice) - 1]

        # Get target BSSID
        bssid = get_validated_input("Enter target BSSID (e.g., 00:11:22:33:44:55): ",
                                   lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                   "Invalid BSSID format. Use format: 00:11:22:33:44:55")

        # Client MAC (optional)
        client_choice = self.get_user_choice("Target specific client or all clients?\n1. Specific client\n2. All clients: ", ["1", "2"])

        client_mac = None
        if client_choice == "1":
            client_mac = get_validated_input("Enter client MAC address: ",
                                           lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                           "Invalid MAC format. Use format: 00:11:22:33:44:55")

        # Packet count
        count_choice = self.get_user_choice("Number of deauth packets:\n1. 10 packets\n2. 100 packets\n3. Continuous (until stopped): ", ["1", "2", "3"])

        count_map = {"1": 10, "2": 100, "3": 0}  # 0 means continuous
        count = count_map[count_choice]

        # Delay
        delay = 0.1  # Default delay
        if count > 0:
            delay_input = input("Delay between packets (seconds, default 0.1): ").strip()
            if delay_input:
                try:
                    delay = float(delay_input)
                    if delay < 0:
                        delay = 0.1
                except ValueError:
                    delay = 0.1

        # Execute attack
        manager = AttackManager()
        success = manager.deauth_attack(bssid, client_mac, count, delay, selected_interface)

        if success:
            if count == 0:
                self.logger.info("Continuous attack started. Press Ctrl+C to stop.")
                try:
                    input("Press Enter to stop the attack...")
                except KeyboardInterrupt:
                    pass
                manager.stop_all_attacks()
            else:
                self.logger.success("Deauthentication attack completed")
        else:
            self.logger.error("Deauthentication attack failed")

        input("\nPress Enter to continue...")

    def handle_handshake_capture(self):
        from modules.attack import AttackManager
        from modules.monitor_mode import scan_adapters
        from utils.helpers import get_validated_input

        print("\n" + "="*50)
        print("WPA Handshake Capture")
        print("="*50)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.warning("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(monitor_interfaces) + 1)])

        selected_interface = monitor_interfaces[int(choice) - 1]

        # Get target BSSID and channel
        bssid = get_validated_input("Enter target BSSID: ",
                                   lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                   "Invalid BSSID format")

        channel = input("Enter target channel: ").strip()
        if not channel.isdigit() or not (1 <= int(channel) <= 165):
            self.logger.error("Invalid channel (must be 1-165)")
            input("\nPress Enter to continue...")
            return

        channel = int(channel)

        # Output file
        output_file = input("Output file name (without extension): ").strip() or f"handshake_{bssid.replace(':', '')}"

        # Deauth option
        deauth_choice = self.get_user_choice("Use deauthentication to force handshake?\n1. Yes\n2. No: ", ["1", "2"])
        use_deauth = (deauth_choice == "1")

        if not get_user_confirmation(f"Start handshake capture on {bssid} channel {channel}?"):
            self.logger.info("Handshake capture cancelled")
            input("\nPress Enter to continue...")
            return

        # Start capture
        manager = AttackManager()
        result = manager.handshake_capture(bssid, channel, selected_interface, output_file, use_deauth)

        if result:
            self.logger.success(f"Handshake capture completed: {result}")
        else:
            self.logger.warning("Handshake capture completed but no handshake was captured")

        input("\nPress Enter to continue...")

    def handle_evil_twin(self):
        from modules.attack import AttackManager
        from utils.helpers import get_validated_input

        print("\n" + "="*50)
        print("Evil Twin Attack")
        print("="*50)

        self.logger.warning("Evil Twin attack requires manual setup of hostapd and dnsmasq")
        self.logger.info("This feature is not yet fully automated")

        # Basic setup guidance
        print("\nEvil Twin Attack Setup:")
        print("1. Configure hostapd.conf for fake AP")
        print("2. Configure dnsmasq.conf for DHCP")
        print("3. Start hostapd and dnsmasq services")
        print("4. Set up traffic capture")
        print()
        print("This is a complex attack that requires careful setup.")
        print("Please refer to documentation for detailed instructions.")

        if get_user_confirmation("Continue with basic evil twin setup?"):
            # This would implement the full evil twin attack
            self.logger.info("Evil Twin attack setup would go here")
            self.logger.warning("Feature not yet implemented")

        input("\nPress Enter to continue...")

    def handle_wps_attack(self):
        from modules.attack import AttackManager
        from utils.helpers import get_validated_input

        print("\n" + "="*50)
        print("WPS Attack")
        print("="*50)

        self.logger.info("WPS attacks target wireless routers with WPS enabled")

        # Get target BSSID
        bssid = get_validated_input("Enter target BSSID: ",
                                   lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                   "Invalid BSSID format")

        print("\nWPS Attack Methods:")
        print("1. Reaver (brute force PIN)")
        print("2. Pixie Dust attack")
        print("3. Online brute force")

        method_choice = self.get_user_choice("Choose method (1-3): ", ["1", "2", "3"])

        if not get_user_confirmation(f"Start WPS attack on {bssid}?"):
            self.logger.info("WPS attack cancelled")
            input("\nPress Enter to continue...")
            return

        # This would implement the actual WPS attacks
        manager = AttackManager()

        if method_choice == "1":
            self.logger.info("Starting Reaver attack...")
            # manager.reaver_attack(bssid)
            self.logger.warning("Reaver attack not yet implemented")
        elif method_choice == "2":
            self.logger.info("Starting Pixie Dust attack...")
            # manager.pixie_dust_attack(bssid)
            self.logger.warning("Pixie Dust attack not yet implemented")
        else:
            self.logger.info("Starting online brute force...")
            # manager.wps_brute_force(bssid)
            self.logger.warning("WPS brute force not yet implemented")

        input("\nPress Enter to continue...")

    def handle_beacon_flood(self):
        from modules.attack import AttackManager
        from modules.monitor_mode import scan_adapters

        print("\n" + "="*50)
        print("Beacon Flood Attack")
        print("="*50)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.warning("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(monitor_interfaces) + 1)])

        selected_interface = monitor_interfaces[int(choice) - 1]

        # SSID configuration
        print("\nSSID Configuration:")
        print("1. Use default fake SSIDs")
        print("2. Custom SSID list")

        ssid_choice = self.get_user_choice("Choose option (1-2): ", ["1", "2"])

        if ssid_choice == "1":
            ssid_list = None  # Use defaults
        else:
            ssids = input("Enter SSIDs (comma-separated): ").strip()
            ssid_list = [ssid.strip() for ssid in ssids.split(',') if ssid.strip()]

        count = int(input("Beacons per SSID (default 1000): ").strip() or "1000")
        delay = float(input("Delay between floods (seconds, default 0.1): ").strip() or "0.1")

        if not get_user_confirmation("Start beacon flood attack?"):
            self.logger.info("Beacon flood cancelled")
            input("\nPress Enter to continue...")
            return

        # Execute attack
        manager = AttackManager()
        success = manager.beacon_flood(selected_interface, ssid_list, count, delay)

        if success:
            self.logger.success("Beacon flood completed")
        else:
            self.logger.error("Beacon flood failed")

        input("\nPress Enter to continue...")

    def handle_bluetooth_attack(self):
        from modules.attack import AttackManager

        print("\n" + "="*50)
        print("Bluetooth Attacks")
        print("="*50)

        print("\nBluetooth Attack Options:")
        print("1. Scan for devices")
        print("2. BlueBorne vulnerability scan")
        print("3. Basic pairing attack")

        attack_choice = self.get_user_choice("Choose attack (1-3): ", ["1", "2", "3"])

        if attack_choice == "1":
            # Device scanning
            manager = AttackManager()
            devices = manager.bluetooth_scan()

            if devices:
                self.logger.success(f"Found {len(devices)} Bluetooth device(s)")
            else:
                self.logger.warning("No Bluetooth devices found")

        elif attack_choice == "2":
            self.logger.warning("BlueBorne vulnerability scanning not yet implemented")

        elif attack_choice == "3":
            self.logger.warning("Basic pairing attacks not yet implemented")

        input("\nPress Enter to continue...")

    def handle_wpa_cracking(self):
        from modules.cracker import PasswordCracker
        from utils.helpers import get_validated_input

        print("\n" + "="*50)
        print("WPA Handshake Cracking")
        print("="*50)

        # Get handshake file
        handshake_file = input("Enter path to handshake file (.cap): ").strip()
        if not handshake_file or not os.path.exists(handshake_file):
            self.logger.error("Invalid or missing handshake file")
            input("\nPress Enter to continue...")
            return

        # Wordlist selection
        wordlist_choice = self.get_user_choice("Wordlist options:\n1. Use default wordlists\n2. Specify custom wordlist: ", ["1", "2"])

        wordlist = None
        if wordlist_choice == "2":
            wordlist = input("Enter path to wordlist: ").strip()
            if not wordlist or not os.path.exists(wordlist):
                self.logger.error("Invalid wordlist file")
                input("\nPress Enter to continue...")
                return

        # Cracking method
        method_choice = self.get_user_choice("Cracking method:\n1. Aircrack-ng (recommended)\n2. Hashcat (advanced): ", ["1", "2"])
        use_hashcat = (method_choice == "2")

        if not get_user_confirmation(f"Start WPA cracking on {handshake_file}?"):
            self.logger.info("WPA cracking cancelled")
            input("\nPress Enter to continue...")
            return

        # Start cracking
        cracker = PasswordCracker()
        success = cracker.crack_wpa_handshake(handshake_file, wordlist, use_hashcat)

        if success:
            self.logger.success("WPA cracking completed successfully!")
        else:
            self.logger.warning("WPA cracking completed but key not found")

        input("\nPress Enter to continue...")

    def handle_password_generation(self):
        from modules.password_generator import AdvancedPasswordGenerator

        print("\n" + "="*50)
        print("Password Generation")
        print("="*50)

        print("\nGeneration Methods:")
        print("1. Template-based (e.g., Pass????)")
        print("2. Leet speak variations")
        print("3. Common patterns")
        print("4. Brute force")
        print("5. Mixed dictionary")

        method_choice = self.get_user_choice("Choose method (1-5): ", ["1", "2", "3", "4", "5"])

        generator = AdvancedPasswordGenerator()

        if method_choice == "1":
            template = input("Enter template (e.g., Pass???? for Pass + 4 chars): ").strip()
            count = int(input("Number of passwords to generate: ").strip() or "100")
            passwords = generator.generate_from_template(template, count)

        elif method_choice == "2":
            base_words = input("Enter base words (comma-separated): ").strip().split(',')
            base_words = [word.strip() for word in base_words if word.strip()]
            intensity = int(input("Leet intensity (1-3): ").strip() or "1")
            count = int(input("Number of passwords to generate: ").strip() or "100")
            passwords = generator.generate_leet_speak(base_words, intensity, count)

        elif method_choice == "3":
            personal_info = {}
            personal_info['name'] = input("Name: ").strip() or "john"
            personal_info['birth_year'] = input("Birth year: ").strip() or "1990"
            personal_info['pet'] = input("Pet name: ").strip() or "fluffy"
            personal_info['city'] = input("City: ").strip() or "paris"
            count = int(input("Number of passwords to generate: ").strip() or "1000")
            passwords = generator.generate_common_patterns(personal_info, count)

        elif method_choice == "4":
            charset = input("Character set (default: lowercase): ").strip() or "abcdefghijklmnopqrstuvwxyz"
            min_length = int(input("Minimum length: ").strip() or "4")
            max_length = int(input("Maximum length: ").strip() or "8")
            count = int(input("Number of passwords to generate: ").strip() or "1000")
            passwords = generator.generate_brute_force(charset, min_length, max_length, count)

        elif method_choice == "5":
            dictionaries = [
                input("Dictionary 1 words (comma-separated): ").strip().split(','),
                input("Dictionary 2 words (comma-separated): ").strip().split(','),
                input("Dictionary 3 words (comma-separated): ").strip().split(',')
            ]
            dictionaries = [[word.strip() for word in d if word.strip()] for d in dictionaries]
            count = int(input("Number of passwords to generate: ").strip() or "10000")
            passwords = generator.generate_mixed_dictionary(dictionaries, count=count)

        if 'passwords' in locals() and passwords:
            # Display sample
            print(f"\nGenerated {len(passwords)} passwords")
            print("\nSample passwords:")
            for pwd in passwords[:10]:
                print(f"  {pwd}")

            # Save option
            save_choice = self.get_user_choice("Save passwords to file?\n1. Yes\n2. No: ", ["1", "2"])
            if save_choice == "1":
                filename = input("Enter filename: ").strip() or f"passwords_{method_choice}.txt"
                format_choice = self.get_user_choice("Format:\n1. Text\n2. CSV\n3. JSON: ", ["1", "2", "3"])
                format_map = {"1": "text", "2": "csv", "3": "json"}
                success = generator.save_to_file(passwords, filename, format_map[format_choice])
                if success:
                    print(f"Passwords saved to: {filename}")

            # Analysis
            analysis = generator.analyze_password_strength(passwords)
        else:
            self.logger.error("Password generation failed")

        input("\nPress Enter to continue...")

    def handle_packet_capture(self):
        from modules.analysis import PacketCapture
        from modules.monitor_mode import scan_adapters

        print("\n" + "="*50)
        print("Packet Capture")
        print("="*50)

        # Check for available interfaces
        adapters = scan_adapters()
        interfaces = [adapter['interface'] for adapter in adapters]

        if not interfaces:
            self.logger.error("No network interfaces found")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable interfaces:")
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(interfaces) + 1)])

        selected_interface = interfaces[int(choice) - 1]

        # Capture options
        duration = self.get_user_choice("Capture duration (seconds, default 60): ", ["30", "60", "120", "300"])
        duration = int(duration)

        filter_choice = self.get_user_choice("Use capture filter?\n1. No filter\n2. TCP only\n3. UDP only\n4. Custom filter: ", ["1", "2", "3", "4"])

        filter_expr = ""
        if filter_choice == "2":
            filter_expr = "tcp"
        elif filter_choice == "3":
            filter_expr = "udp"
        elif filter_choice == "4":
            filter_expr = input("Enter Wireshark-style filter: ").strip()

        use_scapy = self.get_user_choice("Capture method:\n1. pyshark (recommended)\n2. Scapy: ", ["1", "2"]) == "2"

        # Generate output filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = f"capture_{timestamp}.pcap"

        if not get_user_confirmation(f"Start capture on {selected_interface} for {duration} seconds?"):
            self.logger.info("Packet capture cancelled")
            input("\nPress Enter to continue...")
            return

        # Start capture
        capturer = PacketCapture()
        result = capturer.capture_packets(selected_interface, duration, filter_expr, output_file, use_scapy)

        if result:
            self.logger.success(f"Packet capture completed: {result}")
        else:
            self.logger.error("Packet capture failed")

        input("\nPress Enter to continue...")

    def handle_client_analysis(self):
        from modules.analysis import ClientAnalyzer
        from modules.scanner import NetworkScanner
        from modules.monitor_mode import scan_adapters

        print("\n" + "="*50)
        print("Client Analysis")
        print("="*50)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.warning("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(monitor_interfaces) + 1)])

        selected_interface = monitor_interfaces[int(choice) - 1]

        # Analysis duration
        duration_options = {
            "1": 60,    # 1 minute
            "2": 300,   # 5 minutes
            "3": 900,   # 15 minutes
            "4": 3600   # 1 hour
        }

        print("\nAnalysis duration:")
        print("1. 1 minute")
        print("2. 5 minutes")
        print("3. 15 minutes")
        print("4. 1 hour")

        duration_choice = self.get_user_choice("Choose duration: ", ["1", "2", "3", "4"])
        duration = duration_options[duration_choice]

        if not get_user_confirmation(f"Start client analysis for {duration} seconds on {selected_interface}?"):
            self.logger.info("Client analysis cancelled")
            input("\nPress Enter to continue...")
            return

        # First scan for current clients
        self.logger.info("Scanning for current clients...")
        scanner = NetworkScanner()
        result = scanner.scan_networks(selected_interface, duration=10)

        if result and result['clients']:
            self.logger.success(f"Found {len(result['clients'])} clients to analyze")

            # Start analysis
            analyzer = ClientAnalyzer()
            analysis = analyzer.analyze_clients(result['clients'], duration)

            if analysis:
                self.logger.success("Client analysis completed")
            else:
                self.logger.warning("Client analysis failed or was interrupted")
        else:
            self.logger.warning("No clients found to analyze")
            self.logger.info("Try scanning for networks first to populate client data")

        input("\nPress Enter to continue...")

    def handle_port_scanning(self):
        from modules.analysis import PortScanner
        from utils.helpers import get_validated_input

        print("\n" + "="*50)
        print("Port Scanning")
        print("="*50)

        # Get target IP
        target_ip = get_validated_input("Enter target IP address: ",
                                      lambda x: len(x.split('.')) == 4 and all(i.isdigit() and 0 <= int(i) <= 255 for i in x.split('.')),
                                      "Invalid IP address format")

        # Port range options
        print("\nPort range options:")
        print("1. Quick scan (common ports: 21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389)")
        print("2. Well-known ports (1-1024)")
        print("3. Registered ports (1024-49151)")
        print("4. All ports (1-65535)")
        print("5. Custom range")

        port_choice = self.get_user_choice("Choose port range: ", ["1", "2", "3", "4", "5"])

        port_ranges = {
            "1": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389",
            "2": "1-1024",
            "3": "1024-49151",
            "4": "1-65535"
        }

        if port_choice in port_ranges:
            ports = port_ranges[port_choice]
        else:
            ports = input("Enter custom port range (e.g., 80,443 or 1-1000): ").strip()

        # Scan type
        print("\nScan type options:")
        print("1. TCP SYN scan (stealthy, fast)")
        print("2. TCP connect scan (reliable)")
        print("3. UDP scan (slower, detects UDP services)")
        print("4. Aggressive scan (comprehensive, noisy)")

        scan_types = {
            "1": "tcp",
            "2": "connect",
            "3": "udp",
            "4": "aggressive"
        }

        scan_choice = self.get_user_choice("Choose scan type: ", ["1", "2", "3", "4"])
        scan_type = scan_types[scan_choice]

        # Timing
        timing_options = {
            "1": "T5",  # Insane (very fast, might miss ports)
            "2": "T4",  # Aggressive (fast)
            "3": "T3",  # Normal
            "4": "T2",  # Polite (slower)
            "5": "T1"   # Sneaky (very slow)
        }

        print("\nTiming options:")
        print("1. Insane (very fast)")
        print("2. Aggressive (fast)")
        print("3. Normal")
        print("4. Polite (slower)")
        print("5. Sneaky (very slow)")

        timing_choice = self.get_user_choice("Choose timing: ", ["1", "2", "3", "4", "5"])
        timing = timing_options[timing_choice]

        if not get_user_confirmation(f"Start {scan_type.upper()} port scan on {target_ip} with ports {ports}?"):
            self.logger.info("Port scan cancelled")
            input("\nPress Enter to continue...")
            return

        # Execute scan
        scanner = PortScanner()
        result = scanner.scan_ports(target_ip, ports, scan_type, timing)

        if result and isinstance(result, list):
            self.logger.success(f"Port scan completed. Found {len(result)} open ports.")
        elif result is False:
            self.logger.error("Port scan failed")
        else:
            self.logger.info("Port scan completed with no open ports found")

        input("\nPress Enter to continue...")

    def handle_signal_analysis(self):
        from modules.scanner import NetworkScanner
        from modules.monitor_mode import scan_adapters

        print("\n" + "="*50)
        print("Signal Strength Analysis")
        print("="*50)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.warning("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(monitor_interfaces) + 1)])

        selected_interface = monitor_interfaces[int(choice) - 1]

        # Analysis options
        duration_options = {
            "1": 60,    # 1 minute
            "2": 300,   # 5 minutes
            "3": 900,   # 15 minutes
        }

        print("\nAnalysis duration:")
        print("1. 1 minute")
        print("2. 5 minutes")
        print("3. 15 minutes")

        duration_choice = self.get_user_choice("Choose duration: ", ["1", "2", "3"])
        duration = duration_options[duration_choice]

        # Target network (optional)
        target_choice = self.get_user_choice("Analyze specific network?\n1. All networks\n2. Specific BSSID: ", ["1", "2"])

        target_bssid = None
        if target_choice == "2":
            from utils.helpers import get_validated_input
            target_bssid = get_validated_input("Enter target BSSID: ",
                                             lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                             "Invalid BSSID format")

        if not get_user_confirmation(f"Start signal analysis for {duration} seconds{' on ' + target_bssid if target_bssid else ''}?"):
            self.logger.info("Signal analysis cancelled")
            input("\nPress Enter to continue...")
            return

        # Start analysis
        scanner = NetworkScanner()
        signal_data = scanner.signal_analysis(selected_interface, target_bssid, duration)

        if signal_data:
            self.logger.success("Signal analysis completed")
        else:
            self.logger.warning("Signal analysis failed or found no data")

        input("\nPress Enter to continue...")

    def handle_traffic_analysis(self):
        from modules.scanner import NetworkScanner
        from modules.monitor_mode import scan_adapters

        print("\n" + "="*50)
        print("Traffic Analysis")
        print("="*50)

        # Check for available interfaces (can use regular interfaces for traffic analysis)
        adapters = scan_adapters()
        interfaces = [adapter['interface'] for adapter in adapters]

        if not interfaces:
            self.logger.error("No network interfaces found")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable interfaces:")
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(interfaces) + 1)])

        selected_interface = interfaces[int(choice) - 1]

        # Analysis duration
        duration_options = {
            "1": 30,    # 30 seconds
            "2": 60,    # 1 minute
            "3": 300,   # 5 minutes
        }

        print("\nAnalysis duration:")
        print("1. 30 seconds")
        print("2. 1 minute")
        print("3. 5 minutes")

        duration_choice = self.get_user_choice("Choose duration: ", ["1", "2", "3"])
        duration = duration_options[duration_choice]

        # Filter options
        print("\nTraffic filter:")
        print("1. All traffic")
        print("2. TCP only")
        print("3. UDP only")
        print("4. HTTP/HTTPS traffic")
        print("5. Custom filter")

        filter_options = {
            "1": "",
            "2": "tcp",
            "3": "udp",
            "4": "tcp port 80 or tcp port 443",
        }

        filter_choice = self.get_user_choice("Choose filter: ", ["1", "2", "3", "4", "5"])

        if filter_choice == "5":
            filter_expr = input("Enter Wireshark-style filter: ").strip()
        else:
            filter_expr = filter_options[filter_choice]

        # BSSID filter for wireless interfaces
        from modules.monitor_mode import get_adapter_info
        info = get_adapter_info(selected_interface)
        bssid_filter = None

        if info and info.get('mode') == 'Monitor':
            bssid_choice = self.get_user_choice("Filter by specific BSSID?\n1. No\n2. Yes: ", ["1", "2"])
            if bssid_choice == "2":
                from utils.helpers import get_validated_input
                bssid_filter = get_validated_input("Enter BSSID to filter: ",
                                                 lambda x: len(x.split(':')) == 6 and all(len(part) == 2 for part in x.split(':')),
                                                 "Invalid BSSID format")

        if not get_user_confirmation(f"Start traffic analysis for {duration} seconds on {selected_interface}?"):
            self.logger.info("Traffic analysis cancelled")
            input("\nPress Enter to continue...")
            return

        # Start analysis
        scanner = NetworkScanner()
        traffic_data = scanner.traffic_analysis(selected_interface, duration, bssid_filter)

        if traffic_data:
            self.logger.success("Traffic analysis completed")
        else:
            self.logger.warning("Traffic analysis failed or captured no data")

        input("\nPress Enter to continue...")

    def handle_vulnerability_scan(self):
        from modules.analysis import VulnerabilityScanner
        from modules.scanner import NetworkScanner
        from modules.monitor_mode import scan_adapters

        print("\n" + "="*50)
        print("Vulnerability Scanning")
        print("="*50)

        # Check for monitor interfaces
        adapters = scan_adapters()
        monitor_interfaces = []

        for adapter in adapters:
            from modules.monitor_mode import get_adapter_info
            info = get_adapter_info(adapter['interface'])
            if info and info.get('mode') == 'Monitor':
                monitor_interfaces.append(adapter['interface'])

        if not monitor_interfaces:
            self.logger.warning("No interfaces in monitor mode found")
            self.logger.info("Please enable monitor mode first")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable monitor interfaces:")
        for i, interface in enumerate(monitor_interfaces, 1):
            print(f"{i}. {interface}")

        choice = self.get_user_choice("\nSelect interface (number): ", [str(i) for i in range(1, len(monitor_interfaces) + 1)])

        selected_interface = monitor_interfaces[int(choice) - 1]

        if not get_user_confirmation("Scan for Wi-Fi networks and check for vulnerabilities?"):
            self.logger.info("Vulnerability scan cancelled")
            input("\nPress Enter to continue...")
            return

        # Scan networks first
        self.logger.info("Scanning for networks...")
        scanner = NetworkScanner()
        result = scanner.scan_networks(selected_interface, duration=20)

        if result and result['networks']:
            # Scan for vulnerabilities
            vuln_scanner = VulnerabilityScanner()
            vulnerabilities = vuln_scanner.scan_wifi_vulnerabilities(result['networks'])

            if vulnerabilities:
                print(f"\nFound {len(vulnerabilities)} potential vulnerabilities")
                save_choice = self.get_user_choice("Save vulnerability report?\n1. Yes\n2. No: ", ["1", "2"])

                if save_choice == "1":
                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    filename = f"vulnerability_report_{timestamp}.txt"

                    with open(filename, 'w') as f:
                        f.write("WiFiSniper Vulnerability Report\n")
                        f.write("="*40 + "\n")
                        f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Interface: {selected_interface}\n")
                        f.write(f"Networks Scanned: {len(result['networks'])}\n")
                        f.write(f"Vulnerabilities Found: {len(vulnerabilities)}\n\n")

                        for vuln in vulnerabilities:
                            f.write(f"[{vuln['severity'].upper()}] {vuln['network']}\n")
                            f.write(f"Type: {vuln['type']}\n")
                            f.write(f"Description: {vuln['description']}\n")
                            f.write(f"Recommendation: {vuln['recommendation']}\n")
                            f.write("-" * 40 + "\n")

                    self.logger.success(f"Report saved to: {filename}")
            else:
                self.logger.success("No vulnerabilities detected in scanned networks")
        else:
            self.logger.warning("No networks found to scan for vulnerabilities")

        input("\nPress Enter to continue...")

    def handle_dependency_check(self):
        self.logger.info("Running dependency check...")
        if check_dependencies():
            self.logger.success("All dependencies are satisfied!")
        else:
            self.logger.error("Some dependencies are missing. Please install them and try again.")
        input("\nPress Enter to continue...")

    def handle_adapter_management(self):
        from modules.monitor_mode import MonitorModeManager, scan_adapters

        print("\n" + "="*50)
        print("Adapter Management")
        print("="*50)

        # Scan for adapters
        adapters = scan_adapters()
        if not adapters:
            self.logger.error("No wireless adapters found")
            input("\nPress Enter to continue...")
            return

        print("\nAvailable adapters:")
        for i, adapter in enumerate(adapters, 1):
            print(f"{i}. {adapter['interface']} - {adapter['description']}")

        choice = self.get_user_choice("\nSelect adapter (number): ", [str(i) for i in range(1, len(adapters) + 1)])

        selected_adapter = adapters[int(choice) - 1]['interface']
        manager = MonitorModeManager()

        # Get detailed info
        info = manager.get_adapter_info(selected_adapter)

        print(f"\nDetailed information for {selected_adapter}:")
        if info:
            for key, value in info.items():
                print(f"  {key.capitalize()}: {value}")
        else:
            print("  Could not retrieve adapter information")

        # Management options
        print("\nManagement Options:")
        print("1. Enable Monitor Mode")
        print("2. Disable Monitor Mode")
        print("3. Kill Interfering Processes")
        print("4. Set as Default Interface")

        action = self.get_user_choice("Choose action (1-4): ", ["1", "2", "3", "4"])

        if action == "1":
            monitor_interface = manager.enable_monitor_mode(selected_adapter)
            if monitor_interface:
                self.logger.success(f"Monitor mode enabled: {monitor_interface}")
            else:
                self.logger.error("Failed to enable monitor mode")
        elif action == "2":
            if manager.disable_monitor_mode(selected_adapter):
                self.logger.success("Monitor mode disabled")
            else:
                self.logger.error("Failed to disable monitor mode")
        elif action == "3":
            from utils.helpers import kill_process_by_name
            processes_to_kill = ["NetworkManager", "wpa_supplicant", "dhclient"]
            killed = 0
            for process in processes_to_kill:
                if kill_process_by_name(process):
                    killed += 1
            if killed > 0:
                self.logger.success(f"Killed {killed} interfering processes")
            else:
                self.logger.info("No interfering processes found")
        elif action == "4":
            from core.config import set_config
            set_config("default_interface", selected_adapter)
            self.logger.success(f"Set {selected_adapter} as default interface")

        input("\nPress Enter to continue...")

    def handle_logs_reports(self):
        from core.logging_system import advanced_logger
        from core.reports import report_generator

        print("\n" + "="*50)
        print("Logs and Reports")
        print("="*50)

        print("\nOptions:")
        print("1. View Recent Logs")
        print("2. Export Logs")
        print("3. Generate Session Report")
        print("4. View Report History")

        choice = self.get_user_choice("Choose option (1-4): ", ["1", "2", "3", "4"])

        if choice == "1":
            # View recent logs
            logs = advanced_logger.get_recent_logs(20)
            print("\nRecent Logs (last 20 entries):")
            print("-" * 50)
            for log in logs:
                print(log)

        elif choice == "2":
            # Export logs
            filename = advanced_logger.export_logs()
            if filename:
                print(f"\nLogs exported to: {filename}")

        elif choice == "3":
            # Generate session report
            # This would typically track session data throughout the application
            session_data = {
                'duration': 'Current Session',
                'activities': {'scans': 0, 'attacks': 0, 'analyses': 0},  # Would be populated by actual usage
                'networks_discovered': 0,
                'attacks_performed': 0,
                'vulnerabilities_found': 0
            }

            report_file = report_generator.generate_session_summary(session_data)
            if report_file:
                print(f"\nSession report saved to: {report_file}")

        elif choice == "4":
            # View report history
            report_dir = os.path.expanduser("~/wifisniper_scans")
            if os.path.exists(report_dir):
                reports = [f for f in os.listdir(report_dir) if f.endswith(('.txt', '.json', '.csv'))]
                if reports:
                    print(f"\nReport files in {report_dir}:")
                    for i, report in enumerate(reports, 1):
                        print(f"{i}. {report}")
                else:
                    print(f"\nNo report files found in {report_dir}")
            else:
                print(f"\nReport directory {report_dir} does not exist")

        input("\nPress Enter to continue...")

    def handle_configuration(self):
        from core.config import config_manager

        print("\n" + "="*50)
        print("Configuration Management")
        print("="*50)

        print("\nOptions:")
        print("1. View Current Configuration")
        print("2. Edit Configuration")
        print("3. Reset to Defaults")
        print("4. Save Configuration")

        choice = self.get_user_choice("Choose option (1-4): ", ["1", "2", "3", "4"])

        if choice == "1":
            # View configuration
            config_manager.show_config()

        elif choice == "2":
            # Edit configuration
            print("\nConfiguration Sections:")
            print("1. Default Interface")
            print("2. Scan Settings")
            print("3. Attack Settings")
            print("4. UI Settings")
            print("5. Logging Settings")

            section_choice = self.get_user_choice("Choose section to edit (1-5): ", ["1", "2", "3", "4", "5"])

            if section_choice == "1":
                interface = input("Enter default interface: ").strip()
                config_manager.set("default_interface", interface)
                self.logger.success("Default interface updated")

            elif section_choice == "2":
                print("\nScan Settings:")
                duration = input("Default scan duration (seconds): ").strip()
                if duration.isdigit():
                    config_manager.set("scan_settings.default_duration", int(duration))

                auto_save = self.get_user_choice("Auto-save scans? (y/n): ", ["y", "n"])
                config_manager.set("scan_settings.auto_save_scans", auto_save == "y")

                output_dir = input("Scan output directory: ").strip()
                if output_dir:
                    config_manager.set("scan_settings.scan_output_dir", output_dir)

                self.logger.success("Scan settings updated")

            elif section_choice == "3":
                print("\nAttack Settings:")
                deauth_count = input("Default deauth count: ").strip()
                if deauth_count.isdigit():
                    config_manager.set("attack_settings.default_deauth_count", int(deauth_count))

                deauth_delay = input("Default deauth delay (seconds): ").strip()
                try:
                    delay = float(deauth_delay)
                    config_manager.set("attack_settings.default_deauth_delay", delay)
                except ValueError:
                    pass

                confirm = self.get_user_choice("Confirm destructive actions? (y/n): ", ["y", "n"])
                config_manager.set("attack_settings.confirm_destructive_actions", confirm == "y")

                self.logger.success("Attack settings updated")

            elif section_choice == "4":
                print("\nUI Settings:")
                colors = self.get_user_choice("Enable colored output? (y/n): ", ["y", "n"])
                config_manager.set("ui_settings.color_output", colors == "y")

                timestamps = self.get_user_choice("Show timestamps? (y/n): ", ["y", "n"])
                config_manager.set("ui_settings.show_timestamps", timestamps == "y")

                self.logger.success("UI settings updated")

            elif section_choice == "5":
                print("\nLogging Settings:")
                log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
                print("Log levels:", ", ".join(log_levels))
                level = input("Log level: ").strip().upper()
                if level in log_levels:
                    config_manager.set("logging.log_level", level)

                log_file = input("Log file path: ").strip()
                if log_file:
                    config_manager.set("logging.log_file", log_file)

                self.logger.success("Logging settings updated")

        elif choice == "3":
            # Reset to defaults
            if self.get_user_choice("Reset configuration to defaults? (y/n): ", ["y", "n"]) == "y":
                config_manager.reset_to_defaults()
                self.logger.success("Configuration reset to defaults")

        elif choice == "4":
            # Save configuration
            if config_manager.save_config():
                self.logger.success("Configuration saved")

        input("\nPress Enter to continue...")

    def handle_help_about(self):
        self.print_header()
        print(f"{Fore.GREEN}WiFiSniper v1.0{Style.RESET_ALL}")
        print("A modular, menu-driven Wi-Fi pentesting toolkit")
        print()
        print("Features:")
        print("- Wireless network scanning and analysis")
        print("- Deauthentication and handshake capture")
        print("- Password cracking with aircrack-ng")
        print("- Evil twin and WPS attacks")
        print("- Network analysis and monitoring")
        print("- Plugin system for extensibility")
        print()
        print("For more information, see README.md")
        print()
        print(f"{Fore.YELLOW}WARNING: Use only on networks you own or have permission to test!{Style.RESET_ALL}")
        print()
        input("Press Enter to continue...")

    def plugins_menu(self):
        """Plugins menu"""
        while True:
            self.print_header()

            print(f"{Fore.GREEN}Plugins Menu{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*20}{Style.RESET_ALL}")
            print()

            # Get available plugins by category
            from core.plugin_loader import get_plugins_by_category

            categories = {
                'attacks': 'Wireless Attacks',
                'analysis': 'Network Analysis',
                'utilities': 'Utilities',
                'cracking': 'Password Cracking',
                'bluetooth': 'Bluetooth'
            }

            menu_items = []
            plugin_map = {}

            for cat_key, cat_name in categories.items():
                plugins = get_plugins_by_category(cat_key)
                if plugins:
                    print(f"{cat_name}:")
                    for plugin_key, plugin in plugins.items():
                        menu_items.append(f"  {len(menu_items) + 1}. {plugin.name} v{plugin.version}")
                        plugin_map[str(len(menu_items))] = plugin
                    print()

            if not menu_items:
                print("No plugins loaded.")
                print()
                print("Available plugin categories:")
                for cat_name in categories.values():
                    print(f"  - {cat_name}")
                print()
                print("To add plugins, place them in the plugins/ directory.")
            else:
                print("0. Back to Main Menu")
                print()

                choice = self.get_user_choice(f"Select plugin (0-{len(menu_items)}): ",
                                            ["0"] + [str(i+1) for i in range(len(menu_items))])

                if choice == "0":
                    return
                else:
                    selected_plugin = plugin_map[choice]
                    print(f"\nRunning plugin: {selected_plugin.name}")
                    print(f"Description: {selected_plugin.description}")
                    print()

                    try:
                        # Run the plugin
                        selected_plugin.run()
                    except Exception as e:
                        self.logger.error(f"Plugin execution failed: {e}")

                    input("\nPress Enter to continue...")

def main():
    try:
        # Run dependency check first
        print_banner()
        logger = Logger()
        logger.info("Checking system dependencies...")

        if not check_dependencies():
            logger.error("Dependency check failed. Please install missing dependencies and try again.")
            sys.exit(1)

        # Load plugins
        logger.info("Loading plugins...")
        load_plugins()

        # Start the menu system
        menu = MenuSystem()
        menu.main_menu()

    except KeyboardInterrupt:
        print("\n")
        print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
