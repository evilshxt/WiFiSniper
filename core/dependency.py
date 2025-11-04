import subprocess
import sys
import os
from colorama import Fore, Style

class DependencyChecker:
    def __init__(self):
        self.python_deps = {
            'colorama': 'Colored terminal output',
            'prettytable': 'Formatted table display',
            'scapy': 'Packet manipulation',
            'pyshark': 'Packet capture'
        }

        self.system_deps = {
            'aircrack-ng': {
                'check_cmd': 'aircrack-ng --help',
                'install_cmd': 'sudo apt install aircrack-ng',
                'description': 'Wi-Fi security auditing tools suite'
            },
            'nmap': {
                'check_cmd': 'nmap --version',
                'install_cmd': 'sudo apt install nmap',
                'description': 'Network discovery and security auditing'
            },
            'hostapd': {
                'check_cmd': 'hostapd -v',
                'install_cmd': 'sudo apt install hostapd',
                'description': 'User space daemon for access point and authentication servers'
            },
            'dnsmasq': {
                'check_cmd': 'dnsmasq --version',
                'install_cmd': 'sudo apt install dnsmasq',
                'description': 'DNS forwarder and DHCP server'
            },
            'reaver': {
                'check_cmd': 'reaver --help',
                'install_cmd': 'sudo apt install reaver',
                'description': 'Brute force attack against WPS'
            },
            'wireshark-common': {
                'check_cmd': 'tshark -v',
                'install_cmd': 'sudo apt install wireshark-common',
                'description': 'Network protocol analyzer'
            }
        }

    def check_python_dependencies(self):
        """Check if Python dependencies are installed"""
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Checking Python dependencies...")

        missing_deps = []
        for dep, description in self.python_deps.items():
            try:
                __import__(dep)
                print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {dep} - {description}")
            except ImportError:
                print(f"{Fore.RED}[MISSING]{Style.RESET_ALL} {dep} - {description}")
                missing_deps.append(dep)

        return missing_deps

    def check_system_dependencies(self):
        """Check if system dependencies are installed"""
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Checking system dependencies...")

        missing_deps = []
        for dep, info in self.system_deps.items():
            try:
                result = subprocess.run(
                    info['check_cmd'].split(),
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {dep} - {info['description']}")
                else:
                    print(f"{Fore.RED}[MISSING]{Style.RESET_ALL} {dep} - {info['description']}")
                    missing_deps.append(dep)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                print(f"{Fore.RED}[MISSING]{Style.RESET_ALL} {dep} - {info['description']}")
                missing_deps.append(dep)

        return missing_deps

    def install_python_dependencies(self, deps):
        """Install missing Python dependencies"""
        if not deps:
            return True

        print(f"\n{Fore.YELLOW}[ACTION]{Style.RESET_ALL} Installing Python dependencies...")
        try:
            cmd = [sys.executable, '-m', 'pip', 'install'] + deps
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Python dependencies installed successfully")
                return True
            else:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to install Python dependencies")
                print(f"Error: {result.stderr}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Exception during Python dependency installation: {e}")
            return False

    def install_system_dependencies(self, deps):
        """Install missing system dependencies"""
        if not deps:
            return True

        print(f"\n{Fore.YELLOW}[ACTION]{Style.RESET_ALL} Installing system dependencies...")
        print(f"{Fore.CYAN}Note:{Style.RESET_ALL} You may be prompted for sudo password")

        for dep in deps:
            if dep in self.system_deps:
                install_cmd = self.system_deps[dep]['install_cmd']
                print(f"{Fore.CYAN}[INSTALLING]{Style.RESET_ALL} {dep}...")

                try:
                    result = subprocess.run(install_cmd.split(), capture_output=True, text=True)

                    if result.returncode == 0:
                        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {dep} installed successfully")
                    else:
                        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to install {dep}")
                        print(f"Try manual installation: {install_cmd}")
                        return False
                except Exception as e:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Exception during {dep} installation: {e}")
                    return False

        return True

    def check_root_privileges(self):
        """Check if running with root privileges"""
        if os.geteuid() != 0:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} WiFiSniper requires root privileges for most operations")
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Run with: sudo python main.py")
            return False
        return True

    def run_full_check(self, auto_install=False):
        """Run complete dependency check"""
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}WiFiSniper Dependency Check{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        # Check root privileges
        has_root = self.check_root_privileges()

        # Check Python dependencies
        missing_python = self.check_python_dependencies()

        # Check system dependencies
        missing_system = self.check_system_dependencies()

        # Summary
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        all_good = True

        if missing_python:
            print(f"{Fore.RED}[PYTHON DEPS MISSING]{Style.RESET_ALL} {len(missing_python)} package(s)")
            all_good = False
        else:
            print(f"{Fore.GREEN}[PYTHON DEPS]{Style.RESET_ALL} All packages installed")

        if missing_system:
            print(f"{Fore.RED}[SYSTEM DEPS MISSING]{Style.RESET_ALL} {len(missing_system)} package(s)")
            all_good = False
        else:
            print(f"{Fore.GREEN}[SYSTEM DEPS]{Style.RESET_ALL} All packages installed")

        if not has_root:
            print(f"{Fore.YELLOW}[ROOT PRIVILEGES]{Style.RESET_ALL} Not running as root")
            all_good = False
        else:
            print(f"{Fore.GREEN}[ROOT PRIVILEGES]{Style.RESET_ALL} Running as root")

        # Auto-install if requested
        if auto_install and (missing_python or missing_system):
            print(f"\n{Fore.YELLOW}[AUTO-INSTALL]{Style.RESET_ALL} Attempting to install missing dependencies...")

            if missing_python:
                if not self.install_python_dependencies(missing_python):
                    all_good = False

            if missing_system:
                if not self.install_system_dependencies(missing_system):
                    all_good = False

            # Re-check after installation
            if missing_python or missing_system:
                print(f"\n{Fore.CYAN}[RE-CHECK]{Style.RESET_ALL} Re-checking dependencies after installation...")
                missing_python = self.check_python_dependencies()
                missing_system = self.check_system_dependencies()

                if not missing_python and not missing_system:
                    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} All dependencies now installed!")
                    all_good = True

        if all_good:
            print(f"\n{Fore.GREEN}[READY]{Style.RESET_ALL} WiFiSniper is ready to use!")
            return True
        else:
            print(f"\n{Fore.RED}[NOT READY]{Style.RESET_ALL} Please install missing dependencies and try again")
            print(f"{Fore.CYAN}[HELP]{Style.RESET_ALL} Check the README.md for manual installation instructions")
            return False

# Convenience function for external use
def check_dependencies(auto_install=False):
    """Convenience function to run dependency check"""
    checker = DependencyChecker()
    return checker.run_full_check(auto_install)