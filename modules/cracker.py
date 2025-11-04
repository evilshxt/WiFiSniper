"""
Password Cracking Module
Handle WPA/WPA2 handshake cracking and password generation
"""

import os
import time
import subprocess
from core.logger import Logger
from utils.helpers import run_command, ensure_root_privileges, get_user_confirmation

logger = Logger()

class PasswordCracker:
    def __init__(self):
        self.logger = logger

    def crack_wpa_handshake(self, handshake_file, wordlist=None, use_hashcat=False):
        """
        Crack WPA/WPA2 handshake using aircrack-ng or hashcat
        """
        if not ensure_root_privileges():
            return False

        if not os.path.exists(handshake_file):
            self.logger.error(f"Handshake file not found: {handshake_file}")
            return False

        self.logger.info("Starting WPA handshake cracking...")
        self.logger.info(f"Handshake file: {handshake_file}")

        # Check if handshake file contains valid handshake
        check_cmd = f"aircrack-ng {handshake_file} | grep -i 'wpa handshake'"
        success, output, error = run_command(check_cmd, shell=True)

        if not success or "WPA handshake" not in output:
            self.logger.error("No valid WPA handshake found in file")
            return False

        # Use default wordlist if none provided
        if not wordlist:
            default_wordlists = [
                "/usr/share/wordlists/rockyou.txt",
                "/usr/share/dict/words",
                "/usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt"
            ]

            for wl in default_wordlists:
                if os.path.exists(wl):
                    wordlist = wl
                    break

            if not wordlist:
                self.logger.error("No wordlist found. Please specify a wordlist file.")
                return False

        if not os.path.exists(wordlist):
            self.logger.error(f"Wordlist not found: {wordlist}")
            return False

        self.logger.info(f"Using wordlist: {wordlist}")

        if use_hashcat:
            return self.crack_with_hashcat(handshake_file, wordlist)
        else:
            return self.crack_with_aircrack(handshake_file, wordlist)

    def crack_with_aircrack(self, handshake_file, wordlist):
        """
        Crack using aircrack-ng
        """
        self.logger.info("Using aircrack-ng for cracking...")

        cmd = f"aircrack-ng -w {wordlist} -b {self.extract_bssid_from_cap(handshake_file)} {handshake_file}"

        self.logger.info(f"Running: {cmd}")

        try:
            # Run aircrack-ng
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            key_found = False
            cracked_key = None

            # Monitor output
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
                    if "KEY FOUND" in output:
                        key_found = True
                        # Extract the key from output
                        lines = output.split('\n')
                        for line in lines:
                            if "KEY FOUND" in line:
                                # Look for the key in the next few lines
                                continue
                    elif "KEY:" in output and "FOUND" in output:
                        # Alternative format
                        key_found = True

            rc = process.poll()

            if key_found:
                self.logger.success("WPA key found!")
                return True
            else:
                self.logger.warning("WPA key not found in wordlist")
                return False

        except KeyboardInterrupt:
            self.logger.info("Cracking interrupted by user")
            if 'process' in locals():
                process.terminate()
            return False
        except Exception as e:
            self.logger.error(f"Aircrack-ng error: {e}")
            return False

    def crack_with_hashcat(self, handshake_file, wordlist):
        """
        Crack using hashcat (more advanced)
        """
        self.logger.info("Using hashcat for cracking...")

        try:
            # First convert cap to hccapx format using hcxtools
            hccapx_file = handshake_file.replace('.cap', '.hccapx')

            convert_cmd = f"hcxpcapngtool -o {hccapx_file} {handshake_file}"
            success, output, error = run_command(convert_cmd)

            if not success:
                self.logger.error(f"Failed to convert handshake file: {error}")
                return False

            # Now run hashcat
            hashcat_cmd = f"hashcat -m 2500 {hccapx_file} {wordlist}"

            self.logger.info(f"Running: {hashcat_cmd}")

            process = subprocess.Popen(
                hashcat_cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Monitor hashcat output
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())

            rc = process.poll()

            # Check if key was found
            if rc == 0:
                self.logger.success("Password cracking completed!")
                # Check hashcat output files for results
                potfile = os.path.expanduser("~/.hashcat/hashcat.potfile")
                if os.path.exists(potfile):
                    with open(potfile, 'r') as f:
                        content = f.read()
                        if hccapx_file in content:
                            self.logger.success("Password found in hashcat potfile!")
                            return True

            self.logger.warning("Password not found")
            return False

        except KeyboardInterrupt:
            self.logger.info("Hashcat cracking interrupted by user")
            if 'process' in locals():
                process.terminate()
            return False
        except Exception as e:
            self.logger.error(f"Hashcat error: {e}")
            return False

    def extract_bssid_from_cap(self, cap_file):
        """
        Extract BSSID from cap file using aircrack-ng
        """
        try:
            cmd = f"aircrack-ng {cap_file} | grep 'BSSID'"
            success, output, error = run_command(cmd, shell=True)

            if success and output:
                lines = output.split('\n')
                for line in lines:
                    if 'BSSID' in line and len(line.split()) >= 2:
                        bssid = line.split()[1].strip()
                        if len(bssid.split(':')) == 6:
                            return bssid

            return "00:00:00:00:00:00"  # Default fallback

        except Exception:
            return "00:00:00:00:00:00"

class PasswordGenerator:
    def __init__(self):
        self.logger = logger

    def generate_passwords(self, pattern=None, length=8, count=1000, output_file=None):
        """
        Generate custom passwords based on patterns
        """
        import string
        import random

        self.logger.info("Starting password generation...")

        if not pattern:
            # Default pattern: mixed case letters, numbers, symbols
            pattern = string.ascii_letters + string.digits + "!@#$%^&*"

        if length < 1:
            self.logger.error("Password length must be at least 1")
            return False

        self.logger.info(f"Generating {count} passwords of length {length}")
        self.logger.info(f"Character set: {pattern}")

        passwords = []
        for i in range(count):
            password = ''.join(random.choice(pattern) for _ in range(length))
            passwords.append(password)

        # Remove duplicates
        original_count = len(passwords)
        passwords = list(set(passwords))
        duplicate_count = original_count - len(passwords)

        if duplicate_count > 0:
            self.logger.info(f"Removed {duplicate_count} duplicate passwords")

        self.logger.success(f"Generated {len(passwords)} unique passwords")

        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    for pwd in passwords:
                        f.write(pwd + '\n')
                self.logger.success(f"Passwords saved to: {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to save passwords: {e}")
                return False

        # Display sample
        if passwords:
            print("\nSample passwords:")
            for pwd in passwords[:10]:  # Show first 10
                print(f"  {pwd}")
            if len(passwords) > 10:
                print(f"  ... and {len(passwords) - 10} more")

        return passwords

    def generate_wordlist_from_pattern(self, base_words=None, transforms=None, output_file=None):
        """
        Generate wordlist by applying transformations to base words
        """
        if not base_words:
            base_words = ["password", "admin", "user", "login", "welcome"]

        if not transforms:
            transforms = [
                lambda w: w,  # Original
                lambda w: w.upper(),  # Uppercase
                lambda w: w.lower(),  # Lowercase
                lambda w: w.capitalize(),  # Capitalize
                lambda w: w + "123",  # Add numbers
                lambda w: w + "!",  # Add symbol
                lambda w: "123" + w,  # Prefix numbers
                lambda w: w + "2024",  # Add year
                lambda w: w.replace('a', '@').replace('o', '0').replace('i', '1'),  # Leet speak
            ]

        self.logger.info("Generating wordlist from patterns...")
        self.logger.info(f"Base words: {len(base_words)}")
        self.logger.info(f"Transforms: {len(transforms)}")

        passwords = set()

        for word in base_words:
            for transform in transforms:
                try:
                    transformed = transform(word)
                    passwords.add(transformed)
                except Exception:
                    continue

        passwords = list(passwords)
        self.logger.success(f"Generated {len(passwords)} unique passwords")

        # Save to file
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    for pwd in sorted(passwords):
                        f.write(pwd + '\n')
                self.logger.success(f"Wordlist saved to: {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to save wordlist: {e}")
                return False

        # Display sample
        if passwords:
            print("\nSample generated passwords:")
            for pwd in sorted(passwords)[:15]:  # Show first 15
                print(f"  {pwd}")
            if len(passwords) > 15:
                print(f"  ... and {len(passwords) - 15} more")

        return passwords

# Convenience functions
def crack_wpa_handshake(handshake_file, wordlist=None, use_hashcat=False):
    """Convenience function for WPA cracking"""
    cracker = PasswordCracker()
    return cracker.crack_wpa_handshake(handshake_file, wordlist, use_hashcat)

def generate_passwords(pattern=None, length=8, count=1000, output_file=None):
    """Convenience function for password generation"""
    generator = PasswordGenerator()
    return generator.generate_passwords(pattern, length, count, output_file)