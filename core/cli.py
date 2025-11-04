from .ascii_art import print_banner
from .logger import Logger
from colorama import Fore, Style

def main():
    print_banner()
    logger = Logger()
    logger.success("Welcome to WiFiSniper! Your modular Wi-Fi pentesting toolkit.")
    print(f"{Fore.RED}Made by evilshxt{Style.RESET_ALL}")
    logger.info("Future: Dependency checks and main menu will appear here.")
