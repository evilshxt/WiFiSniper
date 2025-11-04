"""
Advanced logging system for WiFiSniper
"""

import os
import logging
import logging.handlers
from datetime import datetime
from core.logger import Logger
from core.config import get_config

class WiFiSniperLogger:
    def __init__(self):
        self.console_logger = Logger()
        self.setup_file_logging()

    def setup_file_logging(self):
        """Setup file logging with rotation"""
        log_file = os.path.expanduser(get_config('logging.log_file', '~/wifisniper.log'))
        log_level = getattr(logging, get_config('logging.log_level', 'INFO').upper())
        max_size = get_config('logging.max_log_size', 10485760)  # 10MB default

        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)

        # Setup logger
        self.file_logger = logging.getLogger('wifisniper')
        self.file_logger.setLevel(log_level)

        # Remove existing handlers
        for handler in self.file_logger.handlers[:]:
            self.file_logger.removeHandler(handler)

        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=5
        )

        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)

        self.file_logger.addHandler(file_handler)

    def log_action(self, action, details=None, level='info'):
        """Log a user action with details"""
        message = f"ACTION: {action}"
        if details:
            message += f" - {details}"

        # Log to file
        log_method = getattr(self.file_logger, level.lower(), self.file_logger.info)
        log_method(message)

        # Also log to console if configured
        if get_config('ui_settings.show_timestamps', True):
            timestamp = datetime.now().strftime('%H:%M:%S')
            message = f"[{timestamp}] {message}"

        console_method = getattr(self.console_logger, level.lower(), self.console_logger.info)
        console_method(message)

    def log_attack(self, attack_type, target, parameters=None):
        """Log attack actions"""
        details = f"Type: {attack_type}, Target: {target}"
        if parameters:
            details += f", Parameters: {parameters}"

        self.log_action("ATTACK_EXECUTED", details, 'warning')

    def log_scan(self, scan_type, interface, results_summary=None):
        """Log scanning actions"""
        details = f"Type: {scan_type}, Interface: {interface}"
        if results_summary:
            details += f", Results: {results_summary}"

        self.log_action("SCAN_EXECUTED", details)

    def log_error(self, component, error_message):
        """Log errors"""
        self.log_action("ERROR_OCCURRED", f"Component: {component}, Error: {error_message}", 'error')

    def log_system_info(self, info_type, details):
        """Log system information"""
        self.log_action("SYSTEM_INFO", f"Type: {info_type}, Details: {details}")

    def get_recent_logs(self, lines=50):
        """Get recent log entries"""
        log_file = os.path.expanduser(get_config('logging.log_file', '~/wifisniper.log'))

        if not os.path.exists(log_file):
            return ["No log file found"]

        try:
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return [line.strip() for line in all_lines[-lines:]]
        except Exception as e:
            return [f"Error reading log file: {e}"]

    def export_logs(self, filename=None, format_type='text'):
        """Export logs to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifisniper_logs_{timestamp}.txt"

        logs = self.get_recent_logs(1000)  # Export last 1000 lines

        try:
            with open(filename, 'w') as f:
                f.write("WiFiSniper Log Export\n")
                f.write("="*40 + "\n")
                f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Entries: {len(logs)}\n\n")

                for log in logs:
                    f.write(log + "\n")

            self.console_logger.success(f"Logs exported to: {filename}")
            return filename
        except Exception as e:
            self.console_logger.error(f"Failed to export logs: {e}")
            return None

# Global logger instance
advanced_logger = WiFiSniperLogger()

def log_action(action, details=None, level='info'):
    """Convenience function for logging actions"""
    advanced_logger.log_action(action, details, level)

def log_attack(attack_type, target, parameters=None):
    """Convenience function for logging attacks"""
    advanced_logger.log_attack(attack_type, target, parameters)

def log_scan(scan_type, interface, results_summary=None):
    """Convenience function for logging scans"""
    advanced_logger.log_scan(scan_type, interface, results_summary)