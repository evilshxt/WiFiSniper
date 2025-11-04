"""
Configuration management for WiFiSniper
"""

import json
import os
from core.logger import Logger

class ConfigManager:
    def __init__(self):
        self.logger = Logger()
        self.config_file = os.path.expanduser("~/.wifisniper/config.json")
        self.config = self.load_config()

    def load_config(self):
        """Load configuration from file"""
        default_config = {
            "default_interface": "",
            "scan_settings": {
                "default_duration": 30,
                "auto_save_scans": True,
                "scan_output_dir": "~/wifisniper_scans"
            },
            "attack_settings": {
                "default_deauth_count": 10,
                "default_deauth_delay": 0.1,
                "confirm_destructive_actions": True
            },
            "ui_settings": {
                "color_output": True,
                "table_style": "default",
                "show_timestamps": True
            },
            "logging": {
                "log_level": "INFO",
                "log_file": "~/wifisniper.log",
                "max_log_size": 10485760  # 10MB
            }
        }

        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults
                    self._merge_configs(default_config, loaded_config)
                    return default_config
            except Exception as e:
                self.logger.error(f"Failed to load config: {e}")
                return default_config
        else:
            # Create default config
            self.save_config(default_config)
            return default_config

    def _merge_configs(self, base, update):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_configs(base[key], value)
            else:
                base[key] = value

    def save_config(self, config=None):
        """Save configuration to file"""
        if config:
            self.config = config

        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            self.logger.success(f"Configuration saved to {self.config_file}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            return False

    def get(self, key, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key, value):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config

        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]

        # Set the value
        config[keys[-1]] = value
        self.save_config()

    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        default_config = {
            "default_interface": "",
            "scan_settings": {
                "default_duration": 30,
                "auto_save_scans": True,
                "scan_output_dir": "~/wifisniper_scans"
            },
            "attack_settings": {
                "default_deauth_count": 10,
                "default_deauth_delay": 0.1,
                "confirm_destructive_actions": True
            },
            "ui_settings": {
                "color_output": True,
                "table_style": "default",
                "show_timestamps": True
            },
            "logging": {
                "log_level": "INFO",
                "log_file": "~/wifisniper.log",
                "max_log_size": 10485760
            }
        }

        self.config = default_config
        self.save_config()
        self.logger.success("Configuration reset to defaults")

    def show_config(self):
        """Display current configuration"""
        print("\n" + "="*50)
        print("WiFiSniper Configuration")
        print("="*50)

        def print_config_section(config, prefix=""):
            for key, value in config.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    print(f"\n[{key.upper()}]")
                    print_config_section(value, full_key)
                else:
                    print(f"{full_key}: {value}")

        print_config_section(self.config)
        print(f"\nConfig file: {self.config_file}")

# Global config instance
config_manager = ConfigManager()

def get_config(key, default=None):
    """Convenience function to get config value"""
    return config_manager.get(key, default)

def set_config(key, value):
    """Convenience function to set config value"""
    return config_manager.set(key, value)