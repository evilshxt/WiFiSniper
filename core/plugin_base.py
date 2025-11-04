"""
Plugin base class for WiFiSniper extensibility
"""

from abc import ABC, abstractmethod
from core.logger import Logger

class PluginBase(ABC):
    """
    Base class for all WiFiSniper plugins
    """

    # Plugin metadata (must be defined by subclasses)
    name = "Base Plugin"
    description = "Base plugin description"
    category = "utilities"  # attacks, analysis, utilities, cracking, bluetooth
    version = "1.0.0"

    def __init__(self):
        self.logger = Logger()

    @abstractmethod
    def run(self, **kwargs):
        """
        Main plugin execution method
        Should be implemented by subclasses
        """
        pass

    def get_menu_options(self):
        """
        Return list of menu options provided by this plugin
        Default implementation returns a single option to run the plugin
        """
        return [
            {
                "name": f"Run {self.name}",
                "function": self.run
            }
        ]

    def validate_input(self, input_data, validation_type="text"):
        """
        Basic input validation helper
        """
        if validation_type == "mac":
            # Basic MAC address validation
            import re
            if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", input_data):
                return True
        elif validation_type == "ip":
            # Basic IP address validation
            import re
            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", input_data):
                return True
        elif validation_type == "number":
            try:
                int(input_data)
                return True
            except ValueError:
                return False
        elif validation_type == "text":
            return bool(input_data.strip())

        return False

    def get_user_input(self, prompt, validation_type="text", default=None):
        """
        Get validated user input
        """
        while True:
            if default:
                user_input = input(f"{prompt} (default: {default}): ").strip()
                if not user_input:
                    return default
            else:
                user_input = input(f"{prompt}: ").strip()

            if self.validate_input(user_input, validation_type):
                return user_input
            else:
                self.logger.error(f"Invalid input. Please enter a valid {validation_type}.")

    def confirm_action(self, message):
        """
        Get user confirmation for actions
        """
        while True:
            response = input(f"{message} (y/N): ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no', '']:
                return False
            else:
                print("Please enter 'y' for yes or 'n' for no.")