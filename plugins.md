# WiFiSniper Plugin System

## Overview
WiFiSniper features a modular plugin system that allows users and developers to extend the toolkit's functionality without modifying the core codebase. Plugins can add new attack vectors, analysis tools, or utilities.

## Plugin Structure
Plugins are Python modules placed in the `plugins/` directory. Each plugin must follow a specific interface to integrate seamlessly with the main application.

### Basic Plugin Template
```python
from core.plugin_base import PluginBase

class MyPlugin(PluginBase):
    name = "My Custom Plugin"
    description = "Description of what this plugin does"
    category = "attacks"  # or "analysis", "utilities", etc.
    version = "1.0.0"

    def __init__(self):
        super().__init__()

    def run(self, **kwargs):
        # Main plugin logic here
        pass

    def get_menu_options(self):
        # Return list of menu options this plugin provides
        return [
            {"name": "Option 1", "function": self.option1},
            {"name": "Option 2", "function": self.option2}
        ]

    def option1(self):
        # Implementation of option 1
        pass

    def option2(self):
        # Implementation of option 2
        pass
```

## Plugin Categories
- **attacks**: Offensive security tools (deauth, evil twin, etc.)
- **analysis**: Network analysis and monitoring
- **utilities**: Helper tools and configurations
- **cracking**: Password cracking and generation
- **bluetooth**: Bluetooth-related attacks and analysis

## Plugin Discovery
The system automatically discovers plugins by:
1. Scanning the `plugins/` directory for Python files
2. Importing each module
3. Checking if the module contains a class that inherits from `PluginBase`
4. Registering valid plugins with the menu system

## Plugin Requirements
- Must inherit from `core/plugin_base.py`
- Must define `name`, `description`, `category`, and `version` attributes
- Must implement `run()` method
- Should implement `get_menu_options()` for menu integration
- Can use any WiFiSniper utilities (logger, helpers, etc.)

## Example Plugin: Custom Deauth
```python
from core.plugin_base import PluginBase
from modules.attack import deauth_attack
from utils.helpers import validate_mac

class CustomDeauthPlugin(PluginBase):
    name = "Custom Deauth Attack"
    description = "Advanced deauthentication with custom parameters"
    category = "attacks"
    version = "1.0.0"

    def run(self, **kwargs):
        bssid = input("Enter target BSSID: ")
        if not validate_mac(bssid):
            self.logger.error("Invalid BSSID format")
            return

        client = input("Enter client MAC (or 'all' for broadcast): ")
        count = int(input("Number of deauth packets (0 for infinite): ") or 0)
        delay = float(input("Delay between packets (seconds): ") or 0.1)

        deauth_attack(bssid, client, count, delay)

    def get_menu_options(self):
        return [
            {"name": "Run Custom Deauth", "function": self.run}
        ]
```

## Plugin Development Guidelines
1. Use the provided logger for output (self.logger)
2. Validate user input thoroughly
3. Handle exceptions gracefully
4. Follow the existing code style and naming conventions
5. Test plugins in a safe environment before deployment
6. Document plugin usage and requirements

## Loading Plugins
Plugins are loaded at startup. If a plugin fails to load, an error is logged but doesn't prevent the application from running.

## Security Considerations
- Plugins run with the same privileges as the main application
- Be cautious with plugins from untrusted sources
- Review plugin code before installation
- Plugins can access all system resources the main app can access

## Contributing Plugins
To contribute a plugin:
1. Create a pull request with your plugin in the `plugins/` directory
2. Include documentation and usage examples
3. Ensure compatibility with the current plugin interface
4. Test on multiple systems if possible

This plugin system makes WiFiSniper highly extensible while maintaining a clean, organized codebase.