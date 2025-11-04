"""
Plugin loading system for WiFiSniper
"""

import os
import importlib
import inspect
from core.logger import Logger
from core.plugin_base import PluginBase

logger = Logger()

class PluginLoader:
    def __init__(self):
        self.plugins = {}
        self.plugin_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'plugins')

    def discover_plugins(self):
        """Discover and load all available plugins"""
        if not os.path.exists(self.plugin_dir):
            logger.warning(f"Plugin directory not found: {self.plugin_dir}")
            return

        logger.info("Discovering plugins...")

        # Get all Python files in plugins directory
        plugin_files = [f for f in os.listdir(self.plugin_dir)
                       if f.endswith('.py') and not f.startswith('__')]

        loaded_count = 0

        for plugin_file in plugin_files:
            plugin_name = plugin_file[:-3]  # Remove .py extension

            try:
                # Import the plugin module
                module_path = f"plugins.{plugin_name}"
                plugin_module = importlib.import_module(module_path)

                # Find plugin classes that inherit from PluginBase
                for name, obj in inspect.getmembers(plugin_module):
                    if (inspect.isclass(obj) and
                        issubclass(obj, PluginBase) and
                        obj != PluginBase):

                        # Instantiate the plugin
                        plugin_instance = obj()
                        plugin_key = f"{plugin_instance.category}.{plugin_name}"

                        self.plugins[plugin_key] = plugin_instance
                        loaded_count += 1

                        logger.success(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")

            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_name}: {e}")

        logger.info(f"Plugin discovery complete. Loaded {loaded_count} plugins.")

    def get_plugins_by_category(self, category):
        """Get all plugins in a specific category"""
        return {key: plugin for key, plugin in self.plugins.items()
                if key.startswith(f"{category}.")}

    def get_plugin(self, category, name):
        """Get a specific plugin by category and name"""
        key = f"{category}.{name}"
        return self.plugins.get(key)

    def get_all_plugins(self):
        """Get all loaded plugins"""
        return self.plugins.copy()

    def reload_plugins(self):
        """Reload all plugins"""
        logger.info("Reloading plugins...")

        # Clear current plugins
        self.plugins.clear()

        # Clear import cache for plugins
        import sys
        modules_to_remove = [mod for mod in sys.modules.keys() if mod.startswith('plugins.')]
        for mod in modules_to_remove:
            del sys.modules[mod]

        # Re-discover plugins
        self.discover_plugins()

# Global plugin loader instance
plugin_loader = PluginLoader()

def load_plugins():
    """Convenience function to load all plugins"""
    plugin_loader.discover_plugins()

def get_plugins_by_category(category):
    """Convenience function to get plugins by category"""
    return plugin_loader.get_plugins_by_category(category)

def get_plugin(category, name):
    """Convenience function to get a specific plugin"""
    return plugin_loader.get_plugin(category, name)