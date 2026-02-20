import os
import importlib
import logging
from typing import Dict, List
from .config import Config
from ..plugins.core import Plugin, ParserPlugin, DetectorPlugin

logger = logging.getLogger(__name__)


class Engine:
    # Core engine for the R.A.I.D. framework.
    def __init__(self, config_path: str = None):
        self.config = Config(config_path)
        self.plugins: Dict[str, Plugin] = {}
        self.parsers: Dict[str, ParserPlugin] = {}
        self.detectors: Dict[str, DetectorPlugin] = {}
        
    def load_plugins(self):
        # Load all available plugins.
        plugin_dirs = [
            ('parsers', os.path.join(os.path.dirname(__file__), '..', 'plugins', 'parsers')),
            ('detectors', os.path.join(os.path.dirname(__file__), '..', 'plugins', 'detectors')),
        ]
        
        for plugin_type, plugin_dir in plugin_dirs:
            for filename in os.listdir(plugin_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    module_name = filename[:-3]
                    module_path = f"raid.plugins.{plugin_type}.{module_name}"
                    
                    try:
                        module = importlib.import_module(module_path)
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (isinstance(attr, type) and 
                                issubclass(attr, Plugin) and 
                                attr != Plugin and
                                attr != ParserPlugin and
                                attr != DetectorPlugin):
                                
                                plugin_instance = attr()
                                plugin_name = plugin_instance.name
                                
                                if plugin_type == 'parsers':
                                    self.parsers[plugin_name] = plugin_instance
                                else:
                                    self.detectors[plugin_name] = plugin_instance
                                    
                                self.plugins[plugin_name] = plugin_instance
                                logger.info(f"Loaded {plugin_type} plugin: {plugin_name}")
                    except Exception as e:
                        logger.error(f"Failed to load plugin {module_name}: {str(e)}")
    
    def get_parser(self, name: str) -> ParserPlugin:
        # Get a parser plugin by name.
        if name not in self.parsers:
            raise ValueError(f"Parser plugin '{name}' not found")
        return self.parsers[name]
    
    def get_detector(self, name: str) -> DetectorPlugin:
        # Get a detector plugin by name.
        if name not in self.detectors:
            raise ValueError(f"Detector plugin '{name}' not found")
        return self.detectors[name]
    
    def list_parsers(self) -> List[str]:
        # List all available parser plugins.
        return list(self.parsers.keys())
    
    def list_detectors(self) -> List[str]:
        # List all available detector plugins.
        return list(self.detectors.keys())