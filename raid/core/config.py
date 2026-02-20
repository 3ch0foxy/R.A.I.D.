import os
from typing import Dict, Any, Optional
import yaml


class Config:
    # Simple configuration manager for R.A.I.D.
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_default_config()
        
        if config_path and os.path.exists(config_path):
            self._load_config_file(config_path)
    
    def _load_default_config(self) -> Dict[str, Any]:
        # Load default configuration.
        return {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'plugins': {
                'directory': 'plugins'
            },
            'detectors': {
                'default_thresholds': {
                    'brute_force': 5,
                    'suspicious_user': 3
                }
            }
        }
    
    def _load_config_file(self, config_path: str):
        # Load configuration from a YAML file.
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f)

            # If the YAML file is empty, safe_load returns None
            if not isinstance(file_config, dict):
                return

            # Merge with default config
            self._merge_config(self.config, file_config)
        except Exception as e:
            print(f"Error loading config file: {str(e)}")
    
    def _merge_config(self, default: Dict[str, Any], override: Dict[str, Any]):
        # Recursively merge override values into default config.
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        # Get a configuration value.
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        # Set a configuration value.
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value