from typing import List, Dict, Any
from ..core import DetectorPlugin


class BaseDetector(DetectorPlugin):
    # Shared base class for detector plugins.
    
    def __init__(self):
        super().__init__()
        self.name = "base_detector"
        self.description = "Base detector with common functionality"
        self.version = "1.0.0"
    
    def get_info(self) -> Dict[str, str]:
        # Return basic plugin metadata.
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def detect(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Analyze parsed data and return findings.
        raise NotImplementedError("Subclasses must implement the detect method")