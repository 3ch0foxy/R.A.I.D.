from typing import List, Dict, Any
from ..core import ParserPlugin


class BaseParser(ParserPlugin):
    # Shared base class for parser plugins.
    
    def __init__(self):
        super().__init__()
        self.name = "base_parser"
        self.description = "Base parser with common functionality"
        self.version = "1.0.0"
    
    def get_info(self) -> Dict[str, str]:
        # Return basic plugin metadata.
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        # Parse a log file and return structured records.
        raise NotImplementedError("Subclasses must implement the parse method")