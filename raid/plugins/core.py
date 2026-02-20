# Plugin Development Guideline for R.A.I.D.
# To create a custom plugin for R.A.I.D., follow these steps:
# 1. Inherit from one of the base classes in this file:
#    - Plugin: For general plugins.
#    - ParserPlugin: For plugins that parse log files.
#    - DetectorPlugin: For plugins that analyze data and detect threats.

# 2. Implement all abstract methods:
#    - get_info(self): Return a dictionary with plugin information (name, description, version, etc).
#    - parse(self, file_path): (For ParserPlugin) Parse the given file and return structured data as a list of dictionaries.
#    - detect(self, data): (For DetectorPlugin) Analyze the data and return a list of detected threats or findings.

# 3. Example:
#    from raid.plugins.core import ParserPlugin
#    class MyCustomParser(ParserPlugin):
#        def get_info(self):
#            return {
#                'name': 'MyCustomParser',
#                'description': 'Parses custom log files.',
#                'version': '1.0.0'
#            }
#        def parse(self, file_path):
#            # Implement parsing logic here
#            return []

# 4. Place your plugin in the appropriate directory (e.g., plugins/parsers/ or plugins/detectors/).
# 5. Ensure your plugin is discoverable and properly imported by the R.A.I.D. engine.
# For more details, refer to the README or existing plugins for reference.

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class Plugin(ABC):
    "Base class for all R.A.I.D. plugins."

    def __init__(self):
        self.name = self.__class__.__name__
        self.description = ""
        self.version = "1.0.0"

    @abstractmethod
    def get_info(self) -> Dict[str, str]:
        "Return plugin information."
        pass


class ParserPlugin(Plugin):
    "Base class for parser plugins."

    @abstractmethod
    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        "Parse a log file and return structured data."
        pass


class DetectorPlugin(Plugin):
    "Base class for detector plugins."

    @abstractmethod
    def detect(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        "Analyze data and return potential threats."
        pass
