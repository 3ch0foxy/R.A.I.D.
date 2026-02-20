import re
from datetime import datetime
from typing import List, Dict, Any

from .base_parser import BaseParser


class AuthLogParser(BaseParser):
    # Parser for Linux authentication logs.
    
    def __init__(self):
        super().__init__()
        self.name = "auth_log_parser"
        self.description = "Parses Linux authentication logs"
        self.version = "1.0.0"
        
        # Regex pattern for auth log lines.
        self.pattern = re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\w+)\s+(?P<process>\w+[\[\]\d]*):\s+(?P<message>.*)'
        )
    
    def get_info(self) -> Dict[str, str]:
        # Return basic plugin metadata.
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        # Parse an auth log file into records.
        records = []
        
        with open(file_path, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                match = self.pattern.match(line)
                if match:
                    record = {
                        'id': f"{file_path}:{line_num}",
                        'timestamp': self._parse_timestamp(match.group('timestamp')),
                        'hostname': match.group('hostname'),
                        'process': match.group('process'),
                        'message': match.group('message'),
                        'raw': line
                    }
                    
                    # Pull out useful fields from the message text.
                    self._extract_message_fields(record)
                    
                    records.append(record)
        
        return records
    
    def _parse_timestamp(self, timestamp_str: str) -> str:
        # Parse and normalize the timestamp.
        try:
            # Add current year because auth logs usually omit it.
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            dt = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            return timestamp_str
    
    def _extract_message_fields(self, record: Dict[str, Any]):
        # Extract structured fields from a raw log message.
        message = record['message']
        
        # Extract IP addresses.
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ips = ip_pattern.findall(message)
        if ips:
            record['ips'] = ips
            # Treat the first IP as source IP.
            record['source_ip'] = ips[0]
        
        # Extract usernames.
        user_pattern = re.compile(r'user\s+(\w+)|for\s+(\w+)|invalid\s+user\s+(\w+)')
        user_match = user_pattern.search(message)
        if user_match:
            # Use the first captured username.
            username = next((group for group in user_match.groups() if group is not None), None)
            if username:
                record['username'] = username
        
        # Label the event type.
        if 'failed password' in message.lower():
            record['event_type'] = 'failed_login'
        elif 'accepted password' in message.lower():
            record['event_type'] = 'successful_login'
        elif 'invalid user' in message.lower():
            record['event_type'] = 'invalid_user'
        else:
            record['event_type'] = 'other'