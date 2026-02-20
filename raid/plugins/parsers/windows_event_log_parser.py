import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import logging

from .base_parser import BaseParser

logger = logging.getLogger(__name__)

try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


class WindowsEventLogParser(BaseParser):
    # Parser for Windows Event Log (`.evtx`) files.
    
    def __init__(self):
        super().__init__()
        self.name = "windows_event_log_parser"
        self.description = "Parses Windows Event Log (.evtx) files"
        self.version = "1.0.0"
        
        if not EVTX_AVAILABLE:
            logger.warning("python-evtx not available. Install with: pip install python-evtx")
    
    def get_info(self) -> Dict[str, str]:
        # Return basic plugin metadata.
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        # Parse one `.evtx` file into structured records.
        if not EVTX_AVAILABLE:
            logger.error("python-evtx library not installed. Run: pip install python-evtx")
            return []
        
        records = []
        
        try:
            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        
                        # Convert raw XML event into a record dictionary.
                        event_data = self._parse_event_xml(root, file_path)
                        if event_data:
                            records.append(event_data)
                    except Exception as e:
                        logger.debug(f"Error parsing record: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error reading event log {file_path}: {e}")
        
        return records
    
    def _parse_event_xml(self, root: ET.Element, file_path: str) -> Dict[str, Any]:
        # Parse one XML event element.
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        try:
            # Read core fields from the System section.
            system = root.find('ns:System', ns)
            if system is None:
                return None
            
            event_id_elem = system.find('ns:EventID', ns)
            event_id = event_id_elem.text if event_id_elem is not None else 'Unknown'
            
            timestamp_elem = system.find('ns:TimeCreated', ns)
            timestamp = timestamp_elem.get('SystemTime', '') if timestamp_elem is not None else ''
            
            source_elem = system.find('ns:Provider', ns)
            source = source_elem.get('Name', '') if source_elem is not None else 'Unknown'
            
            level_elem = system.find('ns:Level', ns)
            level = level_elem.text if level_elem is not None else 'Information'
            
            computer_elem = system.find('ns:Computer', ns)
            computer = computer_elem.text if computer_elem is not None else 'Unknown'
            
            # Read key/value fields from EventData.
            event_data_elem = root.find('ns:EventData', ns)
            event_data_dict = {}
            if event_data_elem is not None:
                for data in event_data_elem.findall('ns:Data', ns):
                    name = data.get('Name', '')
                    text = data.text or ''
                    event_data_dict[name] = text
            
            record = {
                'id': f"{file_path}:{event_id}:{timestamp}",
                'timestamp': timestamp,
                'source': source,
                'event_id': event_id,
                'level': level,
                'computer': computer,
                'event_data': event_data_dict,
                'raw': ET.tostring(root, encoding='unicode')
            }
            
            # Add normalized security fields for detectors.
            self._extract_security_fields(record, event_data_dict, source, event_id)
            
            return record
        except Exception as e:
            logger.debug(f"Error parsing event XML: {e}")
            return None
    
    def _extract_security_fields(self, record: Dict[str, Any], event_data: Dict[str, str], 
                                 source: str, event_id: str):
        # Map common Windows events into normalized fields.
        # Security Log - Event ID 4625: Failed Logon
        if source == 'Microsoft-Windows-Security-Auditing' and event_id == '4625':
            record['event_type'] = 'failed_login'
            record['username'] = event_data.get('TargetUserName', '')
            record['source_ip'] = event_data.get('IpAddress', '')
            record['source_port'] = event_data.get('IpPort', '')
            record['failure_reason'] = event_data.get('FailureReason', '')
        
        # Security Log - Event ID 4624: Successful Logon
        elif source == 'Microsoft-Windows-Security-Auditing' and event_id == '4624':
            record['event_type'] = 'successful_login'
            record['username'] = event_data.get('TargetUserName', '')
            record['source_ip'] = event_data.get('IpAddress', '')
            record['logon_type'] = event_data.get('LogonType', '')
        
        # Security Log - Event ID 4688: Process Creation
        elif source == 'Microsoft-Windows-Security-Auditing' and event_id == '4688':
            record['event_type'] = 'process_creation'
            record['new_process_name'] = event_data.get('NewProcessName', '')
            record['username'] = event_data.get('SubjectUserName', '')
            record['command_line'] = event_data.get('CommandLine', '')
        
        # Security Log - Event ID 4698: Scheduled Task Created
        elif source == 'Microsoft-Windows-Security-Auditing' and event_id == '4698':
            record['event_type'] = 'scheduled_task_created'
            record['username'] = event_data.get('SubjectUserName', '')
            record['task_name'] = event_data.get('TaskName', '')
        
        # Security Log - Event ID 4696: Token Right Adjusted
        elif source == 'Microsoft-Windows-Security-Auditing' and event_id == '4696':
            record['event_type'] = 'privilege_escalation'
            record['username'] = event_data.get('SubjectUserName', '')
            record['target_user'] = event_data.get('TargetUserName', '')
        
        # PowerShell Operational - Script execution
        elif source == 'Microsoft-Windows-PowerShell' and event_id in ['4103', '4104']:
            record['event_type'] = 'script_execution'
            record['script_block'] = event_data.get('ScriptBlockText', '')
            record['user'] = event_data.get('UserId', '')
        
        # Windows Defender - Threat detection
        elif 'Windows Defender' in source:
            record['event_type'] = 'threat_detection'
            record['threat_name'] = event_data.get('Threat Name', '')
            record['action'] = event_data.get('Action ID', '')
        
        # Firewall - Blocked connection
        elif 'Windows Firewall' in source and event_id == '5152':
            record['event_type'] = 'firewall_block'
            record['source_ip'] = event_data.get('SourceAddress', '')
            record['dest_ip'] = event_data.get('DestAddress', '')
            record['protocol'] = event_data.get('Protocol', '')
        
        else:
            record['event_type'] = 'other'
