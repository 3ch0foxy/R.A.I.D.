from typing import List, Dict, Any
from collections import defaultdict

from .base_detector import BaseDetector


class WindowsEventDetector(BaseDetector):
    # Detect suspicious patterns in Windows event logs.
    
    def __init__(self):
        super().__init__()
        self.name = "windows_event_detector"
        self.description = "Detects suspicious activities in Windows Event Logs (failed logins, PowerShell execution, etc.)"
        self.version = "1.0.0"
        self.failed_logon_threshold = 3
        self.script_execution_threshold = 2
        self.process_creation_threshold = 10
    
    def get_info(self) -> Dict[str, str]:
        # Return basic plugin metadata.
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def detect(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Run all Windows-event detection checks.
        findings = []
        
        # Check failed logon patterns.
        findings.extend(self._detect_failed_logons(data))
        
        # Check process creation patterns.
        findings.extend(self._detect_suspicious_processes(data))
        
        # Check PowerShell activity.
        findings.extend(self._detect_powershell_activity(data))
        
        # Check firewall block patterns.
        findings.extend(self._detect_firewall_blocks(data))
        
        return findings
    
    def _detect_failed_logons(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Detect suspicious failed-logon patterns.
        findings = []
        
        # Group failed logins by IP and username.
        failed_by_ip = defaultdict(list)
        failed_by_user = defaultdict(list)
        
        for record in data:
            if record.get('event_type') == 'failed_login':
                source_ip = record.get('source_ip', 'unknown')
                username = record.get('username', 'unknown')
                
                if source_ip and source_ip != 'unknown':
                    failed_by_ip[source_ip].append(record)
                
                if username and username != 'unknown':
                    failed_by_user[username].append(record)
        
        # Alert on many failed logins from one IP.
        for ip, attempts in failed_by_ip.items():
            if len(attempts) >= self.failed_logon_threshold:
                # Calculate severity based on failed login count.
                if len(attempts) > 20:
                    severity = 'high'
                elif len(attempts) > 10:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                # Dynamically determine MITRE tactics based on severity.
                if severity == 'high':
                    tactics = ['Credential Access', 'Persistence']
                    techniques = ['T1110 - Brute Force', 'T1078 - Valid Accounts']
                else:
                    tactics = ['Credential Access']
                    techniques = ['T1110 - Brute Force']
                
                finding = {
                    'id': f"win_failed_logon_{ip}",
                    'detector': self.name,
                    'severity': severity,
                    'source_ip': ip,
                    'event_type': 'suspicious_failed_logons',
                    'description': f"Detected {len(attempts)} failed login attempts from {ip}",
                    'details': {
                        'attempt_count': len(attempts),
                        'threshold': self.failed_logon_threshold,
                        'affected_users': list(set(r.get('username') for r in attempts if r.get('username'))),
                        'attempts': [{'timestamp': r.get('timestamp'), 'user': r.get('username')} for r in attempts]
                    },
                    'mitre_tactics': tactics,
                    'mitre_techniques': techniques
                }
                findings.append(finding)
        
        # Alert on one account targeted from many IPs (spraying).
        for user, attempts in failed_by_user.items():
            if len(attempts) >= self.failed_logon_threshold:
                unique_ips = set(r.get('source_ip') for r in attempts if r.get('source_ip'))
                if len(unique_ips) > 1:
                    # Calculate severity based on number of unique IPs and attempts.
                    if len(unique_ips) >= 7 or len(attempts) > 10:
                        severity = 'high'
                        tactics = ['Credential Access', 'Discovery']
                        techniques = ['T1110 - Brute Force', 'T1087 - Account Discovery']
                    elif len(unique_ips) >= 4 or len(attempts) > 5:
                        severity = 'medium'
                        tactics = ['Credential Access']
                        techniques = ['T1110 - Brute Force']
                    else:
                        severity = 'low'
                        tactics = ['Credential Access']
                        techniques = ['T1110 - Brute Force']
                    
                    finding = {
                        'id': f"win_account_spray_{user}",
                        'detector': self.name,
                        'severity': severity,
                        'username': user,
                        'event_type': 'account_spraying',
                        'description': f"Account '{user}' targeted by failed logins from {len(unique_ips)} different IPs",
                        'details': {
                            'attempt_count': len(attempts),
                            'source_ips': list(unique_ips),
                            'attempts': [{'timestamp': r.get('timestamp'), 'ip': r.get('source_ip')} for r in attempts]
                        },
                        'mitre_tactics': tactics,
                        'mitre_techniques': techniques
                    }
                    findings.append(finding)
        
        return findings
    
    def _detect_suspicious_processes(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Detect high process-creation activity.
        findings = []
        
        process_events = [r for r in data if r.get('event_type') == 'process_creation']
        
        if len(process_events) >= self.process_creation_threshold:
            # Group process creation events by username.
            processes_by_user = defaultdict(list)
            for event in process_events:
                user = event.get('username', 'unknown')
                processes_by_user[user].append(event)
            
            # Alert when one user spawns many processes.
            for user, events in processes_by_user.items():
                if len(events) >= self.process_creation_threshold:
                    # Calculate severity based on process count.
                    if len(events) >= 50:
                        severity = 'high'
                        tactics = ['Execution', 'Defense Evasion', 'Persistence']
                        techniques = ['T1059 - Command and Scripting Interpreter', 'T1036 - Masquerading', 'T1547 - Boot or Logon Autostart Execution']
                    elif len(events) >= 20:
                        severity = 'medium'
                        tactics = ['Execution', 'Defense Evasion']
                        techniques = ['T1059 - Command and Scripting Interpreter', 'T1036 - Masquerading']
                    else:
                        severity = 'low'
                        tactics = ['Execution']
                        techniques = ['T1059 - Command and Scripting Interpreter']
                    
                    finding = {
                        'id': f"win_process_creation_{user}",
                        'detector': self.name,
                        'severity': severity,
                        'username': user,
                        'event_type': 'high_process_creation_rate',
                        'description': f"User '{user}' created {len(events)} processes",
                        'details': {
                            'process_count': len(events),
                            'threshold': self.process_creation_threshold,
                            'processes': [r.get('new_process_name', 'unknown') for r in events[:10]]
                        },
                        'mitre_tactics': tactics,
                        'mitre_techniques': techniques
                    }
                    findings.append(finding)
        
        return findings
    
    def _detect_powershell_activity(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Detect suspicious PowerShell script usage.
        findings = []
        
        # Map keywords to MITRE tactics and techniques.
        keyword_to_mitre = {
            'invoke-webrequest': (['Command and Control', 'Execution'], ['T1071 - Application Layer Protocol', 'T1059 - Command and Scripting Interpreter']),
            'iwr': (['Command and Control', 'Execution'], ['T1071 - Application Layer Protocol', 'T1059 - Command and Scripting Interpreter']),
            'downloadstring': (['Command and Control', 'Execution'], ['T1105 - Ingress Tool Transfer', 'T1059 - Command and Scripting Interpreter']),
            'downloadfile': (['Command and Control', 'Execution'], ['T1105 - Ingress Tool Transfer', 'T1059 - Command and Scripting Interpreter']),
            'system.net.webclient': (['Command and Control', 'Execution'], ['T1105 - Ingress Tool Transfer', 'T1059 - Command and Scripting Interpreter']),
            'powershell.exe -enc': (['Execution', 'Defense Evasion'], ['T1059 - Command and Scripting Interpreter', 'T1027 - Obfuscation']),
            'powershellv3 -enc': (['Execution', 'Defense Evasion'], ['T1059 - Command and Scripting Interpreter', 'T1027 - Obfuscation']),
            'hidden': (['Defense Evasion', 'Execution'], ['T1027 - Obfuscation', 'T1059 - Command and Scripting Interpreter']),
            '-nop': (['Defense Evasion'], ['T1027 - Obfuscation']),
            '-nologo': (['Defense Evasion'], ['T1027 - Obfuscation']),
            'bypass': (['Defense Evasion', 'Privilege Escalation'], ['T1562 - Impair Defenses', 'T1027 - Obfuscation']),
            'unrestricted': (['Defense Evasion', 'Privilege Escalation'], ['T1562 - Impair Defenses', 'T1027 - Obfuscation']),
            'reflection.assembly': (['Defense Evasion', 'Execution'], ['T1027 - Obfuscation', 'T1059 - Command and Scripting Interpreter']),
            'activator.createinstance': (['Defense Evasion', 'Execution'], ['T1027 - Obfuscation', 'T1059 - Command and Scripting Interpreter']),
            'rundll32': (['Defense Evasion', 'Execution'], ['T1218 - System Binary Proxy Execution']),
            'regsvcs.exe': (['Defense Evasion', 'Execution'], ['T1218 - System Binary Proxy Execution']),
            'regasm.exe': (['Defense Evasion', 'Execution'], ['T1218 - System Binary Proxy Execution']),
            'csc.exe': (['Defense Evasion', 'Execution'], ['T1218 - System Binary Proxy Execution']),
        }
        
        powershell_scripts = []
        detected_techniques = set()
        detected_tactics = set()
        
        for record in data:
            if record.get('event_type') == 'script_execution':
                script_block = record.get('script_block', '').lower()
                
                # Check for suspicious PowerShell keywords and track which techniques are detected.
                for keyword, (tactics, techniques) in keyword_to_mitre.items():
                    if keyword in script_block:
                        powershell_scripts.append(record)
                        detected_techniques.update(techniques)
                        detected_tactics.update(tactics)
                        break
        
        if len(powershell_scripts) >= self.script_execution_threshold:
            # Calculate severity based on script count.
            if len(powershell_scripts) >= 10:
                severity = 'high'
            elif len(powershell_scripts) >= 5:
                severity = 'medium'
            else:
                severity = 'low'
            
            finding = {
                'id': f"win_powershell_suspicious",
                'detector': self.name,
                'severity': severity,
                'event_type': 'suspicious_powershell',
                'description': f"Detected {len(powershell_scripts)} suspicious PowerShell script executions",
                'details': {
                    'script_count': len(powershell_scripts),
                    'threshold': self.script_execution_threshold,
                    'scripts': [{'timestamp': r.get('timestamp'), 'user': r.get('user')} for r in powershell_scripts[:10]]
                },
                'mitre_tactics': sorted(list(detected_tactics)) if detected_tactics else ['Execution', 'Defense Evasion'],
                'mitre_techniques': sorted(list(detected_techniques)) if detected_techniques else ['T1059 - Command and Scripting Interpreter', 'T1027 - Obfuscation']
            }
            findings.append(finding)
        
        return findings
    
    def _detect_firewall_blocks(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Detect unusual firewall-block patterns.
        findings = []
        
        firewall_blocks = defaultdict(list)
        
        for record in data:
            if record.get('event_type') == 'firewall_block':
                source_ip = record.get('source_ip', 'unknown')
                if source_ip and source_ip != 'unknown':
                    firewall_blocks[source_ip].append(record)
        
        # Alert on many firewall blocks from one source.
        for ip, blocks in firewall_blocks.items():
            if len(blocks) > 20:
                # Calculate severity based on block count.
                if len(blocks) >= 100:
                    severity = 'high'
                    tactics = ['Lateral Movement', 'Discovery', 'Command and Control']
                    techniques = ['T1046 - Network Service Discovery', 'T1090 - Proxy', 'T1571 - Non-Standard Port']
                elif len(blocks) >= 50:
                    severity = 'medium'
                    tactics = ['Lateral Movement', 'Discovery']
                    techniques = ['T1046 - Network Service Discovery', 'T1123 - Audio Capture']
                else:
                    severity = 'low'
                    tactics = ['Discovery']
                    techniques = ['T1046 - Network Service Discovery']
                
                finding = {
                    'id': f"win_firewall_blocks_{ip}",
                    'detector': self.name,
                    'severity': severity,
                    'source_ip': ip,
                    'event_type': 'excessive_firewall_blocks',
                    'description': f"Detected {len(blocks)} firewall blocks from {ip}",
                    'details': {
                        'block_count': len(blocks),
                        'dest_ips': list(set(r.get('dest_ip') for r in blocks if r.get('dest_ip')))[:5],
                        'blocks': [{'timestamp': r.get('timestamp'), 'dest': r.get('dest_ip')} for r in blocks[:10]]
                    },
                    'mitre_tactics': tactics,
                    'mitre_techniques': techniques
                }
                findings.append(finding)
        
        return findings
