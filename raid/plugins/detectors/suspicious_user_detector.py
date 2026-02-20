from typing import List, Dict, Any
from collections import defaultdict

from .base_detector import BaseDetector


class SuspiciousUserDetector(BaseDetector):
    # Detect suspicious multi-account login attempts.
    
    def __init__(self):
        super().__init__()
        self.name = "suspicious_user_detector"
        self.description = "Detects suspicious user activities like multiple failed logins for different accounts"
        self.version = "1.0.0"
        self.failed_accounts_threshold = 3  # Number of different accounts with failed logins
    
    def get_info(self) -> Dict[str, str]:
        # Return basic plugin metadata.
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def detect(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Analyze records for suspicious user activity.
        findings = []
        
        # Group failed logins by source IP and username.
        failed_logins_by_ip = defaultdict(set)
        failed_logins_details = defaultdict(list)
        
        for record in data:
            if (record.get('event_type') in ['failed_login', 'invalid_user'] and 
                'source_ip' in record and 'username' in record):
                
                ip = record['source_ip']
                username = record['username']
                failed_logins_by_ip[ip].add(username)
                failed_logins_details[ip].append({
                    'timestamp': record.get('timestamp'),
                    'username': username,
                    'event_type': record.get('event_type'),
                    'id': record.get('id')
                })
        
        # Create findings for IPs targeting multiple accounts.
        for ip, usernames in failed_logins_by_ip.items():
            if len(usernames) >= self.failed_accounts_threshold:
                # Calculate severity based on number of different accounts targeted.
                if len(usernames) >= 10:
                    severity = 'high'
                    tactics = ['Credential Access', 'Discovery', 'Reconnaissance']
                    techniques = ['T1110 - Brute Force', 'T1087 - Account Discovery', 'T1589 - Gather Victim Identity Information']
                elif len(usernames) >= 5:
                    severity = 'medium'
                    tactics = ['Credential Access', 'Discovery']
                    techniques = ['T1110 - Brute Force', 'T1087 - Account Discovery']
                else:
                    severity = 'low'
                    tactics = ['Credential Access']
                    techniques = ['T1110 - Brute Force']
                
                finding = {
                    'id': f"sus_user_{ip}",
                    'detector': self.name,
                    'severity': severity,
                    'source_ip': ip,
                    'event_type': 'suspicious_user_activity',
                    'description': f"Detected failed login attempts for {len(usernames)} different accounts from {ip}",
                    'details': {
                        'unique_usernames': list(usernames),
                        'username_count': len(usernames),
                        'threshold': self.failed_accounts_threshold,
                        'failed_logins': failed_logins_details[ip]
                    },
                    'mitre_tactics': tactics,
                    'mitre_techniques': techniques
                }
                findings.append(finding)
        
        return findings