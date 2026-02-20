from typing import List, Dict, Any
from collections import defaultdict
from .base_detector import BaseDetector

class BruteForceDetector(BaseDetector):
    # Detect potential brute-force login behavior.
    def __init__(self):
        super().__init__()
        self.name = "brute_force_detector"
        self.description = "Detects potential brute force attacks based on failed login attempts"
        self.version = "1.0.0"
        self.failed_login_threshold = 5  # Number of failed logins to trigger an alert
    
    def get_info(self) -> Dict[str, str]:
        # Return basic plugin metadata.
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def detect(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Analyze records for brute-force patterns.
        findings = []
        
        # Count failed logins per source IP.
        failed_logins_by_ip = defaultdict(int)
        failed_logins_details = defaultdict(list)
        
        for record in data:
            if record.get('event_type') == 'failed_login' and 'source_ip' in record:
                ip = record['source_ip']
                failed_logins_by_ip[ip] += 1
                failed_logins_details[ip].append({
                    'timestamp': record.get('timestamp'),
                    'username': record.get('username'),
                    'id': record.get('id')
                })
        
        # Create findings for IPs above the threshold.
        for ip, count in failed_logins_by_ip.items():
            if count >= self.failed_login_threshold:
                # Calculate severity based on failed login count.
                if count > 20:
                    severity = 'high'
                    tactics = ['Credential Access', 'Persistence']
                    techniques = ['T1110 - Brute Force', 'T1555 - Credentials from Password Managers']
                elif count > 10:
                    severity = 'medium'
                    tactics = ['Credential Access']
                    techniques = ['T1110 - Brute Force']
                else:
                    severity = 'low'
                    tactics = ['Credential Access']
                    techniques = ['T1110 - Brute Force']
                
                finding = {
                    'id': f"bf_{ip}",
                    'detector': self.name,
                    'severity': severity,
                    'source_ip': ip,
                    'event_type': 'potential_brute_force',
                    'description': f"Detected {count} failed login attempts from {ip}",
                    'details': {
                        'failed_login_count': count,
                        'threshold': self.failed_login_threshold,
                        'failed_logins': failed_logins_details[ip]
                    },
                    'mitre_tactics': tactics,
                    'mitre_techniques': techniques
                }
                findings.append(finding)
        
        return findings