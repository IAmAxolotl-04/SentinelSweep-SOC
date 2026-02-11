"""
Minimal Triage Engine - Just Works Version
"""

import socket
from typing import Dict, Optional
import ipaddress

class TriageEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.stats = {
            'services_triaged': 0,
            'banners_grabbed': 0,
            'risks_adjusted': 0,
            'errors': 0
        }
        
    def triage_service(self, ip: str, port: int) -> Dict:
        """Simple triage that always works."""
        
        # Update stats
        self.stats['services_triaged'] += 1
        
        # ALWAYS initialize all required keys
        result = {
            'ip': ip,
            'port': port,
            'service_guess': self._guess_service(port),
            'banner': None,
            'verification': 'Port detection',
            'reliability': 'MEDIUM',
            'details': {},  # Always exists
            'final_risk': self._default_risk(port, ip),
            'adjustment_reason': 'Initial assessment',
            'checks_passed': [],  # Always exists
            'checks_failed': [],  # Always exists
            'network_context': self._get_network_context(ip)
        }
        
        # Add service-specific banner grabbing
        banner = self._grab_banner(ip, port)
        if banner:
            result['banner'] = banner
            result['verification'] = f'Banner: {banner[:50]}...'
            self.stats['banners_grabbed'] += 1
            
            # Simple risk adjustments based on banner
            if port == 3389 and 'NLA' in banner.upper():
                result['final_risk'] = 'MEDIUM'
                result['adjustment_reason'] = 'RDP with NLA detected'
                self.stats['risks_adjusted'] += 1
            elif port == 22 and 'SSH-2.0' in banner:
                if self._get_network_context(ip) == 'Internal_Network':
                    result['final_risk'] = 'MEDIUM'
                else:
                    result['final_risk'] = 'HIGH'
                result['adjustment_reason'] = f'SSH version detected'
                self.stats['risks_adjusted'] += 1
            elif port == 80 and ('It works' in banner or 'Welcome' in banner):
                result['final_risk'] = 'MEDIUM'
                result['adjustment_reason'] = 'Default web page detected'
                self.stats['risks_adjusted'] += 1
        
        return result
    
    def _grab_banner(self, ip: str, port: int, timeout: int = 2) -> Optional[str]:
        """Simple banner grabber."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send newline for most services
            sock.send(b'\n')
            
            # Try to receive banner
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner if banner else None
        except:
            return None
    
    def _guess_service(self, port: int) -> str:
        common = {
            22: 'SSH', 3389: 'RDP', 80: 'HTTP', 443: 'HTTPS',
            445: 'SMB', 21: 'FTP', 23: 'Telnet', 25: 'SMTP',
            3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB'
        }
        return common.get(port, f'Port-{port}')
    
    def _get_network_context(self, ip: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return 'Internal_Network'
            return 'External_Network'
        except:
            return 'Unknown'
    
    def _default_risk(self, port: int, ip: str) -> str:
        high_risk = [21, 23, 445, 3389]
        medium_risk = [22, 80, 25, 3306, 5432]
        low_risk = [443]
        
        if port in high_risk:
            base = 'HIGH'
        elif port in medium_risk:
            base = 'MEDIUM'
        elif port in low_risk:
            base = 'LOW'
        else:
            base = 'MEDIUM'
        
        # Downgrade internal networks
        if self._get_network_context(ip) == 'Internal_Network' and base == 'HIGH':
            return 'MEDIUM'
        return base
    
    def get_stats(self) -> Dict:
        """Return triage statistics."""
        return self.stats.copy()
