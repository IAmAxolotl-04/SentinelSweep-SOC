"""
SentinelSweep-SOC Triage Engine
The intelligent brain that reduces false positives through contextual analysis.
"""

import socket
import time
from typing import Dict, List, Optional, Tuple
import ipaddress

class TriageEngine:
    """Main engine for performing intelligent analysis on discovered services."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the triage engine with optional configuration."""
        self.config = config or {}
        self.internal_networks = self.config.get('internal_networks', [])
        
        # Statistics for reporting
        self.stats = {
            'services_triaged': 0,
            'risks_downgraded': 0,
            'risks_upgraded': 0,
            'banners_grabbed': 0
        }
    
    def triage_service(self, ip: str, port: int) -> Dict:
        """
        Main entry point: perform comprehensive triage on a single service.
        Returns a dictionary of triage findings to be merged with assessment.
        """
        self.stats['services_triaged'] += 1
        
        # Initialize result structure
        result = {
            'ip': ip,
            'port': port,
            'service_guess': self._guess_service(port),
            'banner': None,
            'verification': 'Basic port detection',
            'reliability': 'MEDIUM',
            'details': {},
            'final_risk': None,
            'adjustment_reason': None,
            'checks_passed': [],
            'checks_failed': []
        }
        
        # Perform service-specific deep dive for critical ports
        if port in [22, 3389, 445, 21, 23, 5900]:
            result = self._deep_dive_triage(ip, port, result)
        
        # Apply network context
        result = self._apply_network_context(ip, result)
        
        return result
    
    def _deep_dive_triage(self, ip: str, port: int, result: Dict) -> Dict:
        """Perform detailed analysis on critical services."""
        
        if port == 3389:  # RDP
            result = self._triage_rdp(ip, port, result)
        elif port == 22:  # SSH
            result = self._triage_ssh(ip, port, result)
        elif port == 445:  # SMB
            result = self._triage_smb(ip, port, result)
        # Add more services as needed
        
        return result
    
    def _triage_rdp(self, ip: str, port: int, result: Dict) -> Dict:
        """Specialized triage for RDP services."""
        result['service_guess'] = 'RDP'
        
        try:
            # Attempt to grab banner for more info
            banner = self._grab_banner(ip, port, timeout=2)
            if banner:
                result['banner'] = banner
                result['verification'] = f'Service banner: {banner[:50]}...'
                self.stats['banners_grabbed'] += 1
                
                # Check for Network Level Authentication (NLA) indicators
                if any(indicator in banner.upper() for indicator in ['SSL', 'NLA', 'SECURE']):
                    result['details']['nla_enabled'] = True
                    result['checks_passed'].append('NLA_ENABLED')
                    result['reliability'] = 'HIGH'
                else:
                    result['details']['nla_enabled'] = False
                    result['checks_failed'].append('NLA_ENABLED')
            
            # Determine risk based on findings
            if result['details'].get('nla_enabled', False):
                if self._is_internal_network(ip):
                    result['final_risk'] = 'MEDIUM'
                    result['adjustment_reason'] = 'RDP has NLA and is on internal network'
                    self.stats['risks_downgraded'] += 1
                else:
                    result['final_risk'] = 'MEDIUM_HIGH'
                    result['adjustment_reason'] = 'RDP has NLA but is on external network'
            else:
                result['final_risk'] = 'CRITICAL'
                result['adjustment_reason'] = 'RDP exposed with weak or no authentication'
                self.stats['risks_upgraded'] += 1
                
        except Exception as e:
            result['verification'] = f'Banner grab failed: {str(e)}'
            result['details']['error'] = str(e)
        
        return result
    
    def _triage_ssh(self, ip: str, port: int, result: Dict) -> Dict:
        """Specialized triage for SSH services."""
        result['service_guess'] = 'SSH'
        
        try:
            banner = self._grab_banner(ip, port, timeout=2)
            if banner:
                result['banner'] = banner
                result['verification'] = f'SSH banner: {banner[:50]}...'
                self.stats['banners_grabbed'] += 1
                
                # Check SSH protocol version (v1 is vulnerable)
                if 'SSH-1.' in banner:
                    result['details']['ssh_v1'] = True
                    result['checks_failed'].append('SSH_V2_ONLY')
                    result['final_risk'] = 'HIGH'
                    result['adjustment_reason'] = 'SSH protocol version 1 detected (insecure)'
                else:
                    result['details']['ssh_v1'] = False
                    result['checks_passed'].append('SSH_V2_ONLY')
                    result['final_risk'] = 'MEDIUM' if self._is_internal_network(ip) else 'HIGH'
        except Exception as e:
            result['verification'] = f'SSH check failed: {str(e)}'
        
        return result
    
    def _triage_smb(self, ip: str, port: int, result: Dict) -> Dict:
        """Specialized triage for SMB services."""
        result['service_guess'] = 'SMB'
        result['final_risk'] = 'HIGH'  # SMB is always high risk
        result['adjustment_reason'] = 'SMB protocol exposure (potential lateral movement)'
        
        return result
    
    def _grab_banner(self, ip: str, port: int, timeout: int = 2) -> Optional[str]:
        """Attempt to grab a service banner from the specified port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send a newline to trigger some services
            sock.send(b'\n')
            
            # Try to receive some data
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return None
        except Exception:
            return None
    
    def _guess_service(self, port: int) -> str:
        """Guess service name based on port number."""
        common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP',
            5900: 'VNC', 8080: 'HTTP-Proxy'
        }
        return common_ports.get(port, f'Unknown-Port-{port}')
    
    def _is_internal_network(self, ip: str) -> bool:
        """Check if an IP belongs to configured internal networks."""
        if not self.internal_networks:
            # Default internal ranges if none configured
            self.internal_networks = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
        
        ip_obj = ipaddress.ip_address(ip)
        for network in self.internal_networks:
            if ip_obj in ipaddress.ip_network(network):
                return True
        return False
    
    def _apply_network_context(self, ip: str, result: Dict) -> Dict:
        """Apply network-based context to the finding."""
        if self._is_internal_network(ip):
            result['details']['network_context'] = 'Internal_Network'
            # Internal services generally get slightly lower risk
            if result['final_risk'] in ['CRITICAL', 'HIGH'] and not result['adjustment_reason']:
                if result.get('details', {}).get('nla_enabled') or result.get('details', {}).get('ssh_v1') is False:
                    result['final_risk'] = 'MEDIUM'
                    result['adjustment_reason'] = 'Internal network context applied'
        else:
            result['details']['network_context'] = 'External_Network'
        
        return result
    
    def get_stats(self) -> Dict:
        """Return triage statistics."""
        return self.stats.copy()


# Convenience function for simple use cases
def triage_service(ip: str, port: int, config: Optional[Dict] = None) -> Dict:
    """Convenience function to triage a single service."""
    engine = TriageEngine(config)
    return engine.triage_service(ip, port)
