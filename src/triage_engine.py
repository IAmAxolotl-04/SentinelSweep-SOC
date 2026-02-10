import socket
from typing import Dict, Optional

class TriageEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.stats = {'services_triaged': 0}
    
    def triage_service(self, ip: str, port: int) -> Dict:
        self.stats['services_triaged'] += 1
        
        result = {
            'ip': ip,
            'port': port,
            'service_guess': self._guess_service(port),
            'banner': None,
            'verification': 'Basic port detection',
            'reliability': 'MEDIUM',
            'details': {},
            'final_risk': None,
            'adjustment_reason': None
        }
        
        if port == 3389:
            result = self._triage_rdp(ip, port, result)
        elif port == 22:
            result = self._triage_ssh(ip, port, result)
        
        return result
    
    def _triage_rdp(self, ip: str, port: int, result: Dict) -> Dict:
        result['service_guess'] = 'RDP'
        
        try:
            banner = self._grab_banner(ip, port, timeout=2)
            if banner:
                result['banner'] = banner
                result['verification'] = f'Service banner: {banner[:50]}...'
                
                if any(indicator in banner.upper() for indicator in ['SSL', 'NLA', 'SECURE']):
                    result['details']['nla_enabled'] = True
                    result['final_risk'] = 'MEDIUM'
                    result['adjustment_reason'] = 'RDP has NLA enabled'
                else:
                    result['details']['nla_enabled'] = False
                    result['final_risk'] = 'CRITICAL'
                    result['adjustment_reason'] = 'RDP without NLA detected'
        except Exception as e:
            result['verification'] = f'Banner grab failed: {str(e)}'
        
        return result
    
    def _triage_ssh(self, ip: str, port: int, result: Dict) -> Dict:
        result['service_guess'] = 'SSH'
        result['final_risk'] = 'MEDIUM'
        result['adjustment_reason'] = 'SSH service detected'
        return result
    
    def _grab_banner(self, ip: str, port: int, timeout: int = 2) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(b'\n')
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner if banner else None
        except:
            return None
    
    def _guess_service(self, port: int) -> str:
        common_ports = {
            22: 'SSH', 3389: 'RDP', 80: 'HTTP', 443: 'HTTPS',
            445: 'SMB', 21: 'FTP', 23: 'Telnet', 5900: 'VNC'
        }
        return common_ports.get(port, f'Port-{port}')

def triage_service(ip: str, port: int, config: Optional[Dict] = None) -> Dict:
    engine = TriageEngine(config)
    return engine.triage_service(ip, port)
