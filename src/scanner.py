"""
Defensive network scanner with Windows Defender-safe practices.
Rate-limited TCP connect scanning only.
"""

import socket
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DefenderSafeScanner:
    """Windows Defender-safe TCP scanner with rate limiting."""
    
    def __init__(self, timeout: float = 1.5, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self.scan_stats = {'hosts_scanned': 0, 'ports_checked': 0, 'open_ports_found': 0}
    
    def safe_tcp_connect(self, ip: str, port: int) -> Tuple[int, bool]:
        """Single TCP connection attempt with explicit error handling."""
        try:
            # Windows Defender-safe: Explicit TCP connect (not SYN)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect attempt
            result = sock.connect_ex((ip, port))
            sock.close()
            
            self.scan_stats['ports_checked'] += 1
            is_open = result == 0
            
            if is_open:
                self.scan_stats['open_ports_found'] += 1
                logger.debug(f"Port {port} open on {ip}")
            
            return port, is_open
            
        except socket.timeout:
            return port, False
        except socket.error as e:
            logger.warning(f"Socket error on {ip}:{port} - {e}")
            return port, False
        except Exception as e:
            logger.error(f"Unexpected error on {ip}:{port} - {e}")
            return port, False
    
    def scan_host(self, ip: str, ports: List[int], delay: float = 0.25) -> List[int]:
        """Scan a single host with rate limiting."""
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.safe_tcp_connect, ip, port): port for port in ports}
            
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                
                # Rate limiting to avoid Defender detection
                time.sleep(delay)
        
        self.scan_stats['hosts_scanned'] += 1
        return sorted(open_ports)
    
    def validate_cidr(self, cidr: str) -> List[str]:
        """Validate and expand CIDR notation."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logger.error(f"Invalid CIDR: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Return scanning statistics."""
        return self.scan_stats.copy()

# Legacy function for backward compatibility
def scan_host(ip: str, ports: List[int], timeout: float = 1.5, delay: float = 0.25) -> List[int]:
    scanner = DefenderSafeScanner(timeout=timeout)
    return scanner.scan_host(ip, ports, delay)
