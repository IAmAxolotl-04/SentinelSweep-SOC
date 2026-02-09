"""
SOC-grade risk assessment engine with MITRE ATT&CK mapping.
"""

from typing import List, Dict, Tuple
import datetime

# MITRE ATT&CK Enterprise v13 Mapping
MITRE_ATTACK_MAP = {
    21: {'technique': 'T1071.001', 'tactic': 'Command and Control', 
         'name': 'FTP - File Transfer Protocol', 'risk': 'MEDIUM'},
    22: {'technique': 'T1021.004', 'tactic': 'Lateral Movement', 
         'name': 'SSH - Secure Shell', 'risk': 'HIGH'},
    23: {'technique': 'T1071.001', 'tactic': 'Command and Control', 
         'name': 'Telnet', 'risk': 'HIGH'},
    25: {'technique': 'T1071.003', 'tactic': 'Command and Control', 
         'name': 'SMTP - Simple Mail Transfer', 'risk': 'MEDIUM'},
    80: {'technique': 'T1190', 'tactic': 'Initial Access', 
         'name': 'HTTP - Web Service', 'risk': 'MEDIUM'},
    443: {'technique': 'T1190', 'tactic': 'Initial Access', 
          'name': 'HTTPS - Secure Web', 'risk': 'MEDIUM'},
    445: {'technique': 'T1021.002', 'tactic': 'Lateral Movement', 
          'name': 'SMB - File Sharing', 'risk': 'CRITICAL'},
    3389: {'technique': 'T1021.001', 'tactic': 'Lateral Movement', 
           'name': 'RDP - Remote Desktop', 'risk': 'CRITICAL'},
    5900: {'technique': 'T1021.005', 'tactic': 'Lateral Movement', 
           'name': 'VNC - Virtual Network', 'risk': 'HIGH'},
    8080: {'technique': 'T1190', 'tactic': 'Initial Access', 
           'name': 'HTTP-Alt', 'risk': 'MEDIUM'},
    8443: {'technique': 'T1190', 'tactic': 'Initial Access', 
           'name': 'HTTPS-Alt', 'risk': 'MEDIUM'}
}

class SOCRiskEngine:
    """SOC analyst risk assessment engine."""
    
    def __init__(self):
        self.findings = []
        self.risk_scores = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 6, 'CRITICAL': 10}
    
    def assess_exposure(self, ip: str, open_ports: List[int]) -> Dict:
        """Comprehensive risk assessment for a host."""
        
        risk_score = 0
        mitre_findings = []
        recommendations = []
        
        # Analyze each open port
        for port in open_ports:
            if port in MITRE_ATTACK_MAP:
                mitre_data = MITRE_ATTACK_MAP[port]
                mitre_findings.append({
                    'port': port,
                    'technique': mitre_data['technique'],
                    'tactic': mitre_data['tactic'],
                    'service': mitre_data['name'],
                    'risk': mitre_data['risk']
                })
                risk_score += self.risk_scores[mitre_data['risk']]
                
                # Generate recommendations
                if port == 3389:
                    recommendations.append("Restrict RDP to VPN or jump host")
                elif port == 22:
                    recommendations.append("Implement SSH key authentication only")
                elif port == 80 and 443 not in open_ports:
                    recommendations.append("Redirect HTTP to HTTPS")
                elif port == 445:
                    recommendations.append("Restrict SMB to internal subnets only")
        
        # Determine overall risk level
        if risk_score >= 15:
            risk_level = 'CRITICAL'
        elif risk_score >= 10:
            risk_level = 'HIGH'
        elif risk_score >= 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Check for concerning combinations
        if 3389 in open_ports and 445 in open_ports:
            risk_level = 'CRITICAL'
            recommendations.append("CRITICAL: Both RDP and SMB exposed - high lateral movement risk")
        
        return {
            'ip': ip,
            'open_ports': open_ports,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'mitre_findings': mitre_findings,
            'recommendations': recommendations,
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'
        }
    
    def generate_executive_summary(self, assessments: List[Dict]) -> Dict:
        """Generate executive-level summary report."""
        
        summary = {
            'total_hosts': len(assessments),
            'hosts_with_exposure': 0,
            'critical_hosts': 0,
            'high_hosts': 0,
            'total_open_ports': 0,
            'common_ports': {},
            'top_risks': []
        }
        
        for assessment in assessments:
            if assessment['open_ports']:
                summary['hosts_with_exposure'] += 1
            
            if assessment['risk_level'] == 'CRITICAL':
                summary['critical_hosts'] += 1
            elif assessment['risk_level'] == 'HIGH':
                summary['high_hosts'] += 1
            
            summary['total_open_ports'] += len(assessment['open_ports'])
            
            # Count port frequencies
            for port in assessment['open_ports']:
                summary['common_ports'][port] = summary['common_ports'].get(port, 0) + 1
        
        # Sort and get top 5 ports
        summary['common_ports'] = dict(sorted(
            summary['common_ports'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5])
        
        return summary

# Legacy function
def assess_risk(ports: List[int]) -> Tuple[str, List[str], List[Dict]]:
    engine = SOCRiskEngine()
    result = engine.assess_exposure('0.0.0.0', ports)
    findings = [f"{result['risk_level']} risk: {len(ports)} ports open"]
    return result['risk_level'], findings, result['mitre_findings']
