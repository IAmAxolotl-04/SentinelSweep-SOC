from typing import List, Dict, Tuple, Optional
import datetime

MITRE_ATTACK_MAP = {
    21: {'technique': 'T1071.001', 'tactic': 'Command and Control', 'name': 'FTP', 'risk': 'MEDIUM'},
    22: {'technique': 'T1021.004', 'tactic': 'Lateral Movement', 'name': 'SSH', 'risk': 'HIGH'},
    23: {'technique': 'T1071.001', 'tactic': 'Command and Control', 'name': 'Telnet', 'risk': 'HIGH'},
    25: {'technique': 'T1071.003', 'tactic': 'Command and Control', 'name': 'SMTP', 'risk': 'MEDIUM'},
    80: {'technique': 'T1190', 'tactic': 'Initial Access', 'name': 'HTTP', 'risk': 'MEDIUM'},
    443: {'technique': 'T1190', 'tactic': 'Initial Access', 'name': 'HTTPS', 'risk': 'MEDIUM'},
    445: {'technique': 'T1021.002', 'tactic': 'Lateral Movement', 'name': 'SMB', 'risk': 'CRITICAL'},
    3389: {'technique': 'T1021.001', 'tactic': 'Lateral Movement', 'name': 'RDP', 'risk': 'CRITICAL'},
    5900: {'technique': 'T1021.005', 'tactic': 'Lateral Movement', 'name': 'VNC', 'risk': 'HIGH'},
    8080: {'technique': 'T1190', 'tactic': 'Initial Access', 'name': 'HTTP-Alt', 'risk': 'MEDIUM'},
    8443: {'technique': 'T1190', 'tactic': 'Initial Access', 'name': 'HTTPS-Alt', 'risk': 'MEDIUM'}
}

class SOCRiskEngine:
    def __init__(self):
        self.findings = []
        self.risk_scores = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 6, 'CRITICAL': 10}
    
    def assess_exposure(self, ip: str, open_ports: List[int], triage_data: Optional[Dict] = None) -> Dict:
        port_details = triage_data if triage_data else {}
        
        risk_score = 0
        mitre_findings = []
        recommendations = []
        
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
                
                if port == 3389:
                    recommendations.append("Restrict RDP to VPN or jump host")
                elif port == 22:
                    recommendations.append("Implement SSH key authentication only")
                elif port == 80 and 443 not in open_ports:
                    recommendations.append("Redirect HTTP to HTTPS")
                elif port == 445:
                    recommendations.append("Restrict SMB to internal subnets only")
        
        if risk_score >= 15:
            initial_risk_level = 'CRITICAL'
        elif risk_score >= 10:
            initial_risk_level = 'HIGH'
        elif risk_score >= 5:
            initial_risk_level = 'MEDIUM'
        else:
            initial_risk_level = 'LOW'
        
        if 3389 in open_ports and 445 in open_ports:
            initial_risk_level = 'CRITICAL'
            recommendations.append("CRITICAL: Both RDP and SMB exposed")
        
        enhanced_finding = {
            'ip': ip,
            'open_ports': open_ports,
            'initial_risk': initial_risk_level,
            'risk_score': risk_score,
            'verification': port_details.get('verification', 'Standard port detection'),
            'reliability': port_details.get('reliability', 'MEDIUM'),
            'context': {
                'mitre_findings': mitre_findings,
                'asset_owner': 'Unknown',
                'network_segment': self._determine_network_segment(ip),
                'triage_details': port_details.get('details', {})
            },
            'transferable_data': {
                'siem_ready': True,
                'ticket_fields': {
                    'priority': initial_risk_level,
                    'assignment_group': 'Network-Security'
                }
            },
            'recommendations': recommendations,
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'
        }
        
        if 'final_risk' in port_details:
            enhanced_finding['true_risk'] = port_details['final_risk']
            enhanced_finding['risk_adjusted'] = True
            enhanced_finding['adjustment_reason'] = port_details.get('adjustment_reason', 'Contextual triage applied')
        else:
            enhanced_finding['true_risk'] = initial_risk_level
            enhanced_finding['risk_adjusted'] = False
        
        return enhanced_finding
    
    def _determine_network_segment(self, ip: str) -> str:
        if ip.startswith('192.168.10.'):
            return 'Internal_Management'
        elif ip.startswith('192.168.20.'):
            return 'User_Network'
        elif ip.startswith('10.0.'):
            return 'Server_Farm'
        else:
            return 'General_Network'
    
    def generate_executive_summary(self, assessments: List[Dict]) -> Dict:
        summary = {
            'total_hosts': len(assessments),
            'hosts_with_exposure': 0,
            'critical_hosts': 0,
            'high_hosts': 0,
            'medium_hosts': 0,
            'low_hosts': 0,
            'adjusted_risks': 0,
            'total_open_ports': 0,
            'common_ports': {},
            'top_risks': []
        }
        
        for assessment in assessments:
            if assessment['open_ports']:
                summary['hosts_with_exposure'] += 1
            
            risk_level = assessment['true_risk']
            if risk_level == 'CRITICAL':
                summary['critical_hosts'] += 1
            elif risk_level == 'HIGH':
                summary['high_hosts'] += 1
            elif risk_level == 'MEDIUM':
                summary['medium_hosts'] += 1
            elif risk_level == 'LOW':
                summary['low_hosts'] += 1
            
            if assessment.get('risk_adjusted', False):
                summary['adjusted_risks'] += 1
            
            summary['total_open_ports'] += len(assessment['open_ports'])
            
            for port in assessment['open_ports']:
                summary['common_ports'][port] = summary['common_ports'].get(port, 0) + 1
        
        summary['common_ports'] = dict(sorted(
            summary['common_ports'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5])
        
        return summary

def assess_risk(ports: List[int], triage_data: Optional[Dict] = None) -> Tuple[str, List[str], List[Dict]]:
    engine = SOCRiskEngine()
    result = engine.assess_exposure('0.0.0.0', ports, triage_data)
    findings = [f"{result['true_risk']} risk: {len(ports)} ports open"]
    return result['true_risk'], findings, result['context']['mitre_findings']
