"""
Advanced reporting with SIEM integration and baseline comparison.
"""

import json
import pandas as pd
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
import hashlib
import logging

logger = logging.getLogger(__name__)

class SOCReporter:
    """SIEM-ready reporting engine."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def generate_reports(self, assessments: List[Dict], summary: Dict) -> Dict:
        """Generate all report formats."""
        
        # Convert to DataFrame
        df = pd.DataFrame(assessments)
        
        # Create report metadata
        metadata = {
            'report_id': f"sentinel_{self.timestamp}",
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'tool_version': 'SentinelSweep-SOC v2.0',
            'scan_summary': summary,
            'total_records': len(assessments)
        }
        
        # 1. JSON Report (SIEM Ready)
        json_report = {
            'metadata': metadata,
            'assessments': assessments,
            'schema_version': '2.0'
        }
        
        json_path = self.output_dir / f"sentinel_sweep_{self.timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        
        # 2. CSV Report (Spreadsheet Ready)
        csv_path = self.output_dir / f"sentinel_sweep_{self.timestamp}.csv"
        
        # Flatten data for CSV
        flat_data = []
        for assessment in assessments:
            flat_row = {
                'ip': assessment['ip'],
                'open_ports': ';'.join(map(str, assessment['open_ports'])),
                'risk_level': assessment['risk_level'],
                'risk_score': assessment['risk_score'],
                'timestamp': assessment['timestamp']
            }
            
            # Add MITRE findings
            for i, finding in enumerate(assessment.get('mitre_findings', [])[:3]):
                flat_row[f'mitre_tech_{i+1}'] = finding['technique']
                flat_row[f'mitre_service_{i+1}'] = finding['service']
            
            flat_data.append(flat_row)
        
        pd.DataFrame(flat_data).to_csv(csv_path, index=False)
        
        # 3. HTML Report (Executive)
        html_path = self.output_dir / f"sentinel_sweep_{self.timestamp}.html"
        self._generate_html_report(assessments, summary, html_path, metadata)
        
        # 4. Generate baseline for drift detection
        baseline_path = self._generate_baseline(assessments)
        
        return {
            'json': str(json_path),
            'csv': str(csv_path),
            'html': str(html_path),
            'baseline': baseline_path,
            'metadata': metadata
        }
    
    def _generate_html_report(self, assessments, summary, path, metadata):
        """Generate HTML executive report."""
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SentinelSweep-SOC Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .risk-critical {{ color: #e74c3c; font-weight: bold; }}
        .risk-high {{ color: #e67e22; }}
        .risk-medium {{ color: #f1c40f; }}
        .risk-low {{ color: #27ae60; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .summary-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SentinelSweep-SOC v2.0 Report</h1>
        <p>Generated: {metadata['generated_at']} | Report ID: {metadata['report_id']}</p>
    </div>
    
    <div class="summary-box">
        <h2>Executive Summary</h2>
        <p><strong>Total Hosts Scanned:</strong> {summary['total_hosts']}</p>
        <p><strong>Hosts with Exposure:</strong> {summary['hosts_with_exposure']}</p>
        <p><strong>Critical Risk Hosts:</strong> {summary['critical_hosts']}</p>
        <p><strong>High Risk Hosts:</strong> {summary['high_hosts']}</p>
    </div>
    
    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Open Ports</th>
            <th>Risk Level</th>
            <th>Risk Score</th>
            <th>MITRE Techniques</th>
        </tr>
        {"".join([
            f"<tr><td>{a['ip']}</td><td>{', '.join(map(str, a['open_ports']))}</td>"
            f"<td class='risk-{a['risk_level'].lower()}'>{a['risk_level']}</td>"
            f"<td>{a['risk_score']}</td><td>{', '.join([f['technique'] for f in a['mitre_findings'][:2]])}</td></tr>"
            for a in assessments if a['open_ports']
        ])}
    </table>
    
    <h2>Most Common Exposed Ports</h2>
    <table>
        <tr><th>Port</th><th>Count</th><th>Service</th></tr>
        {"".join([
            f"<tr><td>{port}</td><td>{count}</td><td>Service</td></tr>"
            for port, count in list(summary['common_ports'].items())[:5]
        ])}
    </table>
    
    <footer>
        <p><em>Report generated by SentinelSweep-SOC v2.0 - Defensive Security Assessment Tool</em></p>
        <p><em>For authorized use only. All scans performed with explicit network authorization.</em></p>
    </footer>
</body>
</html>
        """
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_template)
    
    def _generate_baseline(self, assessments: List[Dict]) -> str:
        """Create baseline for future drift detection."""
        
        baseline = {
            'created_at': datetime.utcnow().isoformat() + 'Z',
            'hash': hashlib.sha256(
                json.dumps(assessments, sort_keys=True).encode()
            ).hexdigest(),
            'host_count': len(assessments),
            'assessments': assessments
        }
        
        baseline_path = self.output_dir / f"baseline_{self.timestamp}.json"
        with open(baseline_path, 'w') as f:
            json.dump(baseline, f, indent=2, default=str)
        
        return str(baseline_path)
    
    def detect_drift(self, current_assessments: List[Dict]) -> Dict:
        """Compare current scan with baseline to detect changes."""
        
        baseline_path = max(self.output_dir.glob('baseline_*.json'), default=None)
        
        if not baseline_path:
            return {'drift_detected': False, 'message': 'No baseline found'}
        
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)
        
        # Simple drift detection - compare host counts and ports
        current_hash = hashlib.sha256(
            json.dumps(current_assessments, sort_keys=True).encode()
        ).hexdigest()
        
        drift_detected = current_hash != baseline['hash']
        
        return {
            'drift_detected': drift_detected,
            'baseline_time': baseline['created_at'],
            'current_time': datetime.utcnow().isoformat() + 'Z',
            'host_count_change': len(current_assessments) - baseline['host_count'],
            'baseline_hash': baseline['hash'],
            'current_hash': current_hash
        }

# Legacy function
def write_reports(results):
    reporter = SOCReporter()
    return reporter.generate_reports(results, {})
