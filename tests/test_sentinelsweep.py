\"\"\"
Test suite for SentinelSweep-SOC v2.0
\"\"\"

import unittest
import tempfile
import json
from pathlib import Path
from src.scanner import DefenderSafeScanner
from src.risk_engine import SOCRiskEngine
from src.reporter import SOCReporter

class TestDefenderSafeScanner(unittest.TestCase):
    \"\"\"Test the Defender-safe scanner.\"\"\"
    
    def setUp(self):
        self.scanner = DefenderSafeScanner(timeout=0.1, max_workers=2)
    
    def test_cidr_validation(self):
        \"\"\"Test CIDR validation and expansion.\"\"\"
        # Valid CIDR
        hosts = self.scanner.validate_cidr(\"192.168.1.0/30\")
        self.assertEqual(len(hosts), 2)  # 192.168.1.1 and 192.168.1.2
        
        # Invalid CIDR
        hosts = self.scanner.validate_cidr(\"invalid\")
        self.assertEqual(len(hosts), 0)
    
    def test_scan_localhost_common_ports(self):
        \"\"\"Test scanning localhost on common ports (should be fast).\"\"\"
        # Test common ports - some may be open
        ports = [80, 443, 8080]
        open_ports = self.scanner.scan_host(\"127.0.0.1\", ports, delay=0.01)
        
        # Just verify function runs without error
        self.assertIsInstance(open_ports, list)
    
    def test_scanner_stats(self):
        \"\"\"Test scanner statistics tracking.\"\"\"
        # Run a minimal scan
        self.scanner.scan_host(\"127.0.0.1\", [9999], delay=0.01)
        stats = self.scanner.get_stats()
        
        self.assertIn('hosts_scanned', stats)
        self.assertIn('ports_checked', stats)
        self.assertEqual(stats['hosts_scanned'], 1)

class TestSOCRiskEngine(unittest.TestCase):
    \"\"\"Test the SOC risk assessment engine.\"\"\"
    
    def setUp(self):
        self.engine = SOCRiskEngine()
    
    def test_risk_assessment(self):
        \"\"\"Test risk assessment logic.\"\"\"
        # Test with known risky ports
        assessment = self.engine.assess_exposure(\"192.168.1.100\", [3389, 445])
        
        self.assertEqual(assessment['ip'], \"192.168.1.100\")
        self.assertEqual(assessment['open_ports'], [3389, 445])
        self.assertIn('risk_level', assessment)
        self.assertIn('risk_score', assessment)
        self.assertIn('mitre_findings', assessment)
        
        # Should be CRITICAL with both RDP and SMB
        self.assertEqual(assessment['risk_level'], 'CRITICAL')
        self.assertGreater(assessment['risk_score'], 10)
    
    def test_executive_summary(self):
        \"\"\"Test executive summary generation.\"\"\"
        assessments = [
            self.engine.assess_exposure(\"192.168.1.100\", [3389]),
            self.engine.assess_exposure(\"192.168.1.101\", [80]),
            self.engine.assess_exposure(\"192.168.1.102\", []),
        ]
        
        summary = self.engine.generate_executive_summary(assessments)
        
        self.assertEqual(summary['total_hosts'], 3)
        self.assertEqual(summary['hosts_with_exposure'], 2)
        self.assertIn('common_ports', summary)

class TestSOCReporter(unittest.TestCase):
    \"\"\"Test the reporting engine.\"\"\"
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.reporter = SOCReporter(output_dir=self.test_dir)
        self.engine = SOCRiskEngine()
    
    def test_report_generation(self):
        \"\"\"Test report generation.\"\"\"
        # Create test assessment
        assessment = self.engine.assess_exposure(\"192.168.1.100\", [80, 443])
        summary = self.engine.generate_executive_summary([assessment])
        
        # Generate reports
        report_paths = self.reporter.generate_reports([assessment], summary)
        
        # Check all report types were created
        self.assertIn('json', report_paths)
        self.assertIn('csv', report_paths)
        self.assertIn('html', report_paths)
        
        # Verify JSON report exists and is valid
        json_path = Path(report_paths['json'])
        self.assertTrue(json_path.exists())
        
        with open(json_path, 'r') as f:
            report_data = json.load(f)
        
        self.assertIn('metadata', report_data)
        self.assertIn('assessments', report_data)
    
    def test_baseline_generation(self):
        \"\"\"Test baseline creation.\"\"\"
        assessment = self.engine.assess_exposure(\"192.168.1.100\", [80])
        
        # Generate baseline
        baseline_path = self.reporter._generate_baseline([assessment])
        
        self.assertTrue(Path(baseline_path).exists())
    
    def test_drift_detection(self):
        \"\"\"Test drift detection.\"\"\"
        assessment1 = self.engine.assess_exposure(\"192.168.1.100\", [80])
        assessment2 = self.engine.assess_exposure(\"192.168.1.100\", [80, 443])
        
        # Create baseline
        self.reporter._generate_baseline([assessment1])
        
        # Detect drift with changed assessment
        drift_result = self.reporter.detect_drift([assessment2])
        
        self.assertIn('drift_detected', drift_result)
        # Should detect drift since ports changed
        self.assertTrue(drift_result['drift_detected'])

if __name__ == '__main__':
    unittest.main()
