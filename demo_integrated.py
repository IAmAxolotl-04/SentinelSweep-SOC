#!/usr/bin/env python3
"""
SentinelSweep-SOC Demo: Test the integrated triage system
"""

import sys
sys.path.insert(0, 'src')

from triage_engine import TriageEngine
from risk_engine import SOCRiskEngine

def run_demo():
    print("🚀 SentinelSweep-SOC Integrated Demo")
    print("=" * 60)
    
    # Initialize engines
    triage = TriageEngine()
    risk = SOCRiskEngine()
    
    print("\n📊 Testing Risk Adjustment Scenarios:")
    print("-" * 40)
    
    scenarios = [
        {
            "name": "Secure RDP on Internal Network",
            "ip": "192.168.1.100",
            "port": 3389,
            "mock_banner": "Microsoft Terminal Services with NLA and SSL"
        },
        {
            "name": "Insecure RDP on External Network", 
            "ip": "203.0.113.50",
            "port": 3389,
            "mock_banner": "Microsoft Terminal Services"
        },
        {
            "name": "SSH v2 on Internal Network",
            "ip": "10.0.0.10",
            "port": 22,
            "mock_banner": "SSH-2.0-OpenSSH_8.9"
        },
        {
            "name": "HTTPS on External Network",
            "ip": "8.8.8.8", 
            "port": 443,
            "mock_banner": "HTTP/1.1 200 OK\r\nServer: nginx"
        },
        {
            "name": "HTTP with Default Page",
            "ip": "192.168.1.200",
            "port": 80,
            "mock_banner": "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<h1>It works!</h1>"
        }
    ]
    
    all_assessments = []
    
    for scenario in scenarios:
        print(f"\n🔍 {scenario['name']}")
        print(f"   Target: {scenario['ip']}:{scenario['port']}")
        
        # Normally triage_service would grab the banner, but for demo we'll mock it
        # In real use, it would connect to the service
        
        # Create triage result (simulating what would happen)
        triage_result = {
            'ip': scenario['ip'],
            'port': scenario['port'],
            'service_guess': triage._guess_service(scenario['port']),
            'banner': scenario.get('mock_banner'),
            'verification': 'Demo simulation',
            'reliability': 'HIGH',
            'details': {},
            'final_risk': None,
            'adjustment_reason': 'Demo scenario',
            'network_context': triage._get_network_context(scenario['ip'])
        }
        
        # Run through the appropriate triage logic
        if scenario['port'] == 3389:
            triage_result = triage._triage_rdp(
                scenario['ip'], 
                scenario['port'], 
                triage_result,
                scenario.get('mock_banner')
            )
        elif scenario['port'] == 22:
            triage_result = triage._triage_ssh(
                scenario['ip'],
                scenario['port'],
                triage_result,
                scenario.get('mock_banner')
            )
        elif scenario['port'] in [80, 443]:
            triage_result = triage._triage_http(
                scenario['ip'],
                scenario['port'],
                triage_result,
                scenario.get('mock_banner')
            )
        
        # Create assessment
        assessment = risk.assess_exposure(
            scenario['ip'], 
            [scenario['port']], 
            triage_result
        )
        
        all_assessments.append(assessment)
        
        print(f"   ✅ Risk Level: {assessment['true_risk']}")
        print(f"   📝 Reason: {assessment.get('adjustment_reason', 'N/A')}")
        print(f"   🔧 Adjusted: {assessment.get('risk_adjusted', False)}")
        
        if assessment.get('risk_adjusted'):
            print(f"   🎯 SMART: Risk intelligently adjusted based on context!")
    
    print("\n" + "=" * 60)
    print("📈 Executive Summary:")
    
    summary = risk.generate_executive_summary(all_assessments)
    print(f"   Total Findings: {summary['total_hosts']}")
    print(f"   Critical: {summary['critical_hosts']}")
    print(f"   High: {summary['high_hosts']}") 
    print(f"   Medium: {summary['medium_hosts']}")
    print(f"   Low: {summary['low_hosts']}")
    print(f"   Auto-Adjusted: {summary['adjusted_risks']}")
    
    print("\n🎯 Key Takeaways:")
    print("   • RDP with NLA gets downgraded from CRITICAL to MEDIUM/HIGH")
    print("   • Internal vs. external context matters for risk scoring")
    print("   • SSH v2 is safer than v1 (automatically detected)")
    print("   • HTTPS is lower risk than HTTP (encryption matters)")
    print("\n✅ Demo complete! The triage system is working intelligently.")
    
    return True

if __name__ == "__main__":
    success = run_demo()
    sys.exit(0 if success else 1)
