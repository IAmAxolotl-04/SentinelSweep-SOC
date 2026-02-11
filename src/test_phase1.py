#!/usr/bin/env python3
"""
Quick test for Phase 1 updates.
"""

import sys
sys.path.insert(0, 'src')

from risk_engine import SOCRiskEngine
from triage_engine import TriageEngine

def test_phase1():
    print("🧪 Testing Phase 1 Updates...")
    
    # Test 1: Basic risk engine
    print("\n1. Testing updated risk engine...")
    engine = SOCRiskEngine()
    
    # Test without triage data
    assessment = engine.assess_exposure("192.168.1.100", [22, 80, 3389])
    print(f"   Basic assessment created: {assessment['ip']}")
    print(f"   Initial Risk: {assessment['initial_risk']}")
    print(f"   True Risk: {assessment['true_risk']}")
    print(f"   Has MITRE mapping: {len(assessment['context']['mitre_findings'])} findings")
    
    # Test 2: Triage engine
    print("\n2. Testing triage engine...")
    triage = TriageEngine()
    
    # Test RDP triage
    rdp_result = triage.triage_service("192.168.1.105", 3389)
    print(f"   RDP triage completed: {rdp_result['service_guess']}")
    print(f"   Verification: {rdp_result['verification']}")
    print(f"   Final Risk: {rdp_result['final_risk']}")
    
    # Test SSH triage
    ssh_result = triage.triage_service("192.168.1.106", 22)
    print(f"   SSH triage completed: {ssh_result['service_guess']}")
    
    # Test 3: Combined workflow
    print("\n3. Testing combined workflow...")
    triage_data = triage.triage_service("10.0.1.50", 3389)
    enhanced_assessment = engine.assess_exposure("10.0.1.50", [3389], triage_data)
    print(f"   Enhanced assessment created with triage data")
    print(f"   Risk Adjusted: {enhanced_assessment.get('risk_adjusted', False)}")
    if enhanced_assessment.get('risk_adjusted'):
        print(f"   Adjustment Reason: {enhanced_assessment.get('adjustment_reason')}")
    
    # Test 4: Executive summary
    print("\n4. Testing executive summary...")
    assessments = [
        engine.assess_exposure("192.168.1.100", [22, 80]),
        engine.assess_exposure("192.168.1.101", [443]),
        engine.assess_exposure("192.168.1.102", [3389, 445])
    ]
    summary = engine.generate_executive_summary(assessments)
    print(f"   Total hosts: {summary['total_hosts']}")
    print(f"   Hosts with exposure: {summary['hosts_with_exposure']}")
    print(f"   Critical hosts: {summary['critical_hosts']}")
    
    print("\n✅ Phase 1 tests completed successfully!")
    print("\n📊 Triage Engine Stats:")
    for key, value in triage.get_stats().items():
        print(f"   {key}: {value}")

if __name__ == "__main__":
    test_phase1()