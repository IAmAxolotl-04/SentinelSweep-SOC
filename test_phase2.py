#!/usr/bin/env python3
"""
Phase 2 Test: Enhanced Banner Grabbing & Contextual Triage
"""

import sys
sys.path.insert(0, 'src')

from risk_engine import SOCRiskEngine
from triage_engine import TriageEngine

def test_phase2():
    print("🧪 Testing Phase 2: Enhanced Triage Engine")
    print("=" * 60)
    
    # Initialize engines
    risk_engine = SOCRiskEngine()
    triage_engine = TriageEngine()
    
    print("\n1. Testing banner grabbing on local services...")
    
    # Test cases: (ip, port, expected_service)
    test_cases = [
        ('127.0.0.1', 22, 'SSH'),
        ('127.0.0.1', 80, 'HTTP'),
        ('127.0.0.1', 443, 'HTTPS'),
        ('192.168.1.1', 3389, 'RDP'),
        ('192.168.1.1', 445, 'SMB'),
    ]
    
    for ip, port, expected_service in test_cases:
        print(f"\n   Testing {expected_service} on {ip}:{port}...")
        
        # Try to triage the service
        try:
            triage_result = triage_engine.triage_service(ip, port)
            
            print(f"     Service Guess: {triage_result.get('service_guess')}")
            print(f"     Banner: {triage_result.get('banner', 'No banner')[:80]}")
            print(f"     Final Risk: {triage_result.get('final_risk')}")
            print(f"     Reason: {triage_result.get('adjustment_reason')}")
            
            # Create assessment with triage data
            assessment = risk_engine.assess_exposure(ip, [port], triage_result)
            
            print(f"     Assessment Risk: {assessment['true_risk']}")
            print(f"     Risk Adjusted: {assessment.get('risk_adjusted', False)}")
            
            if assessment.get('risk_adjusted'):
                print(f"     ✓ Risk adjustment working!")
            
        except Exception as e:
            print(f"     ✗ Error: {e}")
    
    print("\n2. Testing network context analysis...")
    
    test_ips = [
        ('192.168.1.100', 'Internal_Network'),
        ('10.0.0.1', 'Internal_Network'),
        ('172.16.0.1', 'Internal_Network'),
        ('8.8.8.8', 'External_Network'),
        ('203.0.113.1', 'External_Network')
    ]
    
    for ip, expected_context in test_ips:
        context = triage_engine._get_network_context(ip)
        status = "✓" if context == expected_context else "✗"
        print(f"   {status} {ip} -> {context} (expected: {expected_context})")
    
    print("\n3. Testing RDP security feature detection...")
    
    # Simulate different RDP banners
    rdp_test_banners = [
        ("RDP with NLA", "SSL/TLS with NLA supported", ['NLA_ENABLED'], 'MEDIUM'),
        ("Insecure RDP", "Microsoft RDP", [], 'CRITICAL'),
        ("Secure RDP", "RDP with SSL and CredSSP", ['SSL_ENABLED', 'CREDSSP_ENABLED'], 'MEDIUM')
    ]
    
    for banner_name, banner_text, expected_checks, expected_risk in rdp_test_banners:
        # Create a mock result with banner
        mock_result = {
            'service_guess': 'RDP',
            'banner': banner_text,
            'network_context': 'Internal_Network',
            'checks_passed': [],
            'checks_failed': []
        }
        
        # Run through RDP triage logic
        result = triage_engine._triage_rdp('192.168.1.100', 3389, mock_result)
        
        checks_match = set(result.get('checks_passed', [])) == set(expected_checks)
        risk_match = result.get('final_risk') == expected_risk
        
        status = "✓" if checks_match and risk_match else "✗"
        print(f"   {status} {banner_name}: Risk={result.get('final_risk')}, Checks={result.get('checks_passed')}")
    
    print("\n4. Testing SSH version detection...")
    
    ssh_banners = [
        ("Secure SSH v2", "SSH-2.0-OpenSSH_8.9", 'SSH_V2_SECURE', 'MEDIUM'),
        ("Insecure SSH v1", "SSH-1.5-OpenSSH_3.9", 'SSH_V1_INSECURE', 'HIGH'),
        ("Vulnerable version", "SSH-2.0-OpenSSH_7.3", 'VULNERABLE_VERSION', 'HIGH')
    ]
    
    for banner_name, banner_text, expected_check, expected_risk in ssh_banners:
        mock_result = {
            'service_guess': 'SSH',
            'banner': banner_text,
            'network_context': 'Internal_Network',
            'checks_passed': [],
            'checks_failed': []
        }
        
        result = triage_engine._triage_ssh('192.168.1.100', 22, mock_result)
        
        has_check = expected_check in (result.get('checks_passed', []) + result.get('checks_failed', []))
        risk_match = result.get('final_risk') == expected_risk
        
        status = "✓" if has_check and risk_match else "✗"
        print(f"   {status} {banner_name}: Risk={result.get('final_risk')}, Check={expected_check}")
    
    print("\n" + "=" * 60)
    print("📊 Triage Engine Statistics:")
    stats = triage_engine.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Phase 2 tests completed!")
    print("\n🎯 What we've implemented:")
    print("   • Service-specific banner grabbing with intelligent probes")
    print("   • RDP security feature detection (NLA, SSL, etc.)")
    print("   • SSH version and vulnerability detection")
    print("   • Network context analysis (internal vs. external)")
    print("   • Automated risk adjustment based on findings")
    print("\n🚀 Ready for Phase 3: Main loop integration and reporting!")

if __name__ == "__main__":
    test_phase2()
