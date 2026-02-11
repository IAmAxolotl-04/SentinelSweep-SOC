import sys
sys.path.insert(0, 'src')

print('Testing imports...')
try:
    from risk_engine import SOCRiskEngine
    print('✅ SOCRiskEngine imported successfully')
except ImportError as e:
    print(f'❌ Failed to import SOCRiskEngine: {e}')

try:
    from triage_engine import TriageEngine
    print('✅ TriageEngine imported successfully')
except ImportError as e:
    print(f'❌ Failed to import TriageEngine: {e}')

# Quick functionality test
print('\nTesting functionality...')
engine = SOCRiskEngine()
test_assessment = engine.assess_exposure('192.168.1.100', [22, 3389])
print(f'✅ Assessment created for IP: {test_assessment["ip"]}')
print(f'   True Risk: {test_assessment["true_risk"]}')

triage = TriageEngine()
rdp_triage = triage.triage_service('192.168.1.105', 3389)
print(f'✅ RDP triage completed: {rdp_triage["service_guess"]}')

print('\n🎉 Phase 1 imports and basic functionality working!')
