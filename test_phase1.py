import sys
sys.path.insert(0, "src")
from triage_engine import TriageEngine

t = TriageEngine()
print("Testing triage engine with safe IPs...")

# Test with internal IP (safe)
result = t.triage_service("192.168.1.100", 3389)
print(f"RDP on internal network: {result['final_risk']} - {result['adjustment_reason']}")

# Test with external IP (safe)
result2 = t.triage_service("8.8.8.8", 22)
print(f"SSH on external network: {result2['final_risk']} - {result2['adjustment_reason']}")

print("\n✅ Triage engine working correctly!")
