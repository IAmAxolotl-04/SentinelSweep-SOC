#!/usr/bin/env python3
"""
SentinelSweep-SOC Demo
Generates a professional HTML security report with sample data.
"""

import sys
from pathlib import Path
from datetime import datetime
import webbrowser

# Ensure src is importable
BASE_DIR = Path(__file__).parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

try:
    from reporter import SOCReporter
except ImportError as e:
    print("❌ Failed to import SOCReporter:", e)
    sys.exit(1)

# Optional: risk engine (if available)
try:
    from risk_engine import SOCRiskEngine
    RISK_ENGINE_AVAILABLE = True
except ImportError:
    RISK_ENGINE_AVAILABLE = False


# ==========================================================
# Sample Data Generator
# ==========================================================

def generate_sample_assessments():
    """
    Create realistic sample assessment data.
    Works with or without SOCRiskEngine.
    """

    assessments = []

    samples = [
        ("192.168.1.105", [3389, 445], "CRITICAL", 95),
        ("203.0.113.50", [23], "CRITICAL", 90),
        ("192.168.1.110", [22], "HIGH", 75),
        ("10.0.0.15", [80], "HIGH", 70),
        ("192.168.1.120", [443], "MEDIUM", 55),
        ("172.16.1.5", [3306], "MEDIUM", 60),
        ("192.168.1.130", [3389], "LOW", 40),
        ("10.0.0.20", [22], "LOW", 35),
    ]

    if RISK_ENGINE_AVAILABLE:
        engine = SOCRiskEngine()

        for ip, ports, _, _ in samples:
            assessment = engine.assess_exposure(ip, ports, None)
            assessments.append(assessment)

    else:
        # Fallback manual sample structure
        for ip, ports, risk, score in samples:
            assessments.append({
                "ip": ip,
                "open_ports": ports,
                "initial_risk": risk,
                "true_risk": risk,
                "risk_score": score,
                "risk_adjusted": False,
                "context": {
                    "network_segment": "Internal"
                }
            })

    return assessments


# ==========================================================
# Main
# ==========================================================

def main():
    print("🎨 Generating professional SentinelSweep report...")

    assessments = generate_sample_assessments()

    reporter = SOCReporter()

    reports = reporter.generate_reports(assessments)

    print("\n✅ Report generated successfully!")
    print(f"📊 HTML Report: {reports['html']}")
    print(f"📈 JSON Report: {reports['json']}")
    print(f"📉 CSV Report: {reports['csv']}")

    # Open HTML report automatically
    try:
        html_path = Path(reports["html"]).resolve()
        webbrowser.open(f"file:///{html_path}")
        print("🌐 Opening report in browser...")
    except Exception as e:
        print("⚠️ Could not open browser automatically:", e)


if __name__ == "__main__":
    main()
