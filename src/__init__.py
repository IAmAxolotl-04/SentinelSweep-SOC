"""
SentinelSweep-SOC v2.0 - Defensive Network Exposure Assessment
"""

__version__ = "2.0.0"
__author__ = "SentinelSweep Team"
__description__ = "SOC-grade defensive network exposure assessment platform"

from .banner import display_banner
from .scanner import DefenderSafeScanner, scan_host
from .risk_engine import SOCRiskEngine, assess_risk
from .reporter import SOCReporter, write_reports

__all__ = [
    'display_banner',
    'DefenderSafeScanner',
    'scan_host',
    'SOCRiskEngine',
    'assess_risk',
    'SOCReporter',
    'write_reports'
]
