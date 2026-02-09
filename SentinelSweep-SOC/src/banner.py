"""
SentinelSweep-SOC v2.0 - Defensive Intent Banner
Displays compliance notice and authorization warning.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import datetime

def display_banner():
    console = Console()
    
    # ASCII Art Banner
    banner_text = """
    ╔══════════════════════════════════════════════════════╗
    ║                SENTINELSWEEP-SOC v2.0                ║
    ║       Defensive Network Exposure Assessment          ║
    ╚══════════════════════════════════════════════════════╝
    """
    
    compliance_text = Text()
    compliance_text.append("COMPLIANCE NOTICE\n", style="bold red")
    compliance_text.append("• Authorized environments only\n", style="yellow")
    compliance_text.append("• No exploitation or credential testing performed\n", style="yellow")
    compliance_text.append("• Defensive security assessment only\n", style="yellow")
    compliance_text.append(f"• Scan Timestamp: {datetime.datetime.utcnow().isoformat()}Z\n", style="cyan")
    
    console.print(Panel(banner_text, border_style="green"))
    console.print(Panel(compliance_text, title="[bold]Legal & Compliance", border_style="red"))
    console.print("\n")
    
    # User confirmation
    confirm = input("[?] Confirm you have authorization to scan target network (y/N): ")
    if confirm.lower() != 'y':
        console.print("[!] Scan aborted - authorization required", style="bold red")
        exit(1)
    
    return True
