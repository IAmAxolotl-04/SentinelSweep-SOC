#!/usr/bin/env python3
"""
SentinelSweep-SOC Demo - Simple & Working
"""

import sys
sys.path.insert(0, 'src')

from triage_engine import TriageEngine
from risk_engine import SOCRiskEngine
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def main():
    console.print(Panel.fit("[bold cyan]🚀 SentinelSweep-SOC Demo[/bold cyan]", border_style="cyan"))
    
    # Initialize
    triage = TriageEngine()
    risk = SOCRiskEngine()
    
    # Test scenarios
    scenarios = [
        ("192.168.1.100", 3389, "RDP - Internal with NLA"),
        ("203.0.113.50", 3389, "RDP - External without NLA"),
        ("10.0.0.10", 22, "SSH - Internal v2"),
        ("8.8.8.8", 443, "HTTPS - External"),
        ("192.168.1.200", 80, "HTTP - Internal default page"),
        ("172.16.1.5", 445, "SMB - Internal"),
    ]
    
    table = Table(title="Intelligent Risk Assessment Results")
    table.add_column("Service", style="cyan")
    table.add_column("Context", style="white")
    table.add_column("Initial Risk", style="yellow")
    table.add_column("Final Risk", style="bold")
    table.add_column("Reason", style="dim")
    
    for ip, port, desc in scenarios:
        # Get triage data
        triage_data = triage.triage_service(ip, port)
        
        # Get assessment
        assessment = risk.assess_exposure(ip, [port], triage_data)
        
        # Color based on risk
        risk_color = {
            'CRITICAL': 'red',
            'HIGH': 'orange3',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }.get(assessment['true_risk'], 'white')
        
        table.add_row(
            f"{desc}",
            triage_data['network_context'],
            assessment.get('initial_risk', 'UNKNOWN'),
            f"[{risk_color}]{assessment['true_risk']}[/{risk_color}]",
            assessment.get('adjustment_reason', 'No adjustment')[:40]
        )
    
    console.print(table)
    
    # Show stats
    stats = triage.get_stats()
    console.print(f"\n[bold]📊 Demo Statistics:[/bold]")
    console.print(f"  Services triaged: {stats.get('services_triaged', 0)}")
    console.print(f"  Risks intelligently adjusted: {stats.get('risks_adjusted', 0)}")
    
    console.print("\n[bold green]✅ Demo completed successfully![/bold green]")
    console.print("[dim]This shows how SentinelSweep intelligently reduces false positives[/dim]")

if __name__ == "__main__":
    main()
