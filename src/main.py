"""
Clean Main File - Just Works Version
"""

import os
import sys
from dotenv import load_dotenv

from banner import display_banner
from scanner import DefenderSafeScanner
from risk_engine import SOCRiskEngine
from triage_engine import TriageEngine
from reporter import SOCReporter

from rich.console import Console

def main():
    console = Console()
    
    # Display compliance banner
    if not display_banner():
        sys.exit(1)
    
    # Load configuration
    try:
        load_dotenv('config.env')
        
        NETWORK_CIDR = os.getenv('NETWORK_CIDR', '192.168.1.0/24')
        PORTS = [22, 80, 443, 3389]  # Simple defaults
        
        console.print(f"[cyan]Configuration Loaded:[/cyan]")
        console.print(f"  Network: {NETWORK_CIDR}")
        console.print(f"  Ports: {PORTS}")
        
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)
    
    # Initialize components
    scanner = DefenderSafeScanner()
    risk_engine = SOCRiskEngine()
    triage_engine = TriageEngine()
    reporter = SOCReporter()
    
    # Get target hosts (limit to 5 for testing)
    targets = scanner.validate_cidr(NETWORK_CIDR)[:5]
    
    if not targets:
        console.print("[red]No valid targets found.[/red]")
        sys.exit(1)
    
    console.print(f"[green]Testing with {len(targets)} hosts[/green]")
    
    assessments = []
    
    # Simple scan loop
    for host in targets:
        console.print(f"[dim]Checking {host}...[/dim]")
        
        # For demo, just check a few common ports
        open_ports = []
        for port in PORTS:
            # Simple port check
            if scanner.scan_host(host, [port], delay=0.1):
                open_ports.append(port)
                
                # Triage the service
                triage_data = triage_engine.triage_service(host, port)
                assessment = risk_engine.assess_exposure(host, [port], triage_data)
                assessments.append(assessment)
                
                # Show finding
                risk = assessment['true_risk']
                if risk in ['HIGH', 'CRITICAL']:
                    console.print(f"[red]  ! {host}:{port} -> {risk}[/red]")
                elif risk == 'MEDIUM':
                    console.print(f"[yellow]  • {host}:{port} -> {risk}[/yellow]")
        
        if not open_ports:
            console.print(f"[dim]  No open ports[/dim]")
    
    # Generate summary
    if assessments:
        summary = risk_engine.generate_executive_summary(assessments)
        
        console.print("\n[bold]Summary:[/bold]")
        console.print(f"  Total findings: {summary['total_hosts']}")
        console.print(f"  High/Critical: {summary['critical_hosts'] + summary['high_hosts']}")
        
        # Generate reports
        try:
            report_paths = reporter.generate_reports(assessments, summary)
            console.print(f"\n[green]Reports saved to /reports/[/green]")
        except Exception as e:
            console.print(f"[yellow]Note: Could not generate reports: {e}[/yellow]")
    else:
        console.print("\n[green]✅ No exposures found![/green]")
    
    console.print("\n[bold green]Scan complete![/bold green]")

if __name__ == "__main__":
    main()




