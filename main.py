"""
SentinelSweep-SOC Main Entry Point
"""

import os
import sys
from dotenv import load_dotenv

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

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
        PORTS = list(map(int, os.getenv('PORTS', '22,80,443,3389').split(',')))
        
        console.print(f"[cyan]Configuration:[/cyan]")
        console.print(f"  Network: {NETWORK_CIDR}")
        console.print(f"  Ports: {PORTS}")
        console.print()
        
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        sys.exit(1)
    
    # Initialize components
    scanner = DefenderSafeScanner()
    risk_engine = SOCRiskEngine()
    triage_engine = TriageEngine()
    
    console.print("[green]Initializing scan...[/green]")
    
    # Get target hosts (limit for testing)
    targets = scanner.validate_cidr(NETWORK_CIDR)
    if not targets:
        console.print("[red]No valid targets[/red]")
        sys.exit(1)
    
    # Limit to 3 hosts for quick test
    test_targets = targets[:3]
    console.print(f"[dim]Testing with {len(test_targets)} hosts[/dim]")
    
    assessments = []
    
    # Simple scan
    for host in test_targets:
        console.print(f"[dim]Scanning {host}...[/dim]")
        
        # Check each port
        for port in PORTS:
            # Simple port check
            result = scanner.scan_host(host, [port], delay=0.1)
            if result:  # If port is open
                console.print(f"[yellow]  Found open port: {port}[/yellow]")
                
                # Triage the service
                triage_data = triage_engine.triage_service(host, port)
                
                # Create assessment
                assessment = risk_engine.assess_exposure(host, [port], triage_data)
                assessments.append(assessment)
                
                # Show risk
                risk_color = {
                    'CRITICAL': 'red',
                    'HIGH': 'bright_red',
                    'MEDIUM': 'yellow',
                    'LOW': 'green'
                }.get(assessment['true_risk'], 'white')
                
                console.print(f"[{risk_color}]    Risk: {assessment['true_risk']} - {assessment.get('adjustment_reason', '')}[/{risk_color}]")
    
    # Summary
    if assessments:
        console.print(f"\n[green]✅ Found {len(assessments)} exposed services[/green]")
        
        # Generate report
        try:
            reporter = SOCReporter()
            summary = risk_engine.generate_executive_summary(assessments)
            report_paths = reporter.generate_reports(assessments, summary)
            
            console.print(f"[cyan]Reports generated in /reports/ folder[/cyan]")
        except Exception as e:
            console.print(f"[yellow]Note: Report generation skipped: {e}[/yellow]")
    else:
        console.print(f"\n[green]✅ No exposed services found[/green]")
    
    console.print(f"\n[bold green]Scan complete![/bold green]")

if __name__ == "__main__":
    main()
