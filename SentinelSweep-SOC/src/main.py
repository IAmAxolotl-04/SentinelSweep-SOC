"""
SentinelSweep-SOC v2.0 Main Orchestrator
SOC-grade defensive network exposure assessment.
"""

import os
import sys
import time
from datetime import datetime
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Local imports
from src.banner import display_banner
from src.scanner import DefenderSafeScanner
from src.risk_engine import SOCRiskEngine
from src.reporter import SOCReporter

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel

def main():
    """Main execution flow."""
    
    console = Console()
    
    # Display compliance banner
    if not display_banner():
        sys.exit(1)
    
    # Load configuration
    try:
        load_dotenv('config.env')
        
        NETWORK_CIDR = os.getenv('NETWORK_CIDR', '192.168.1.0/24')
        PORTS = list(map(int, os.getenv('PORTS', '22,80,443,3389').split(',')))
        TIMEOUT = float(os.getenv('TIMEOUT', '1.5'))
        DELAY = float(os.getenv('DELAY', '0.25'))
        MAX_THREADS = int(os.getenv('MAX_THREADS', '50'))
        
        console.print(f"[cyan]Configuration Loaded:[/cyan]")
        console.print(f"  Network: {NETWORK_CIDR}")
        console.print(f"  Ports: {PORTS}")
        console.print(f"  Max Threads: {MAX_THREADS}")
        console.print()
        
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)
    
    # Initialize components
    scanner = DefenderSafeScanner(timeout=TIMEOUT, max_workers=MAX_THREADS)
    risk_engine = SOCRiskEngine()
    reporter = SOCReporter()
    
    # Get target hosts
    targets = scanner.validate_cidr(NETWORK_CIDR)
    
    if not targets:
        console.print("[red]No valid targets found. Check CIDR notation.[/red]")
        sys.exit(1)
    
    console.print(f"[green]Targets identified: {len(targets)} hosts[/green]")
    
    # Perform scan with progress bar
    assessments = []
    scan_start = time.time()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Scanning network...", total=len(targets))
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_host = {
                executor.submit(scanner.scan_host, host, PORTS, DELAY): host 
                for host in targets[:50]  # Limit for demo
            }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                
                try:
                    open_ports = future.result(timeout=TIMEOUT * len(PORTS) + 5)
                    
                    if open_ports:
                        assessment = risk_engine.assess_exposure(host, open_ports)
                        assessments.append(assessment)
                        
                        # Display finding
                        risk_color = {
                            'CRITICAL': 'red',
                            'HIGH': 'yellow',
                            'MEDIUM': 'cyan',
                            'LOW': 'green'
                        }.get(assessment['risk_level'], 'white')
                        
                        console.print(
                            f"[{risk_color}]• {host}: {len(open_ports)} ports open "
                            f"({assessment['risk_level']})[/{risk_color}]"
                        )
                    
                except Exception as e:
                    console.print(f"[yellow]Warning scanning {host}: {e}[/yellow]")
                
                progress.update(task, advance=1)
    
    scan_duration = time.time() - scan_start
    
    # Generate summary and reports
    summary = risk_engine.generate_executive_summary(assessments)
    
    console.print()
    console.print(Panel.fit(
        f"[bold]Scan Complete[/bold]\n"
        f"Duration: {scan_duration:.1f}s\n"
        f"Hosts with exposure: {summary['hosts_with_exposure']}/{summary['total_hosts']}\n"
        f"Critical findings: {summary['critical_hosts']}\n"
        f"Scanner stats: {scanner.get_stats()}",
        title="Summary",
        border_style="green"
    ))
    
    # Generate reports
    try:
        report_paths = reporter.generate_reports(assessments, summary)
        
        console.print("\n[bold green]📊 Reports Generated:[/bold green]")
        for format_name, path in report_paths.items():
            if format_name != 'metadata':
                console.print(f"  • {format_name.upper()}: {path}")
        
        # Check for drift
        drift_result = reporter.detect_drift(assessments)
        if drift_result['drift_detected']:
            console.print(
                Panel.fit(
                    f"[yellow]⚠️  DRIFT DETECTED[/yellow]\n"
                    f"Network configuration has changed since baseline.\n"
                    f"Baseline: {drift_result['baseline_time']}",
                    title="Drift Detection Alert",
                    border_style="yellow"
                )
            )
        
    except Exception as e:
        console.print(f"[red]Error generating reports: {e}[/red]")
        sys.exit(1)
    
    # Display final summary table
    if assessments:
        table = Table(title="Top Findings", show_header=True, header_style="bold magenta")
        table.add_column("IP", style="cyan")
        table.add_column("Ports", style="white")
        table.add_column("Risk", justify="right")
        table.add_column("MITRE", style="yellow")
        
        for assessment in sorted(assessments, 
                                key=lambda x: x['risk_score'], 
                                reverse=True)[:10]:
            
            mitre_str = ', '.join([f['technique'] for f in assessment['mitre_findings'][:2]])
            table.add_row(
                assessment['ip'],
                ', '.join(map(str, assessment['open_ports'][:5])),
                f"[bold]{assessment['risk_level']}[/bold]",
                mitre_str if mitre_str else "None"
            )
        
        console.print(table)
    
    console.print("\n[bold green]✅ SentinelSweep-SOC assessment completed successfully![/bold green]")
    console.print("[dim]Next: Review reports in /reports/ directory[/dim]")

if __name__ == "__main__":
    main()
