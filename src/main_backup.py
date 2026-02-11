"""
SentinelSweep-SOC v2.0 Main Orchestrator
SOC-grade defensive network exposure assessment with intelligent triage.
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
from src.triage_engine import TriageEngine

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

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
    triage_engine = TriageEngine()  # Single instance for stats tracking
    
    # Get target hosts
    targets = scanner.validate_cidr(NETWORK_CIDR)
    
    if not targets:
        console.print("[red]No valid targets found. Check CIDR notation.[/red]")
        sys.exit(1)
    
    console.print(f"[green]Targets identified: {len(targets)} hosts[/green]")
    console.print("[yellow]Note: Running in demo mode (first 10 hosts only)[/yellow]")
    
    # Limit targets for demo
    demo_targets = targets[:10]
    
    # Perform scan with progress bar
    assessments = []
    scan_start = time.time()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Scanning network...", total=len(demo_targets))
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_host = {
                executor.submit(scanner.scan_host, host, PORTS, DELAY): host 
                for host in demo_targets
            }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                
                try:
                    open_ports = future.result(timeout=TIMEOUT * len(PORTS) + 5)
                    
                    if open_ports:
                        host_assessments = []
                        
                        # Triage each open port individually
                        for port in open_ports:
                            # Only perform deep triage on critical ports
                            if port in [22, 3389, 445, 21, 23, 80, 443]:
                                triage_data = triage_engine.triage_service(host, port)
                                assessment = risk_engine.assess_exposure(host, [port], triage_data)
                                
                                # Color-coded display based on risk
                                risk_level = assessment['true_risk']
                                risk_color = {
                                    'CRITICAL': 'bright_red',
                                    'HIGH': 'red',
                                    'MEDIUM': 'yellow',
                                    'LOW': 'green'
                                }.get(risk_level, 'white')
                                
                                service_name = triage_data.get('service_guess', f'Port-{port}')
                                reason = assessment.get('adjustment_reason', '')
                                
                                # Show only MEDIUM and HIGH risks (LOW is usually OK)
                                if risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
                                    icon = '⚠️ ' if risk_level in ['HIGH', 'CRITICAL'] else '•'
                                    progress.console.print(
                                        f"[{risk_color}]{icon} {host}:{port} ({service_name}) -> {risk_level}[/{risk_color}]"
                                    )
                                    if reason and risk_level != 'CRITICAL':
                                        progress.console.print(f"    [dim]{reason}[/dim]")
                                
                            else:
                                # Quick assessment for non-critical ports
                                assessment = risk_engine.assess_exposure(host, [port])
                            
                            host_assessments.append(assessment)
                        
                        # Add all assessments to main list
                        assessments.extend(host_assessments)
                        
                        # Show summary for host
                        if host_assessments:
                            critical_count = sum(1 for a in host_assessments if a['true_risk'] in ['CRITICAL', 'HIGH'])
                            if critical_count > 0:
                                progress.console.print(f"[dim]  Found {critical_count} high-risk services on {host}[/dim]")
                    
                    else:
                        # Host with no open ports
                        progress.console.print(f"[dim]  {host}: No open ports found[/dim]")
                
                except Exception as e:
                    progress.console.print(f"[yellow]Warning scanning {host}: {e}[/yellow]")
                
                progress.update(task, advance=1)
    
    scan_duration = time.time() - scan_start
    
    # Show triage statistics
    triage_stats = triage_engine.get_stats()
    console.print()
    console.print(Panel.fit(
        f"[bold]Scan Complete[/bold]\n"
        f"Duration: {scan_duration:.1f}s\n"
        f"Hosts scanned: {len(demo_targets)}\n"
        f"Services triaged: {triage_stats['services_triaged']}\n"
        f"Banners grabbed: {triage_stats['banners_grabbed']}\n"
        f"Risks adjusted: {triage_stats['risks_adjusted']}",
        title="Performance Summary",
        border_style="green"
    ))
    
    # Generate summary and reports
    if assessments:
        summary = risk_engine.generate_executive_summary(assessments)
        
        console.print()
        console.print(Panel.fit(
            f"[bold]Exposure Summary[/bold]\n"
            f"Hosts with exposure: {summary['hosts_with_exposure']}/{summary['total_hosts']}\n"
            f"Critical: {summary['critical_hosts']} | High: {summary['high_hosts']}\n"
            f"Medium: {summary['medium_hosts']} | Low: {summary['low_hosts']}\n"
            f"Risks auto-adjusted: {summary['adjusted_risks']}",
            title="Risk Assessment",
            border_style="blue"
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
        
        # Display final summary table (top 10 findings)
        if assessments:
            table = Table(title="Top 10 Findings", show_header=True, header_style="bold magenta")
            table.add_column("Host", style="cyan", no_wrap=True)
            table.add_column("Service", style="white")
            table.add_column("Risk", justify="center")
            table.add_column("Context", style="yellow")
            
            # Sort by risk score (highest first) and take top 10
            sorted_assessments = sorted(assessments, 
                                      key=lambda x: x.get('risk_score', 0), 
                                      reverse=True)[:10]
            
            for assessment in sorted_assessments:
                ip = assessment['ip']
                ports = assessment['open_ports']
                risk = assessment['true_risk']
                
                # Get service name from triage details if available
                service_name = "Multiple" if len(ports) > 1 else ""
                if len(ports) == 1:
                    context = assessment.get('context', {})
                    triage_details = context.get('triage_details', {})
                    service_name = triage_details.get('service_guess', f'Port {ports[0]}')
                
                # Get adjustment reason if available
                context_note = assessment.get('adjustment_reason', 'Standard detection')
                
                # Color code risk column
                risk_style = {
                    'CRITICAL': 'bright_red',
                    'HIGH': 'red',
                    'MEDIUM': 'yellow',
                    'LOW': 'green'
                }.get(risk, 'white')
                
                table.add_row(
                    ip,
                    service_name,
                    f"[{risk_style}]{risk}[/{risk_style}]",
                    context_note[:40] + "..." if len(context_note) > 40 else context_note
                )
            
            console.print(table)
        
        console.print("\n[bold green]✅ SentinelSweep-SOC assessment completed successfully![/bold green]")
        console.print("[dim]Next: Review reports in /reports/ directory[/dim]")
    else:
        console.print("\n[green]✅ No exposures found. Network appears secure![/green]")

if __name__ == "__main__":
    main()
