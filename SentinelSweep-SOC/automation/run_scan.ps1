# SentinelSweep-SOC Automated Scan Runner with Logging
# Run this script via Task Scheduler for daily assessments

# --- Setup ---
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$LogDir = Join-Path $ProjectRoot "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

$LogFile = Join-Path $LogDir ("scan_log_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")
Start-Transcript -Path $LogFile -Append

Write-Host "=== Starting SentinelSweep-SOC Automated Scan ===" -ForegroundColor Cyan

# --- Activate virtual environment ---
$VenvActivate = Join-Path $ProjectRoot "venv\Scripts\Activate.ps1"
if (Test-Path $VenvActivate) {
    & $VenvActivate
    Write-Host "Virtual environment activated" -ForegroundColor Green
} else {
    Write-Host "Virtual environment not found!" -ForegroundColor Yellow
}

# --- Install dependencies if needed ---
$RequirementsFile = Join-Path $ProjectRoot "requirements.txt"
if (Test-Path $RequirementsFile) {
    Write-Host "Installing dependencies..." -ForegroundColor Cyan
    pip install -r $RequirementsFile
}

# --- Run the scan ---
Write-Host "Running SentinelSweep scan..." -ForegroundColor Cyan
python -m src.main

# --- Check for latest JSON report ---
$ReportsDir = Join-Path $ProjectRoot "reports"
$latestReport = Get-ChildItem "$ReportsDir\*.json" | Sort-Object LastWriteTime | Select-Object -Last 1

if ($latestReport) {
    Write-Host "Scan completed. Report generated: $($latestReport.FullName)" -ForegroundColor Green
    
    # Optional: Send notification
    # Send-MailMessage -To "security-team@example.com" `
    #                  -Subject "SentinelSweep Scan Complete" `
    #                  -Body "New scan report available: $($latestReport.FullName)"
} else {
    Write-Host "Scan completed but no report generated." -ForegroundColor Yellow
}

Write-Host "=== Automation complete ===" -ForegroundColor Cyan

Stop-Transcript

