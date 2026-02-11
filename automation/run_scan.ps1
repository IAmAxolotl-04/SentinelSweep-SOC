# SentinelSweep-SOC Automated Scan Runner
# Run this script via Task Scheduler for daily assessments

Write-Host "Starting SentinelSweep-SOC Automated Scan..." -ForegroundColor Cyan

# Activate virtual environment if it exists
if (Test-Path "venv\Scripts\Activate.ps1") {
    & .\venv\Scripts\Activate.ps1
    Write-Host "Virtual environment activated" -ForegroundColor Green
}

# Install dependencies if needed
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
}

# Run the scan
python src/main.py

# Check for reports
 = Get-ChildItem "reports\*.json" | Sort-Object LastWriteTime | Select-Object -Last 1

if () {
    Write-Host "Scan completed. Report generated: " -ForegroundColor Green
    
    # Optional: Send notification
    # Send-MailMessage -To "security-team@example.com" -Subject "SentinelSweep Scan Complete" -Body "New scan report available"
} else {
    Write-Host "Scan completed but no report generated." -ForegroundColor Yellow
}

Write-Host "Automation complete." -ForegroundColor Cyan
