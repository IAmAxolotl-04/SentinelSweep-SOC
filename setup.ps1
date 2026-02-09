# SentinelSweep-SOC Setup Script
# Run this to initialize the project environment

Write-Host "Setting up SentinelSweep-SOC v2.0..." -ForegroundColor Cyan

# Check Python installation
 = python --version 2>&1
if ( -ne 0) {
    Write-Host "❌ Python not found. Please install Python 3.8 or higher." -ForegroundColor Red
    exit 1
}
Write-Host "✓ Python found: " -ForegroundColor Green

# Create virtual environment
Write-Host "Creating virtual environment..." -ForegroundColor Yellow
python -m venv venv
if ( -ne 0) {
    Write-Host "❌ Failed to create virtual environment" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Virtual environment created" -ForegroundColor Green

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv\Scripts\Activate.ps1") {
    & .\venv\Scripts\Activate.ps1
    Write-Host "✓ Virtual environment activated" -ForegroundColor Green
} else {
    Write-Host "❌ Could not activate virtual environment" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip
pip install -r requirements.txt
if ( -ne 0) {
    Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Dependencies installed" -ForegroundColor Green

# Create sample configuration if config.env doesn't exist
if (-not (Test-Path "config.env")) {
    Write-Host "Creating sample configuration..." -ForegroundColor Yellow
    Copy-Item "config.env.example" -Destination "config.env" -ErrorAction SilentlyContinue
    Write-Host "✓ Sample configuration created" -ForegroundColor Green
}

# Display setup completion
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Green
Write-Host "✅ SETUP COMPLETE" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Edit config.env with your network settings"
Write-Host "2. Run: python src/main.py"
Write-Host "3. Check generated reports in /reports/"
Write-Host ""
Write-Host "Need help? Check README.md for detailed instructions"
Write-Host ""
