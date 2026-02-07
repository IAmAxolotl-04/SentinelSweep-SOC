Write-Host "Initializing SentinelSweep..."

mkdir src, reports, logs -ErrorAction SilentlyContinue | Out-Null

@"
python-dotenv
pandas
rich
"@ | Out-File requirements.txt -Encoding utf8

@"
venv/
__pycache__/
.env
reports/
logs/
"@ | Out-File .gitignore -Encoding utf8

@"
NETWORK_CIDR=192.168.1.0/24
PORTS=22,80,443,3389
MAX_THREADS=100
TIMEOUT=0.5
"@ | Out-File config.env -Encoding utf8

@"
print('SentinelSweep ready')
"@ | Out-File src/main.py -Encoding utf8

Write-Host "SentinelSweep initialized successfully."
