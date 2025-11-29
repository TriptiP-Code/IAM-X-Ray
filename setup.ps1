# setup.ps1 - Works on Windows PowerShell 5.1 and PowerShell 7+
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "IAM X-Ray Setup Starting..." -ForegroundColor Cyan

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root

# ------------------------------
# 1. Python check
# ------------------------------
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python NOT FOUND. Please install Python 3.9+ from python.org and ensure it's in PATH." -ForegroundColor Red
    Exit 1
}

# ------------------------------
# 2. Create Virtual Environment
# ------------------------------
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
    Write-Host ".venv created."
} else {
    Write-Host ".venv already exists — skipping"
}

# Activate venv
& .\.venv\Scripts\Activate.ps1

# ------------------------------
# 3. Install Dependencies
# ------------------------------
Write-Host "Installing dependencies..."
python -m pip install --upgrade pip | Out-Null
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
    Write-Host "Dependencies installed."
} else {
    Write-Host "requirements.txt missing!" -ForegroundColor Red
    Exit 1
}

# ------------------------------
# 4. Create .env file if missing
# ------------------------------
$envFile = ".env"
if (-not (Test-Path $envFile)) {
    Write-Host "Generating encryption key..."
    $key = python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    
    $content = @"
IAM_XRAY_FERNET_KEY=$key
AWS_REGION=us-east-1
CACHE_TTL=3600
KEEP_DAYS=30
"@

    $content | Out-File -FilePath $envFile -Encoding UTF8
    Write-Host ".env created with secure key."
} else {
    Write-Host ".env already exists — skipping"
}

# ------------------------------
# 5. Ensure demo snapshot exists
# ------------------------------
Write-Host "Ensuring demo snapshot..."
python -c "
import os, json, sys
os.makedirs('data', exist_ok=True)
demo_path = 'data/sample_snapshot.json'

if not os.path.exists(demo_path):
    demo = {
        '_meta': {
            'fetched_at': 'demo',
            'fast_mode': True,
            'counts': {'users': 3, 'roles': 1, 'policies': 3}
        },
        'users': [
            {'UserName': 'demo-user', 'Arn': 'arn:aws:iam::123456:user/demo', 'IsRisky': False,
             'AttachedPolicies': [{'PolicyName': 'DemoPolicy'}]},
            {'UserName': 'alice', 'Arn': 'arn:aws:iam::123456:user/alice', 'IsRisky': True,
             'AttachedPolicies': [{'PolicyName': 'AdminPolicy'}]},
            {'UserName': 'bob', 'Arn': 'arn:aws:iam::123456:user/bob', 'IsRisky': False,
             'AttachedPolicies': [{'PolicyName': 'ReadOnlyPolicy'}]}
        ],
        'roles': [
            {'RoleName': 'DemoRole', 'AttachedPolicies': [{'PolicyName': 'DemoPolicy'}],
             'AssumePolicyRisk': False}
        ],
        'groups': [],
        'policies': [
            {'PolicyName': 'DemoPolicy', 'RiskScore': 1, 'IsRisky': False,
             'Arn': 'arn:aws:iam::123456:policy/DemoPolicy'},
            {'PolicyName': 'AdminPolicy', 'RiskScore': 9, 'IsRisky': True,
             'Arn': 'arn:aws:iam::123456:policy/AdminPolicy'},
            {'PolicyName': 'ReadOnlyPolicy', 'RiskScore': 1, 'IsRisky': False,
             'Arn': 'arn:aws:iam::123456:policy/ReadOnlyPolicy'}
        ]
    }
    with open(demo_path, 'w', encoding='utf-8') as f:
        json.dump(demo, f, indent=2)
    print('Demo snapshot created:', demo_path)
else:
    print('Demo snapshot already exists.')
"

Write-Host "Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To start the app:" -ForegroundColor Yellow
Write-Host "   .\start.ps1" -ForegroundColor White
Write-Host ""
Write-Host "First time? Just run .\start.ps1 and select 'Demo' mode!" -ForegroundColor Cyan

Pop-Location