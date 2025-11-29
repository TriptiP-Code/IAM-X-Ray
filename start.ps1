# start.ps1 - Works everywhere
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root

if (-not (Test-Path ".venv")) {
    Write-Host ".venv not found! Run setup.ps1 first." -ForegroundColor Red
    Exit 1
}

& .\.venv\Scripts\Activate.ps1

# Load .env if exists
if (Test-Path ".env") {
    Get-Content .env | Where-Object { $_ -and -not $_.StartsWith("#") } | ForEach-Object {
        if ($_ -match "^\s*([^=]+)=(.*)$") {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
    Write-Host ".env loaded"
}

Write-Host "Starting IAM X-Ray..." -ForegroundColor Cyan
Write-Host "Open your browser: http://localhost:8501" -ForegroundColor Green

streamlit run app/main.py --server.port=8501 --server.address=0.0.0.0

Pop-Location