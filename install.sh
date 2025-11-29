#!/usr/bin/env bash
set -euo pipefail

# Better OS detection
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Running Linux/macOS setup..."
    if [ ! -f "setup.sh" ]; then
        echo "setup.sh not found!"
        exit 1
    fi
    chmod +x setup.sh
    ./setup.sh
    echo "Done! Now run: ./start.sh"

elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]] || [[ -n "$COMSPEC" ]]; then
    echo "Windows detectedystem detected"
    if [ -f "setup.ps1" ]; then
        if command -v pwsh >/dev/null 2>&1; then
            pwsh -File ./setup.ps1
        else
            powershell -ExecutionPolicy Bypass -File ./setup.ps1
        fi
        echo "Done! Now run: .\\start.ps1"
    else
        echo "setup.ps1 not found!"
        exit 1
    fi
else
    echo "Unknown OS, trying bash setup..."
    chmod +x setup.sh 2>/dev/null || true
    ./setup.sh || echo "Failed. Try running setup.ps1 manually on Windows."
fi